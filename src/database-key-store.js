'use strict';

const path = require('node:path');
const {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync
} = require('node:crypto');

const Database = require('better-sqlite3');

const DATABASE_NAME = 'totally_not_my_privateKeys.db';
const KEY_LIFETIME_SECONDS = 60 * 60;

/**
 * Persists RSA private keys in SQLite and derives JWKs only when needed.
 * SQL statements bind all values through placeholders rather than interpolation.
 */
class DatabaseKeyStore {
  /**
   * Opens the SQLite database, creates its schema, and guarantees usable keys.
   *
   * @param {{ now?: () => number, dbPath?: string }} options Configuration for
   * deterministic tests or a custom database location.
   */
  constructor({ now = () => Date.now(), dbPath } = {}) {
    this.now = now;

    this.dbPath =
      dbPath || path.join(__dirname, '..', DATABASE_NAME);

    try {
      this.db = new Database(this.dbPath);
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS keys (
          kid INTEGER PRIMARY KEY AUTOINCREMENT,
          key BLOB NOT NULL,
          exp INTEGER NOT NULL
        )
      `);
      this.ensureRequiredKeys();
    } catch (error) {
      throw new Error(
        `Unable to initialize the SQLite key store at ${this.dbPath}.`,
        { cause: error }
      );
    }
  }

  /** @returns {number} The current UNIX timestamp in seconds. */
  currentTimeSeconds() {
    return Math.floor(this.now() / 1000);
  }

  /**
   * Generates and saves a private key in PKCS#8 PEM form.
   *
   * @param {number} expirationTime UNIX timestamp in seconds.
   * @returns {{ kid: string, expiresAt: number, privateKey: import('node:crypto').KeyObject }}
   */
  createAndStoreKey(expirationTime) {
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048
    });

    const privatePem = Buffer.from(
      privateKey.export({
        type: 'pkcs8',
        format: 'pem'
      })
    );

    // Bound parameters prevent data from becoming executable SQL.
    const result = this.db
      .prepare('INSERT INTO keys (key, exp) VALUES (?, ?)')
      .run(privatePem, expirationTime);

    return this.getKeyById(result.lastInsertRowid);
  }

  ensureRequiredKeys() {
    const now = this.currentTimeSeconds();

    const activeRow = this.db
      .prepare(
        'SELECT kid FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1'
      )
      .get(now);

    if (!activeRow) {
      this.createAndStoreKey(now + KEY_LIFETIME_SECONDS);
    }

    const expiredRow = this.db
      .prepare(
        'SELECT kid FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1'
      )
      .get(now);

    if (!expiredRow) {
      this.createAndStoreKey(now - KEY_LIFETIME_SECONDS);
    }
  }

  /**
   * Looks up a signing key by database identifier.
   *
   * @param {number|string} kid Database key identifier.
   * @returns {{ kid: string, expiresAt: number, privateKey: import('node:crypto').KeyObject }|null}
   */
  getKeyById(kid) {
    const keyId = Number(kid);

    if (!Number.isSafeInteger(keyId) || keyId < 1) {
      return null;
    }

    const row = this.db
      .prepare(
        'SELECT kid, key, exp FROM keys WHERE kid = ?'
      )
      .get(keyId);

    if (!row) {
      return null;
    }

    return this.rowToSigningKey(row);
  }

  rowToSigningKey(row) {
    return {
      kid: String(row.kid),
      expiresAt: row.exp * 1000,
      privateKey: createPrivateKey(row.key)
    };
  }

  /**
   * Retrieves either an unexpired signing key or the most recent expired key.
   *
   * @param {{ expired?: boolean }} options Choose the expired key when true.
   * @returns {{ kid: string, expiresAt: number, privateKey: import('node:crypto').KeyObject }}
   */
  getSigningKey({ expired = false } = {}) {
    this.ensureRequiredKeys();

    const now = this.currentTimeSeconds();

    let row;

    if (expired) {
      row = this.db
        .prepare(`
          SELECT kid, key, exp
          FROM keys
          WHERE exp <= ?
          ORDER BY exp DESC
          LIMIT 1
        `)
        .get(now);
    } else {
      row = this.db
        .prepare(`
          SELECT kid, key, exp
          FROM keys
          WHERE exp > ?
          ORDER BY exp DESC
          LIMIT 1
        `)
        .get(now);
    }

    if (!row) {
      throw new Error('The SQLite key store did not return a signing key.');
    }

    return this.rowToSigningKey(row);
  }

  /**
   * Converts all currently valid private keys into public JWK documents.
   *
   * @returns {Array<Record<string, string>>} Public signing keys for a JWKS.
   */
  getPublicKeys() {
    this.ensureRequiredKeys();

    const now = this.currentTimeSeconds();

    const rows = this.db
      .prepare(`
        SELECT kid, key, exp
        FROM keys
        WHERE exp > ?
        ORDER BY kid ASC
      `)
      .all(now);

    return rows.map((row) => {
      const privateKey = createPrivateKey(row.key);

      const publicJwk = createPublicKey(privateKey).export({
        format: 'jwk'
      });

      return {
        ...publicJwk,
        kid: String(row.kid),
        use: 'sig',
        alg: 'RS256',
        kty: 'RSA'
      };
    });
  }

  /** Closes the SQLite database connection. */
  close() {
    this.db.close();
  }
}

module.exports = { DatabaseKeyStore };
