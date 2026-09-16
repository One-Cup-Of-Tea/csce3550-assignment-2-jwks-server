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

class DatabaseKeyStore {
  constructor({ now = () => Date.now(), dbPath } = {}) {
    this.now = now;

    // Always create the database in the project root.
    this.dbPath =
      dbPath || path.join(__dirname, '..', DATABASE_NAME);

    this.db = new Database(this.dbPath);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
      )
    `);

    this.ensureRequiredKeys();
  }

  currentTimeSeconds() {
    return Math.floor(this.now() / 1000);
  }

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

    // Parameterised SQL query.
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

  getKeyById(kid) {
    const row = this.db
      .prepare(
        'SELECT kid, key, exp FROM keys WHERE kid = ?'
      )
      .get(kid);

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

    return this.rowToSigningKey(row);
  }

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
}

module.exports = { DatabaseKeyStore };