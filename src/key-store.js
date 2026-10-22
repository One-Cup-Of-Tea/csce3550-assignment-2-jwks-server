'use strict';

const { generateKeyPairSync, randomUUID } = require('node:crypto');

const RSA_MODULUS_LENGTH = 2048;
const ACTIVE_KEY_LIFETIME_MS = 60 * 60 * 1000;
const EXPIRED_KEY_AGE_MS = 60 * 60 * 1000;

/**
 * Stores RSA signing keys and provides their public representations as JWKs.
 * A real system would persist and rotate these keys in a key-management service.
 */
class KeyStore {
  /**
   * Creates an in-memory store for legacy unit tests.
   * The running server uses DatabaseKeyStore instead.
   *
   * @param {{ now?: () => number, keyGenerator?: () => object }} options
   * Clock and key-pair generator overrides for deterministic tests.
   */
  constructor({ now = () => Date.now(), keyGenerator = generateRsaKeyPair } = {}) {
    this.now = now;
    this.keyGenerator = keyGenerator;
    this.activeKey = this.createKey(this.now() + ACTIVE_KEY_LIFETIME_MS);
    this.expiredKey = this.createKey(this.now() - EXPIRED_KEY_AGE_MS);
  }

  /**
   * Generates one signing key record.
   *
   * @param {number} expiresAt Expiration time in milliseconds since epoch.
   * @returns {object} An RSA private key and its public JWK representation.
   */
  createKey(expiresAt) {
    const pair = this.keyGenerator();

    return {
      kid: randomUUID(),
      expiresAt,
      privateKey: pair.privateKey,
      publicJwk: {
        ...pair.publicKey.export({ format: 'jwk' }),
        use: 'sig',
        alg: 'RS256',
        kty: 'RSA'
      }
    };
  }

  /**
   * Selects the current or deliberately expired signing key.
   *
   * @param {{ expired?: boolean }} options Choose the expired key when true.
   * @returns {object} The selected in-memory key record.
   */
  getSigningKey({ expired = false } = {}) {
    return expired ? this.expiredKey : this.activeKey;
  }

  /**
   * Returns public JWKs for keys whose expiration is still in the future.
   *
   * @returns {Array<object>} Currently valid public signing keys.
   */
  getPublicKeys() {
    const currentTime = this.now();

    return [this.activeKey, this.expiredKey]
      .filter((key) => key.expiresAt > currentTime)
      .map((key) => ({ ...key.publicJwk, kid: key.kid }));
  }
}

/** @returns {object} A newly generated 2048-bit RSA key pair. */
function generateRsaKeyPair() {
  return generateKeyPairSync('rsa', {
    modulusLength: RSA_MODULUS_LENGTH
  });
}

module.exports = { KeyStore, generateRsaKeyPair };
