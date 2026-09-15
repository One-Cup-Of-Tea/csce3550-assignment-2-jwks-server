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
  constructor({ now = () => Date.now(), keyGenerator = generateRsaKeyPair } = {}) {
    this.now = now;
    this.keyGenerator = keyGenerator;
    this.activeKey = this.createKey(this.now() + ACTIVE_KEY_LIFETIME_MS);
    this.expiredKey = this.createKey(this.now() - EXPIRED_KEY_AGE_MS);
  }

  createKey(expiresAt) {
    const pair = this.keyGenerator();

    return {
      kid: randomUUID(),
      expiresAt,
      privateKey: pair.privateKey,
      publicJwk: {
        ...pair.publicKey.export({ format: 'jwk' }),
        kid: undefined,
        use: 'sig',
        alg: 'RS256',
        kty: 'RSA'
      }
    };
  }

  getSigningKey({ expired = false } = {}) {
    return expired ? this.expiredKey : this.activeKey;
  }

  getPublicKeys() {
    const currentTime = this.now();

    return [this.activeKey, this.expiredKey]
      .filter((key) => key.expiresAt > currentTime)
      .map((key) => ({ ...key.publicJwk, kid: key.kid }));
  }
}

function generateRsaKeyPair() {
  return generateKeyPairSync('rsa', {
    modulusLength: RSA_MODULUS_LENGTH
  });
}

module.exports = { KeyStore, generateRsaKeyPair };
