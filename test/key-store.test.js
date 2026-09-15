'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const { KeyStore } = require('../src/key-store');

function generateTestPair() {
  return generateKeyPairSync('rsa', { modulusLength: 1024 });
}

test('KeyStore supplies one active key and excludes the expired key from JWKS', () => {
  const now = 1_800_000_000_000;
  const store = new KeyStore({ now: () => now, keyGenerator: generateTestPair });

  const publicKeys = store.getPublicKeys();

  assert.equal(publicKeys.length, 1);
  assert.equal(publicKeys[0].kid, store.activeKey.kid);
  assert.equal(publicKeys[0].use, 'sig');
  assert.equal(publicKeys[0].alg, 'RS256');
  assert.equal(publicKeys[0].kty, 'RSA');
  assert.ok(publicKeys[0].n);
  assert.ok(publicKeys[0].e);
  assert.equal(publicKeys.some((key) => key.kid === store.expiredKey.kid), false);
});

test('KeyStore selects the requested signing key', () => {
  const store = new KeyStore({ keyGenerator: generateTestPair });

  assert.equal(store.getSigningKey(), store.activeKey);
  assert.equal(store.getSigningKey({ expired: true }), store.expiredKey);
});

test('KeyStore removes every key after its expiry time', () => {
  let now = 1_800_000_000_000;
  const store = new KeyStore({ now: () => now, keyGenerator: generateTestPair });

  now = store.activeKey.expiresAt;

  assert.deepEqual(store.getPublicKeys(), []);
});
