'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');

const { DatabaseKeyStore } = require('../src/database-key-store');

function createTestStore() {
  const folder = mkdtempSync(path.join(tmpdir(), 'jwks-test-'));
  const dbPath = path.join(folder, 'test.db');
  const now = 1_800_000_000_000;

  const store = new DatabaseKeyStore({
    now: () => now,
    dbPath
  });

  return { store, folder, dbPath, now };
}

function cleanUp(store, folder) {
  store.db.close();
  rmSync(folder, { recursive: true, force: true });
}

test('DatabaseKeyStore stores active and expired keys correctly', () => {
  const { store, folder, now } = createTestStore();

  try {
    const publicKeys = store.getPublicKeys();
    const activeKey = store.getSigningKey();
    const expiredKey = store.getSigningKey({ expired: true });

    assert.equal(publicKeys.length, 1);

    assert.equal(publicKeys[0].kid, activeKey.kid);
    assert.equal(publicKeys[0].kty, 'RSA');
    assert.equal(publicKeys[0].alg, 'RS256');
    assert.equal(publicKeys[0].use, 'sig');

    assert.ok(publicKeys[0].n);
    assert.ok(publicKeys[0].e);

    assert.ok(activeKey.expiresAt > now);
    assert.ok(expiredKey.expiresAt <= now);

    assert.equal(
      publicKeys.some((key) => key.kid === expiredKey.kid),
      false
    );
  } finally {
    cleanUp(store, folder);
  }
});

test('DatabaseKeyStore returns null for a missing key', () => {
  const { store, folder } = createTestStore();

  try {
    const key = store.getKeyById(999999);

    assert.equal(key, null);
  } finally {
    cleanUp(store, folder);
  }
});

test('DatabaseKeyStore keeps keys in the database', () => {
  const { store, folder, dbPath, now } = createTestStore();

  try {
    const firstKey = store.getSigningKey();
    const firstKid = firstKey.kid;

    store.db.close();

    const reopenedStore = new DatabaseKeyStore({
      now: () => now,
      dbPath
    });

    try {
      const reopenedKey = reopenedStore.getSigningKey();

      assert.equal(reopenedKey.kid, firstKid);
    } finally {
      reopenedStore.db.close();
    }
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
});