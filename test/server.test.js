'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createJwksServer } = require('../src/server');

async function withServer(options, callback) {
  const server = createJwksServer(options);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  try {
    await callback(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
}

function makeKey(kid) {
  return { kid, expiresAt: 1_900_000_000_000, privateKey: 'private-key' };
}

test('GET /.well-known/jwks.json returns active public keys only', async () => {
  const keyStore = {
    getPublicKeys: () => [{ kty: 'RSA', kid: 'current', n: 'modulus', e: 'AQAB' }]
  };

  await withServer({ keyStore }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/.well-known/jwks.json`);

    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type'), /^application\/json/);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await response.json(), { keys: keyStore.getPublicKeys() });
  });
});

test('POST /auth returns a token from the active key', async () => {
  const activeKey = makeKey('active');
  const expiredKey = makeKey('expired');
  const keyStore = {
    getSigningKey: ({ expired }) => (expired ? expiredKey : activeKey),
    getPublicKeys: () => []
  };

  await withServer({ keyStore, jwtIssuer: (key) => `token-for-${key.kid}` }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth`, { method: 'POST' });

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { token: 'token-for-active' });
  });
});

test('POST /auth?expired returns a token signed by the expired key', async () => {
  const activeKey = makeKey('active');
  const expiredKey = makeKey('expired');
  const selected = [];
  const keyStore = {
    getSigningKey: ({ expired }) => {
      selected.push(expired);
      return expired ? expiredKey : activeKey;
    },
    getPublicKeys: () => []
  };

  await withServer({ keyStore, jwtIssuer: (key) => `token-for-${key.kid}` }, async (baseUrl) => {
    const response = await fetch(`${baseUrl}/auth?expired` , { method: 'POST' });

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { token: 'token-for-expired' });
    assert.deepEqual(selected, [true]);
  });
});

test('unsupported routes and methods return JSON 404 responses', async () => {
  const keyStore = { getPublicKeys: () => [], getSigningKey: () => makeKey('unused') };

  await withServer({ keyStore, jwtIssuer: () => 'unused' }, async (baseUrl) => {
    const getAuth = await fetch(`${baseUrl}/auth`);
    const unknown = await fetch(`${baseUrl}/unknown`, { method: 'POST' });

    assert.equal(getAuth.status, 404);
    assert.deepEqual(await getAuth.json(), { error: 'Not found' });
    assert.equal(unknown.status, 404);
    assert.deepEqual(await unknown.json(), { error: 'Not found' });
  });
});
