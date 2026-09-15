'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync, verify } = require('node:crypto');
const { base64UrlEncode, issueJwt } = require('../src/jwt');

function decodePart(part) {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

test('base64UrlEncode emits URL-safe base64', () => {
  assert.equal(base64UrlEncode('a?'), 'YT8');
});

test('issueJwt creates an RS256 token with kid, expiry, and a valid signature', () => {
  const pair = generateKeyPairSync('rsa', { modulusLength: 1024 });
  const expiresAt = 1_800_000_300_000;
  const token = issueJwt(
    { kid: 'active-key', expiresAt, privateKey: pair.privateKey },
    { now: () => 1_800_000_000_000 }
  );
  const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');

  assert.deepEqual(decodePart(encodedHeader), { alg: 'RS256', typ: 'JWT', kid: 'active-key' });
  assert.deepEqual(decodePart(encodedPayload), {
    sub: 'fake-user',
    iat: 1_800_000_000,
    exp: 1_800_000_300
  });
  assert.equal(
    verify(
      'RSA-SHA256',
      Buffer.from(`${encodedHeader}.${encodedPayload}`),
      pair.publicKey,
      Buffer.from(encodedSignature, 'base64url')
    ),
    true
  );
});
