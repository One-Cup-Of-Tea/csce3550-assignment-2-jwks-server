'use strict';

const { sign } = require('node:crypto');

function base64UrlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

/** Creates a compact, RS256-signed JWT using the selected key. */
function issueJwt(key, { now = Date.now } = {}) {
  const issuedAt = Math.floor(now() / 1000);
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: key.kid
  };
  const payload = {
    sub: 'fake-user',
    iat: issuedAt,
    exp: Math.floor(key.expiresAt / 1000)
  };
  const signingInput = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(payload))}`;
  const signature = sign('RSA-SHA256', Buffer.from(signingInput), key.privateKey);

  return `${signingInput}.${signature.toString('base64url')}`;
}

module.exports = { base64UrlEncode, issueJwt };
