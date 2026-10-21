'use strict';

const http = require('node:http');
const { DatabaseKeyStore } = require('./database-key-store');
const { issueJwt } = require('./jwt');

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store'
  });

  response.end(JSON.stringify(body));
}

/**
 * Builds the HTTP server. A custom key store can be supplied for tests.
 * Database failures are reported as JSON instead of terminating the process.
 */
function createJwksServer({
  keyStore = new DatabaseKeyStore(),
  jwtIssuer = issueJwt
} = {}) {
  return http.createServer((request, response) => {
    try {
      const requestUrl = new URL(
        request.url,
        `http://${request.headers.host || 'localhost'}`
      );

      if (
        request.method === 'GET' &&
        requestUrl.pathname === '/.well-known/jwks.json'
      ) {
        sendJson(response, 200, {
          keys: keyStore.getPublicKeys()
        });

        return;
      }

      if (
        request.method === 'POST' &&
        requestUrl.pathname === '/auth'
      ) {
        const expired =
          requestUrl.searchParams.has('expired');

        const key = keyStore.getSigningKey({
          expired
        });

        sendJson(response, 200, {
          token: jwtIssuer(key)
        });

        return;
      }

      sendJson(response, 404, {
        error: 'Not found'
      });
    } catch (error) {
      console.error('Request handling failed:', error.message);
      sendJson(response, 500, { error: 'Internal server error' });
    }
  });
}

module.exports = {
  createJwksServer,
  sendJson
};
