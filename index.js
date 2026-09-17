'use strict';

const { createJwksServer } = require('./src/server');

const port = Number.parseInt(process.env.PORT || '8080', 10);
const server = createJwksServer();

server.listen(port, () => {
  console.log(`JWKS server listening at http://localhost:${port}`);
  console.log(`JWKS endpoint: http://localhost:${port}/.well-known/jwks.json`);
});