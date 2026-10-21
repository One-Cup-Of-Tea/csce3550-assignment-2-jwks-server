'use strict';

const { createJwksServer } = require('./src/server');

const port = Number.parseInt(process.env.PORT || '8080', 10);
const server = createJwksServer();

server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${port} is already in use. Stop the other server first.`);
  } else {
    console.error('Unable to start the JWKS server:', error.message);
  }

  process.exitCode = 1;
});

server.listen(port, () => {
  console.log(`JWKS server listening at http://localhost:${port}`);
  console.log(`JWKS endpoint: http://localhost:${port}/.well-known/jwks.json`);
});
