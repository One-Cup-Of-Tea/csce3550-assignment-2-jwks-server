# Basic JWKS Server

An educational REST service that creates two RSA key pairs at startup and issues RS256 JSON Web Tokens (JWTs). One key is active for one hour; the other is already expired. The JWKS endpoint intentionally publishes only currently valid public keys.

## Requirements

- Node.js 20 or newer (tested with Node 24)

No external packages are required.

## Run

```sh
npm start
```

The service listens on port `8080` by default. Set `PORT` to use another port.

## API

| Method | Endpoint | Result |
| --- | --- | --- |
| `GET` | `/.well-known/jwks.json` | A JWKS document containing only unexpired RSA public keys. |
| `POST` | `/auth` | A JSON object with an unexpired JWT, signed by the active key. No request body is required. |
| `POST` | `/auth?expired` | A JSON object with an expired JWT, signed by the expired key. |

Example:

```sh
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth
curl -X POST 'http://localhost:8080/auth?expired'
```

Each token uses `RS256` and carries the signing key's `kid` in its protected JWT header. The expired token's key is deliberately not published in the JWKS response.

## Quality checks

```sh
npm run lint
npm test
npm run coverage
```

The tests cover key selection and expiry filtering, JWKS route behavior, normal and expired authentication responses, unsupported routes, JWT contents, and RSA signature verification. Node's built-in test coverage report is included in the `coverage` command output.

## Submission evidence

Run the provided course test client while this server is running, then capture its successful output. Also run `npm run coverage` and capture its percentage. Add both screenshots to this repository before submitting, with your name and date visible as required by the course.

This project intentionally mocks user authentication. Production services should use persistent key rotation, an authenticated identity provider, strict input policies, TLS, and secret/key management.
