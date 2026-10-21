# SQLite-backed JWKS Server

An educational REST service that persists RSA private keys in SQLite and issues RS256 JSON Web Tokens (JWTs). It is the Project 2 extension of the basic JWKS server.

## Requirements

- Node.js 20 or newer (tested with Node 24)
- npm

Install the dependency once after cloning:

```sh
npm install
```

## Run

```sh
npm start
```

The service listens on port `8080` by default. Set `PORT` to use another port.

At startup, the server opens or creates `totally_not_my_privateKeys.db` in the project directory. It creates the required SQLite table:

```sql
CREATE TABLE IF NOT EXISTS keys (
  kid INTEGER PRIMARY KEY AUTOINCREMENT,
  key BLOB NOT NULL,
  exp INTEGER NOT NULL
)
```

The server keeps at least one expired RSA private key and one key valid for one hour in this database. Private keys are serialized as PKCS#8 PEM bytes, then converted back into crypto key objects only when a JWT or JWKS response is needed. All database values are passed with SQLite placeholders (`?`), never constructed through SQL string interpolation.

## API

| Method | Endpoint | Result |
| --- | --- | --- |
| `GET` | `/.well-known/jwks.json` | A JWKS document derived from all unexpired private keys stored in SQLite. |
| `POST` | `/auth` | A JSON object containing an unexpired JWT signed with a valid database key. |
| `POST` | `/auth?expired` | A JSON object containing an expired JWT signed with an expired database key. |

The Project 2 gradebot can send HTTP Basic auth and a JSON body to `/auth`. Authentication is intentionally mocked for this assignment, so those values are accepted and the server still returns a token.

Example requests:

```sh
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth
curl -X POST 'http://localhost:8080/auth?expired'
```

Each JWT uses `RS256`, contains the database `kid` in its protected header, and has an `exp` value matching the selected key. Expired keys are deliberately omitted from the JWKS response.

## Quality checks

```sh
npm run lint
npm test
npm run coverage
```

The tests cover database creation and persistence, expired-versus-active key selection, PKCS#8/JWK conversion, bound SQL parameter behavior, JWT signing, the JWKS route, normal and expired authentication, the gradebot's Basic-auth/JSON request shape, and error routes.

## Gradebot and submission evidence

1. Start the server with `npm start` and leave it running.
2. Run the provided test client using its `project2` command from the project directory so it can see `totally_not_my_privateKeys.db`.
3. Add a screenshot of the client rubric/points table and a screenshot of `npm run coverage` output to `screenshots/`.
4. Ensure both screenshots visibly include your identifying information before pushing to GitHub.

This project deliberately mocks user authentication. A production service should use persistent key rotation, an authenticated identity provider, strict input policies, TLS, secret/key management, and a hardened database deployment.
