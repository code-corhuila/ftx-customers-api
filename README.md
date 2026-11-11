# ftx-customers-api

> Customers domain API: administrator login, sessions and the keys that sign them

Part of **Futbolix**, the distributed system for reserving the four football courts of a
single sports facility. Governance and documentation live in
[`ftx-docs`](https://github.com/code-corhuila/ftx-docs). User story: HU-ADM-002 (Administrator
Login). Contract: `ftx-docs/07-api/contracts/openapi/auth-service.yaml`.

ADR-012 places the documented **user-service** in `ftx-customers-*`. It authenticates the only
authenticated actor of the MVP, the **administrator**. Customers have no account and never log in
(`01-context/scope.md`, assumption 3).

## Endpoints

| Method and path | Who | Responses |
|---|---|---|
| `POST /api/v1/auth/login` | Public | 200 `AuthResponse`; 400 invalid body; 401 `INVALID_CREDENTIALS`; 429 `TOO_MANY_REQUESTS` with `Retry-After` |
| `POST /api/v1/auth/refresh` | Public (needs a refresh token) | 200 `AuthResponse` with a **new** refresh token; 400; 401 `INVALID_REFRESH_TOKEN` |
| `POST /api/v1/auth/logout` | `Bearer` access token | 204; 401 `UNAUTHORIZED` |
| `GET /api/v1/auth/jwks` | Public | 200 `{ "keys": [...] }`, public keys only, cacheable 5 minutes |
| `GET /api/v1/health` | Public | 200 `{ "status": "ok", "timestamp", "dependencies": { "database": "ok" } }`; 503 |
| `GET /health/liveness`, `/health/readiness` | Container probes | 200 `UP` |

Responses with tokens carry `Cache-Control: no-store`. Errors use `ErrorResponse` of
`_shared.yaml`, with the request's `X-Correlation-Id` as `traceId`, and never echo a submitted value.

## Security rules implemented

Source: `00-governance/security-policy.md`, `00-governance/security-rules.md` and HU-ADM-002.

| Rule | How |
|---|---|
| Access token: JWT RS256, 1 hour, claims `sub`, `iat`, `exp`, `jti`, `roles` | `RsaAccessTokens`; also `iss` (`ftx-customers-api`) and the `kid` header. Nothing personal in the payload |
| Consumers verify with the public key | `GET /api/v1/auth/jwks`; the private key never leaves the service |
| Refresh token: opaque, 7 days, stored with BCrypt, one use, rotated | Token `<id>.<secret>` (256 random bits); `customers.refresh_token` keeps only the BCrypt hash of the secret |
| Reuse of a revoked or used token revokes the whole family | Every token of one login shares `family_id`; a spent token presented again revokes the family (also when two requests race for the same token) |
| Passwords with BCrypt, strength 12 or more | `BcryptSecretHasher`; the database refuses anything that is not a BCrypt hash |
| Generic answer for login failures | Unknown email, wrong password and locked account all answer 401 `INVALID_CREDENTIALS`, and take the same time (a dummy BCrypt check runs for an unknown email) |
| Lockout after 5 consecutive failures | 15 minutes; the counter is updated in one SQL statement, so parallel failures all count. The refusal still commits the counter |
| 10 login attempts per address in 5 minutes | `InMemoryLoginRateLimiter` (one replica in the MVP); the gateway limits in front of it too (ftx-docs#51) |
| Security events | `AUTH_LOGIN_SUCCESS`, `AUTH_LOGIN_FAILURE`, `AUTH_BRUTE_FORCE_DETECTED`, `AUTH_TOKEN_REVOKED`, `AUTH_UNAUTHORIZED_ACCESS_ATTEMPT` on the `security` logger, with administrator id and client address only: never an email, a password or a token |
| An administrator cannot end another administrator's session | `logout` revokes a refresh token only if it belongs to the caller; otherwise nothing changes and an `AUTH_UNAUTHORIZED_ACCESS_ATTEMPT` is logged |

`logout` with `allDevices: true`, or without a refresh token, revokes every active session of the
caller. The access token itself stays valid until it expires (contract).

**Differences from the documentation, on purpose:**

- `security-policy.md` asks for the refresh token in an `httpOnly` cookie, while
  `auth-service.yaml` returns it in the JSON body. This service follows the contract (the frontend
  already uses it); moving to a cookie needs a contract change first. Recorded in ADR-012.
- The lock duration (15 minutes) is not in the documentation; ADR-012 sets it.

## The first administrator

No migration seeds a credential. At start-up the service creates **one** administrator from three
variables, only if no account with that email exists, and never changes an existing account:

| Variable | Value |
|---|---|
| `CUSTOMERS_BOOTSTRAP_ADMIN_NAME` | Full name |
| `CUSTOMERS_BOOTSTRAP_ADMIN_EMAIL` | Email (stored in lower case) |
| `CUSTOMERS_BOOTSTRAP_ADMIN_PASSWORD_HASH` | **BCrypt hash**, strength 12 or more. Never the password |

All three or none; a weak hash or a plain password stops the start-up. Make the hash on your own
machine and type the password only there, for example:

```bash
docker run --rm -it httpd:2.4-alpine htpasswd -nBC 12 "" | tr -d ':\n'   # asks for the password
```

In a Compose env file wrap the hash in single quotes, because it contains `$`.

## Signing key

```bash
# One line, PKCS#8, without the BEGIN/END lines: the format an env file can hold.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | sed '1d;$d' | tr -d '\n'
```

Put it in `CUSTOMERS_JWT_PRIVATE_KEY` and a name of your choice in `CUSTOMERS_JWT_KEY_ID` (for
example the date, `2026-11`). Keys are per environment and never versioned. Without them the
service does not start. For local development only, `CUSTOMERS_JWT_EPHEMERAL=true` makes a new key on
every start (every token dies with the process).

## Architecture (hexagonal)

```
domain/                  Administrator, LoginPolicy, RefreshToken: rules only, no framework, no I/O
application/             AuthService (login, refresh, logout), AdministratorBootstrap, and the ports
  port/in/               Login, RefreshSession, Logout
  port/out/              AdministratorRepository, RefreshTokenRepository, SecretHasher, AccessTokens,
                         TokenSecrets, LoginRateLimiter, SecurityEventLog
adapter/in/web/          controllers, ErrorResponse, correlation id
adapter/out/persistence/ Spring JDBC on customers.user_account and customers.refresh_token
adapter/out/security/    BCrypt, RS256 + JWKS (Nimbus), rate limiter, security event log
adapter/config/          wiring; each use case runs in one transaction
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CUSTOMERS_DB_URL` | `jdbc:postgresql://postgres:5432/ftx` | The single instance of `ftx-infra-postgres` |
| `CUSTOMERS_DB_USER` | `customers_app` | Login user created by `ftx-infra-postgres` |
| `CUSTOMERS_DB_PASSWORD` | none (required) | Its password, from `env/<environment>.env` of `ftx-infra-postgres` |
| `CUSTOMERS_JWT_PRIVATE_KEY` | none (required) | RSA private key, see "Signing key" |
| `CUSTOMERS_JWT_KEY_ID` | none (required) | `kid` of the key |
| `CUSTOMERS_JWT_ISSUER` | `ftx-customers-api` | `iss` claim; consumers check it |
| `CUSTOMERS_JWT_EPHEMERAL` | `false` | Local development only |
| `CUSTOMERS_BCRYPT_STRENGTH` | `12` | BCrypt cost for refresh-token hashes |
| `CUSTOMERS_BOOTSTRAP_ADMIN_*` | empty | See "The first administrator" |
| `PORT` | `8081` | HTTP port (the user-service port of `auth-service.yaml`) |

The service never runs migrations: the `customers` schema belongs to `ftx-customers-db`. Logs are
JSON (ECS) with the `correlationId` of each request.

## Run it

Requirements: JDK 21 and Maven 3.9, the database of `ftx-infra-postgres` running and the
`ftx-customers-db` migrations applied (see their READMEs).

```bash
mvn package -DskipTests
CUSTOMERS_DB_URL=jdbc:postgresql://localhost:5432/ftx CUSTOMERS_DB_PASSWORD=<customers_app password> \
CUSTOMERS_JWT_EPHEMERAL=true java -jar target/ftx-customers-api-0.1.0.jar
```

With Docker Compose, from `ftx-infra-postgres`:
`docker compose --env-file env/dev.env up -d --build --wait ftx-customers-api`.

## Tests

```bash
mvn verify
```

- Unit tests of the domain, the use cases (lockout, rate limit, rotation, reuse, logout) and the
  token, hashing and rate-limit adapters.
- Web tests of every response of the contract: status codes, error codes, `Retry-After`,
  `Cache-Control`, and that a submitted value is never echoed.
- Integration tests against a real PostgreSQL with the **real migrations** of the sibling
  `ftx-customers-db` clone (`-Dcustomers.db.dir=...`, default `../ftx-customers-db`), connected as
  `customers_app` with only the rights `ftx-customers-db` grants it. The database is a
  Testcontainers PostgreSQL 16 when Docker is available, or an existing one given by
  `FTX_IT_JDBC_URL`, `FTX_IT_ADMIN_USER` and `FTX_IT_ADMIN_PASSWORD` (it drops and rebuilds the
  `customers` schema there: never point it at a shared database). Without either, they are skipped.
- Two-owner tests: one administrator cannot revoke, log out or lock another one.

The tests that touch a database use no fixed credential: the administrator passwords, their hashes
and the database password of `customers_app` are made on each run.

The `ci` workflow runs `mvn verify`, gitleaks over the whole history and the image build.

## Branching

`develop`, `qa` and `main` accept no direct commits. Changes enter `develop` from `feat/`,
`fix/` or `chore/` branches through a Pull Request; promotion to `qa` and `main` re-applies them
with `git cherry-pick -x` (`00-governance/branching-policy.md` in `ftx-docs`). `main` requires the
approval of `ariel5253`.
