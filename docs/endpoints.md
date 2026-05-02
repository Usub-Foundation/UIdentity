# Runtime Endpoints

The runtime server in `src/main.cpp` exposes a small authentication surface. It defaults to `http://127.0.0.1:22813`.

## Login

```http
GET /auth/login?realm=<realm>
```

Starts a PKCE authorization flow for the requested realm. On success, the server returns `302` with a `Location` header pointing at the Keycloak authorization endpoint.

Errors:

- `400 {"ok":false,"error":"missing_realm"}`
- `404 {"ok":false,"error":"unknown_realm"}`

## Callback

```http
GET  /api/v1/callback?code=<code>&state=<state>
POST /api/v1/callback
```

Completes the authorization-code flow. For `POST`, form-encoded body fields are merged with query parameters.

On success, the server sets realm-scoped token cookies and returns `302` to `UIDENTITY_POST_LOGIN_REDIRECT`.

Common errors:

- `400 {"ok":false,"error":"missing_code_or_state"}`
- `401 {"ok":false,"error":"invalid_or_expired_state"}`
- OAuth errors returned by Keycloak during token exchange.

## Logout

```http
GET /auth/logout?realm=<realm>
```

Optionally revokes the refresh token, expires the realm-scoped access and refresh token cookies, and redirects to `UIDENTITY_POST_LOGOUT_REDIRECT`.

## Current User

```http
GET /api/v1/me?realm=<realm>
```

Reads realm-scoped token cookies, validates the access token, refreshes when the access token is expired and a refresh token is available, and returns selected identity context.

Successful response:

```json
{
  "ok": true,
  "sub": "user-id",
  "preferred_username": "alice",
  "realm": "trader",
  "issuer": "http://localhost:8080/realms/trader",
  "client_id": "myclient"
}
```

Possible errors include missing realm, unknown realm, missing access-token cookie, expired or invalid JWTs, JWKS failures, audience mismatch, and refresh failures.

## Probes

```http
GET /health/live
GET /health/ready
GET /health/startup
```

Paths are configurable. Readiness and startup depend on Redis bootstrap state in the runtime service.

