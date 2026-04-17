# UIdentity

`UIdentity` is a small C++23 Keycloak/OIDC integration library with a lightweight example executable.

## What it does

- PKCE authorization URL generation
- OAuth callback handling with one-time state consumption
- Token exchange and refresh
- Token revocation, introspection, and userinfo requests
- OIDC discovery from the well-known configuration endpoint
- Bearer token middleware with JWT signature and claim validation against JWKS
- JWKS caching for repeated token validation
- Cookie-based login, logout, and protected route access in the example app
- Redis-backed PKCE state storage

## Current shape

This repository is organized as a library target, `UIdentityLib`, plus a runnable example service in `src/main.cpp`.

The HTTP transport stays dependency-injected through the async HTTP concepts in `include/api_models/concepts.hpp`. That keeps the auth logic testable and lets callers plug in their own HTTP layer.

## Still pending

- Broader production hardening is still pending.
- The full Docker Keycloak flow is available locally, while CI currently covers build-and-test only.

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Configuration

Copy [.env.example](/home/dev_elseif/UIdentity/.env.example) into your own environment and set the values you need.

Important variables:

- `UIDENTITY_KEYCLOAK_REALMS`: whitespace- or comma-separated list of supported realms, for example `trader merchant`
- `UIDENTITY_KEYCLOAK_AUTH_BASE_URL`: the browser-facing Keycloak URL used in generated login redirects
- `UIDENTITY_KEYCLOAK_INTERNAL_BASE_URL`: the URL the app itself uses to call Keycloak token/JWKS endpoints
- `UIDENTITY_KEYCLOAK_REDIRECT_URI`: the callback URL registered with Keycloak
- `UIDENTITY_KEYCLOAK_CLIENT_ID_<REALM>`: per-realm client ids, such as `UIDENTITY_KEYCLOAK_CLIENT_ID_TRADER`
- `UIDENTITY_AUTH_EXPECTED_AZP_<REALM>`: optional per-realm AZP validation overrides
- `UIDENTITY_REDIS_HOST` / `UIDENTITY_REDIS_PORT`: Redis connection settings
- `UIDENTITY_LISTEN_HOST` / `UIDENTITY_LISTEN_PORT`: app bind address
- `UIDENTITY_AUTH_JWKS_CACHE_TTL_SECONDS`: JWKS cache lifetime
- `UIDENTITY_COOKIE_ACCESS_TOKEN_NAME` / `UIDENTITY_COOKIE_REFRESH_TOKEN_NAME`: cookie names used by the example app
- `UIDENTITY_POST_LOGIN_REDIRECT` / `UIDENTITY_POST_LOGOUT_REDIRECT`: browser redirects after login/logout
- `UIDENTITY_HEALTH_PATH` / `UIDENTITY_READY_PATH`: live and readiness endpoints

## Docker Demo

This repository now includes a self-contained local stack:

```bash
docker compose up --build
```

Services:

- App: `http://localhost:22813`
- Keycloak: `http://localhost:8080`
- Redis: `localhost:6379`

Health endpoints:

- Live: `http://localhost:22813/health/live`
- Ready: `http://localhost:22813/health/ready`

Bundled demo credentials:

- Keycloak admin: `admin` / `adminadmin`
- `trader` realm user: `alice` / `alice123`
- `merchant` realm user: `mona` / `mona123`

Demo flow:

1. Open `http://localhost:22813/auth/login?realm=trader` or `http://localhost:22813/auth/login?realm=merchant`
2. Sign in with a user from that realm
3. Keycloak redirects back to the callback, which stores the access and refresh tokens in realm-scoped `HttpOnly` cookies such as `access_token_trader`
4. Open `http://localhost:22813/api/v1/me?realm=trader` or `http://localhost:22813/api/v1/me?realm=merchant` in the same browser session
5. Optionally call `GET http://localhost:22813/auth/logout?realm=trader` or `...realm=merchant` to clear that realm's cookies and revoke its refresh token

Example:

```bash
curl -i \
  --cookie "access_token_trader=<access_token>; refresh_token_trader=<refresh_token>" \
  "http://localhost:22813/api/v1/me?realm=trader"
```

## Tests

The repository now includes a self-contained test executable in `tests/keycloak_flow_tests.cpp` that covers:

- OIDC discovery
- PKCE start and callback completion
- Token service endpoints
- JWT validation against JWKS
- Bearer middleware context propagation
- Cookie helpers plus login/logout handler behavior
- Optional live Redis integration when `UIDENTITY_TEST_REDIS=1`
