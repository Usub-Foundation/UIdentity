# UIdentity

`UIdentity` is a small C++23 Keycloak/OIDC integration library with a lightweight example executable.

## What it does

- PKCE authorization URL generation
- OAuth callback handling with one-time state consumption
- Token exchange and refresh
- Token revocation, introspection, and userinfo requests
- OIDC discovery from the well-known configuration endpoint
- Bearer token middleware with JWT signature and claim validation against JWKS
- Redis-backed PKCE state storage

## Current shape

This repository is organized as a library target, `UIdentityLib`, plus a runnable example service in `src/main.cpp`.

The HTTP transport stays dependency-injected through the async HTTP concepts in `include/api_models/concepts.hpp`. That keeps the auth logic testable and lets callers plug in their own HTTP layer.

## Still pending

- JWKS caching and broader production hardening are still pending.
- Live end-to-end integration against a real Keycloak instance is available through Docker, but not yet covered by automated CI.

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Configuration

Copy [.env.example](/home/dev_elseif/UIdentity/.env.example) into your own environment and set the values you need.

Important variables:

- `UIDENTITY_KEYCLOAK_AUTH_BASE_URL`: the browser-facing Keycloak URL used in generated login redirects
- `UIDENTITY_KEYCLOAK_INTERNAL_BASE_URL`: the URL the app itself uses to call Keycloak token/JWKS endpoints
- `UIDENTITY_REDIS_HOST` / `UIDENTITY_REDIS_PORT`: Redis connection settings
- `UIDENTITY_LISTEN_HOST` / `UIDENTITY_LISTEN_PORT`: app bind address
- `UIDENTITY_AUTH_JWKS_CACHE_TTL_SECONDS`: JWKS cache lifetime
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
- Demo user: `alice` / `alice123`

Demo flow:

1. Open `http://localhost:22813/auth/login`
2. Sign in as `alice`
3. The callback returns JSON tokens
4. Call `GET http://localhost:22813/api/v1/me` with `Authorization: Bearer <access_token>`

Example:

```bash
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:22813/api/v1/me
```

## Tests

The repository now includes a self-contained test executable in `tests/keycloak_flow_tests.cpp` that covers:

- OIDC discovery
- PKCE start and callback completion
- Token service endpoints
- JWT validation against JWKS
- Bearer middleware context propagation
- Optional live Redis integration when `UIDENTITY_TEST_REDIS=1`
