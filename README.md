# UIdentity

`UIdentity` is a C++23 Keycloak/OIDC integration library.

## What It Does

- PKCE authorization URL generation
- OAuth callback handling with one-time state consumption
- Token exchange and refresh
- Token revocation, introspection, and userinfo requests
- OIDC discovery from the well-known configuration endpoint
- Bearer token middleware with JWT signature and claim validation against JWKS
- JWKS caching for repeated token validation
- Cookie helpers for login, logout, and protected-route flows
- Redis-backed and in-memory PKCE state storage

## Project Shape

This repository currently builds the library target `UIdentity`.

The HTTP transport stays dependency-injected through the async HTTP concepts in `include/uidentity/api_models/concepts.hpp`. That keeps the auth logic testable and lets callers plug in their own HTTP layer.

## Build

```bash
cmake -S . -B build
cmake --build build --target UIdentity
```

## Tests

The test source exists at `tests/keycloak_flow_tests.cpp`, but the CMake test target is currently commented out.

The test executable in `tests/keycloak_flow_tests.cpp` covers:

- OIDC discovery
- PKCE start and callback completion
- Token service endpoints
- JWT validation against JWKS
- Bearer middleware context propagation
- Cookie helpers plus login/logout handler behavior
- Optional live Redis integration when `UIDENTITY_TEST_REDIS=1`

## Docker

The Dockerfile is intended to be a library build/test image.

```bash
docker build -t uidentity .
```

At the moment, the Dockerfile references `UIdentityLib` and `UIdentityTests`, while the active CMake target is `UIdentity` and the test target is commented out. Align those target names before relying on the Docker image as the canonical build/test path.

## Local Dependencies

The repository includes Docker Compose services for local Keycloak and Redis development. They can be started independently when you need live integration dependencies:

```bash
docker compose up redis keycloak
```

Set a local Keycloak admin password before starting Keycloak:

```bash
KEYCLOAK_ADMIN_PASSWORD=<local-password> docker compose up redis keycloak
```

The imported demo users do not include passwords. Create local test credentials in the Keycloak admin UI when needed.
