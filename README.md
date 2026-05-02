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

This repository builds the library target `UIdentityLib`.

The HTTP transport stays dependency-injected through the async HTTP concepts in `include/uidentity/api_models/concepts.hpp`. That keeps the auth logic testable and lets callers plug in their own HTTP layer.

## Build

```bash
cmake -S . -B build
cmake --build build --target UIdentityLib
```

## Tests

```bash
cmake --build build --target UIdentityTests
ctest --test-dir build --output-on-failure
```

The test executable in `tests/keycloak_flow_tests.cpp` covers:

- OIDC discovery
- PKCE start and callback completion
- Token service endpoints
- JWT validation against JWKS
- Bearer middleware context propagation
- Cookie helpers plus login/logout handler behavior
- Optional live Redis integration when `UIDENTITY_TEST_REDIS=1`

## Docker

The Dockerfile is a library build/test image. It configures CMake, builds `UIdentityLib` and `UIdentityTests`, and runs the test suite.

```bash
docker build -t uidentity .
```

To rerun the tests from the built image:

```bash
docker run --rm uidentity
```

## Local Dependencies

The repository includes Docker Compose services for local Keycloak and Redis development. They can be started independently when you need live integration dependencies:

```bash
docker compose up redis keycloak
```

Bundled demo credentials:

- Keycloak admin: `admin` / `adminadmin`
- `trader` realm user: `alice` / `alice123`
- `merchant` realm user: `mona` / `mona123`
