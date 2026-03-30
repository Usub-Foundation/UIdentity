# UIdentity

`UIdentity` is a small C++23 Keycloak/OIDC integration library with a lightweight example executable.

## What it does

- PKCE authorization URL generation
- OAuth callback handling with one-time state consumption
- Token exchange and refresh
- Token revocation, introspection, and userinfo requests
- OIDC discovery from the well-known configuration endpoint
- Bearer token middleware with JWT signature and claim validation against JWKS
- In-memory PKCE state storage

## Current shape

This repository is organized as a library target, `UIdentityLib`, plus a tiny example executable in `src/main.cpp`.

The HTTP transport stays dependency-injected through the `HttpClientLike` concept in `include/api_models/concepts.hpp`. That keeps the auth logic testable and lets callers plug in their own HTTP layer.

## Still pending

- `RedisStateStore` is still incomplete. The current store interface is synchronous, while the referenced Redis client appears to be coroutine-oriented, so that integration needs either a safe sync bridge or an async state-store surface.
- A concrete production HTTP adapter is not included yet. Tests use a fake transport.

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Tests

The repository now includes a self-contained test executable in `tests/keycloak_flow_tests.cpp` that covers:

- OIDC discovery
- PKCE start and callback completion
- Token service endpoints
- JWT validation against JWKS
- Bearer middleware context propagation
