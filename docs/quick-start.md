# Quick Start

## Requirements

UIdentity is built with CMake and C++23. The Dockerfile uses Ubuntu 24.04 with:

- `build-essential`
- `cmake`
- `ninja-build`
- `pkg-config`
- `git`
- `libssl-dev`

CMake fetches these project dependencies with `FetchContent`:

- `ulog`
- `uredis`
- `unet`
- `glaze`
- `jwt-cpp`
- `uvent`

## Build Locally

```bash
cmake -S . -B build
cmake --build build --target UIdentity
```

## Build With Docker

```bash
docker build -t uidentity .
```

The Dockerfile currently attempts to build `UIdentityLib` and `UIdentityTests`, while the active CMake file defines `UIdentity` and has the test target commented out. Align the Dockerfile or restore those CMake targets before relying on the image build.

## Start Local Services

The compose file provides Redis and Keycloak:

```bash
docker compose up redis keycloak
```

Keycloak is exposed on `http://localhost:8080` and imports realms from `docker/keycloak/realm-import`.

Set a local Keycloak admin password before starting Keycloak:

```bash
KEYCLOAK_ADMIN_PASSWORD=<local-password> docker compose up redis keycloak
```

The imported demo users do not include passwords. Create local test credentials in the Keycloak admin UI when needed.

## Run The Runtime Service

After building, run the compiled service from your build directory. Configure it with environment variables as needed:

```bash
UIDENTITY_KEYCLOAK_AUTH_BASE_URL=http://localhost:8080 \
UIDENTITY_KEYCLOAK_INTERNAL_BASE_URL=http://localhost:8080 \
UIDENTITY_KEYCLOAK_REALMS=trader,merchant \
UIDENTITY_AUTH_EXPECTED_ISSUER_TRADER=http://localhost:8080/realms/trader \
UIDENTITY_AUTH_EXPECTED_ISSUER_MERCHANT=http://localhost:8080/realms/merchant \
UIDENTITY_AUTH_JWKS_URL_TRADER=http://localhost:8080/realms/trader/protocol/openid-connect/certs \
UIDENTITY_AUTH_JWKS_URL_MERCHANT=http://localhost:8080/realms/merchant/protocol/openid-connect/certs \
UIDENTITY_AUTH_EXPECTED_AUDIENCE_TRADER=myclient \
UIDENTITY_AUTH_EXPECTED_AUDIENCE_MERCHANT=myclient \
UIDENTITY_COOKIE_SECURE=false \
./build/UIdentity
```

The service defaults to `127.0.0.1:22813`.
