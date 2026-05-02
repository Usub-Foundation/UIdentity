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

Bundled demo credentials:

- Keycloak admin: `admin` / `adminadmin`
- `trader` realm user: `alice` / `alice123`
- `merchant` realm user: `mona` / `mona123`

## Run The Runtime Service

After building, run the compiled service from your build directory. Configure it with environment variables as needed:

```bash
UIDENTITY_KEYCLOAK_AUTH_BASE_URL=http://localhost:8080 \
UIDENTITY_KEYCLOAK_INTERNAL_BASE_URL=http://localhost:8080 \
UIDENTITY_KEYCLOAK_REALMS=trader,merchant \
UIDENTITY_COOKIE_SECURE=false \
./build/UIdentity
```

The service defaults to `127.0.0.1:22813`.

