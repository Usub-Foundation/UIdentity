# Installation

UIdentity is built with CMake and C++23. The repository currently builds the `UIdentity` library target and fetches its third-party dependencies through CMake `FetchContent`.

## Requirements

- A C++23-capable compiler.
- CMake.
- OpenSSL development headers.
- Optional Docker and Docker Compose for container builds and local Keycloak or Redis services.

The Dockerfile uses Ubuntu 24.04 and installs:

- `build-essential`
- `cmake`
- `ninja-build`
- `pkg-config`
- `git`
- `libssl-dev`

## CMake Build

From the repository root:

```bash
cmake -S . -B build
cmake --build build --target UIdentity
```

## Dependencies

CMake fetches the library dependencies during configuration:

- `ulog`
- `uredis`
- `unet`
- `glaze`
- `jwt-cpp`
- `uvent`

## Docker Build

```bash
docker build -t uidentity .
```

!!! note
    The Dockerfile currently references `UIdentityLib` and `UIdentityTests`, while the active CMake target is `UIdentity` and the test target is commented out. Align those target names before relying on the Docker build as the canonical installation path.
