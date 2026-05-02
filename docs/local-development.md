# Local Development

## Local Keycloak And Redis

Start dependencies with Docker Compose:

```bash
docker compose up redis keycloak
```

The Keycloak container imports all realm JSON files from `docker/keycloak/realm-import`.

Default exposed services:

- Keycloak: `http://localhost:8080`
- Redis: internal compose service only unless ports are added locally

## Example Local Runtime Environment

```bash
export UIDENTITY_KEYCLOAK_AUTH_BASE_URL=http://localhost:8080
export UIDENTITY_KEYCLOAK_INTERNAL_BASE_URL=http://localhost:8080
export UIDENTITY_KEYCLOAK_REALMS=trader,merchant
export UIDENTITY_KEYCLOAK_CLIENT_ID=myclient
export UIDENTITY_COOKIE_SECURE=false
export UIDENTITY_REDIS_HOST=127.0.0.1
```

If Redis is only running inside Compose without a host port mapping, either add a port mapping for local execution or run the service in the same Docker network.

## Test Source

The repository includes `tests/keycloak_flow_tests.cpp`. The source covers:

- OIDC discovery.
- PKCE start and callback completion.
- Token service endpoints.
- JWT validation against JWKS.
- Bearer middleware context propagation.
- Cookie helpers and login/logout handler behavior.
- Optional live Redis integration with `UIDENTITY_TEST_REDIS=1`.

At the moment, the CMake test target is commented out. Re-enable `enable_testing()`, `add_executable(UIdentityTests ...)`, `target_link_libraries(...)`, and `add_test(...)` before running the documented test commands.

## Documentation Preview

The docs use MkDocs Material with `docs/mkdocs.yml` and `docs_dir: .`.

```bash
cd docs
mkdocs serve -f mkdocs.yml
```

