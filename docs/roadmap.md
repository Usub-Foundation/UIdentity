# Roadmap

This page tracks the current documentation-facing roadmap for UIdentity.

## Build And Packaging

- Align CMake target names, Docker targets, and documentation examples.
- Restore the test target when the test suite is ready to run in CI.
- Add an install/export target for downstream CMake consumers.

## Runtime

- Keep the unet runtime focused on login, callback, logout, `/me`, and health probes.
- Document production deployment expectations for Redis, Keycloak, cookies, and reverse proxies.
- Clarify multi-realm behavior for cookie names, issuer validation, and realm-specific environment overrides.

## Authentication

- Expand examples for bearer-token middleware.
- Add examples for audience validation and authorized-party checks.
- Document token refresh behavior and failure modes in more detail.

## Documentation

- Add full API examples for the public headers under `include/uidentity`.
- Add deployment recipes for local development, Docker Compose, and production Keycloak.
- Keep the MkDocs Material layout aligned with the rest of the Usub-development documentation sites.
