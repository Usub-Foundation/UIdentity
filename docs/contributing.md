# Contributing

Contributions should keep the authentication library reusable and the runtime server thin. Prefer changes that preserve the separation between Keycloak/OIDC logic and the injected HTTP transport.

## Local Workflow

Configure and build from the repository root:

```bash
cmake -S . -B build
cmake --build build --target UIdentity
```

Start local dependencies when working on live Keycloak or Redis behavior:

```bash
docker compose up redis keycloak
```

## Code Guidelines

- Keep public APIs under `include/uidentity`.
- Keep implementation files under `src`.
- Use the existing async HTTP concepts instead of binding library code directly to a concrete transport.
- Prefer realm-specific configuration paths when adding multi-realm behavior.
- Keep cookie, JWT, and PKCE changes covered by tests where possible.

## Documentation

The documentation site is configured by `docs/mkdocs.yml` with `docs_dir: .`.

Preview it locally with:

```bash
python3 -m venv .venv-docs
. .venv-docs/bin/activate
python -m pip install -r docs/requirements.txt
cd docs
mkdocs serve -f mkdocs.yml
```

When adding pages, include them in the grouped navigation so the site keeps the same structure as the rest of the documentation.
