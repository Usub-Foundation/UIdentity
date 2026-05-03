# Security Notes

## PKCE State

PKCE state entries are one-time values. The callback consumes state before exchanging the authorization code. This protects against state replay and ties the callback to the generated verifier.

Use `RedisStateStore` for deployments with more than one service instance. `MemoryStateStore` is process-local and should only be used where that limitation is acceptable.

## Cookies

Access and refresh tokens are stored in `HttpOnly` cookies. The runtime appends the realm name to the configured cookie names, such as `access_token_trader`.

`UIDENTITY_COOKIE_SECURE` defaults to `true`. Keep it enabled in HTTPS environments. Disable it only for local HTTP development.

## JWT Validation

The validator checks signatures using JWKS, caches keys for `UIDENTITY_AUTH_JWKS_CACHE_TTL_SECONDS`, validates the configured issuer, and validates time-based claims with `UIDENTITY_AUTH_CLOCK_SKEW_SECONDS`.

Issuer and JWKS configuration are required:

```bash
UIDENTITY_AUTH_EXPECTED_ISSUER=https://login.example.com/realms/trader
UIDENTITY_AUTH_JWKS_URL=https://login.example.com/realms/trader/protocol/openid-connect/certs
```

Audience validation is enabled by default. Keep it enabled for production APIs and set the expected API audience:

```bash
UIDENTITY_AUTH_REQUIRE_AUDIENCE=true
UIDENTITY_AUTH_EXPECTED_AUDIENCE=<expected-audience>
```

If issuer, JWKS URL, or required audience values are missing, validation fails closed with a configuration error. The `azp` claim is checked when `UIDENTITY_AUTH_EXPECTED_AZP` is set. By default, the runtime uses the configured Keycloak client id.

## Logout

Logout expires both token cookies. By default, it also attempts to revoke the refresh token:

```bash
UIDENTITY_REVOKE_REFRESH_TOKEN_ON_LOGOUT=true
```

Revocation failures are intentionally not surfaced to the browser logout flow in the current handler.
