# Configuration

`src/main.cpp` loads runtime configuration from environment variables. Realm-specific values can be overridden by suffixing the variable name with the uppercased realm name. For example, `UIDENTITY_KEYCLOAK_CLIENT_ID_MERCHANT` overrides `UIDENTITY_KEYCLOAK_CLIENT_ID` for the `merchant` realm.

## Server

| Variable | Default | Description |
| --- | --- | --- |
| `UIDENTITY_LISTEN_HOST` | `127.0.0.1` | HTTP bind host. |
| `UIDENTITY_LISTEN_PORT` | `22813` | HTTP bind port. |
| `UIDENTITY_UVENT_THREADS` | `1` | Number of uvent threads. |
| `UIDENTITY_LIVENESS_PATH` | `/health/live` | Liveness endpoint path. |
| `UIDENTITY_HEALTH_PATH` | `/health/live` | Fallback for liveness path. |
| `UIDENTITY_READINESS_PATH` | `/health/ready` | Readiness endpoint path. |
| `UIDENTITY_READY_PATH` | `/health/ready` | Fallback for readiness path. |
| `UIDENTITY_STARTUP_PATH` | `/health/startup` | Startup endpoint path. |

## Keycloak

| Variable | Default | Description |
| --- | --- | --- |
| `UIDENTITY_KEYCLOAK_AUTH_BASE_URL` | `UIDENTITY_KEYCLOAK_BASE_URL` or `https://keycloak.0x000f.com` | Public Keycloak base URL used in redirects and issuer expectations. |
| `UIDENTITY_KEYCLOAK_INTERNAL_BASE_URL` | Public base URL | Internal Keycloak URL used for server-to-server token and JWKS calls. |
| `UIDENTITY_KEYCLOAK_REALMS` | empty | Comma- or whitespace-separated list of realms. |
| `UIDENTITY_KEYCLOAK_REALM` | `trader` | Single fallback realm when `UIDENTITY_KEYCLOAK_REALMS` is empty. |
| `UIDENTITY_KEYCLOAK_CLIENT_ID` | `myclient` | OIDC client id. Realm suffix supported. |
| `UIDENTITY_KEYCLOAK_CLIENT_SECRET` | unset | Optional OIDC client secret. Realm suffix supported. |
| `UIDENTITY_KEYCLOAK_REDIRECT_URI` | `http://<host>:<port>/api/v1/callback` | Redirect URI registered with Keycloak. Realm suffix supported. |
| `UIDENTITY_KEYCLOAK_SCOPES` | `openid profile email` | Whitespace-separated authorization scopes. |

## JWT Validation

| Variable | Default | Description |
| --- | --- | --- |
| `UIDENTITY_AUTH_EXPECTED_ISSUER` | `<public-base>/realms/<realm>` | Expected `iss` claim. Realm suffix supported. |
| `UIDENTITY_AUTH_JWKS_URL` | `<internal-base>/realms/<realm>/protocol/openid-connect/certs` | JWKS endpoint. Realm suffix supported. |
| `UIDENTITY_AUTH_JWKS_CACHE_TTL_SECONDS` | `300` | JWKS cache lifetime. |
| `UIDENTITY_AUTH_REQUIRE_AUDIENCE` | `true` | Whether to enforce `aud`. Keep enabled for production APIs. |
| `UIDENTITY_AUTH_EXPECTED_AUDIENCE` | required when audience checks are enabled | Expected audience. Realm suffix supported. |
| `UIDENTITY_AUTH_EXPECTED_AZP` | client id | Expected authorized party/client claim. Realm suffix supported. |
| `UIDENTITY_AUTH_CLOCK_SKEW_SECONDS` | `60` | Allowed clock skew for time-based claims. |

`UIDENTITY_AUTH_EXPECTED_ISSUER` and `UIDENTITY_AUTH_JWKS_URL` are required by the validator. When `UIDENTITY_AUTH_REQUIRE_AUDIENCE=true`, `UIDENTITY_AUTH_EXPECTED_AUDIENCE` is also required. Missing values fail closed with a configuration error instead of silently weakening JWT validation.

## Cookies And Redirects

| Variable | Default | Description |
| --- | --- | --- |
| `UIDENTITY_COOKIE_ACCESS_TOKEN_NAME` | `access_token` | Base access-token cookie name. The runtime appends `_<realm>`. |
| `UIDENTITY_COOKIE_REFRESH_TOKEN_NAME` | `refresh_token` | Base refresh-token cookie name. The runtime appends `_<realm>`. |
| `UIDENTITY_COOKIE_PATH` | `/` | Cookie path. |
| `UIDENTITY_COOKIE_SECURE` | `true` | Adds the `Secure` cookie attribute. Set to `false` for local HTTP-only development. |
| `UIDENTITY_COOKIE_SAMESITE` | `Lax` | SameSite attribute. |
| `UIDENTITY_POST_LOGIN_REDIRECT` | `/` | Redirect target after a successful callback. |
| `UIDENTITY_POST_LOGOUT_REDIRECT` | `/` | Redirect target after logout. |
| `UIDENTITY_REVOKE_REFRESH_TOKEN_ON_LOGOUT` | `true` | Revoke the refresh token during logout when present. |

## Redis

| Variable | Default | Description |
| --- | --- | --- |
| `UIDENTITY_REDIS_HOST` | `127.0.0.1` | Redis host. |
| `UIDENTITY_REDIS_PORT` | `6379` | Redis port. |
| `UIDENTITY_REDIS_USERNAME` | unset | Optional Redis username. |
| `UIDENTITY_REDIS_PASSWORD` | unset | Optional Redis password. |
| `UIDENTITY_REDIS_CONNECT_TIMEOUT_MS` | `5000` | Connect timeout. |
| `UIDENTITY_REDIS_IO_TIMEOUT_MS` | `5000` | I/O timeout. |
| `UIDENTITY_REDIS_MAX_REDIRECTIONS` | `5` | Maximum cluster redirections. |
| `UIDENTITY_REDIS_MAX_CONNECTIONS_PER_NODE` | `4` | Per-node connection cap. |
| `UIDENTITY_REDIS_FORCE_STANDALONE` | `true` | Force standalone Redis behavior. |
