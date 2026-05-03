# Architecture

UIdentity separates the authentication flow from the HTTP transport as much as possible. The reusable library code lives under `include/uidentity` and `src/keycloak`; `src/main.cpp` wires those pieces into a concrete unet server.

## Main Components

| Component | Location | Responsibility |
| --- | --- | --- |
| `PkceAuthStrategy` | `include/uidentity/keycloak/auth/pkce_auth_strat.hpp` | Builds Keycloak authorization URLs with `S256` PKCE challenge data. |
| `TokenService` | `include/uidentity/keycloak/oauth/token_service.hpp` | Exchanges authorization codes, refreshes tokens, revokes tokens, introspects tokens, and fetches userinfo. |
| `AccessTokenValidator` | `include/uidentity/keycloak/jwt/access_token_validator.hpp` | Validates JWT format, algorithm support, RSA signature, issuer, time claims, audience, and authorized party. |
| `BearerAuthMiddleware` | `include/uidentity/keycloak/auth/bearer_auth_middleware.hpp` | Authenticates `Authorization: Bearer` requests and stores a `usub::uidentity::RequestContext`. |
| `AuthHandler` | `include/uidentity/handlers/AuthHandler.h` | Provides login, callback, and logout handlers for unet. |
| `MultiRealmManager` | `include/uidentity/keycloak/multi_realm.hpp` | Hosts per-realm token services, validators, and PKCE strategy. |
| `MemoryStateStore` | `include/uidentity/keycloak/state_store/memory.hpp` | In-process state store for development and tests. |
| `RedisStateStore` | `include/uidentity/keycloak/state_store/redis.hpp` | Redis-backed one-time state store for runtime use. |

## PKCE Login Flow

1. `/auth/login?realm=<realm>` calls `MultiRealmManager::start_login`.
2. A PKCE verifier/challenge pair is generated.
3. The verifier and realm are stored as a one-time state entry with a TTL.
4. The user is redirected to Keycloak.
5. Keycloak redirects back to `/api/v1/callback`.
6. The callback consumes the state entry, exchanges the authorization code, and sets access and refresh token cookies scoped to the realm.

## Request Authentication Flow

`/api/v1/me` uses cookies rather than an `Authorization` header. It validates the access token for the requested realm. If validation fails because the token is expired and a refresh token exists, the runtime refreshes tokens, updates cookies, and validates the new access token.

For APIs that use bearer headers, `BearerAuthMiddleware` validates the token and writes `usub::uidentity::RequestContext` into `request.user_data`.

## Multi-Realm Behavior

The runtime accepts `UIDENTITY_KEYCLOAK_REALMS` as a comma- or whitespace-separated list. Each realm gets its own:

- `KeycloakRealmConfig`
- `TokenServiceConfig`
- `usub::uidentity::AuthConfig`
- `TokenService`
- `AccessTokenValidator`
- `PkceAuthStrategy`

Cookie names are also realm-scoped by appending `_<realm>` to the configured base names.

