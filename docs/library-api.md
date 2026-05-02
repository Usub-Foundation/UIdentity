# Library API

This page summarizes the public API surface most consumers are likely to use. See headers under `include/uidentity` for exact signatures.

## HTTP Client Concept

Most Keycloak services are templated over an async HTTP client:

```cpp
template <class C>
concept AsyncHttpClientLike =
    requires(C &c, const usub::unet::http::Request &request) {
        { c.send(request) } -> std::same_as<
            usub::uvent::task::Awaitable<usub::unet::http::Response>>;
    };
```

This keeps transport concerns outside the auth logic. The runtime provides `UnetHttpClient` in `src/main.cpp`.

## Key Configuration Types

`keycloak::KeycloakRealmConfig`:

- `base_url`
- `realm`
- `client_id`
- `redirect_uri`
- `scopes`
- `pkce_verifier_len`
- `omit_default_port`

`keycloak::TokenServiceConfig`:

- `base_url`
- `realm`
- `client_id`
- `client_secret`
- `redirect_uri`

`AuthConfig`:

- `expected_issuer`
- `jwks_url`
- `jwks_cache_ttl`
- `require_audience`
- `expected_audience`
- `expected_azp`
- `clock_skew_seconds`

## TokenService

`keycloak::TokenService<HttpClient>` supports:

- `exchange_authorization_code(code, code_verifier)`
- `refresh_tokens(refresh_token)`
- `revoke_token(token, token_type_hint)`
- `introspect_token(token)`
- `fetch_user_info(access_token)`

Methods return `keycloak::OAuthResult`, which contains `ok`, `http_status`, `error`, `TokenSet`, and `UserInfo`.

## AccessTokenValidator

`keycloak::AccessTokenValidator<HttpClient>` validates JWT access tokens against JWKS. Successful validation returns a `JwtValidationResult` with a populated `RequestContext`.

Validation includes:

- JWT structure and supported algorithm checks.
- JWKS fetch and cache.
- RSA signature verification.
- `iss`, `exp`, and `nbf` checks.
- Optional `aud` check.
- `azp` check when configured.

## State Stores

State stores provide one-time PKCE state consumption.

`MemoryStateStore` is useful for tests and single-process development. `RedisStateStore` is intended for runtime deployments where callbacks may reach different service instances.

The multi-realm flow stores both the PKCE verifier and realm name in a `StateEntry`.

## Request Context

Authenticated identity data is carried in `RequestContext`:

```cpp
struct RequestContext {
    bool authenticated;
    std::string sub;
    std::string preferred_username;
    std::string realm;
    std::string issuer;
    std::string client_id;
    std::vector<std::string> roles;
    std::vector<std::string> scopes;
};
```

Use `get_request_context(request)` after middleware or validation code calls `set_request_context(request, context)`.

