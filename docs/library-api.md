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

`usub::uidentity::keycloak::KeycloakRealmConfig`:

- `base_url`
- `realm`
- `client_id`
- `redirect_uri`
- `scopes`
- `pkce_verifier_len`
- `omit_default_port`

`usub::uidentity::keycloak::TokenServiceConfig`:

- `base_url`
- `realm`
- `client_id`
- `client_secret`
- `redirect_uri`

`usub::uidentity::AuthConfig`:

- `expected_issuer`
- `jwks_url`
- `jwks_cache_ttl`
- `require_audience`
- `expected_audience`
- `expected_azp`
- `clock_skew_seconds`

`expected_issuer` and `jwks_url` are required. `require_audience` defaults to `true`; when it is enabled, `expected_audience` is also required. Missing required values fail closed with a configuration error.

## TokenService

`usub::uidentity::keycloak::TokenService<HttpClient>` supports:

- `exchange_authorization_code(code, code_verifier)`
- `refresh_tokens(refresh_token)`
- `revoke_token(token, token_type_hint)`
- `introspect_token(token)`
- `fetch_user_info(access_token)`

Methods return `usub::uidentity::keycloak::OAuthResult`, which contains `ok`, `http_status`, `error`, `TokenSet`, and `UserInfo`.

## AccessTokenValidator

`usub::uidentity::keycloak::AccessTokenValidator<HttpClient>` validates JWT access tokens against JWKS. Successful validation returns a `JwtValidationResult` with a populated `usub::uidentity::RequestContext`.

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

Authenticated identity data is carried in `usub::uidentity::RequestContext`:

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

Use `usub::uidentity::get_request_context(request)` after middleware or validation code calls `usub::uidentity::set_request_context(request, context)`.
