#include <chrono>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <uvent/Uvent.h>
#include <unet/http.hpp>
#include <uvent/tasks/AwaitableFrame.h>
#include <uredis/RedisClusterClient.h>

#include "uidentity/api_models/http_context.hpp"
#include "uidentity/handlers/AuthHandler.h"
#include "uidentity/keycloak/auth/bearer_auth_middleware.hpp"
#include "uidentity/keycloak/auth/pkce_auth_strat.hpp"
#include "uidentity/keycloak/detail/oidc_utils.hpp"
#include "uidentity/keycloak/jwt/access_token_validator.hpp"
#include "uidentity/keycloak/keycloak_client.hpp"
#include "uidentity/keycloak/oidc/discovery.hpp"
#include "uidentity/keycloak/state_store/memory.hpp"
#include "uidentity/keycloak/state_store/redis.hpp"
#include "uidentity/utils/cookies.hpp"

namespace
{
    using namespace usub::uidentity;

    struct FakeHttpClient
    {
        std::function<usub::unet::http::Response(const usub::unet::http::Request &)> handler;
        std::vector<usub::unet::http::Request> requests;

        usub::uvent::task::Awaitable<usub::unet::http::Response> send(const usub::unet::http::Request &request)
        {
            requests.push_back(request);
            if (!handler)
            {
                co_return usub::unet::http::Response{};
            }
            co_return handler(request);
        }
    };

    struct FakeAuthMiddleware
    {
        usub::uvent::task::Awaitable<AuthResult> authenticate(usub::unet::http::Request &, RequestContext &) const
        {
            co_return AuthResult{
                .ok = true,
                .http_status = 200,
                .error = "",
            };
        }
    };

    struct FakeHandlerClient
    {
        usub::uidentity::keycloak::CallbackResult callback_result{};

        bool has_realm(std::string_view realm) const
        {
            return realm == "trader";
        }

        usub::uvent::task::Awaitable<usub::uidentity::keycloak::AuthStart> start_login(std::string_view realm, std::chrono::seconds)
        {
            co_return usub::uidentity::keycloak::AuthStart{
                .authorization_url = "https://issuer.example/auth?realm=" + std::string(realm) + "&state=state-1",
                .state = "state-1",
            };
        }

        usub::uvent::task::Awaitable<usub::uidentity::keycloak::CallbackResult> complete_login(const usub::uidentity::keycloak::CallbackInput &)
        {
            co_return callback_result;
        }
    };

    struct FakeHandlerTokenService
    {
        std::vector<std::string> revoked_tokens;
        std::vector<std::string> revoked_realms;

        bool has_realm(std::string_view realm) const
        {
            return realm == "trader";
        }

        usub::uvent::task::Awaitable<usub::uidentity::keycloak::OAuthResult> revoke_token(std::string_view realm,
                                                                         std::string_view token,
                                                                         std::string_view = "refresh_token")
        {
            revoked_realms.emplace_back(realm);
            revoked_tokens.emplace_back(token);
            co_return usub::uidentity::keycloak::OAuthResult{
                .ok = true,
                .http_status = 204,
                .error = "",
            };
        }
    };

    void require(bool condition, std::string_view message)
    {
        if (!condition)
        {
            throw std::runtime_error(std::string(message));
        }
    }

    template <class Fn>
    void run_async_test(Fn &&fn)
    {
        usub::Uvent uvent{1};
        std::exception_ptr failure;

        usub::uvent::system::co_spawn([&]() -> usub::uvent::task::Awaitable<void>
        {
            try
            {
                co_await fn();
            }
            catch (...)
            {
                failure = std::current_exception();
            }

            uvent.stop();
            co_return;
        }());

        uvent.run();

        if (failure)
        {
            std::rethrow_exception(failure);
        }
    }

    std::optional<std::string> getenv_string(const char *name)
    {
        if (const char *value = std::getenv(name))
        {
            if (*value != '\0')
            {
                return std::string(value);
            }
        }
        return std::nullopt;
    }

    int getenv_int(const char *name, int fallback)
    {
        if (auto value = getenv_string(name))
        {
            try
            {
                return std::stoi(*value);
            }
            catch (...)
            {
                return fallback;
            }
        }
        return fallback;
    }

    std::string base64url_encode(std::string_view input)
    {
        const auto encoded_size = 4 * ((static_cast<int>(input.size()) + 2) / 3);
        std::string encoded(encoded_size, '\0');
        const int written = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(encoded.data()),
                                            reinterpret_cast<const unsigned char *>(input.data()),
                                            static_cast<int>(input.size()));
        encoded.resize(written);

        for (char &ch : encoded)
        {
            if (ch == '+')
            {
                ch = '-';
            }
            else if (ch == '/')
            {
                ch = '_';
            }
        }

        while (!encoded.empty() && encoded.back() == '=')
        {
            encoded.pop_back();
        }

        return encoded;
    }

    std::string bn_to_base64url(const BIGNUM *bn)
    {
        std::string bytes(static_cast<std::size_t>(BN_num_bytes(bn)), '\0');
        BN_bn2bin(bn, reinterpret_cast<unsigned char *>(bytes.data()));
        return base64url_encode(bytes);
    }

    struct TestKeyMaterial
    {
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> private_key{nullptr, &EVP_PKEY_free};
        std::string jwks_json;
    };

    TestKeyMaterial make_test_key_material()
    {
        BIGNUM *exponent = BN_new();
        require(exponent != nullptr, "BN_new failed");
        require(BN_set_word(exponent, RSA_F4) == 1, "BN_set_word failed");

        RSA *rsa = RSA_new();
        require(rsa != nullptr, "RSA_new failed");
        require(RSA_generate_key_ex(rsa, 2048, exponent, nullptr) == 1, "RSA_generate_key_ex failed");
        BN_free(exponent);

        auto pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(EVP_PKEY_new(), &EVP_PKEY_free);
        require(static_cast<bool>(pkey), "EVP_PKEY_new failed");
        require(EVP_PKEY_assign_RSA(pkey.get(), rsa) == 1, "EVP_PKEY_assign_RSA failed");

        const RSA *public_rsa = EVP_PKEY_get0_RSA(pkey.get());
        require(public_rsa != nullptr, "EVP_PKEY_get0_RSA failed");

        const BIGNUM *n = nullptr;
        const BIGNUM *e = nullptr;
        RSA_get0_key(public_rsa, &n, &e, nullptr);
        require(n != nullptr && e != nullptr, "RSA_get0_key failed");

        const std::string jwks =
            "{\"keys\":[{\"kid\":\"test-kid\",\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\","
            "\"n\":\"" + bn_to_base64url(n) + "\","
            "\"e\":\"" + bn_to_base64url(e) + "\"}]}";

        return TestKeyMaterial{
            .private_key = std::move(pkey),
            .jwks_json = jwks,
        };
    }

    std::string sign_rs256(EVP_PKEY *private_key,
                           std::string_view signing_input)
    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        require(ctx != nullptr, "EVP_MD_CTX_new failed");

        require(EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, private_key) == 1,
                "EVP_DigestSignInit failed");
        require(EVP_DigestSignUpdate(ctx, signing_input.data(), signing_input.size()) == 1,
                "EVP_DigestSignUpdate failed");

        std::size_t signature_size = 0;
        require(EVP_DigestSignFinal(ctx, nullptr, &signature_size) == 1, "EVP_DigestSignFinal size failed");

        std::string signature(signature_size, '\0');
        require(EVP_DigestSignFinal(ctx,
                                    reinterpret_cast<unsigned char *>(signature.data()),
                                    &signature_size) == 1,
                "EVP_DigestSignFinal failed");
        signature.resize(signature_size);
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    std::string make_signed_jwt_with_payload(EVP_PKEY *private_key, std::string_view payload)
    {
        const std::string header = R"({"alg":"RS256","typ":"JWT","kid":"test-kid"})";
        const auto signing_input = base64url_encode(header) + "." + base64url_encode(payload);
        const auto signature = sign_rs256(private_key, signing_input);
        return signing_input + "." + base64url_encode(signature);
    }

    std::string make_signed_jwt(EVP_PKEY *private_key,
                                std::string_view issuer,
                                std::string_view audience,
                                std::string_view azp)
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();

        const std::string payload =
            std::string("{") +
            "\"iss\":\"" + std::string(issuer) + "\"," +
            "\"sub\":\"user-123\"," +
            "\"preferred_username\":\"alice\"," +
            "\"aud\":[\"" + std::string(audience) + "\"]," +
            "\"azp\":\"" + std::string(azp) + "\"," +
            "\"scope\":\"openid profile email\"," +
            "\"exp\":" + std::to_string(now + 3600) + "," +
            "\"nbf\":" + std::to_string(now - 5) + "," +
            "\"realm_access\":{\"roles\":[\"admin\"]}," +
            "\"resource_access\":{\"api\":{\"roles\":[\"reader\"]}}" +
            "}";

        return make_signed_jwt_with_payload(private_key, payload);
    }

    usub::uvent::task::Awaitable<void> test_oidc_discovery()
    {
        FakeHttpClient http;
        http.handler = [](const usub::unet::http::Request &request)
        {
            require(request.metadata.method_token == "GET", "discovery should use GET");
            usub::unet::http::Response response;
            response.setStatus(200);
            response.body = R"({"issuer":"https://issuer.example/realms/demo","authorization_endpoint":"https://issuer.example/auth","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks","userinfo_endpoint":"https://issuer.example/userinfo","revocation_endpoint":"https://issuer.example/revoke","introspection_endpoint":"https://issuer.example/introspect","end_session_endpoint":"https://issuer.example/logout"})";
            return response;
        };

        usub::uidentity::keycloak::OidcDiscoveryClient<FakeHttpClient> discovery(http);
        const auto result = co_await discovery.discover("https://issuer.example", "demo");
        require(result.ok, "discovery should succeed");
        require(result.endpoints.jwks_uri == "https://issuer.example/jwks", "jwks endpoint mismatch");
        co_return;
    }

    usub::uvent::task::Awaitable<void> test_pkce_and_callback_flow()
    {
        usub::uidentity::keycloak::KeycloakRealmConfig cfg;
        cfg.base_url = "https://issuer.example";
        cfg.realm = "demo";
        cfg.client_id = "client-app";
        cfg.redirect_uri = "https://service.example/callback";
        cfg.scopes = {"openid", "profile"};

        usub::uidentity::keycloak::MemoryStateStore store;
        FakeAuthMiddleware auth_middleware;

        FakeHttpClient http;
        http.handler = [&](const usub::unet::http::Request &request)
        {
            require(usub::uidentity::keycloak::detail::request_url(request) == usub::uidentity::keycloak::detail::token_endpoint(cfg.base_url, cfg.realm), "callback should post to token endpoint");
            require(request.body.find("grant_type=authorization_code") != std::string::npos, "callback grant type missing");
            usub::unet::http::Response response;
            response.setStatus(200);
            response.body = R"({"access_token":"access-1","refresh_token":"refresh-1","id_token":"id-1","token_type":"Bearer","scope":"openid profile","expires_in":300,"refresh_expires_in":3600})";
            return response;
        };

        usub::uidentity::keycloak::TokenServiceConfig token_cfg{
            .base_url = cfg.base_url,
            .realm = cfg.realm,
            .client_id = cfg.client_id,
            .client_secret = std::nullopt,
            .redirect_uri = cfg.redirect_uri,
        };

        usub::uidentity::keycloak::TokenService<FakeHttpClient> token_service(token_cfg, http);
        usub::uidentity::keycloak::KeycloakClient<usub::uidentity::keycloak::MemoryStateStore,
                                 usub::uidentity::keycloak::TokenService<FakeHttpClient>,
                                 FakeAuthMiddleware>
            client(cfg, store, token_service, auth_middleware);

        const auto auth_start = co_await client.start_login(std::chrono::minutes(5));
        require(!auth_start.state.empty(), "state should be generated");
        require(auth_start.authorization_url.find("code_challenge=") != std::string::npos, "authorization URL should include PKCE challenge");

        const usub::uidentity::keycloak::CallbackInput callback_input{
            .code = "auth-code",
            .state = auth_start.state,
        };
        const auto callback_result = co_await client.complete_login(callback_input);
        require(callback_result.ok, "callback should succeed");
        require(callback_result.tokens.access_token == "access-1", "callback access token mismatch");

        const auto second_try = co_await client.complete_login(callback_input);
        require(!second_try.ok, "state replay should fail");
        co_return;
    }

    usub::uvent::task::Awaitable<void> test_token_service_endpoints()
    {
        FakeHttpClient http;
        usub::uidentity::keycloak::TokenServiceConfig token_cfg{
            .base_url = "https://issuer.example",
            .realm = "demo",
            .client_id = "client-app",
            .client_secret = std::string("secret"),
            .redirect_uri = "https://service.example/callback",
        };

        http.handler = [&](const usub::unet::http::Request &request)
        {
            if (usub::uidentity::keycloak::detail::request_url(request) == usub::uidentity::keycloak::detail::token_endpoint(token_cfg.base_url, token_cfg.realm))
            {
                if (request.body.find("grant_type=refresh_token") != std::string::npos)
                {
                    usub::unet::http::Response response;
                    response.setStatus(200);
                    response.body = R"({"access_token":"access-2","refresh_token":"refresh-2","token_type":"Bearer","scope":"openid","expires_in":111,"refresh_expires_in":222})";
                    return response;
                }

                usub::unet::http::Response response;
                response.setStatus(200);
                response.body = R"({"access_token":"access-1","refresh_token":"refresh-1","id_token":"id-1","token_type":"Bearer","scope":"openid profile","expires_in":300,"refresh_expires_in":3600})";
                return response;
            }

            if (usub::uidentity::keycloak::detail::request_url(request) == usub::uidentity::keycloak::detail::revocation_endpoint(token_cfg.base_url, token_cfg.realm))
            {
                usub::unet::http::Response response;
                response.setStatus(204);
                return response;
            }

            if (usub::uidentity::keycloak::detail::request_url(request) == usub::uidentity::keycloak::detail::introspection_endpoint(token_cfg.base_url, token_cfg.realm))
            {
                usub::unet::http::Response response;
                response.setStatus(200);
                response.body = R"({"active":true,"sub":"user-123","preferred_username":"alice","email":"alice@example.com","scope":"openid profile","realm_access":{"roles":["admin"]}})";
                return response;
            }

            if (usub::uidentity::keycloak::detail::request_url(request) == usub::uidentity::keycloak::detail::userinfo_endpoint(token_cfg.base_url, token_cfg.realm))
            {
                usub::unet::http::Response response;
                response.setStatus(200);
                response.body = R"({"sub":"user-123","preferred_username":"alice","email":"alice@example.com","resource_access":{"api":{"roles":["reader"]}}})";
                return response;
            }

            throw std::runtime_error("unexpected request in test_token_service_endpoints");
        };

        usub::uidentity::keycloak::TokenService<FakeHttpClient> token_service(token_cfg, http);

        const auto exchange = co_await token_service.exchange_authorization_code("code-1", "verifier-1");
        require(exchange.ok, "authorization code exchange should succeed");
        require(exchange.tokens.access_token == "access-1", "exchange access token mismatch");

        const auto refresh = co_await token_service.refresh_tokens("refresh-1");
        require(refresh.ok, "refresh should succeed");
        require(refresh.tokens.access_token == "access-2", "refresh access token mismatch");

        const auto revoke = co_await token_service.revoke_token("refresh-2");
        require(revoke.ok, "revoke should succeed");

        const auto introspection = co_await token_service.introspect_token("access-2");
        require(introspection.ok, "introspection should succeed");
        require(introspection.user_info.roles.size() == 1, "introspection should parse roles");

        const auto user_info = co_await token_service.fetch_user_info("access-2");
        require(user_info.ok, "userinfo should succeed");
        require(user_info.user_info.email == "alice@example.com", "userinfo email mismatch");
        co_return;
    }

    usub::uvent::task::Awaitable<void> test_validator_and_bearer_middleware()
    {
        const auto key_material = make_test_key_material();
        const std::string issuer = "https://issuer.example/realms/demo";
        const std::string audience = "api-audience";
        const std::string azp = "spa-client";
        const auto jwt = make_signed_jwt(key_material.private_key.get(), issuer, audience, azp);

        FakeHttpClient http;
        http.handler = [&](const usub::unet::http::Request &request)
        {
            require(usub::uidentity::keycloak::detail::request_url(request) == issuer + "/protocol/openid-connect/certs", "validator should request configured jwks url");
            usub::unet::http::Response response;
            response.setStatus(200);
            response.body = key_material.jwks_json;
            return response;
        };

        AuthConfig auth_cfg{
            .expected_issuer = issuer,
            .jwks_url = issuer + "/protocol/openid-connect/certs",
            .require_audience = true,
            .expected_audience = audience,
            .expected_azp = azp,
            .clock_skew_seconds = 30,
        };

        usub::uidentity::keycloak::AccessTokenValidator<FakeHttpClient> validator(auth_cfg, http);
        const auto validation = co_await validator.validate(jwt);
        require(validation.ok, "validator should accept signed jwt");
        require(validation.context.roles.size() == 2, "validator should merge realm and client roles");
        require(validation.context.preferred_username == "alice", "validator username mismatch");
        require(http.requests.size() == 1, "validator should fetch jwks once");

        const auto validation_again = co_await validator.validate(jwt);
        require(validation_again.ok, "validator should accept signed jwt on second validation");
        require(http.requests.size() == 1, "validator should reuse cached jwks");

        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        const auto missing_issuer_jwt = make_signed_jwt_with_payload(
            key_material.private_key.get(),
            std::string("{") +
                "\"sub\":\"user-123\","
                "\"aud\":[\"" + audience + "\"],"
                "\"azp\":\"" + azp + "\","
                "\"exp\":" + std::to_string(now + 3600) +
                "}");
        const auto missing_issuer = co_await validator.validate(missing_issuer_jwt);
        require(!missing_issuer.ok, "validator should reject jwt without issuer");
        require(missing_issuer.error == "jwt_missing_issuer", "missing issuer error mismatch");

        const auto missing_exp_jwt = make_signed_jwt_with_payload(
            key_material.private_key.get(),
            std::string("{") +
                "\"iss\":\"" + issuer + "\","
                "\"sub\":\"user-123\","
                "\"aud\":[\"" + audience + "\"],"
                "\"azp\":\"" + azp + "\""
                "}");
        const auto missing_exp = co_await validator.validate(missing_exp_jwt);
        require(!missing_exp.ok, "validator should reject jwt without exp");
        require(missing_exp.error == "jwt_missing_exp", "missing exp error mismatch");

        usub::uidentity::keycloak::BearerAuthMiddleware<usub::uidentity::keycloak::AccessTokenValidator<FakeHttpClient>> middleware(validator);
        usub::unet::http::Request request{
            .metadata = {
                .method_token = "GET",
                .uri = {.path = "/protected"},
            },
            .body = "",
        };
        request.headers.addHeader("Authorization", "Bearer " + jwt);
        RequestContext context;
        const auto auth_result = co_await middleware.authenticate(request, context);
        require(auth_result.ok, "middleware should authenticate valid bearer token");
        require(context.authenticated, "middleware should propagate authenticated context");
        const auto *stored_context = get_request_context(request);
        require(stored_context != nullptr, "middleware should store request context in user_data");
        require(stored_context->preferred_username == "alice", "stored request context username mismatch");
        co_return;
    }

    usub::uvent::task::Awaitable<void> test_live_redis_state_store_if_configured()
    {
        if (!getenv_string("UIDENTITY_TEST_REDIS"))
        {
            co_return;
        }

        usub::uredis::RedisClusterConfig redis_cfg;
        redis_cfg.seeds = {{
            .host = getenv_string("UIDENTITY_TEST_REDIS_HOST").value_or("127.0.0.1"),
            .port = static_cast<std::uint16_t>(getenv_int("UIDENTITY_TEST_REDIS_PORT", 6379)),
        }};
        redis_cfg.password = getenv_string("UIDENTITY_TEST_REDIS_PASSWORD");
        redis_cfg.username = getenv_string("UIDENTITY_TEST_REDIS_USERNAME");
        redis_cfg.force_standalone = true;

        usub::uredis::RedisClusterClient redis(redis_cfg);
        const auto connect_result = co_await redis.connect();
        require(static_cast<bool>(connect_result), "redis connect should succeed");

        usub::uidentity::keycloak::RedisStateStore store(redis, "kc:test:state:");
        const auto state = co_await store.create_state("verifier-123", std::chrono::seconds(30));
        require(!state.empty(), "redis state should be created");

        const auto verifier = co_await store.consume_state(state);
        require(verifier.has_value(), "redis state should be consumable");
        require(*verifier == "verifier-123", "redis verifier mismatch");

        const auto second_try = co_await store.consume_state(state);
        require(!second_try.has_value(), "redis state should be one-time use");
        co_return;
    }

    usub::uvent::task::Awaitable<void> test_cookie_helpers_and_auth_handler_flow()
    {
        const auto parsed = usub::uidentity::utils::parse_cookie_header("access_token=abc.def; refresh_token=refresh%201");
        require(parsed.at("access_token") == "abc.def", "access token cookie should parse");
        require(parsed.at("refresh_token") == "refresh 1", "refresh token cookie should decode");

        FakeHandlerClient client{
            .callback_result = {
                .ok = true,
                .http_status = 200,
                .error = "",
                .tokens = {
                    .access_token = "access-1",
                    .id_token = "id-1",
                    .refresh_token = "refresh-1",
                    .token_type = "Bearer",
                    .scope = "openid profile",
                    .expires_in = 300,
                    .refresh_expires_in = 3600,
                },
                .realm = "trader",
            },
        };
        FakeHandlerTokenService token_service;
        usub::uidentity::handlers::AuthHandlerConfig config;
        config.token_cookies.secure = false;
        config.post_login_redirect = "/app";
        config.post_logout_redirect = "/signed-out";

        usub::uidentity::handlers::AuthHandler handler(client, token_service, config);

        usub::unet::http::Request login_request{
            .metadata = {
                .method_token = "GET",
                .uri = {.path = "/auth/login", .query = "realm=trader"},
            },
        };
        usub::unet::http::Response login_response;
        co_await handler.login(login_request, login_response);

        require(login_response.metadata.status_code == 302, "login should redirect");
        require(login_response.headers.value("Location").value_or("").find("realm=trader") != std::string::npos,
                "login should include selected realm");

        usub::unet::http::Request callback_request{
            .metadata = {
                .method_token = "GET",
                .uri = {.path = "/api/v1/callback", .query = "code=auth-code&state=state-1"},
            },
        };
        usub::unet::http::Response callback_response;
        co_await handler.callback(callback_request, callback_response);

        require(callback_response.metadata.status_code == 302, "callback should redirect");
        require(callback_response.headers.value("Location").value_or("") == "/app", "callback redirect mismatch");
        const auto set_cookies = callback_response.headers.all("Set-Cookie");
        require(set_cookies.size() == 2, "callback should set access and refresh cookies");
        require(set_cookies[0].value.find("access_token_trader=access-1") != std::string::npos, "access cookie missing");
        require(set_cookies[1].value.find("refresh_token_trader=refresh-1") != std::string::npos, "refresh cookie missing");
        require(set_cookies[0].value.find("HttpOnly") != std::string::npos, "access cookie should be httpOnly");
        require(set_cookies[0].value.find("SameSite=Lax") != std::string::npos, "access cookie should include sameSite");

        usub::unet::http::Request logout_request{
            .metadata = {
                .method_token = "GET",
                .uri = {.path = "/auth/logout", .query = "realm=trader"},
            },
        };
        logout_request.headers.addHeader(std::string_view{"Cookie"},
                                         std::string_view{"access_token_trader=access-1; refresh_token_trader=refresh-1"});
        usub::unet::http::Response logout_response;
        co_await handler.logout(logout_request, logout_response);

        require(logout_response.metadata.status_code == 302, "logout should redirect");
        require(logout_response.headers.value("Location").value_or("") == "/signed-out", "logout redirect mismatch");
        require(token_service.revoked_tokens.size() == 1, "logout should revoke refresh token");
        require(token_service.revoked_realms[0] == "trader", "logout should route revoke through selected realm");
        require(token_service.revoked_tokens[0] == "refresh-1", "logout should revoke cookie refresh token");
        const auto expired_cookies = logout_response.headers.all("Set-Cookie");
        require(expired_cookies.size() == 2, "logout should clear both cookies");
        require(expired_cookies[0].value.find("Max-Age=0") != std::string::npos, "cleared access cookie should expire");
        require(expired_cookies[1].value.find("Max-Age=0") != std::string::npos, "cleared refresh cookie should expire");
        co_return;
    }
} // namespace

int main()
{
    try
    {
        run_async_test(test_oidc_discovery);
        run_async_test(test_pkce_and_callback_flow);
        run_async_test(test_token_service_endpoints);
        run_async_test(test_validator_and_bearer_middleware);
        run_async_test(test_live_redis_state_store_if_configured);
        run_async_test(test_cookie_helpers_and_auth_handler_flow);
        std::cout << "All UIdentity tests passed.\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Test failure: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
}
