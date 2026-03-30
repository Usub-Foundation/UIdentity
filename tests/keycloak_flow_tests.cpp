#include <chrono>
#include <cstdlib>
#include <cstring>
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

#include "api_models/http_context.hpp"
#include "keycloak/auth/bearer_auth_middleware.hpp"
#include "keycloak/auth/pkce_auth_strat.hpp"
#include "keycloak/detail/oidc_utils.hpp"
#include "keycloak/jwt/access_token_validator.hpp"
#include "keycloak/oauth/callback_service.hpp"
#include "keycloak/oidc/discovery.hpp"
#include "keycloak/state_store/memory.hpp"

namespace
{
    struct FakeHttpClient
    {
        std::function<keycloak::http::Response(const keycloak::http::Request &)> handler;
        std::vector<keycloak::http::Request> requests;

        keycloak::http::Response send(const keycloak::http::Request &request)
        {
            requests.push_back(request);
            if (!handler)
            {
                return {};
            }
            return handler(request);
        }
    };

    void require(bool condition, std::string_view message)
    {
        if (!condition)
        {
            throw std::runtime_error(std::string(message));
        }
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

    std::string make_signed_jwt(EVP_PKEY *private_key,
                                std::string_view issuer,
                                std::string_view audience,
                                std::string_view azp)
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();

        const std::string header = R"({"alg":"RS256","typ":"JWT","kid":"test-kid"})";
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

        const auto signing_input = base64url_encode(header) + "." + base64url_encode(payload);
        const auto signature = sign_rs256(private_key, signing_input);
        return signing_input + "." + base64url_encode(signature);
    }

    void test_oidc_discovery()
    {
        FakeHttpClient http;
        http.handler = [](const keycloak::http::Request &request)
        {
            require(request.method == "GET", "discovery should use GET");
            return keycloak::http::Response{
                .status = 200,
                .headers = {},
                .body = R"({"issuer":"https://issuer.example/realms/demo","authorization_endpoint":"https://issuer.example/auth","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks","userinfo_endpoint":"https://issuer.example/userinfo","revocation_endpoint":"https://issuer.example/revoke","introspection_endpoint":"https://issuer.example/introspect","end_session_endpoint":"https://issuer.example/logout"})",
            };
        };

        keycloak::OidcDiscoveryClient<FakeHttpClient> discovery(http);
        const auto result = discovery.discover("https://issuer.example", "demo");
        require(result.ok, "discovery should succeed");
        require(result.endpoints.jwks_uri == "https://issuer.example/jwks", "jwks endpoint mismatch");
    }

    void test_pkce_and_callback_flow()
    {
        keycloak::KeycloakRealmConfig cfg;
        cfg.base_url = "https://issuer.example";
        cfg.realm = "demo";
        cfg.client_id = "client-app";
        cfg.redirect_uri = "https://service.example/callback";
        cfg.scopes = {"openid", "profile"};

        keycloak::MemoryStateStore store;
        keycloak::PkceAuthStrategy<keycloak::MemoryStateStore> pkce(cfg, store);
        const auto auth_start = pkce.create_authorization_url();
        require(!auth_start.state.empty(), "state should be generated");
        require(auth_start.authorization_url.find("code_challenge=") != std::string::npos, "authorization URL should include PKCE challenge");

        FakeHttpClient http;
        http.handler = [&](const keycloak::http::Request &request)
        {
            require(request.url == keycloak::detail::token_endpoint(cfg.base_url, cfg.realm), "callback should post to token endpoint");
            require(request.body.find("grant_type=authorization_code") != std::string::npos, "callback grant type missing");
            return keycloak::http::Response{
                .status = 200,
                .headers = {},
                .body = R"({"access_token":"access-1","refresh_token":"refresh-1","id_token":"id-1","token_type":"Bearer","scope":"openid profile","expires_in":300,"refresh_expires_in":3600})",
            };
        };

        keycloak::TokenServiceConfig token_cfg{
            .base_url = cfg.base_url,
            .realm = cfg.realm,
            .client_id = cfg.client_id,
            .client_secret = std::nullopt,
            .redirect_uri = cfg.redirect_uri,
        };

        keycloak::TokenService<FakeHttpClient> token_service(token_cfg, http);
        keycloak::CallbackService<keycloak::MemoryStateStore, keycloak::TokenService<FakeHttpClient>> callback(store, token_service);
        const auto callback_result = callback.handle({.code = "auth-code", .state = auth_start.state});
        require(callback_result.ok, "callback should succeed");
        require(callback_result.tokens.access_token == "access-1", "callback access token mismatch");

        const auto second_try = callback.handle({.code = "auth-code", .state = auth_start.state});
        require(!second_try.ok, "state replay should fail");
    }

    void test_token_service_endpoints()
    {
        FakeHttpClient http;
        keycloak::TokenServiceConfig token_cfg{
            .base_url = "https://issuer.example",
            .realm = "demo",
            .client_id = "client-app",
            .client_secret = std::string("secret"),
            .redirect_uri = "https://service.example/callback",
        };

        http.handler = [&](const keycloak::http::Request &request)
        {
            if (request.url == keycloak::detail::token_endpoint(token_cfg.base_url, token_cfg.realm))
            {
                if (request.body.find("grant_type=refresh_token") != std::string::npos)
                {
                    return keycloak::http::Response{
                        .status = 200,
                        .headers = {},
                        .body = R"({"access_token":"access-2","refresh_token":"refresh-2","token_type":"Bearer","scope":"openid","expires_in":111,"refresh_expires_in":222})",
                    };
                }

                return keycloak::http::Response{
                    .status = 200,
                    .headers = {},
                    .body = R"({"access_token":"access-1","refresh_token":"refresh-1","id_token":"id-1","token_type":"Bearer","scope":"openid profile","expires_in":300,"refresh_expires_in":3600})",
                };
            }

            if (request.url == keycloak::detail::revocation_endpoint(token_cfg.base_url, token_cfg.realm))
            {
                return keycloak::http::Response{.status = 204, .headers = {}, .body = ""};
            }

            if (request.url == keycloak::detail::introspection_endpoint(token_cfg.base_url, token_cfg.realm))
            {
                return keycloak::http::Response{
                    .status = 200,
                    .headers = {},
                    .body = R"({"active":true,"sub":"user-123","preferred_username":"alice","email":"alice@example.com","scope":"openid profile","realm_access":{"roles":["admin"]}})",
                };
            }

            if (request.url == keycloak::detail::userinfo_endpoint(token_cfg.base_url, token_cfg.realm))
            {
                return keycloak::http::Response{
                    .status = 200,
                    .headers = {},
                    .body = R"({"sub":"user-123","preferred_username":"alice","email":"alice@example.com","resource_access":{"api":{"roles":["reader"]}}})",
                };
            }

            throw std::runtime_error("unexpected request in test_token_service_endpoints");
        };

        keycloak::TokenService<FakeHttpClient> token_service(token_cfg, http);

        const auto exchange = token_service.exchange_authorization_code("code-1", "verifier-1");
        require(exchange.ok, "authorization code exchange should succeed");
        require(exchange.tokens.access_token == "access-1", "exchange access token mismatch");

        const auto refresh = token_service.refresh_tokens("refresh-1");
        require(refresh.ok, "refresh should succeed");
        require(refresh.tokens.access_token == "access-2", "refresh access token mismatch");

        const auto revoke = token_service.revoke_token("refresh-2");
        require(revoke.ok, "revoke should succeed");

        const auto introspection = token_service.introspect_token("access-2");
        require(introspection.ok, "introspection should succeed");
        require(introspection.user_info.roles.size() == 1, "introspection should parse roles");

        const auto user_info = token_service.fetch_user_info("access-2");
        require(user_info.ok, "userinfo should succeed");
        require(user_info.user_info.email == "alice@example.com", "userinfo email mismatch");
    }

    void test_validator_and_bearer_middleware()
    {
        const auto key_material = make_test_key_material();
        const std::string issuer = "https://issuer.example/realms/demo";
        const std::string audience = "api-audience";
        const std::string azp = "spa-client";
        const auto jwt = make_signed_jwt(key_material.private_key.get(), issuer, audience, azp);

        FakeHttpClient http;
        http.handler = [&](const keycloak::http::Request &request)
        {
            require(request.url == issuer + "/protocol/openid-connect/certs", "validator should request configured jwks url");
            return keycloak::http::Response{
                .status = 200,
                .headers = {},
                .body = key_material.jwks_json,
            };
        };

        AuthConfig auth_cfg{
            .expected_issuer = issuer,
            .jwks_url = issuer + "/protocol/openid-connect/certs",
            .require_audience = true,
            .expected_audience = audience,
            .expected_azp = azp,
            .clock_skew_seconds = 30,
        };

        keycloak::AccessTokenValidator<FakeHttpClient> validator(auth_cfg, http);
        const auto validation = validator.validate(jwt);
        require(validation.ok, "validator should accept signed jwt");
        require(validation.context.roles.size() == 2, "validator should merge realm and client roles");
        require(validation.context.preferred_username == "alice", "validator username mismatch");

        keycloak::BearerAuthMiddleware<keycloak::AccessTokenValidator<FakeHttpClient>> middleware(validator);
        HttpRequest request{
            .method = "GET",
            .path = "/protected",
            .headers = {{"Authorization", "Bearer " + jwt}},
            .body = "",
            .query = "",
        };
        RequestContext context;
        const auto auth_result = middleware.authenticate(request, context);
        require(auth_result.ok, "middleware should authenticate valid bearer token");
        require(context.authenticated, "middleware should propagate authenticated context");
    }
} // namespace

int main()
{
    try
    {
        test_oidc_discovery();
        test_pkce_and_callback_flow();
        test_token_service_endpoints();
        test_validator_and_bearer_middleware();
        std::cout << "All UIdentity tests passed.\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Test failure: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
}
