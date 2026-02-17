#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "api_models/concepts.hpp"
#include "keycloak/oauth/types.hpp"

namespace keycloak
{
    struct TokenServiceConfig
    {
        std::string base_url;
        std::string realm;
        std::string client_id;
        std::optional<std::string> client_secret;
        std::string redirect_uri;
    };

    template <HttpClientLike HttpClient>
    class TokenService
    {
    public:
        TokenService(TokenServiceConfig cfg, HttpClient &http_client)
            : cfg_(std::move(cfg)), http_client_(http_client)
        {
        }

        OAuthResult exchange_authorization_code(std::string_view code,
                                                std::string_view code_verifier)
        {
            (void)code;
            (void)code_verifier;
            return OAuthResult{
                .ok = false,
                .http_status = 501,
                .error = "token_exchange_not_implemented",
            };
        }

        OAuthResult refresh_tokens(std::string_view refresh_token)
        {
            (void)refresh_token;
            return OAuthResult{
                .ok = false,
                .http_status = 501,
                .error = "refresh_not_implemented",
            };
        }

        OAuthResult revoke_token(std::string_view token,
                                 std::string_view token_type_hint = "refresh_token")
        {
            (void)token;
            (void)token_type_hint;
            return OAuthResult{
                .ok = false,
                .http_status = 501,
                .error = "revoke_not_implemented",
            };
        }

        OAuthResult introspect_token(std::string_view token)
        {
            (void)token;
            return OAuthResult{
                .ok = false,
                .http_status = 501,
                .error = "introspect_not_implemented",
            };
        }

        OAuthResult fetch_user_info(std::string_view access_token)
        {
            (void)access_token;
            return OAuthResult{
                .ok = false,
                .http_status = 501,
                .error = "userinfo_not_implemented",
            };
        }

    private:
        TokenServiceConfig cfg_;
        HttpClient &http_client_;
    };
} // namespace keycloak
