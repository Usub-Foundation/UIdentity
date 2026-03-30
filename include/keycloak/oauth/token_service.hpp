#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "api_models/concepts.hpp"
#include "keycloak/detail/json_utils.hpp"
#include "keycloak/detail/jwt_utils.hpp"
#include "keycloak/detail/oidc_utils.hpp"
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
            if (code.empty() || code_verifier.empty())
            {
                return OAuthResult{
                    .ok = false,
                    .http_status = 400,
                    .error = "missing_code_or_code_verifier",
                };
            }

            const auto request_body = [this, code, code_verifier]()
            {
                std::vector<std::pair<std::string_view, std::string_view>> fields{
                    {"grant_type", "authorization_code"},
                    {"code", code},
                    {"client_id", cfg_.client_id},
                    {"redirect_uri", cfg_.redirect_uri},
                    {"code_verifier", code_verifier},
                };

                if (cfg_.client_secret.has_value())
                {
                    fields.emplace_back("client_secret", *cfg_.client_secret);
                }

                return detail::build_form_body(fields);
            }();

            const auto response = http_client_.send(
                detail::make_form_post(detail::token_endpoint(cfg_.base_url, cfg_.realm), request_body));
            return parse_token_response(response, "token_exchange_failed");
        }

        OAuthResult refresh_tokens(std::string_view refresh_token)
        {
            if (refresh_token.empty())
            {
                return OAuthResult{
                    .ok = false,
                    .http_status = 400,
                    .error = "missing_refresh_token",
                };
            }

            const auto request_body = [this, refresh_token]()
            {
                std::vector<std::pair<std::string_view, std::string_view>> fields{
                    {"grant_type", "refresh_token"},
                    {"refresh_token", refresh_token},
                    {"client_id", cfg_.client_id},
                };

                if (cfg_.client_secret.has_value())
                {
                    fields.emplace_back("client_secret", *cfg_.client_secret);
                }

                return detail::build_form_body(fields);
            }();

            const auto response = http_client_.send(
                detail::make_form_post(detail::token_endpoint(cfg_.base_url, cfg_.realm), request_body));
            return parse_token_response(response, "token_refresh_failed");
        }

        OAuthResult revoke_token(std::string_view token,
                                 std::string_view token_type_hint = "refresh_token")
        {
            if (token.empty())
            {
                return OAuthResult{
                    .ok = false,
                    .http_status = 400,
                    .error = "missing_token",
                };
            }

            const auto request_body = [this, token, token_type_hint]()
            {
                std::vector<std::pair<std::string_view, std::string_view>> fields{
                    {"client_id", cfg_.client_id},
                    {"token", token},
                    {"token_type_hint", token_type_hint},
                };

                if (cfg_.client_secret.has_value())
                {
                    fields.emplace_back("client_secret", *cfg_.client_secret);
                }

                return detail::build_form_body(fields);
            }();

            const auto response = http_client_.send(
                detail::make_form_post(detail::revocation_endpoint(cfg_.base_url, cfg_.realm), request_body));
            const int http_status = response.status > 0 ? response.status : 502;

            if (http_status >= 200 && http_status < 300)
            {
                return OAuthResult{
                    .ok = true,
                    .http_status = http_status,
                    .error = "",
                };
            }

            return OAuthResult{
                .ok = false,
                .http_status = http_status,
                .error = detail::extract_json_string(response.body, "error").value_or("token_revoke_failed"),
            };
        }

        OAuthResult introspect_token(std::string_view token)
        {
            if (token.empty())
            {
                return OAuthResult{
                    .ok = false,
                    .http_status = 400,
                    .error = "missing_token",
                };
            }

            const auto request_body = [this, token]()
            {
                std::vector<std::pair<std::string_view, std::string_view>> fields{
                    {"client_id", cfg_.client_id},
                    {"token", token},
                };

                if (cfg_.client_secret.has_value())
                {
                    fields.emplace_back("client_secret", *cfg_.client_secret);
                }

                return detail::build_form_body(fields);
            }();

            const auto response = http_client_.send(
                detail::make_form_post(detail::introspection_endpoint(cfg_.base_url, cfg_.realm), request_body));
            const int http_status = response.status > 0 ? response.status : 502;

            if (http_status < 200 || http_status >= 300)
            {
                return OAuthResult{
                    .ok = false,
                    .http_status = http_status,
                    .error = detail::extract_json_string(response.body, "error").value_or("token_introspection_failed"),
                };
            }

            if (!detail::extract_json_bool(response.body, "active").value_or(false))
            {
                return OAuthResult{
                    .ok = false,
                    .http_status = 401,
                    .error = "inactive_token",
                };
            }

            UserInfo user_info;
            user_info.sub = detail::extract_json_string(response.body, "sub").value_or("");
            user_info.preferred_username = detail::extract_json_string(response.body, "preferred_username").value_or("");
            user_info.email = detail::extract_json_string(response.body, "email").value_or("");
            user_info.roles = detail::extract_all_roles(response.body);

            TokenSet tokens;
            tokens.scope = detail::extract_json_string(response.body, "scope").value_or("");
            tokens.token_type = detail::extract_json_string(response.body, "token_type").value_or("Bearer");
            if (const auto exp = detail::extract_json_int(response.body, "exp"))
            {
                tokens.expires_in = *exp;
            }

            return OAuthResult{
                .ok = true,
                .http_status = http_status,
                .error = "",
                .tokens = std::move(tokens),
                .user_info = std::move(user_info),
            };
        }

        OAuthResult fetch_user_info(std::string_view access_token)
        {
            if (access_token.empty())
            {
                return OAuthResult{
                    .ok = false,
                    .http_status = 400,
                    .error = "missing_access_token",
                };
            }

            const auto response = http_client_.send(
                detail::make_json_get(detail::userinfo_endpoint(cfg_.base_url, cfg_.realm), access_token));
            const int http_status = response.status > 0 ? response.status : 502;

            if (http_status < 200 || http_status >= 300)
            {
                return OAuthResult{
                    .ok = false,
                    .http_status = http_status,
                    .error = detail::extract_json_string(response.body, "error").value_or("userinfo_request_failed"),
                };
            }

            UserInfo user_info;
            user_info.sub = detail::extract_json_string(response.body, "sub").value_or("");
            user_info.preferred_username = detail::extract_json_string(response.body, "preferred_username").value_or("");
            user_info.email = detail::extract_json_string(response.body, "email").value_or("");
            user_info.roles = detail::extract_all_roles(response.body);

            return OAuthResult{
                .ok = true,
                .http_status = http_status,
                .error = "",
                .user_info = std::move(user_info),
            };
        }

    private:
        OAuthResult parse_token_response(const http::Response &response,
                                        std::string_view fallback_error) const
        {
            const int http_status = response.status > 0 ? response.status : 502;
            if (http_status < 200 || http_status >= 300)
            {
                return OAuthResult{
                    .ok = false,
                    .http_status = http_status,
                    .error = detail::extract_json_string(response.body, "error").value_or(std::string(fallback_error)),
                };
            }

            const auto access_token = detail::extract_json_string(response.body, "access_token");
            if (!access_token.has_value())
            {
                return OAuthResult{
                    .ok = false,
                    .http_status = http_status,
                    .error = "token_response_missing_access_token",
                };
            }

            TokenSet tokens;
            tokens.access_token = *access_token;
            tokens.id_token = detail::extract_json_string(response.body, "id_token").value_or("");
            tokens.refresh_token = detail::extract_json_string(response.body, "refresh_token").value_or("");
            tokens.token_type = detail::extract_json_string(response.body, "token_type").value_or("Bearer");
            tokens.scope = detail::extract_json_string(response.body, "scope").value_or("");
            tokens.expires_in = detail::extract_json_int(response.body, "expires_in").value_or(0);
            tokens.refresh_expires_in = detail::extract_json_int(response.body, "refresh_expires_in").value_or(0);

            return OAuthResult{
                .ok = true,
                .http_status = http_status,
                .error = "",
                .tokens = std::move(tokens),
            };
        }

        TokenServiceConfig cfg_;
        HttpClient &http_client_;
    };
} // namespace keycloak
