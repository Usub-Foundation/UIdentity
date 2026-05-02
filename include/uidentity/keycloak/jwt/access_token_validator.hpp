#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <uvent/tasks/Awaitable.h>
#include <uvent/tasks/AwaitableFrame.h>

#include "uidentity/api_models/concepts.hpp"
#include "uidentity/api_models/http_context.hpp"
#include "uidentity/keycloak/detail/json_utils.hpp"
#include "uidentity/keycloak/detail/jwt_utils.hpp"
#include "uidentity/keycloak/detail/oidc_utils.hpp"

namespace keycloak
{
    struct JwtValidationResult
    {
        bool ok = false;
        int http_status = 401;
        std::string error;
        RequestContext context;
    };

    template <AsyncHttpClientLike HttpClient>
    class AccessTokenValidator
    {
    public:
        AccessTokenValidator(AuthConfig cfg, HttpClient &http_client)
            : cfg_(std::move(cfg)), http_client_(http_client)
        {
        }

        usub::uvent::task::Awaitable<JwtValidationResult> validate(std::string_view access_token) const
        {
            if (access_token.empty())
            {
                co_return failure(401, "missing_access_token");
            }

            const auto jwt = detail::decode_jwt(access_token);
            if (!jwt.has_value())
            {
                co_return failure(401, "invalid_jwt_format");
            }

            const auto alg = detail::extract_json_string(jwt->header_json, "alg").value_or("");
            if (alg.empty())
            {
                co_return failure(401, "jwt_missing_alg");
            }

            if (!detail::evp_digest_for_alg(alg))
            {
                co_return failure(401, "unsupported_jwt_alg");
            }

            const auto kid = detail::extract_json_string(jwt->header_json, "kid").value_or("");
            if (kid.empty())
            {
                co_return failure(401, "jwt_missing_kid");
            }

            auto keys = cached_keys(now_seconds());
            if (keys.empty())
            {
                const auto refreshed = co_await refresh_jwks();
                if (!refreshed.ok)
                {
                    co_return failure(refreshed.http_status, std::move(refreshed.error));
                }
                keys = std::move(refreshed.keys);
            }

            const auto key_it = std::find_if(keys.begin(),
                                             keys.end(),
                                             [&kid](const detail::Jwk &key)
                                             {
                                                 return key.kid == kid;
                                             });
            if (key_it == keys.end())
            {
                co_return failure(401, "jwks_key_not_found");
            }

            if (!detail::verify_rsa_signature(*key_it, alg, jwt->signing_input, jwt->signature))
            {
                co_return failure(401, "jwt_signature_invalid");
            }

            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            const auto skew = static_cast<std::int64_t>(cfg_.clock_skew_seconds);

            const auto issuer = detail::extract_json_string(jwt->payload_json, "iss");
            if (!issuer.has_value() || issuer->empty())
            {
                co_return failure(401, "jwt_missing_issuer");
            }
            if (!cfg_.expected_issuer.empty() && *issuer != cfg_.expected_issuer)
            {
                co_return failure(401, "jwt_issuer_mismatch");
            }

            const auto exp = detail::extract_json_int64(jwt->payload_json, "exp");
            if (!exp.has_value())
            {
                co_return failure(401, "jwt_missing_exp");
            }
            if (now > (*exp + skew))
            {
                co_return failure(401, "jwt_expired");
            }

            if (const auto nbf = detail::extract_json_int64(jwt->payload_json, "nbf"))
            {
                if (now + skew < *nbf)
                {
                    co_return failure(401, "jwt_not_yet_valid");
                }
            }

            if (cfg_.require_audience && !cfg_.expected_audience.empty())
            {
                const auto audiences = detail::extract_audience_values(jwt->payload_json);
                if (!detail::contains_string(audiences, cfg_.expected_audience))
                {
                    co_return failure(403, "jwt_audience_mismatch");
                }
            }

            if (!cfg_.expected_azp.empty())
            {
                const auto azp = detail::extract_json_string(jwt->payload_json, "azp").value_or("");
                if (azp != cfg_.expected_azp)
                {
                    co_return failure(403, "jwt_azp_mismatch");
                }
            }

            RequestContext context;
            context.authenticated = true;
            context.sub = detail::extract_json_string(jwt->payload_json, "sub").value_or("");
            context.preferred_username = detail::extract_json_string(jwt->payload_json, "preferred_username").value_or("");
            context.issuer = detail::extract_json_string(jwt->payload_json, "iss").value_or("");
            context.realm = context.issuer.empty() ? "" : detail::last_path_segment(context.issuer);
            context.client_id = detail::extract_json_string(jwt->payload_json, "azp")
                                    .value_or(detail::extract_json_string(jwt->payload_json, "client_id").value_or(""));
            context.roles = detail::extract_all_roles(jwt->payload_json);
            context.scopes = detail::split_ws(detail::extract_json_string(jwt->payload_json, "scope").value_or(""));

            co_return JwtValidationResult{
                .ok = true,
                .http_status = 200,
                .error = "",
                .context = std::move(context),
            };
        }

    private:
        struct JwksFetchResult
        {
            bool ok = false;
            int http_status = 502;
            std::string error;
            std::vector<detail::Jwk> keys;
        };

        struct JwksCache
        {
            std::vector<detail::Jwk> keys;
            std::chrono::steady_clock::time_point expires_at{};
        };

        static JwtValidationResult failure(int http_status, std::string error)
        {
            return JwtValidationResult{
                .ok = false,
                .http_status = http_status,
                .error = std::move(error),
                .context = RequestContext{},
            };
        }

        static std::chrono::steady_clock::time_point now_steady()
        {
            return std::chrono::steady_clock::now();
        }

        static std::int64_t now_seconds()
        {
            return std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        }

        std::vector<detail::Jwk> cached_keys(std::int64_t /*unused*/) const
        {
            std::lock_guard lock(cache_mutex_);
            if (!cache_.keys.empty() && now_steady() < cache_.expires_at)
            {
                return cache_.keys;
            }
            return {};
        }

        usub::uvent::task::Awaitable<JwksFetchResult> refresh_jwks() const
        {
            const auto jwks_response = co_await http_client_.send(detail::make_json_get(cfg_.jwks_url));
            const int jwks_status = jwks_response.metadata.status_code > 0 ? jwks_response.metadata.status_code : 502;
            if (jwks_status < 200 || jwks_status >= 300)
            {
                co_return JwksFetchResult{
                    .ok = false,
                    .http_status = 502,
                    .error = "jwks_fetch_failed",
                };
            }

            auto keys = detail::extract_jwks(jwks_response.body);
            if (keys.empty())
            {
                co_return JwksFetchResult{
                    .ok = false,
                    .http_status = 502,
                    .error = "jwks_parse_failed",
                };
            }

            {
                std::lock_guard lock(cache_mutex_);
                cache_.keys = keys;
                cache_.expires_at = now_steady() + cfg_.jwks_cache_ttl;
            }

            co_return JwksFetchResult{
                .ok = true,
                .http_status = 200,
                .error = "",
                .keys = std::move(keys),
            };
        }

        AuthConfig cfg_;
        HttpClient &http_client_;
        mutable std::mutex cache_mutex_;
        mutable JwksCache cache_;
    };
} // namespace keycloak
