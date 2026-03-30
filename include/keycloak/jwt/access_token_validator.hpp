#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include "api_models/concepts.hpp"
#include "api_models/http_context.hpp"
#include "keycloak/detail/json_utils.hpp"
#include "keycloak/detail/jwt_utils.hpp"
#include "keycloak/detail/oidc_utils.hpp"

namespace keycloak
{
    struct JwtValidationResult
    {
        bool ok = false;
        int http_status = 401;
        std::string error;
        RequestContext context;
    };

    template <HttpClientLike HttpClient>
    class AccessTokenValidator
    {
    public:
        AccessTokenValidator(AuthConfig cfg, HttpClient &http_client)
            : cfg_(std::move(cfg)), http_client_(http_client)
        {
        }

        JwtValidationResult validate(std::string_view access_token) const
        {
            if (access_token.empty())
            {
                return failure(401, "missing_access_token");
            }

            const auto jwt = detail::decode_jwt(access_token);
            if (!jwt.has_value())
            {
                return failure(401, "invalid_jwt_format");
            }

            const auto alg = detail::extract_json_string(jwt->header_json, "alg").value_or("");
            if (alg.empty())
            {
                return failure(401, "jwt_missing_alg");
            }

            if (!detail::evp_digest_for_alg(alg))
            {
                return failure(401, "unsupported_jwt_alg");
            }

            const auto jwks_response = http_client_.send(detail::make_json_get(cfg_.jwks_url));
            const int jwks_status = jwks_response.status > 0 ? jwks_response.status : 502;
            if (jwks_status < 200 || jwks_status >= 300)
            {
                return failure(502, "jwks_fetch_failed");
            }

            const auto kid = detail::extract_json_string(jwt->header_json, "kid").value_or("");
            const auto keys = detail::extract_jwks(jwks_response.body);
            const auto key_it = std::find_if(keys.begin(),
                                             keys.end(),
                                             [&kid](const detail::Jwk &key)
                                             {
                                                 return kid.empty() || key.kid == kid;
                                             });
            if (key_it == keys.end())
            {
                return failure(401, "jwks_key_not_found");
            }

            if (!detail::verify_rsa_signature(*key_it, alg, jwt->signing_input, jwt->signature))
            {
                return failure(401, "jwt_signature_invalid");
            }

            const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            const auto skew = static_cast<std::int64_t>(cfg_.clock_skew_seconds);

            if (const auto issuer = detail::extract_json_string(jwt->payload_json, "iss"))
            {
                if (!cfg_.expected_issuer.empty() && *issuer != cfg_.expected_issuer)
                {
                    return failure(401, "jwt_issuer_mismatch");
                }
            }

            if (const auto exp = detail::extract_json_int64(jwt->payload_json, "exp"))
            {
                if (now > (*exp + skew))
                {
                    return failure(401, "jwt_expired");
                }
            }

            if (const auto nbf = detail::extract_json_int64(jwt->payload_json, "nbf"))
            {
                if (now + skew < *nbf)
                {
                    return failure(401, "jwt_not_yet_valid");
                }
            }

            if (cfg_.require_audience && !cfg_.expected_audience.empty())
            {
                const auto audiences = detail::extract_audience_values(jwt->payload_json);
                if (!detail::contains_string(audiences, cfg_.expected_audience))
                {
                    return failure(403, "jwt_audience_mismatch");
                }
            }

            if (!cfg_.expected_azp.empty())
            {
                const auto azp = detail::extract_json_string(jwt->payload_json, "azp").value_or("");
                if (azp != cfg_.expected_azp)
                {
                    return failure(403, "jwt_azp_mismatch");
                }
            }

            RequestContext context;
            context.authenticated = true;
            context.sub = detail::extract_json_string(jwt->payload_json, "sub").value_or("");
            context.preferred_username = detail::extract_json_string(jwt->payload_json, "preferred_username").value_or("");
            context.issuer = detail::extract_json_string(jwt->payload_json, "iss").value_or("");
            context.client_id = detail::extract_json_string(jwt->payload_json, "azp")
                                    .value_or(detail::extract_json_string(jwt->payload_json, "client_id").value_or(""));
            context.roles = detail::extract_all_roles(jwt->payload_json);
            context.scopes = detail::split_ws(detail::extract_json_string(jwt->payload_json, "scope").value_or(""));

            return JwtValidationResult{
                .ok = true,
                .http_status = 200,
                .error = "",
                .context = std::move(context),
            };
        }

    private:
        static JwtValidationResult failure(int http_status, std::string error)
        {
            return JwtValidationResult{
                .ok = false,
                .http_status = http_status,
                .error = std::move(error),
                .context = RequestContext{},
            };
        }

        AuthConfig cfg_;
        HttpClient &http_client_;
    };
} // namespace keycloak
