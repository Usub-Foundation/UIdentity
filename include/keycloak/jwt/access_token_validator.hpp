#pragma once

#include <string>
#include <string_view>
#include <utility>

#include "api_models/http_context.hpp"
#include "api_models/concepts.hpp"

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
            (void)access_token;
            (void)cfg_;
            (void)http_client_;
            return JwtValidationResult{
                .ok = false,
                .http_status = 501,
                .error = "jwt_validation_not_implemented",
                .context = RequestContext{},
            };
        }

    private:
        AuthConfig cfg_;
        HttpClient &http_client_;
    };
} // namespace keycloak
