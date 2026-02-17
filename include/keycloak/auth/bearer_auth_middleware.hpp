#pragma once

#include <concepts>
#include <string>
#include <string_view>

#include "api_models/http_context.hpp"
#include "keycloak/jwt/access_token_validator.hpp"

namespace keycloak
{
    template <class V>
    concept AccessTokenValidatorLike =
        requires(V &v, std::string_view token) {
            { v.validate(token) } -> std::same_as<JwtValidationResult>;
        };

    template <AccessTokenValidatorLike Validator>
    class BearerAuthMiddleware
    {
    public:
        explicit BearerAuthMiddleware(Validator &validator) : validator_(validator) {}

        AuthResult authenticate(const HttpRequest &request, RequestContext &context) const
        {
            const auto it = request.headers.find("Authorization");
            if (it == request.headers.end())
            {
                return AuthResult{.ok = false, .http_status = 401, .error = "missing_authorization_header"};
            }

            constexpr std::string_view prefix = "Bearer ";
            if (it->second.size() <= prefix.size() || it->second.substr(0, prefix.size()) != prefix)
            {
                return AuthResult{.ok = false, .http_status = 401, .error = "invalid_authorization_scheme"};
            }

            const auto token = std::string_view(it->second).substr(prefix.size());
            const auto result = validator_.validate(token);
            if (!result.ok)
            {
                return AuthResult{.ok = false, .http_status = result.http_status, .error = result.error};
            }

            context = result.context;
            return AuthResult{.ok = true, .http_status = 200, .error = ""};
        }

    private:
        Validator &validator_;
    };
} // namespace keycloak
