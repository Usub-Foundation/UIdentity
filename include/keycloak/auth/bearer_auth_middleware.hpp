#pragma once

#include <concepts>
#include <string>
#include <string_view>

#include <unet/http.hpp>

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

        AuthResult authenticate(usub::unet::http::Request &request, RequestContext &context) const
        {
            const auto auth_header = request.headers.value("Authorization");
            if (!auth_header.has_value())
            {
                return AuthResult{.ok = false, .http_status = 401, .error = "missing_authorization_header"};
            }

            constexpr std::string_view prefix = "Bearer ";
            if (auth_header->size() <= prefix.size() || auth_header->substr(0, prefix.size()) != prefix)
            {
                return AuthResult{.ok = false, .http_status = 401, .error = "invalid_authorization_scheme"};
            }

            const auto token = auth_header->substr(prefix.size());
            const auto result = validator_.validate(token);
            if (!result.ok)
            {
                return AuthResult{.ok = false, .http_status = result.http_status, .error = result.error};
            }

            context = result.context;
            set_request_context(request, result.context);
            return AuthResult{.ok = true, .http_status = 200, .error = ""};
        }

    private:
        Validator &validator_;
    };
} // namespace keycloak
