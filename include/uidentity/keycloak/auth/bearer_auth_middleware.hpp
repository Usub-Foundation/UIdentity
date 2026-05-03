#pragma once

#include <concepts>
#include <string>
#include <string_view>

#include <unet/http.hpp>
#include <uvent/tasks/Awaitable.h>
#include <uvent/tasks/AwaitableFrame.h>

#include "uidentity/api_models/http_context.hpp"
#include "uidentity/keycloak/jwt/access_token_validator.hpp"

namespace usub::uidentity::keycloak
{
    template <class V>
    concept AccessTokenValidatorLike =
        requires(V &v, std::string_view token) {
            { v.validate(token) } -> std::same_as<usub::uvent::task::Awaitable<JwtValidationResult>>;
        };

    template <AccessTokenValidatorLike Validator>
    class BearerAuthMiddleware
    {
    public:
        explicit BearerAuthMiddleware(Validator &validator) : validator_(validator) {}

        usub::uvent::task::Awaitable<AuthResult> authenticate(usub::unet::http::Request &request,
                                                              RequestContext &context) const
        {
            const auto auth_header = request.headers.value("Authorization");
            if (!auth_header.has_value())
            {
                co_return AuthResult{.ok = false, .http_status = 401, .error = "missing_authorization_header"};
            }

            constexpr std::string_view prefix = "Bearer ";
            if (auth_header->size() <= prefix.size() || auth_header->substr(0, prefix.size()) != prefix)
            {
                co_return AuthResult{.ok = false, .http_status = 401, .error = "invalid_authorization_scheme"};
            }

            const auto token = auth_header->substr(prefix.size());
            const auto result = co_await validator_.validate(token);
            if (!result.ok)
            {
                co_return AuthResult{.ok = false, .http_status = result.http_status, .error = result.error};
            }

            context = result.context;
            set_request_context(request, result.context);
            co_return AuthResult{.ok = true, .http_status = 200, .error = ""};
        }

    private:
        Validator &validator_;
    };
} // namespace usub::uidentity::keycloak
