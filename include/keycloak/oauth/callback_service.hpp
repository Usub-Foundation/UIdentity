#pragma once

#include <string>
#include <string_view>

#include "api_models/concepts.hpp"
#include "keycloak/oauth/token_service.hpp"

namespace keycloak
{
    struct CallbackInput
    {
        std::string code;
        std::string state;
    };

    struct CallbackResult
    {
        bool ok = false;
        int http_status = 500;
        std::string error;
        TokenSet tokens;
    };

    template <class T>
    concept TokenServiceLike =
        requires(T &t, std::string_view code, std::string_view verifier) {
            { t.exchange_authorization_code(code, verifier) } -> std::same_as<OAuthResult>;
        };

    template <StateStoreLike Store, TokenServiceLike TokenSvc>
    class CallbackService
    {
    public:
        CallbackService(Store &state_store, TokenSvc &token_service)
            : state_store_(state_store), token_service_(token_service)
        {
        }

        CallbackResult handle(const CallbackInput &input)
        {
            if (input.code.empty() || input.state.empty())
            {
                return CallbackResult{
                    .ok = false,
                    .http_status = 400,
                    .error = "missing_code_or_state",
                };
            }

            const auto verifier = state_store_.consume_state(input.state);
            if (!verifier.has_value())
            {
                return CallbackResult{
                    .ok = false,
                    .http_status = 401,
                    .error = "invalid_or_expired_state",
                };
            }

            const auto oauth_result = token_service_.exchange_authorization_code(input.code, *verifier);
            return CallbackResult{
                .ok = oauth_result.ok,
                .http_status = oauth_result.http_status,
                .error = oauth_result.error,
                .tokens = oauth_result.tokens,
            };
        }

    private:
        Store &state_store_;
        TokenSvc &token_service_;
    };
} // namespace keycloak
