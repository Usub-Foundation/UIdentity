#pragma once

#include <chrono>
#include <concepts>
#include <string>
#include <utility>

#include <unet/http.hpp>

#include "api_models/concepts.hpp"
#include "api_models/http_context.hpp"
#include "keycloak/auth/bearer_auth_middleware.hpp"
#include "keycloak/auth/pkce_auth_strat.hpp"
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

    template <class M>
    concept AuthMiddlewareLike =
        requires(const M &m, usub::unet::http::Request &request, RequestContext &ctx) {
            { m.authenticate(request, ctx) } -> std::same_as<AuthResult>;
        };

    template <StateStoreLike Store, TokenServiceLike TokenSvc, AuthMiddlewareLike Middleware>
    class KeycloakClient
    {
    public:
        KeycloakClient(KeycloakRealmConfig cfg,
                       Store &state_store,
                       TokenSvc &token_service,
                       Middleware &auth_middleware)
            : cfg_(std::move(cfg)),
              state_store_(state_store),
              token_service_(token_service),
              auth_middleware_(auth_middleware),
              auth_strategy_(cfg_)
        {
        }

        AuthStart start_login(std::chrono::seconds ttl = std::chrono::minutes(5))
        {
            const auto pkce = generate_pkce_pair(/*verifier_len=*/64);
            std::string state = state_store_.create_state(pkce.code_verifier, ttl);
            return auth_strategy_.create_authorization_url(std::move(state), pkce);
        }

        CallbackResult complete_login(const CallbackInput &input)
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

        AuthResult authenticate_request(usub::unet::http::Request &request, RequestContext &ctx) const
        {
            return auth_middleware_.authenticate(request, ctx);
        }

    private:
        KeycloakRealmConfig cfg_;
        Store &state_store_;
        TokenSvc &token_service_;
        Middleware &auth_middleware_;
        PkceAuthStrategy auth_strategy_;
    };
} // namespace keycloak
