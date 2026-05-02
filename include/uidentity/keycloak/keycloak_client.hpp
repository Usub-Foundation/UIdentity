#pragma once

#include <chrono>
#include <concepts>
#include <stdexcept>
#include <string>
#include <utility>

#include <unet/http.hpp>
#include <uvent/tasks/Awaitable.h>
#include <uvent/tasks/AwaitableFrame.h>

#include "uidentity/api_models/concepts.hpp"
#include "uidentity/api_models/http_context.hpp"
#include "uidentity/keycloak/auth/bearer_auth_middleware.hpp"
#include "uidentity/keycloak/auth/pkce_auth_strat.hpp"
#include "uidentity/keycloak/oauth/token_service.hpp"

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
        std::string realm;
    };

    template <class T>
    concept TokenServiceLike =
        requires(T &t, std::string_view code, std::string_view verifier) {
            { t.exchange_authorization_code(code, verifier) } -> std::same_as<usub::uvent::task::Awaitable<OAuthResult>>;
        };

    template <class M>
    concept AuthMiddlewareLike =
        requires(const M &m, usub::unet::http::Request &request, RequestContext &ctx) {
            { m.authenticate(request, ctx) } -> std::same_as<usub::uvent::task::Awaitable<AuthResult>>;
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

        usub::uvent::task::Awaitable<AuthStart> start_login(
            std::chrono::seconds ttl = std::chrono::minutes(5))
        {
            const auto pkce = generate_pkce_pair(cfg_.pkce_verifier_len);
            std::string state = co_await state_store_.create_state(pkce.code_verifier, ttl);
            co_return auth_strategy_.create_authorization_url(std::move(state), pkce);
        }

        bool has_realm(std::string_view realm) const
        {
            return realm == cfg_.realm;
        }

        usub::uvent::task::Awaitable<AuthStart> start_login(std::string_view realm,
                                                            std::chrono::seconds ttl)
        {
            if (!has_realm(realm))
            {
                throw std::invalid_argument("unknown realm");
            }
            co_return co_await start_login(ttl);
        }

        usub::uvent::task::Awaitable<CallbackResult> complete_login(const CallbackInput &input)
        {
            if (input.code.empty() || input.state.empty())
            {
                co_return CallbackResult{
                    .ok = false,
                    .http_status = 400,
                    .error = "missing_code_or_state",
                };
            }

            const auto verifier = co_await state_store_.consume_state(input.state);
            if (!verifier.has_value())
            {
                co_return CallbackResult{
                    .ok = false,
                    .http_status = 401,
                    .error = "invalid_or_expired_state",
                };
            }

            const auto oauth_result = co_await token_service_.exchange_authorization_code(input.code, *verifier);
            co_return CallbackResult{
                .ok = oauth_result.ok,
                .http_status = oauth_result.http_status,
                .error = oauth_result.error,
                .tokens = oauth_result.tokens,
                .realm = cfg_.realm,
            };
        }

        usub::uvent::task::Awaitable<AuthResult> authenticate_request(
            usub::unet::http::Request &request,
            RequestContext &ctx) const
        {
            co_return co_await auth_middleware_.authenticate(request, ctx);
        }

    private:
        KeycloakRealmConfig cfg_;
        Store &state_store_;
        TokenSvc &token_service_;
        Middleware &auth_middleware_;
        PkceAuthStrategy auth_strategy_;
    };
} // namespace keycloak
