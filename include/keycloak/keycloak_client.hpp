#pragma once

#include <chrono>
#include <concepts>
#include <string>
#include <utility>

#include "api_models/concepts.hpp"
#include "api_models/http_context.hpp"
#include "keycloak/auth/bearer_auth_middleware.hpp"
#include "keycloak/auth/pkce_auth_strat.hpp"
#include "keycloak/oauth/callback_service.hpp"

namespace keycloak
{
    template <class C>
    concept CallbackServiceLike =
        requires(C &c, const CallbackInput &input) {
            { c.handle(input) } -> std::same_as<CallbackResult>;
        };

    template <class M>
    concept AuthMiddlewareLike =
        requires(const M &m, const HttpRequest &request, RequestContext &ctx) {
            { m.authenticate(request, ctx) } -> std::same_as<AuthResult>;
        };

    template <StateStoreLike Store, CallbackServiceLike CallbackSvc, AuthMiddlewareLike Middleware>
    class KeycloakClient
    {
    public:
        KeycloakClient(KeycloakRealmConfig cfg,
                       Store &state_store,
                       CallbackSvc &callback_service,
                       Middleware &auth_middleware)
            : cfg_(std::move(cfg)),
              state_store_(state_store),
              callback_service_(callback_service),
              auth_middleware_(auth_middleware)
        {
        }

        AuthStart start_login(std::chrono::seconds ttl = std::chrono::minutes(5))
        {
            PkceAuthStrategy<Store> auth_strategy(cfg_, state_store_);
            return auth_strategy.create_authorization_url(ttl);
        }

        CallbackResult complete_login(const CallbackInput &input)
        {
            return callback_service_.handle(input);
        }

        AuthResult authenticate_request(const HttpRequest &request, RequestContext &ctx) const
        {
            return auth_middleware_.authenticate(request, ctx);
        }

    private:
        KeycloakRealmConfig cfg_;
        Store &state_store_;
        CallbackSvc &callback_service_;
        Middleware &auth_middleware_;
    };
} // namespace keycloak
