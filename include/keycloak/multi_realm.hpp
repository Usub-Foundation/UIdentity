#pragma once

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "api_models/http_context.hpp"
#include "keycloak/auth/pkce_auth_strat.hpp"
#include "keycloak/jwt/access_token_validator.hpp"
#include "keycloak/keycloak_client.hpp"
#include "keycloak/oauth/token_service.hpp"
#include "keycloak/state_store/state_store.hpp"

namespace keycloak
{
    struct MultiRealmConfig
    {
        KeycloakRealmConfig realm;
        TokenServiceConfig token;
        AuthConfig auth;
    };

    template <class Store, AsyncHttpClientLike HttpClient>
    class MultiRealmManager
    {
    public:
        MultiRealmManager(std::vector<MultiRealmConfig> configs,
                          Store &state_store,
                          HttpClient &http_client)
            : state_store_(state_store)
        {
            for (auto &config : configs)
            {
                if (config.realm.realm.empty())
                {
                    throw std::invalid_argument("realm name must not be empty");
                }

                auto runtime = std::make_unique<RealmRuntime>(
                    std::move(config.realm),
                    std::move(config.token),
                    std::move(config.auth),
                    http_client);
                const std::string realm_name = runtime->realm_cfg.realm;
                realms_.emplace(realm_name, std::move(runtime));
                realm_order_.push_back(realm_name);
            }

            if (realms_.empty())
            {
                throw std::invalid_argument("at least one realm must be configured");
            }
        }

        bool has_realm(std::string_view realm) const
        {
            return realms_.find(std::string(realm)) != realms_.end();
        }

        const std::vector<std::string> &realm_names() const
        {
            return realm_order_;
        }

        usub::uvent::task::Awaitable<AuthStart> start_login(std::string_view realm,
                                                            std::chrono::seconds ttl = std::chrono::minutes(5))
        {
            auto *runtime = lookup_realm(realm);
            const auto pkce = generate_pkce_pair(runtime->realm_cfg.pkce_verifier_len);
            const std::string state = co_await state_store_.create_state_entry(
                StateEntry{
                    .code_verifier = pkce.code_verifier,
                    .realm = runtime->realm_cfg.realm,
                },
                ttl);

            co_return runtime->auth_strategy.create_authorization_url(state, pkce);
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

            const auto state_entry = co_await state_store_.consume_state_entry(input.state);
            if (!state_entry.has_value())
            {
                co_return CallbackResult{
                    .ok = false,
                    .http_status = 401,
                    .error = "invalid_or_expired_state",
                };
            }

            const auto realm_it = realms_.find(state_entry->realm);
            if (realm_it == realms_.end())
            {
                co_return CallbackResult{
                    .ok = false,
                    .http_status = 400,
                    .error = "unknown_realm",
                };
            }

            auto oauth_result = co_await realm_it->second->token_service.exchange_authorization_code(
                input.code,
                state_entry->code_verifier);
            co_return CallbackResult{
                .ok = oauth_result.ok,
                .http_status = oauth_result.http_status,
                .error = oauth_result.error,
                .tokens = oauth_result.tokens,
                .realm = realm_it->second->realm_cfg.realm,
            };
        }

        usub::uvent::task::Awaitable<OAuthResult> refresh_tokens(std::string_view realm,
                                                                 std::string_view refresh_token)
        {
            auto *runtime = lookup_realm(realm);
            co_return co_await runtime->token_service.refresh_tokens(refresh_token);
        }

        usub::uvent::task::Awaitable<OAuthResult> revoke_token(std::string_view realm,
                                                               std::string_view token,
                                                               std::string_view token_type_hint = "refresh_token")
        {
            auto *runtime = lookup_realm(realm);
            co_return co_await runtime->token_service.revoke_token(token, token_type_hint);
        }

        usub::uvent::task::Awaitable<JwtValidationResult> validate(std::string_view realm,
                                                                   std::string_view access_token) const
        {
            auto *runtime = lookup_realm(realm);
            co_return co_await runtime->validator.validate(access_token);
        }

    private:
        struct RealmRuntime
        {
            KeycloakRealmConfig realm_cfg;
            TokenServiceConfig token_cfg;
            AuthConfig auth_cfg;
            TokenService<HttpClient> token_service;
            AccessTokenValidator<HttpClient> validator;
            PkceAuthStrategy auth_strategy;

            RealmRuntime(KeycloakRealmConfig realm,
                         TokenServiceConfig token,
                         AuthConfig auth,
                         HttpClient &http_client)
                : realm_cfg(std::move(realm)),
                  token_cfg(std::move(token)),
                  auth_cfg(std::move(auth)),
                  token_service(token_cfg, http_client),
                  validator(auth_cfg, http_client),
                  auth_strategy(realm_cfg)
            {
            }
        };

        RealmRuntime *lookup_realm(std::string_view realm) const
        {
            const auto it = realms_.find(std::string(realm));
            if (it == realms_.end())
            {
                throw std::invalid_argument("unknown realm");
            }
            return it->second.get();
        }

        Store &state_store_;
        std::unordered_map<std::string, std::unique_ptr<RealmRuntime>> realms_;
        std::vector<std::string> realm_order_;
    };
} // namespace keycloak
