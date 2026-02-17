#pragma once
#include <chrono>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "api_models/concepts.hpp"
#include "keycloak/config.hpp"
#include "keycloak/pkce.hpp"
#include "utils/url_encode.hpp"

namespace keycloak
{

    struct AuthStart
    {
        std::string authorization_url;
        std::string state;
    };

    namespace detail
    {

        // Build query string with URL-encoding
        inline std::string build_query(const std::vector<std::pair<std::string_view, std::string>> &params)
        {
            std::string q;
            q.reserve(256);

            bool first = true;
            for (const auto &[k, v] : params)
            {
                if (!first)
                    q.push_back('&');
                first = false;

                q += url_encode(std::string(k));
                q.push_back('=');
                q += url_encode(v);
            }
            return q;
        }

        inline std::string authorization_endpoint(const KeycloakRealmConfig &cfg)
        {
            return cfg.base_url + "/realms/" + url_encode(cfg.realm) + "/protocol/openid-connect/auth";
        }

        inline std::string join_scopes(const std::vector<std::string> &scopes)
        {
            std::string out;
            for (size_t i = 0; i < scopes.size(); ++i)
            {
                if (i)
                    out.push_back(' ');
                out += scopes[i];
            }
            return out;
        }

    } // namespace detail

    template <StateStoreLike StateStore>
    class PkceAuthStrategy
    {
    public:
        PkceAuthStrategy(KeycloakRealmConfig cfg, StateStore &store)
            : cfg_(std::move(cfg)), store_(store)
        {
            if (cfg_.base_url.empty() || cfg_.realm.empty() || cfg_.client_id.empty() || cfg_.redirect_uri.empty())
            {
                throw std::runtime_error("PkceAuthStrategy: missing required config fields");
            }
        }

        AuthStart create_authorization_url(std::chrono::seconds ttl = std::chrono::minutes(5))
        {
            // 1) PKCE pair
            const auto pkce = generate_pkce_pair(/*verifier_len=*/64);

            // 2) Store verifier -> get state
            std::string state = store_.create_state(pkce.code_verifier, ttl);

            // 3) scope string
            std::string scope_string = detail::join_scopes(cfg_.scopes);

            // 4) Params
            std::vector<std::pair<std::string_view, std::string>> params;
            params.reserve(7);
            params.emplace_back("response_type", "code");
            params.emplace_back("client_id", cfg_.client_id);
            params.emplace_back("redirect_uri", cfg_.redirect_uri);
            params.emplace_back("state", state);
            params.emplace_back("code_challenge", pkce.code_challenge);
            params.emplace_back("code_challenge_method", "S256");
            params.emplace_back("scope", std::move(scope_string));

            std::string url = detail::authorization_endpoint(cfg_) + "?" + detail::build_query(params);

            return AuthStart{
                .authorization_url = std::move(url),
                .state = std::move(state),
            };
        }

    private:
        KeycloakRealmConfig cfg_;
        StateStore &store_;
    };

} // namespace keycloak
