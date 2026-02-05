#include "keycloak/auth/pkce_auth_strat.hpp"

#include "keycloak/pkce.hpp"
#include "utils/url_encode.hpp"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
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

    inline std::string authorization_endpoint(const keycloak::KeycloakRealmConfig &cfg)
    {
        // base_url assumed like "https://keycloak.example.com" (no trailing slash preferred)
        // endpoint: /realms/{realm}/protocol/openid-connect/auth
        return cfg.base_url + "/realms/" + url_encode(cfg.realm) + "/protocol/openid-connect/auth";
    }

} // namespace

namespace keycloak
{

    PkceAuthStrategy::PkceAuthStrategy(KeycloakRealmConfig cfg,
                                       std::shared_ptr<IStateStore> state_store)
        : cfg_(std::move(cfg)), state_store_(std::move(state_store))
    {
        if (!state_store_)
        {
            throw std::runtime_error("PkceAuthStrategy: state_store is null");
        }
        if (cfg_.base_url.empty() || cfg_.realm.empty() || cfg_.client_id.empty() || cfg_.redirect_uri.empty())
        {
            throw std::runtime_error("PkceAuthStrategy: missing required config fields");
        }
    }

    std::string PkceAuthStrategy::join_scopes(const std::vector<std::string> &scopes)
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

    AuthStart PkceAuthStrategy::create_authorization_url(std::chrono::seconds ttl)
    {
        // 1) PKCE pair
        auto pkce = generate_pkce_pair(/*verifier_len=*/64);

        // 2) Store verifier -> get state
        // The store generates the state token; we store verifier with TTL.
        std::string state = state_store_->create_state(pkce.code_verifier, ttl);

        // 3) scope string
        std::string scope_string = join_scopes(cfg_.scopes);

        // 4) Params
        std::vector<std::pair<std::string_view, std::string>> params;
        params.reserve(7);
        params.emplace_back("response_type", "code");
        params.emplace_back("client_id", cfg_.client_id);
        params.emplace_back("redirect_uri", cfg_.redirect_uri);
        params.emplace_back("state", state);
        params.emplace_back("code_challenge", pkce.code_challenge);
        params.emplace_back("code_challenge_method", "S256");
        params.emplace_back("scope", scope_string);

        std::string url = authorization_endpoint(cfg_) + "?" + build_query(params);

        return AuthStart{
            .authorization_url = std::move(url),
            .state = std::move(state),
        };
    }

} // namespace keycloak
