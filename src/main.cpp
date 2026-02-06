#include <iostream>
#include <memory>

#include "keycloak/config.hpp"
#include "keycloak/auth/pkce_auth_strat.hpp"
#include "keycloak/state_store_memory.hpp"

int main()
{
    keycloak::KeycloakRealmConfig cfg;
    cfg.base_url = "https://keycloak.0x000f.com";
    cfg.realm = "trader";
    cfg.client_id = "myclient";
    cfg.redirect_uri = "https://your-service.example.com/api/v1/callback";
    cfg.scopes = {"openid", "profile", "email"};

    auto store = std::make_shared<keycloak::MemoryStateStore>();
    keycloak::PkceAuthStrategy strat(cfg, store);

    auto start = strat.create_authorization_url();
    std::cout << start.authorization_url << "\n";

    // Endpoint 1: GET /auth/login
    // Endpoint 2: GET /auth/callback?code=...&state=...

    return 0;
}
