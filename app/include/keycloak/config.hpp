#pragma once
#include <string>
#include <vector>

namespace keycloak
{

    struct KeycloakRealmConfig
    {
        // Example: "https://keycloak.0x000f.com"
        std::string base_url;

        // Example: "trader"
        std::string realm;

        // Example: "myclient"
        std::string client_id;

        // Example: "https://service.com/api/v1/callback"
        std::string redirect_uri;

        // Example: {"openid","profile","email"}
        std::vector<std::string> scopes;

        // If true, omit :443 for https and :80 for http (cosmetic)
        bool omit_default_port = true;
    };

} // namespace keycloak
