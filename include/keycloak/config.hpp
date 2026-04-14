#pragma once
#include <cstddef>
#include <string>
#include <vector>

namespace keycloak
{

    struct KeycloakRealmConfig
    {
        // Example: "https://login.example.com"
        std::string base_url;

        // Example: "trader"
        std::string realm;

        // Example: "myclient"
        std::string client_id;

        // Example: "https://service.com/api/v1/callback"
        std::string redirect_uri;

        // Example: {"openid","profile","email"}
        std::vector<std::string> scopes;

        // PKCE code_verifier length. RFC 7636 allows 43..128.
        // The generator clamps out-of-range values; default stays at 64.
        std::size_t pkce_verifier_len = 64;

        // If true, omit :443 for https and :80 for http (cosmetic)
        bool omit_default_port = true;
    };

} // namespace keycloak
