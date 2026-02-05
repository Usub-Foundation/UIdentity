#pragma once
#include <memory>
#include <string>

#include "/home/dev_elseif/UIdentity/app/include/keycloak/config.hpp"
#include "/home/dev_elseif/UIdentity/app/include/keycloak/state_store.hpp"

namespace keycloak
{

    struct AuthStart
    {
        std::string authorization_url; // redirect user-agent here
        std::string state;
        // Note: we do NOT return code_verifier because it should be stored in StateStore.
    };

    class PkceAuthStrategy
    {
    public:
        PkceAuthStrategy(KeycloakRealmConfig cfg,
                         std::shared_ptr<IStateStore> state_store);

        // Creates an authorization URL and stores verifier in state_store.
        // ttl is how long state is valid (e.g. 5 minutes).
        AuthStart create_authorization_url(std::chrono::seconds ttl = std::chrono::minutes(5)); // TODO: consider addint ttl to config instead of param?

    private:
        KeycloakRealmConfig cfg_;
        std::shared_ptr<IStateStore> state_store_;

        static std::string join_scopes(const std::vector<std::string> &scopes);
    };

} // namespace keycloak
