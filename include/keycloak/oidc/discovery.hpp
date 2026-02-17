#pragma once

#include <string>

#include "api_models/concepts.hpp"

namespace keycloak
{
    struct OidcEndpoints
    {
        std::string issuer;
        std::string authorization_endpoint;
        std::string token_endpoint;
        std::string jwks_uri;
        std::string userinfo_endpoint;
        std::string revocation_endpoint;
        std::string introspection_endpoint;
        std::string end_session_endpoint;
    };

    struct DiscoveryResult
    {
        bool ok = false;
        int http_status = 500;
        std::string error;
        OidcEndpoints endpoints;
    };

    template <HttpClientLike HttpClient>
    class OidcDiscoveryClient
    {
    public:
        explicit OidcDiscoveryClient(HttpClient &http_client) : http_client_(http_client) {}

        DiscoveryResult discover(const std::string &base_url,
                                 const std::string &realm)
        {
            (void)http_client_;
            return DiscoveryResult{
                .ok = false,
                .http_status = 501,
                .error = "oidc_discovery_not_implemented",
                .endpoints = OidcEndpoints{
                    .issuer = base_url + "/realms/" + realm,
                    .authorization_endpoint = base_url + "/realms/" + realm + "/protocol/openid-connect/auth",
                    .token_endpoint = base_url + "/realms/" + realm + "/protocol/openid-connect/token",
                    .jwks_uri = base_url + "/realms/" + realm + "/protocol/openid-connect/certs",
                    .userinfo_endpoint = base_url + "/realms/" + realm + "/protocol/openid-connect/userinfo",
                    .revocation_endpoint = base_url + "/realms/" + realm + "/protocol/openid-connect/revoke",
                    .introspection_endpoint = base_url + "/realms/" + realm + "/protocol/openid-connect/token/introspect",
                    .end_session_endpoint = base_url + "/realms/" + realm + "/protocol/openid-connect/logout",
                },
            };
        }

    private:
        HttpClient &http_client_;
    };
} // namespace keycloak
