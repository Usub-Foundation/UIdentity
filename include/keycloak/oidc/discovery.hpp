#pragma once

#include <string>
#include <utility>

#include <uvent/tasks/Awaitable.h>
#include <uvent/tasks/AwaitableFrame.h>

#include "api_models/concepts.hpp"
#include "keycloak/detail/json_utils.hpp"
#include "keycloak/detail/oidc_utils.hpp"

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

    template <AsyncHttpClientLike HttpClient>
    class OidcDiscoveryClient
    {
    public:
        explicit OidcDiscoveryClient(HttpClient &http_client) : http_client_(http_client) {}

        usub::uvent::task::Awaitable<DiscoveryResult> discover(const std::string &base_url,
                                                               const std::string &realm)
        {
            const auto response = co_await http_client_.send(
                detail::make_json_get(detail::discovery_endpoint(base_url, realm)));
            const int http_status = response.metadata.status_code > 0 ? response.metadata.status_code : 502;

            OidcEndpoints endpoints{
                .issuer = detail::extract_json_string(response.body, "issuer").value_or(detail::realm_root(base_url, realm)),
                .authorization_endpoint = detail::extract_json_string(response.body, "authorization_endpoint").value_or(detail::authorization_endpoint(base_url, realm)),
                .token_endpoint = detail::extract_json_string(response.body, "token_endpoint").value_or(detail::token_endpoint(base_url, realm)),
                .jwks_uri = detail::extract_json_string(response.body, "jwks_uri").value_or(detail::jwks_endpoint(base_url, realm)),
                .userinfo_endpoint = detail::extract_json_string(response.body, "userinfo_endpoint").value_or(detail::userinfo_endpoint(base_url, realm)),
                .revocation_endpoint = detail::extract_json_string(response.body, "revocation_endpoint").value_or(detail::revocation_endpoint(base_url, realm)),
                .introspection_endpoint = detail::extract_json_string(response.body, "introspection_endpoint").value_or(detail::introspection_endpoint(base_url, realm)),
                .end_session_endpoint = detail::extract_json_string(response.body, "end_session_endpoint").value_or(detail::logout_endpoint(base_url, realm)),
            };

            if (http_status < 200 || http_status >= 300)
            {
                co_return DiscoveryResult{
                    .ok = false,
                    .http_status = http_status,
                    .error = detail::extract_json_string(response.body, "error").value_or("oidc_discovery_failed"),
                    .endpoints = std::move(endpoints),
                };
            }

            co_return DiscoveryResult{
                .ok = true,
                .http_status = http_status,
                .error = "",
                .endpoints = std::move(endpoints),
            };
        }

    private:
        HttpClient &http_client_;
    };
} // namespace keycloak
