#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "keycloak/http/http_client.hpp"
#include "utils/url_encode.hpp"

namespace keycloak::detail
{
    inline std::string trim_trailing_slash(std::string value)
    {
        while (!value.empty() && value.back() == '/')
        {
            value.pop_back();
        }
        return value;
    }

    inline std::string realm_root(const std::string &base_url,
                                  const std::string &realm)
    {
        return trim_trailing_slash(base_url) + "/realms/" + url_encode(realm);
    }

    inline std::string authorization_endpoint(const std::string &base_url,
                                              const std::string &realm)
    {
        return realm_root(base_url, realm) + "/protocol/openid-connect/auth";
    }

    inline std::string token_endpoint(const std::string &base_url,
                                      const std::string &realm)
    {
        return realm_root(base_url, realm) + "/protocol/openid-connect/token";
    }

    inline std::string jwks_endpoint(const std::string &base_url,
                                     const std::string &realm)
    {
        return realm_root(base_url, realm) + "/protocol/openid-connect/certs";
    }

    inline std::string userinfo_endpoint(const std::string &base_url,
                                         const std::string &realm)
    {
        return realm_root(base_url, realm) + "/protocol/openid-connect/userinfo";
    }

    inline std::string revocation_endpoint(const std::string &base_url,
                                           const std::string &realm)
    {
        return realm_root(base_url, realm) + "/protocol/openid-connect/revoke";
    }

    inline std::string introspection_endpoint(const std::string &base_url,
                                              const std::string &realm)
    {
        return realm_root(base_url, realm) + "/protocol/openid-connect/token/introspect";
    }

    inline std::string logout_endpoint(const std::string &base_url,
                                       const std::string &realm)
    {
        return realm_root(base_url, realm) + "/protocol/openid-connect/logout";
    }

    inline std::string discovery_endpoint(const std::string &base_url,
                                          const std::string &realm)
    {
        return realm_root(base_url, realm) + "/.well-known/openid-configuration";
    }

    inline std::string build_form_body(const std::vector<std::pair<std::string_view, std::string_view>> &fields)
    {
        std::string body;
        bool first = true;

        for (const auto &[key, value] : fields)
        {
            if (!first)
            {
                body.push_back('&');
            }
            first = false;

            body += url_encode(key);
            body.push_back('=');
            body += url_encode(value);
        }

        return body;
    }

    inline http::Request make_form_post(std::string url,
                                        std::string body,
                                        std::optional<std::string_view> bearer_token = std::nullopt)
    {
        http::Request request{
            .method = "POST",
            .url = std::move(url),
            .headers = {
                {"Content-Type", "application/x-www-form-urlencoded"},
                {"Accept", "application/json"},
            },
            .body = std::move(body),
        };

        if (bearer_token.has_value())
        {
            request.headers.emplace("Authorization", "Bearer " + std::string(*bearer_token));
        }

        return request;
    }

    inline http::Request make_json_get(std::string url,
                                       std::optional<std::string_view> bearer_token = std::nullopt)
    {
        http::Request request{
            .method = "GET",
            .url = std::move(url),
            .headers = {
                {"Accept", "application/json"},
            },
            .body = "",
        };

        if (bearer_token.has_value())
        {
            request.headers.emplace("Authorization", "Bearer " + std::string(*bearer_token));
        }

        return request;
    }
} // namespace keycloak::detail
