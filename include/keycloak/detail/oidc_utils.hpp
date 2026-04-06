#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <unet/http.hpp>

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

    inline usub::unet::uri::URI parse_absolute_uri(std::string_view url)
    {
        usub::unet::uri::URI uri;

        const auto scheme_pos = url.find("://");
        const std::size_t authority_start = scheme_pos == std::string_view::npos ? 0 : scheme_pos + 3;
        if (scheme_pos != std::string_view::npos)
        {
            uri.scheme = std::string(url.substr(0, scheme_pos));
        }

        const auto path_start = url.find('/', authority_start);
        const auto query_start = url.find('?', authority_start);
        const std::size_t authority_end = std::min(path_start == std::string_view::npos ? url.size() : path_start,
                                                   query_start == std::string_view::npos ? url.size() : query_start);
        const auto authority = url.substr(authority_start, authority_end - authority_start);

        const auto colon_pos = authority.rfind(':');
        if (colon_pos != std::string_view::npos)
        {
            uri.authority.host = std::string(authority.substr(0, colon_pos));
            const auto port_text = authority.substr(colon_pos + 1);
            if (!port_text.empty())
            {
                uri.authority.port = static_cast<std::uint16_t>(std::stoi(std::string(port_text)));
            }
        }
        else
        {
            uri.authority.host = std::string(authority);
        }

        if (path_start != std::string_view::npos)
        {
            const auto path_end = query_start == std::string_view::npos ? url.size() : query_start;
            uri.path = std::string(url.substr(path_start, path_end - path_start));
        }
        if (uri.path.empty())
        {
            uri.path = "/";
        }

        if (query_start != std::string_view::npos)
        {
            uri.query = std::string(url.substr(query_start + 1));
        }

        return uri;
    }

    inline std::string request_url(const usub::unet::http::Request &request)
    {
        std::string url;
        if (!request.metadata.uri.scheme.empty())
        {
            url += request.metadata.uri.scheme;
            url += "://";
        }

        if (!request.metadata.authority.empty())
        {
            url += request.metadata.authority;
        }
        else
        {
            url += request.metadata.uri.authority.host;
            if (request.metadata.uri.authority.port != 0)
            {
                url += ":" + std::to_string(request.metadata.uri.authority.port);
            }
        }

        url += request.metadata.uri.path.empty() ? "/" : request.metadata.uri.path;
        if (!request.metadata.uri.query.empty())
        {
            url += "?";
            url += request.metadata.uri.query;
        }

        return url;
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

    inline usub::unet::http::Request make_form_post(std::string url,
                                                    std::string body,
                                                    std::optional<std::string_view> bearer_token = std::nullopt)
    {
        auto uri = parse_absolute_uri(url);
        usub::unet::http::Request request;
        request.metadata.method_token = "POST";
        request.metadata.uri = std::move(uri);
        request.metadata.authority = request.metadata.uri.authority.host;
        if (request.metadata.uri.authority.port != 0)
        {
            request.metadata.authority += ":" + std::to_string(request.metadata.uri.authority.port);
        }
        request.headers.addHeader(std::string_view{"Content-Type"},
                                  std::string_view{"application/x-www-form-urlencoded"});
        request.headers.addHeader(std::string_view{"Accept"}, std::string_view{"application/json"});
        request.body = std::move(body);

        if (bearer_token.has_value())
        {
            request.headers.addHeader(std::string{"Authorization"}, "Bearer " + std::string(*bearer_token));
        }

        return request;
    }

    inline usub::unet::http::Request make_json_get(std::string url,
                                                   std::optional<std::string_view> bearer_token = std::nullopt)
    {
        auto uri = parse_absolute_uri(url);
        usub::unet::http::Request request;
        request.metadata.method_token = "GET";
        request.metadata.uri = std::move(uri);
        request.metadata.authority = request.metadata.uri.authority.host;
        if (request.metadata.uri.authority.port != 0)
        {
            request.metadata.authority += ":" + std::to_string(request.metadata.uri.authority.port);
        }
        request.headers.addHeader(std::string_view{"Accept"}, std::string_view{"application/json"});
        request.body.clear();

        if (bearer_token.has_value())
        {
            request.headers.addHeader(std::string{"Authorization"}, "Bearer " + std::string(*bearer_token));
        }

        return request;
    }
} // namespace keycloak::detail
