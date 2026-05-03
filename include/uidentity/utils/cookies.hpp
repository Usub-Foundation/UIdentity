#pragma once

#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include <unet/http.hpp>

#include "uidentity/utils/url_encode.hpp"

namespace usub::uidentity::utils
{

    struct CookieOptions
    {
        std::string path{"/"};
        bool http_only{true};
        bool secure{true};
        std::string same_site{"Lax"};
        std::optional<int> max_age_seconds;
    };

    struct TokenCookieConfig
    {
        std::string access_token_name{"access_token"};
        std::string refresh_token_name{"refresh_token"};
        std::string path{"/"};
        bool secure{true};
        std::string same_site{"Lax"};
    };

    inline std::string trim_copy(std::string_view value)
    {
        std::size_t start = 0;
        std::size_t end = value.size();

        while (start < end && std::isspace(static_cast<unsigned char>(value[start])))
        {
            ++start;
        }
        while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])))
        {
            --end;
        }

        return std::string(value.substr(start, end - start));
    }

    inline std::unordered_map<std::string, std::string> parse_cookie_header(std::string_view raw)
    {
        std::unordered_map<std::string, std::string> cookies;
        std::size_t start = 0;

        while (start < raw.size())
        {
            const std::size_t end = raw.find(';', start);
            const std::string_view part =
                raw.substr(start, end == std::string_view::npos ? raw.size() - start : end - start);

            if (!part.empty())
            {
                const std::size_t eq = part.find('=');
                const std::string name = trim_copy(part.substr(0, eq));
                const std::string value = eq == std::string_view::npos
                                              ? std::string{}
                                              : trim_copy(part.substr(eq + 1));
                if (!name.empty())
                {
                    cookies.insert_or_assign(url_decode(name), url_decode(value));
                }
            }

            if (end == std::string_view::npos)
            {
                break;
            }
            start = end + 1;
        }

        return cookies;
    }

    inline std::optional<std::string> get_cookie(const usub::unet::http::Request &request, std::string_view name)
    {
        const auto raw_cookie = request.headers.value("Cookie");
        if (!raw_cookie.has_value())
        {
            return std::nullopt;
        }

        auto cookies = parse_cookie_header(*raw_cookie);
        const auto it = cookies.find(std::string(name));
        if (it == cookies.end())
        {
            return std::nullopt;
        }

        return it->second;
    }

    inline std::string make_set_cookie(std::string_view name,
                                       std::string_view value,
                                       const CookieOptions &options)
    {
        std::string cookie = url_encode(name) + "=" + url_encode(value);
        cookie += "; Path=" + options.path;

        if (options.max_age_seconds.has_value())
        {
            cookie += "; Max-Age=" + std::to_string(*options.max_age_seconds);
        }
        if (options.http_only)
        {
            cookie += "; HttpOnly";
        }
        if (options.secure)
        {
            cookie += "; Secure";
        }
        if (!options.same_site.empty())
        {
            cookie += "; SameSite=" + options.same_site;
        }

        return cookie;
    }

    inline std::string make_expired_cookie(std::string_view name, const CookieOptions &options)
    {
        CookieOptions expired = options;
        expired.max_age_seconds = 0;
        return make_set_cookie(name, "", expired);
    }

    inline CookieOptions token_cookie_options(const TokenCookieConfig &config, int max_age_seconds)
    {
        return CookieOptions{
            .path = config.path,
            .http_only = true,
            .secure = config.secure,
            .same_site = config.same_site,
            .max_age_seconds = max_age_seconds > 0 ? std::optional<int>(max_age_seconds) : std::nullopt,
        };
    }

    inline CookieOptions token_cookie_options(const TokenCookieConfig &config)
    {
        return CookieOptions{
            .path = config.path,
            .http_only = true,
            .secure = config.secure,
            .same_site = config.same_site,
            .max_age_seconds = std::nullopt,
        };
    }

} // namespace usub::uidentity::utils
