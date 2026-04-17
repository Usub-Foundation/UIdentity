#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

#include <unet/http.hpp>

#include "keycloak/keycloak_client.hpp"
#include "keycloak/oauth/token_service.hpp"
#include "utils/cookies.hpp"
#include "utils/url_encode.hpp"

namespace handlers {

struct AuthHandlerConfig {
    utils::TokenCookieConfig token_cookies;
    std::string post_login_redirect{"/"};
    std::string post_logout_redirect{"/"};
    bool revoke_refresh_token_on_logout{true};
};

template<class Client, class TokenService>
class AuthHandler {
public:
    AuthHandler(Client &client, TokenService &token_service, AuthHandlerConfig config)
        : client_(client), token_service_(token_service), config_(std::move(config)) {}

    ServerHandler login(usub::unet::http::Request &request, usub::unet::http::Response &response) {
        const auto params = parse_form_encoded(request.metadata.uri.query);
        const auto realm_it = params.find("realm");
        if (realm_it == params.end() || realm_it->second.empty()) {
            response.setStatus(400);
            response.addHeader("Content-Type", "application/json");
            response.addHeader("Cache-Control", "no-store");
            response.addHeader("Pragma", "no-cache");
            response.setBody(R"({"ok":false,"error":"missing_realm"})");
            co_return;
        }
        if (!client_.has_realm(realm_it->second)) {
            response.setStatus(404);
            response.addHeader("Content-Type", "application/json");
            response.addHeader("Cache-Control", "no-store");
            response.addHeader("Pragma", "no-cache");
            response.setBody(R"({"ok":false,"error":"unknown_realm"})");
            co_return;
        }

        const auto auth_start = co_await this->client_.start_login(realm_it->second, std::chrono::minutes(5));

        response.setStatus(302);
        response.addHeader("Location", auth_start.authorization_url);
        response.addHeader("Cache-Control", "no-store");
        response.addHeader("Pragma", "no-cache");
        response.setBody("");
        co_return;
    }

    ServerHandler callback(usub::unet::http::Request &request, usub::unet::http::Response &response) {
        auto params = parse_form_encoded(request.metadata.uri.query);

        if (request.metadata.method_token == "POST") {
            auto body_params = parse_form_encoded(request.body);
            for (auto &[key, value]: body_params) {
                params.insert_or_assign(std::move(key), std::move(value));
            }
        }

        const auto code_it = params.find("code");
        const auto state_it = params.find("state");
        const auto result = co_await this->client_.complete_login({
                .code = code_it == params.end() ? std::string{} : code_it->second,
                .state = state_it == params.end() ? std::string{} : state_it->second,
        });

        response.addHeader("Cache-Control", "no-store");
        response.addHeader("Pragma", "no-cache");

        if (!result.ok) {
            response.addHeader("Content-Type", "application/json");
            response.setStatus(static_cast<std::uint16_t>(result.http_status));
            response.setBody(std::string{"{\"ok\":false,\"error\":\""} + json_escape(result.error) + "\"}");
            co_return;
        }

        add_token_cookies(response, result.realm, result.tokens);
        response.setStatus(302);
        response.addHeader("Location", config_.post_login_redirect);
        response.setBody("");
        co_return;
    }

    ServerHandler logout(usub::unet::http::Request &request, usub::unet::http::Response &response) {
        const auto params = parse_form_encoded(request.metadata.uri.query);
        const auto realm_it = params.find("realm");

        response.addHeader("Cache-Control", "no-store");
        response.addHeader("Pragma", "no-cache");

        if (realm_it == params.end() || realm_it->second.empty()) {
            response.addHeader("Content-Type", "application/json");
            response.setStatus(400);
            response.setBody(R"({"ok":false,"error":"missing_realm"})");
            co_return;
        }
        if (!token_service_.has_realm(realm_it->second)) {
            response.addHeader("Content-Type", "application/json");
            response.setStatus(404);
            response.setBody(R"({"ok":false,"error":"unknown_realm"})");
            co_return;
        }

        const auto cookie_cfg = token_cookie_config_for_realm(realm_it->second);
        if (config_.revoke_refresh_token_on_logout) {
            if (const auto refresh_token = utils::get_cookie(request, cookie_cfg.refresh_token_name);
                refresh_token.has_value() && !refresh_token->empty()) {
                (void) co_await token_service_.revoke_token(realm_it->second, *refresh_token, "refresh_token");
            }
        }

        clear_token_cookies(response, realm_it->second);
        response.setStatus(302);
        response.addHeader("Location", config_.post_logout_redirect);
        response.setBody("");
        co_return;
    }

private:
    void add_token_cookies(usub::unet::http::Response &response,
                           std::string_view realm,
                           const keycloak::TokenSet &tokens) const {
        const auto cookie_cfg = token_cookie_config_for_realm(realm);
        response.addHeader("Set-Cookie",
                           utils::make_set_cookie(
                                   cookie_cfg.access_token_name,
                                   tokens.access_token,
                                   utils::token_cookie_options(cookie_cfg, tokens.expires_in)));
        response.addHeader("Set-Cookie",
                           utils::make_set_cookie(
                                   cookie_cfg.refresh_token_name,
                                   tokens.refresh_token,
                                   utils::token_cookie_options(cookie_cfg, tokens.refresh_expires_in)));
    }

    void clear_token_cookies(usub::unet::http::Response &response, std::string_view realm) const {
        const auto cookie_cfg = token_cookie_config_for_realm(realm);
        const auto cookie_options = utils::token_cookie_options(cookie_cfg);
        response.addHeader("Set-Cookie",
                           utils::make_expired_cookie(cookie_cfg.access_token_name, cookie_options));
        response.addHeader("Set-Cookie",
                           utils::make_expired_cookie(cookie_cfg.refresh_token_name, cookie_options));
    }

    utils::TokenCookieConfig token_cookie_config_for_realm(std::string_view realm) const {
        auto cookie_cfg = config_.token_cookies;
        cookie_cfg.access_token_name += "_" + std::string(realm);
        cookie_cfg.refresh_token_name += "_" + std::string(realm);
        return cookie_cfg;
    }

    static std::string decode_form_component(std::string_view value) {
        std::string normalized;
        normalized.reserve(value.size());
        for (const char ch: value) {
            normalized.push_back(ch == '+' ? ' ' : ch);
        }
        return url_decode(normalized);
    }

    static std::unordered_map<std::string, std::string> parse_form_encoded(std::string_view raw) {
        std::unordered_map<std::string, std::string> params;
        std::size_t start = 0;

        while (start <= raw.size()) {
            const std::size_t end = raw.find('&', start);
            const std::string_view part =
                    raw.substr(start, end == std::string_view::npos ? raw.size() - start : end - start);

            if (!part.empty()) {
                const std::size_t eq = part.find('=');
                const std::string_view key = part.substr(0, eq);
                const std::string_view value =
                        eq == std::string_view::npos ? std::string_view{} : part.substr(eq + 1);
                params.insert_or_assign(decode_form_component(key), decode_form_component(value));
            }

            if (end == std::string_view::npos) {
                break;
            }
            start = end + 1;
        }

        return params;
    }

    static std::string json_escape(std::string_view value) {
        std::string escaped;
        escaped.reserve(value.size());

        for (const unsigned char ch: value) {
            switch (ch) {
                case '\\':
                    escaped += "\\\\";
                    break;
                case '"':
                    escaped += "\\\"";
                    break;
                case '\b':
                    escaped += "\\b";
                    break;
                case '\f':
                    escaped += "\\f";
                    break;
                case '\n':
                    escaped += "\\n";
                    break;
                case '\r':
                    escaped += "\\r";
                    break;
                case '\t':
                    escaped += "\\t";
                    break;
                default:
                    escaped.push_back(static_cast<char>(ch));
                    break;
            }
        }

        return escaped;
    }

    Client &client_;
    TokenService &token_service_;
    AuthHandlerConfig config_;
};

} // namespace handlers
