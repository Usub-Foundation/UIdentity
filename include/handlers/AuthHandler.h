#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

#include <unet/http.hpp>

#include "keycloak/keycloak_client.hpp"
#include "utils/url_encode.hpp"

namespace handlers {

template<class Client>
class AuthHandler {
public:
    explicit AuthHandler(Client &client) : client_(client) {}

    ServerHandler login(usub::unet::http::Request &request, usub::unet::http::Response &response) {
        (void) request;

        const auto auth_start = this->client_.start_login(std::chrono::minutes(5));

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
        const auto result = this->client_.complete_login({
                .code = code_it == params.end() ? std::string{} : code_it->second,
                .state = state_it == params.end() ? std::string{} : state_it->second,
        });

        response.addHeader("Cache-Control", "no-store");
        response.addHeader("Pragma", "no-cache");
        response.addHeader("Content-Type", "application/json");
        response.setStatus(static_cast<std::uint16_t>(result.http_status));

        if (!result.ok) {
            response.setBody(std::string{"{\"ok\":false,\"error\":\""} + json_escape(result.error) + "\"}");
            co_return;
        }

        response.setBody(
                "{\"ok\":true,"
                "\"access_token\":\"" + json_escape(result.tokens.access_token) + "\","
                "\"id_token\":\"" + json_escape(result.tokens.id_token) + "\","
                "\"refresh_token\":\"" + json_escape(result.tokens.refresh_token) + "\","
                "\"token_type\":\"" + json_escape(result.tokens.token_type) + "\","
                "\"scope\":\"" + json_escape(result.tokens.scope) + "\","
                "\"expires_in\":" + std::to_string(result.tokens.expires_in) + ","
                "\"refresh_expires_in\":" + std::to_string(result.tokens.refresh_expires_in) + "}");
        co_return;
    }

private:
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
};

} // namespace handlers
