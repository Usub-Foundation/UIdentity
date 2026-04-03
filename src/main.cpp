#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>

#include <uvent/Uvent.h>
#include <uvent/tasks/AwaitableFrame.h>
#include <unet/http.hpp>

#include "api_models/http_context.hpp"
#include "keycloak/auth/bearer_auth_middleware.hpp"
#include "keycloak/config.hpp"
#include "keycloak/http/http_client.hpp"
#include "keycloak/keycloak_client.hpp"
#include "keycloak/oauth/token_service.hpp"
#include "keycloak/state_store/memory.hpp"
#include "utils/url_encode.hpp"

namespace
{
    struct DemoHttpClient
    {
        keycloak::http::Response send(const keycloak::http::Request &request)
        {
            std::cout << "demo token exchange request: " << request.method << ' ' << request.url << "\n";
            return keycloak::http::Response{
                .status = 501,
                .headers = {{"content-type", "application/json"}},
                .body = R"({"error":"demo_http_client_not_configured"})",
            };
        }
    };

    struct DemoAuthMiddleware
    {
        AuthResult authenticate(const HttpRequest &, RequestContext &) const
        {
            return AuthResult{
                .ok = false,
                .http_status = 501,
                .error = "demo_auth_middleware_not_configured",
            };
        }
    };

    std::string decode_form_component(std::string_view value)
    {
        std::string normalized;
        normalized.reserve(value.size());
        for (const char ch : value)
        {
            normalized.push_back(ch == '+' ? ' ' : ch);
        }
        return url_decode(normalized);
    }

    std::unordered_map<std::string, std::string> parse_form_encoded(std::string_view raw)
    {
        std::unordered_map<std::string, std::string> params;
        std::size_t start = 0;

        while (start <= raw.size())
        {
            const std::size_t end = raw.find('&', start);
            const std::string_view part = raw.substr(
                start,
                end == std::string_view::npos ? raw.size() - start : end - start);

            if (!part.empty())
            {
                const std::size_t eq = part.find('=');
                const std::string_view key = part.substr(0, eq);
                const std::string_view value =
                    eq == std::string_view::npos ? std::string_view{} : part.substr(eq + 1);
                params.insert_or_assign(decode_form_component(key), decode_form_component(value));
            }

            if (end == std::string_view::npos)
            {
                break;
            }

            start = end + 1;
        }

        return params;
    }

    std::string json_escape(std::string_view value)
    {
        std::string escaped;
        escaped.reserve(value.size());

        for (const unsigned char ch : value)
        {
            switch (ch)
            {
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
} // namespace

int main()
{
    keycloak::KeycloakRealmConfig cfg;
    cfg.base_url = "https://keycloak.0x000f.com";
    cfg.realm = "trader";
    cfg.client_id = "myclient";
    cfg.redirect_uri = "http://127.0.0.1:22813/api/v1/callback";
    cfg.scopes = {"openid", "profile", "email"};

    keycloak::MemoryStateStore store;
    DemoHttpClient http_client;
    DemoAuthMiddleware auth_middleware;

    keycloak::TokenServiceConfig token_cfg{
        .base_url = cfg.base_url,
        .realm = cfg.realm,
        .client_id = cfg.client_id,
        .client_secret = std::nullopt,
        .redirect_uri = cfg.redirect_uri,
    };

    keycloak::TokenService<DemoHttpClient> token_service(token_cfg, http_client);
    keycloak::KeycloakClient<keycloak::MemoryStateStore,
                             keycloak::TokenService<DemoHttpClient>,
                             DemoAuthMiddleware>
        client(cfg, store, token_service, auth_middleware);

    usub::Uvent runtime{1};
    usub::unet::http::ServerRadix server;

    server.handle("GET",
                  "/auth/login",
                  [&client](usub::unet::http::Request &, usub::unet::http::Response &response)
                      -> usub::uvent::task::Awaitable<void>
                  {
                      const auto auth_start = client.start_login(std::chrono::minutes(5));
                      response.setStatus(302);
                      response.addHeader("Location", auth_start.authorization_url);
                      response.addHeader("Cache-Control", "no-store");
                      response.addHeader("Pragma", "no-cache");
                      response.setBody("");
                      co_return;
                  });

    server.handle(std::set<std::string>{"GET", "POST"},
                  "/api/v1/callback",
                  [&client](usub::unet::http::Request &request, usub::unet::http::Response &response)
                      -> usub::uvent::task::Awaitable<void>
                  {
                      auto params = parse_form_encoded(request.metadata.uri.query);
                      if (request.metadata.method_token == "POST")
                      {
                          auto body_params = parse_form_encoded(request.body);
                          for (auto &[key, value] : body_params)
                          {
                              params.insert_or_assign(std::move(key), std::move(value));
                          }
                      }

                      const auto code_it = params.find("code");
                      const auto state_it = params.find("state");
                      const auto result = client.complete_login({
                          .code = code_it == params.end() ? std::string{} : code_it->second,
                          .state = state_it == params.end() ? std::string{} : state_it->second,
                      });

                      response.setStatus(static_cast<std::uint16_t>(result.http_status));
                      response.addHeader("Cache-Control", "no-store");
                      response.addHeader("Pragma", "no-cache");
                      response.addHeader("Content-Type", "application/json");

                      if (!result.ok)
                      {
                          response.setBody("{\"ok\":false,\"error\":\"" + json_escape(result.error) + "\"}");
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
                  });

    std::cout << "listening on http://127.0.0.1:22813\n";
    std::cout << "login endpoint:    GET  /auth/login\n";
    std::cout << "callback endpoint: GET|POST /api/v1/callback\n";

    runtime.run();
    return 0;
}
