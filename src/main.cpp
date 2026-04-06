#include <iostream>
#include <optional>
#include <set>
#include <string>

#include <uvent/Uvent.h>
#include <unet/http.hpp>

#include "api_models/http_context.hpp"
#include "handlers/AuthHandler.h"
#include "keycloak/config.hpp"
#include "keycloak/keycloak_client.hpp"
#include "keycloak/oauth/token_service.hpp"
#include "keycloak/state_store/memory.hpp"

namespace {

struct DemoHttpClient {
    usub::unet::http::Response send(const usub::unet::http::Request &request) {
        std::cout << "demo token exchange request: "
                  << request.metadata.method_token << ' '
                  << keycloak::detail::request_url(request) << "\n";
        usub::unet::http::Response response;
        response.setStatus(501);
        response.addHeader("content-type", "application/json");
        response.body = R"({"error":"demo_http_client_not_configured"})";
        return response;
    }
};

struct DemoAuthMiddleware {
    AuthResult authenticate(usub::unet::http::Request &, RequestContext &) const {
        return AuthResult{
                .ok = false,
                .http_status = 501,
                .error = "demo_auth_middleware_not_configured",
        };
    }
};

void register_error_handlers(usub::unet::http::ServerRadix &server) {
    server.addErrorHandler("404", [](const usub::unet::http::Request &, usub::unet::http::Response &response) {
        response.setStatus(404);
        response.addHeader("Content-Type", "application/json");
        response.setBody(R"({"ok":false,"error":"route_not_found"})");
    });

    server.addErrorHandler("405", [](const usub::unet::http::Request &, usub::unet::http::Response &response) {
        response.setStatus(405);
        response.addHeader("Content-Type", "application/json");
        response.setBody(R"({"ok":false,"error":"method_not_allowed"})");
    });

    server.addErrorHandler("400", [](const usub::unet::http::Request &, usub::unet::http::Response &response) {
        response.setStatus(400);
        response.addHeader("Content-Type", "application/json");
        response.setBody(R"({"ok":false,"error":"bad_request"})");
    });

}

template<auto Method, class Handler>
auto route(Handler &handler) {
    return [&handler](usub::unet::http::Request &request,
                      usub::unet::http::Response &response) -> usub::uvent::task::Awaitable<void> {
        co_await (handler.*Method)(request, response);
    };
}

} // namespace

int main() {
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

    handlers::AuthHandler auth_handler{client};

    usub::Uvent uvent{1};
    usub::unet::http::ServerRadix server;

    register_error_handlers(server);

    server.handle("GET", "/auth/login", route<&handlers::AuthHandler<decltype(client)>::login>(auth_handler));
    server.handle(std::set<std::string>{"GET", "POST"},
                  "/api/v1/callback",
                  route<&handlers::AuthHandler<decltype(client)>::callback>(auth_handler));

    std::cout << "listening on http://127.0.0.1:22813\n";
    std::cout << "login endpoint:    GET  /auth/login\n";
    std::cout << "callback endpoint: GET|POST /api/v1/callback\n";

    uvent.run();
    return 0;
}
