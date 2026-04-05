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
#include "probes/Probe.h"

namespace {

struct DemoHttpClient {
    keycloak::http::Response send(const keycloak::http::Request &request) {
        std::cout << "demo token exchange request: " << request.method << ' ' << request.url << "\n";
        return keycloak::http::Response{
                .status = 501,
                .headers = {{"content-type", "application/json"}},
                .body = R"({"error":"demo_http_client_not_configured"})",
        };
    }
};

struct DemoAuthMiddleware {
    AuthResult authenticate(const HttpRequest &, RequestContext &) const {
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

    probes::ProbeHandler probes_handler{};
    handlers::AuthHandler auth_handler{client};

    usub::Uvent uvent{1};
    usub::unet::http::ServerRadix server;

    register_error_handlers(server);

    server.handle(std::set<std::string>{"GET"}, "/healthz", route<&probes::ProbeHandler::liveness>(probes_handler));
    server.handle(std::set<std::string>{"GET"}, "/readyz", route<&probes::ProbeHandler::readiness>(probes_handler));
    server.handle(std::set<std::string>{"GET"}, "/startup", route<&probes::ProbeHandler::startup>(probes_handler));

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
