#include <iostream>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <expected>
#include <cstdlib>
#include <chrono>
#include <atomic>
#include <vector>

#include <uvent/Uvent.h>
#include <unet/core/streams/openssl.hpp>
#include <unet/core/streams/plaintext.hpp>
#include <unet/core/config.hpp>
#include <unet/http/client.hpp>
#include <unet/http.hpp>
#include <uredis/RedisClusterClient.h>

#include "api_models/http_context.hpp"
#include "handlers/AuthHandler.h"
#include "keycloak/config.hpp"
#include "keycloak/detail/oidc_utils.hpp"
#include "keycloak/keycloak_client.hpp"
#include "keycloak/oauth/token_service.hpp"
#include "keycloak/state_store/redis.hpp"

namespace {

struct AppConfig {
    keycloak::KeycloakRealmConfig realm;
    keycloak::TokenServiceConfig token;
    AuthConfig auth;

    usub::uredis::RedisClusterConfig redis;

    std::string listen_host{"127.0.0.1"};
    std::uint16_t listen_port{22813};
    int uvent_threads{1};
    std::string health_path{"/health/live"};
    std::string ready_path{"/health/ready"};
};

std::optional<std::string> getenv_string(const char *name) {
    if (const char *value = std::getenv(name)) {
        if (*value != '\0') {
            return std::string(value);
        }
    }
    return std::nullopt;
}

std::string getenv_or(const char *name, std::string fallback) {
    if (auto value = getenv_string(name)) {
        return *value;
    }
    return fallback;
}

int getenv_int(const char *name, int fallback) {
    if (auto value = getenv_string(name)) {
        try {
            return std::stoi(*value);
        } catch (...) {
            return fallback;
        }
    }
    return fallback;
}

bool getenv_bool(const char *name, bool fallback) {
    if (auto value = getenv_string(name)) {
        if (*value == "1" || *value == "true" || *value == "TRUE" || *value == "yes") {
            return true;
        }
        if (*value == "0" || *value == "false" || *value == "FALSE" || *value == "no") {
            return false;
        }
    }
    return fallback;
}

std::vector<std::string> split_ws(std::string raw) {
    return keycloak::detail::split_ws(raw);
}

AppConfig load_config() {
    AppConfig app{};

    app.listen_host = getenv_or("UIDENTITY_LISTEN_HOST", "127.0.0.1");
    app.listen_port = static_cast<std::uint16_t>(getenv_int("UIDENTITY_LISTEN_PORT", 22813));
    app.uvent_threads = std::max(1, getenv_int("UIDENTITY_UVENT_THREADS", 1));

    const std::string public_keycloak_base_url = getenv_or(
            "UIDENTITY_KEYCLOAK_AUTH_BASE_URL",
            getenv_or("UIDENTITY_KEYCLOAK_BASE_URL", "https://keycloak.0x000f.com"));
    const std::string internal_keycloak_base_url = getenv_or(
            "UIDENTITY_KEYCLOAK_INTERNAL_BASE_URL",
            public_keycloak_base_url);

    app.realm.base_url = public_keycloak_base_url;
    app.realm.realm = getenv_or("UIDENTITY_KEYCLOAK_REALM", "trader");
    app.realm.client_id = getenv_or("UIDENTITY_KEYCLOAK_CLIENT_ID", "myclient");
    app.realm.redirect_uri = getenv_or(
            "UIDENTITY_KEYCLOAK_REDIRECT_URI",
            "http://" + app.listen_host + ":" + std::to_string(app.listen_port) + "/api/v1/callback");
    app.realm.scopes = split_ws(getenv_or("UIDENTITY_KEYCLOAK_SCOPES", "openid profile email"));

    app.token = {
            .base_url = internal_keycloak_base_url,
            .realm = app.realm.realm,
            .client_id = app.realm.client_id,
            .client_secret = getenv_string("UIDENTITY_KEYCLOAK_CLIENT_SECRET"),
            .redirect_uri = app.realm.redirect_uri,
    };

    app.auth.expected_issuer = getenv_or(
            "UIDENTITY_AUTH_EXPECTED_ISSUER",
            keycloak::detail::realm_root(public_keycloak_base_url, app.realm.realm));
    app.auth.jwks_url = getenv_or(
            "UIDENTITY_AUTH_JWKS_URL",
            keycloak::detail::jwks_endpoint(internal_keycloak_base_url, app.realm.realm));
    app.auth.jwks_cache_ttl = std::chrono::seconds{std::max(1, getenv_int("UIDENTITY_AUTH_JWKS_CACHE_TTL_SECONDS", 300))};
    app.auth.require_audience = getenv_bool("UIDENTITY_AUTH_REQUIRE_AUDIENCE", false);
    app.auth.expected_audience = getenv_or("UIDENTITY_AUTH_EXPECTED_AUDIENCE", "");
    app.auth.expected_azp = getenv_or("UIDENTITY_AUTH_EXPECTED_AZP", app.realm.client_id);
    app.auth.clock_skew_seconds = getenv_int("UIDENTITY_AUTH_CLOCK_SKEW_SECONDS", 60);

    app.redis.seeds = {{
            .host = getenv_or("UIDENTITY_REDIS_HOST", "127.0.0.1"),
            .port = static_cast<std::uint16_t>(getenv_int("UIDENTITY_REDIS_PORT", 6379)),
    }};
    app.redis.username = getenv_string("UIDENTITY_REDIS_USERNAME");
    app.redis.password = getenv_string("UIDENTITY_REDIS_PASSWORD");
    app.redis.connect_timeout_ms = getenv_int("UIDENTITY_REDIS_CONNECT_TIMEOUT_MS", 5000);
    app.redis.io_timeout_ms = getenv_int("UIDENTITY_REDIS_IO_TIMEOUT_MS", 5000);
    app.redis.max_redirections = getenv_int("UIDENTITY_REDIS_MAX_REDIRECTIONS", 5);
    app.redis.max_connections_per_node = static_cast<std::size_t>(std::max(1, getenv_int("UIDENTITY_REDIS_MAX_CONNECTIONS_PER_NODE", 4)));
    app.redis.force_standalone = getenv_bool("UIDENTITY_REDIS_FORCE_STANDALONE", true);
    app.health_path = getenv_or("UIDENTITY_HEALTH_PATH", "/health/live");
    app.ready_path = getenv_or("UIDENTITY_READY_PATH", "/health/ready");

    return app;
}

usub::unet::core::Config make_server_config(const AppConfig &cfg) {
    usub::unet::core::Config config;
    usub::unet::core::Config::Object section;
    section.emplace("host", usub::unet::core::Config::Value{std::string(cfg.listen_host)});
    section.emplace("port", usub::unet::core::Config::Value{static_cast<std::uint64_t>(cfg.listen_port)});
    config.root.emplace("HTTP", usub::unet::core::Config::Value{
            usub::unet::core::Config::Object{
                    {"PlainTextStream", usub::unet::core::Config::Value{std::move(section)}},
            }});
    return config;
}

std::string json_escape(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const unsigned char ch: value) {
        switch (ch) {
            case '\\': escaped += "\\\\"; break;
            case '"': escaped += "\\\""; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default: escaped.push_back(static_cast<char>(ch)); break;
        }
    }
    return escaped;
}

struct UnetHttpClient {
    using Client = usub::unet::http::ClientImpl<
            usub::unet::core::stream::PlainText,
            usub::unet::core::stream::OpenSSLStream>;

    UnetHttpClient() {
        client_.setStreamConfig<usub::unet::core::stream::OpenSSLStream>({
                .mode = usub::unet::core::stream::OpenSSLStream::MODE::CLIENT,
                .verify_peer = true,
        });
    }

    usub::uvent::task::Awaitable<usub::unet::http::Response> send(const usub::unet::http::Request &request) {
        auto result = co_await client_.request(request, {
                .connect_timeout = std::chrono::milliseconds{3000},
        });
        if (!result) {
            throw std::runtime_error("http request failed: " + result.error().message);
        }

        co_return std::move(*result);
    }

private:
    Client client_;
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

template<class Client>
auto protected_route(Client &client) {
    return [&client](usub::unet::http::Request &request,
                     usub::unet::http::Response &response) -> usub::uvent::task::Awaitable<void> {
        RequestContext context;
        const auto auth_result = co_await client.authenticate_request(request, context);

        response.addHeader("Cache-Control", "no-store");
        response.addHeader("Pragma", "no-cache");
        response.addHeader("Content-Type", "application/json");

        if (!auth_result.ok) {
            response.setStatus(static_cast<std::uint16_t>(auth_result.http_status));
            response.setBody(std::string{"{\"ok\":false,\"error\":\""} + json_escape(auth_result.error) + "\"}");
            co_return;
        }

        response.setStatus(200);
        response.setBody(
                "{\"ok\":true,"
                "\"sub\":\"" + json_escape(context.sub) + "\","
                "\"preferred_username\":\"" + json_escape(context.preferred_username) + "\","
                "\"issuer\":\"" + json_escape(context.issuer) + "\","
                "\"client_id\":\"" + json_escape(context.client_id) + "\"}");
        co_return;
    };
}

usub::uvent::task::Awaitable<void> bootstrap_redis(usub::Uvent &uvent,
                                                   usub::uredis::RedisClusterClient &redis,
                                                   std::atomic<bool> &redis_ready) {
    auto result = co_await redis.connect();
    if (!result) {
        std::cerr << "redis bootstrap failed: " << result.error().message << "\n";
        redis_ready.store(false, std::memory_order_relaxed);
        uvent.stop();
        co_return;
    }
    redis_ready.store(true, std::memory_order_relaxed);
    std::cout << "redis bootstrap succeeded\n";
    co_return;
}

auto health_route() {
    return [](usub::unet::http::Request &,
              usub::unet::http::Response &response) -> usub::uvent::task::Awaitable<void> {
        response.setStatus(200);
        response.addHeader("Content-Type", "application/json");
        response.setBody(R"({"ok":true,"status":"live"})");
        co_return;
    };
}

auto readiness_route(std::atomic<bool> &redis_ready) {
    return [&redis_ready](usub::unet::http::Request &,
                          usub::unet::http::Response &response) -> usub::uvent::task::Awaitable<void> {
        response.addHeader("Content-Type", "application/json");
        if (!redis_ready.load(std::memory_order_relaxed)) {
            response.setStatus(503);
            response.setBody(R"({"ok":false,"status":"not_ready","dependency":"redis"})");
            co_return;
        }

        response.setStatus(200);
        response.setBody(R"({"ok":true,"status":"ready"})");
        co_return;
    };
}

} // namespace

int main() {
    const AppConfig app_cfg = load_config();

    usub::Uvent uvent{app_cfg.uvent_threads};
    std::atomic<bool> redis_ready{false};
    usub::uredis::RedisClusterClient redis_client{app_cfg.redis};
    keycloak::RedisStateStore store(redis_client);
    UnetHttpClient http_client;
    keycloak::TokenService<UnetHttpClient> token_service(app_cfg.token, http_client);
    keycloak::AccessTokenValidator<UnetHttpClient> validator(app_cfg.auth, http_client);
    keycloak::BearerAuthMiddleware<keycloak::AccessTokenValidator<UnetHttpClient>> auth_middleware(validator);
    keycloak::KeycloakClient<keycloak::RedisStateStore,
                             keycloak::TokenService<UnetHttpClient>,
                             keycloak::BearerAuthMiddleware<keycloak::AccessTokenValidator<UnetHttpClient>>>
            client(app_cfg.realm, store, token_service, auth_middleware);

    handlers::AuthHandler auth_handler{client};
    auto server_cfg = make_server_config(app_cfg);
    usub::unet::http::ServerRadix server{uvent, server_cfg};

    register_error_handlers(server);

    server.handle("GET", "/auth/login", route<&handlers::AuthHandler<decltype(client)>::login>(auth_handler));
    server.handle(std::set<std::string>{"GET", "POST"},
                  "/api/v1/callback",
                  route<&handlers::AuthHandler<decltype(client)>::callback>(auth_handler));
    server.handle("GET", "/api/v1/me", protected_route(client));
    server.handle("GET", app_cfg.health_path, health_route());
    server.handle("GET", app_cfg.ready_path, readiness_route(redis_ready));

    usub::uvent::system::co_spawn(bootstrap_redis(uvent, redis_client, redis_ready));

    std::cout << "configured callback server on http://" << app_cfg.listen_host << ":" << app_cfg.listen_port << "\n";
    std::cout << "login endpoint:    GET  /auth/login\n";
    std::cout << "callback endpoint: GET|POST /api/v1/callback\n";
    std::cout << "protected route:   GET  /api/v1/me\n";
    std::cout << "live endpoint:     GET  " << app_cfg.health_path << "\n";
    std::cout << "ready endpoint:    GET  " << app_cfg.ready_path << "\n";

    uvent.run();
    return 0;
}
