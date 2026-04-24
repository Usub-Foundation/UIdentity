#include <iostream>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <expected>
#include <cstdlib>
#include <chrono>
#include <atomic>
#include <cctype>
#include <algorithm>
#include <unordered_map>
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
#include "keycloak/multi_realm.hpp"
#include "keycloak/oauth/token_service.hpp"
#include "keycloak/state_store/redis.hpp"
#include "probes/Probe.h"
#include "utils/cookies.hpp"

namespace {

struct RealmConfig {
    keycloak::KeycloakRealmConfig realm;
    keycloak::TokenServiceConfig token;
    AuthConfig auth;
};

struct AppConfig {
    std::vector<RealmConfig> realms;
    handlers::AuthHandlerConfig handler;

    usub::uredis::RedisClusterConfig redis;

    std::string listen_host{"127.0.0.1"};
    std::uint16_t listen_port{22813};
    int uvent_threads{1};
    std::string health_path{"/health/live"};
    std::string ready_path{"/health/ready"};
    std::string startup_path{"/health/startup"};
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

std::vector<std::string> split_list(std::string raw) {
    for (char &ch: raw) {
        if (ch == ',') {
            ch = ' ';
        }
    }
    return split_ws(std::move(raw));
}

std::string realm_env_suffix(std::string_view realm) {
    std::string suffix;
    suffix.reserve(realm.size());
    for (const unsigned char ch: realm) {
        if (std::isalnum(ch)) {
            suffix.push_back(static_cast<char>(std::toupper(ch)));
        } else {
            suffix.push_back('_');
        }
    }
    return suffix;
}

std::optional<std::string> getenv_realm_string(std::string_view realm, std::string_view name) {
    const std::string suffixed_name = std::string(name) + "_" + realm_env_suffix(realm);
    if (auto value = getenv_string(suffixed_name.c_str())) {
        return value;
    }
    return getenv_string(std::string(name).c_str());
}

std::string getenv_realm_or(std::string_view realm, std::string_view name, std::string fallback) {
    if (auto value = getenv_realm_string(realm, name)) {
        return *value;
    }
    return fallback;
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

    auto realms = split_list(getenv_or("UIDENTITY_KEYCLOAK_REALMS", ""));
    if (realms.empty()) {
        realms.push_back(getenv_or("UIDENTITY_KEYCLOAK_REALM", "trader"));
    }

    const std::string default_redirect_uri = getenv_or(
            "UIDENTITY_KEYCLOAK_REDIRECT_URI",
            "http://" + app.listen_host + ":" + std::to_string(app.listen_port) + "/api/v1/callback");
    const auto default_scopes = split_ws(getenv_or("UIDENTITY_KEYCLOAK_SCOPES", "openid profile email"));
    const auto jwks_cache_ttl = std::chrono::seconds{std::max(1, getenv_int("UIDENTITY_AUTH_JWKS_CACHE_TTL_SECONDS", 300))};
    const bool require_audience = getenv_bool("UIDENTITY_AUTH_REQUIRE_AUDIENCE", false);
    const std::string default_audience = getenv_or("UIDENTITY_AUTH_EXPECTED_AUDIENCE", "");
    const int clock_skew_seconds = getenv_int("UIDENTITY_AUTH_CLOCK_SKEW_SECONDS", 60);

    for (const auto &realm_name: realms) {
        RealmConfig realm_cfg{};
        realm_cfg.realm.base_url = public_keycloak_base_url;
        realm_cfg.realm.realm = realm_name;
        realm_cfg.realm.client_id = getenv_realm_or(realm_name, "UIDENTITY_KEYCLOAK_CLIENT_ID", "myclient");
        realm_cfg.realm.redirect_uri = getenv_realm_or(realm_name, "UIDENTITY_KEYCLOAK_REDIRECT_URI", default_redirect_uri);
        realm_cfg.realm.scopes = default_scopes;

        realm_cfg.token = {
                .base_url = internal_keycloak_base_url,
                .realm = realm_name,
                .client_id = realm_cfg.realm.client_id,
                .client_secret = getenv_realm_string(realm_name, "UIDENTITY_KEYCLOAK_CLIENT_SECRET"),
                .redirect_uri = realm_cfg.realm.redirect_uri,
        };

        realm_cfg.auth.expected_issuer = getenv_realm_or(
                realm_name,
                "UIDENTITY_AUTH_EXPECTED_ISSUER",
                keycloak::detail::realm_root(public_keycloak_base_url, realm_name));
        realm_cfg.auth.jwks_url = getenv_realm_or(
                realm_name,
                "UIDENTITY_AUTH_JWKS_URL",
                keycloak::detail::jwks_endpoint(internal_keycloak_base_url, realm_name));
        realm_cfg.auth.jwks_cache_ttl = jwks_cache_ttl;
        realm_cfg.auth.require_audience = require_audience;
        realm_cfg.auth.expected_audience = getenv_realm_or(
                realm_name,
                "UIDENTITY_AUTH_EXPECTED_AUDIENCE",
                default_audience);
        realm_cfg.auth.expected_azp = getenv_realm_or(
                realm_name,
                "UIDENTITY_AUTH_EXPECTED_AZP",
                realm_cfg.realm.client_id);
        realm_cfg.auth.clock_skew_seconds = clock_skew_seconds;
        app.realms.push_back(std::move(realm_cfg));
    }

    app.handler.token_cookies.access_token_name = getenv_or("UIDENTITY_COOKIE_ACCESS_TOKEN_NAME", "access_token");
    app.handler.token_cookies.refresh_token_name = getenv_or("UIDENTITY_COOKIE_REFRESH_TOKEN_NAME", "refresh_token");
    app.handler.token_cookies.path = getenv_or("UIDENTITY_COOKIE_PATH", "/");
    app.handler.token_cookies.secure = getenv_bool("UIDENTITY_COOKIE_SECURE", true);
    app.handler.token_cookies.same_site = getenv_or("UIDENTITY_COOKIE_SAMESITE", "Lax");
    app.handler.post_login_redirect = getenv_or("UIDENTITY_POST_LOGIN_REDIRECT", "/");
    app.handler.post_logout_redirect = getenv_or("UIDENTITY_POST_LOGOUT_REDIRECT", "/");
    app.handler.revoke_refresh_token_on_logout =
            getenv_bool("UIDENTITY_REVOKE_REFRESH_TOKEN_ON_LOGOUT", true);

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
    app.health_path = getenv_or("UIDENTITY_LIVENESS_PATH", getenv_or("UIDENTITY_HEALTH_PATH", "/health/live"));
    app.ready_path = getenv_or("UIDENTITY_READINESS_PATH", getenv_or("UIDENTITY_READY_PATH", "/health/ready"));
    app.startup_path = getenv_or("UIDENTITY_STARTUP_PATH", "/health/startup");

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

void clear_token_cookies(usub::unet::http::Response &response, const utils::TokenCookieConfig &cookie_cfg) {
    const auto options = utils::token_cookie_options(cookie_cfg);
    response.addHeader("Set-Cookie", utils::make_expired_cookie(cookie_cfg.access_token_name, options));
    response.addHeader("Set-Cookie", utils::make_expired_cookie(cookie_cfg.refresh_token_name, options));
}

std::unordered_map<std::string, std::string> parse_query_params(std::string_view raw) {
    std::unordered_map<std::string, std::string> params;
    std::size_t start = 0;

    while (start <= raw.size()) {
        const std::size_t end = raw.find('&', start);
        const std::string_view part =
                raw.substr(start, end == std::string_view::npos ? raw.size() - start : end - start);

        if (!part.empty()) {
            const std::size_t eq = part.find('=');
            const std::string key = url_decode(part.substr(0, eq));
            const std::string value = eq == std::string_view::npos ? std::string{} : url_decode(part.substr(eq + 1));
            params.insert_or_assign(key, value);
        }

        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1;
    }

    return params;
}

utils::TokenCookieConfig cookie_config_for_realm(const utils::TokenCookieConfig &cookie_cfg, std::string_view realm) {
    auto scoped = cookie_cfg;
    scoped.access_token_name += "_" + std::string(realm);
    scoped.refresh_token_name += "_" + std::string(realm);
    return scoped;
}

template<class RealmManager>
auto protected_route(RealmManager &realm_manager,
                     const utils::TokenCookieConfig &cookie_cfg) {
    return [&realm_manager, cookie_cfg](usub::unet::http::Request &request,
                                        usub::unet::http::Response &response)
            -> usub::uvent::task::Awaitable<void> {
        RequestContext context;
        response.addHeader("Cache-Control", "no-store");
        response.addHeader("Pragma", "no-cache");
        response.addHeader("Content-Type", "application/json");

        const auto params = parse_query_params(request.metadata.uri.query);
        const auto realm_it = params.find("realm");
        if (realm_it == params.end() || realm_it->second.empty()) {
            response.setStatus(400);
            response.setBody(R"({"ok":false,"error":"missing_realm"})");
            co_return;
        }
        if (!realm_manager.has_realm(realm_it->second)) {
            response.setStatus(404);
            response.setBody(R"({"ok":false,"error":"unknown_realm"})");
            co_return;
        }

        const auto scoped_cookie_cfg = cookie_config_for_realm(cookie_cfg, realm_it->second);
        auto access_token = utils::get_cookie(request, scoped_cookie_cfg.access_token_name);
        auto refresh_token = utils::get_cookie(request, scoped_cookie_cfg.refresh_token_name);

        auto validation = access_token.has_value()
                                  ? co_await realm_manager.validate(realm_it->second, *access_token)
                                  : keycloak::JwtValidationResult{
                                            .ok = false,
                                            .http_status = 401,
                                            .error = "missing_access_token_cookie",
                                            .context = RequestContext{},
                                    };

        const bool should_refresh = refresh_token.has_value() &&
                                    ((!access_token.has_value()) || validation.error == "jwt_expired");

        if (!validation.ok && should_refresh) {
            const auto refresh_result = co_await realm_manager.refresh_tokens(realm_it->second, *refresh_token);
            if (!refresh_result.ok) {
                clear_token_cookies(response, scoped_cookie_cfg);
                response.setStatus(static_cast<std::uint16_t>(refresh_result.http_status));
                response.setBody(std::string{"{\"ok\":false,\"error\":\""} + json_escape(refresh_result.error) + "\"}");
                co_return;
            }

            const std::string next_refresh_token = refresh_result.tokens.refresh_token.empty()
                                                           ? *refresh_token
                                                           : refresh_result.tokens.refresh_token;
            response.addHeader("Set-Cookie",
                               utils::make_set_cookie(
                                       scoped_cookie_cfg.access_token_name,
                                       refresh_result.tokens.access_token,
                                       utils::token_cookie_options(scoped_cookie_cfg, refresh_result.tokens.expires_in)));
            response.addHeader("Set-Cookie",
                               utils::make_set_cookie(
                                       scoped_cookie_cfg.refresh_token_name,
                                       next_refresh_token,
                                       utils::token_cookie_options(
                                               scoped_cookie_cfg,
                                               refresh_result.tokens.refresh_expires_in > 0
                                                       ? refresh_result.tokens.refresh_expires_in
                                                       : 0)));

            validation = co_await realm_manager.validate(realm_it->second, refresh_result.tokens.access_token);
        }

        if (!validation.ok) {
            if (validation.error == "jwt_expired") {
                clear_token_cookies(response, scoped_cookie_cfg);
            }
            response.setStatus(static_cast<std::uint16_t>(validation.http_status));
            response.setBody(std::string{"{\"ok\":false,\"error\":\""} + json_escape(validation.error) + "\"}");
            co_return;
        }

        context = validation.context;
        set_request_context(request, validation.context);
        response.setStatus(200);
        response.setBody(
                "{\"ok\":true,"
                "\"sub\":\"" + json_escape(context.sub) + "\","
                "\"preferred_username\":\"" + json_escape(context.preferred_username) + "\","
                "\"realm\":\"" + json_escape(context.realm) + "\","
                "\"issuer\":\"" + json_escape(context.issuer) + "\","
                "\"client_id\":\"" + json_escape(context.client_id) + "\"}");
        co_return;
    };
}

usub::uvent::task::Awaitable<void> bootstrap_redis(usub::Uvent &uvent,
                                                   usub::uredis::RedisClusterClient &redis,
                                                   std::atomic<bool> &running) {
    auto result = co_await redis.connect();
    if (!result) {
        std::cerr << "redis bootstrap failed: " << result.error().message << "\n";
        running.store(false, std::memory_order_release);
        uvent.stop();
        co_return;
    }
    running.store(true, std::memory_order_release);
    std::cout << "redis bootstrap succeeded\n";
    co_return;
}

} // namespace

int main() {
    const AppConfig app_cfg = load_config();

    usub::Uvent uvent{app_cfg.uvent_threads};
    std::atomic<bool> running{false};
    usub::uredis::RedisClusterClient redis_client{app_cfg.redis};
    keycloak::RedisStateStore store(redis_client);
    UnetHttpClient http_client;
    std::vector<keycloak::MultiRealmConfig> realms;
    realms.reserve(app_cfg.realms.size());
    for (const auto &realm_cfg: app_cfg.realms) {
        realms.push_back(keycloak::MultiRealmConfig{
                .realm = realm_cfg.realm,
                .token = realm_cfg.token,
                .auth = realm_cfg.auth,
        });
    }
    keycloak::MultiRealmManager<keycloak::RedisStateStore, UnetHttpClient> realm_manager(
            std::move(realms),
            store,
            http_client);

    handlers::AuthHandler auth_handler{realm_manager, realm_manager, app_cfg.handler};
    probes::ProbeHandler probe_handler{running};
    auto server_cfg = make_server_config(app_cfg);
    usub::unet::http::ServerRadix server{uvent, server_cfg};

    register_error_handlers(server);

    server.handle("GET", "/auth/login", route<&decltype(auth_handler)::login>(auth_handler));
    server.handle(std::set<std::string>{"GET", "POST"},
                  "/api/v1/callback",
                  route<&decltype(auth_handler)::callback>(auth_handler));
    server.handle("GET", "/auth/logout", route<&decltype(auth_handler)::logout>(auth_handler));
    server.handle("GET", "/api/v1/me", protected_route(realm_manager, app_cfg.handler.token_cookies));
    server.handle("GET", app_cfg.health_path, route<&decltype(probe_handler)::liveness>(probe_handler));
    server.handle("GET", app_cfg.ready_path, route<&decltype(probe_handler)::readiness>(probe_handler));
    server.handle("GET", app_cfg.startup_path, route<&decltype(probe_handler)::startup>(probe_handler));

    usub::uvent::system::co_spawn(bootstrap_redis(uvent, redis_client, running));

    std::cout << "configured callback server on http://" << app_cfg.listen_host << ":" << app_cfg.listen_port << "\n";
    std::cout << "configured realms: ";
    for (std::size_t i = 0; i < app_cfg.realms.size(); ++i) {
        if (i > 0) {
            std::cout << ", ";
        }
        std::cout << app_cfg.realms[i].realm.realm;
    }
    std::cout << "\n";
    std::cout << "login endpoint:    GET  /auth/login?realm=<realm>\n";
    std::cout << "callback endpoint: GET|POST /api/v1/callback\n";
    std::cout << "logout endpoint:   GET  /auth/logout?realm=<realm>\n";
    std::cout << "protected route:   GET  /api/v1/me?realm=<realm>\n";
    std::cout << "live endpoint:     GET  " << app_cfg.health_path << "\n";
    std::cout << "ready endpoint:    GET  " << app_cfg.ready_path << "\n";
    std::cout << "startup endpoint:  GET  " << app_cfg.startup_path << "\n";

    uvent.run();
    return 0;
}
