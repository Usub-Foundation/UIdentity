#pragma once
#include <chrono>
#include <concepts>
#include <optional>
#include <string>
#include <string_view>

#include "keycloak/http/http_client.hpp"

namespace keycloak
{

    template <class S>
    concept StateStoreLike =
        requires(S &s, std::string_view verifier, std::chrono::seconds ttl, std::string_view state) {
            { s.create_state(verifier, ttl) } -> std::same_as<std::string>;
            { s.consume_state(state) } -> std::same_as<std::optional<std::string>>;
            { s.random_state_32() } -> std::same_as<std::string>;
            { s.cleanup_expired_unsafe() } -> std::same_as<void>;
        };

    template <class C>
    concept HttpClientLike =
        requires(C &c, const http::Request &request) {
            { c.send(request) } -> std::same_as<http::Response>;
        };

} // namespace keycloak
