#pragma once
#include <chrono>
#include <concepts>
#include <optional>
#include <string>
#include <string_view>

#include <unet/http.hpp>
#include <uvent/tasks/Awaitable.h>

namespace keycloak
{

    template <class S>
    concept StateStoreLike =
        requires(S &s, std::string_view verifier, std::chrono::seconds ttl, std::string_view state) {
            { s.create_state(verifier, ttl) } -> std::same_as<usub::uvent::task::Awaitable<std::string>>;
            { s.consume_state(state) } -> std::same_as<usub::uvent::task::Awaitable<std::optional<std::string>>>;
            { s.random_state_32() } -> std::same_as<std::string>;
            { s.cleanup_expired_unsafe() } -> std::same_as<void>;
        };

    template <class C>
    concept HttpClientLike =
        requires(C &c, const usub::unet::http::Request &request) {
            { c.send(request) } -> std::same_as<usub::unet::http::Response>;
        };

    template <class C>
    concept AsyncHttpClientLike =
        requires(C &c, const usub::unet::http::Request &request) {
            { c.send(request) } -> std::same_as<usub::uvent::task::Awaitable<usub::unet::http::Response>>;
        };

} // namespace keycloak
