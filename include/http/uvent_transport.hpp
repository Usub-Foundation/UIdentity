#pragma once

#include "http/async_transport.hpp"
#include "proxy_config.hpp"

#include <chrono>
#include <cstddef>
#include <string_view>

namespace keycloak::http
{

    // Async HTTP/1.1 transport over uvent TCP sockets.
    // NOTE: HTTPS/TLS is not supported here (TODO: add secure transport later).
    class UventTransport final : public IAsyncTransport, public IProxyAware
    {
    public:
        UventTransport() = default;

        usub::uvent::task::Awaitable<Response, usub::uvent::detail::AwaitableFrame<Response>>
        async_send_request(
            std::string_view host,
            std::string_view port,
            std::string_view method,
            std::string_view path,
            std::string_view body,
            const std::unordered_map<std::string, std::string> &headers) override;

        void set_proxy(const ProxyConfig &config) override { proxy_config_ = config; }

        // Connection establishment timeout (DNS+TCP connect)
        void set_connect_timeout(std::chrono::milliseconds t) { connect_timeout_ = t; }

        // Per-socket IO timeout (read/write operations)
        void set_io_timeout(std::chrono::milliseconds t) { io_timeout_ = t; }

        // Safety cap to prevent unbounded memory growth on large responses.
        void set_max_response_bytes(std::size_t bytes) { max_response_bytes_ = bytes; }

    private:
        ProxyConfig proxy_config_;
        std::chrono::milliseconds connect_timeout_{5000};
        std::chrono::milliseconds io_timeout_{5000};
        std::size_t max_response_bytes_{2u * 1024u * 1024u}; // 2 MiB default
    };

} // namespace keycloak::http
