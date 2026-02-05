#pragma once
#include <string>
#include <cstdint>

namespace keycloak::http
{

    struct ProxyConfig
    {
        std::string host;
        uint16_t port{0};

        bool is_enabled() const { return !host.empty() && port > 0; }
    };

    class IProxyAware
    {
    public:
        virtual ~IProxyAware() = default;

        virtual void set_proxy(const ProxyConfig &config) = 0;
    };

} // namespace keycloak::http
