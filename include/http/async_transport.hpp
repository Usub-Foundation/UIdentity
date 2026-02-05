#pragma once
#include "transport.hpp"
#include <unordered_map>
#include <string>
#include <string_view>

#include "uvent/tasks/Awaitable.h"
#include "uvent/tasks/AwaitableFrame.h"

namespace keycloak::http
{

    class IAsyncTransport
    {
    public:
        virtual ~IAsyncTransport() = default;

        virtual usub::uvent::task::Awaitable<Response, usub::uvent::detail::AwaitableFrame<Response>>
        async_send_request(
            std::string_view host,
            std::string_view port,
            std::string_view method,
            std::string_view path,
            std::string_view body,
            const std::unordered_map<std::string, std::string> &headers) = 0;
    };

} // namespace keycloak::http
