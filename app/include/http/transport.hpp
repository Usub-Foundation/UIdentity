#pragma once
#include <string>
#include <string_view>
#include <memory>
#include <unordered_map>

namespace keycloak::http
{

    struct Response
    {
        int status_code{0};                                   ///< HTTP status code
        std::string body;                                     ///< Response body
        std::unordered_map<std::string, std::string> headers; ///< Response headers
    };

    class ITransport
    {
    public:
        virtual ~ITransport() = default;

        virtual Response send_request(
            std::string_view host,
            std::string_view port,
            std::string_view method,
            std::string_view path,
            std::string_view body,
            const std::unordered_map<std::string, std::string> &headers) = 0;
    };

    std::unique_ptr<ITransport> create_default_transport();

} // namespace keycloak::http
