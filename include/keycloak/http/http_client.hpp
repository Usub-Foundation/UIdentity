#pragma once

#include <string>
#include <unordered_map>

namespace keycloak
{
    namespace http
    {
        struct Request
        {
            std::string method;
            std::string url;
            std::unordered_map<std::string, std::string> headers;
            std::string body;
        };

        struct Response
        {
            int status = 0;
            std::unordered_map<std::string, std::string> headers;
            std::string body;
        };
    } // namespace http

} // namespace keycloak
