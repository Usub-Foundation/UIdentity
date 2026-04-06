#pragma once

#include <any>
#include <string>
#include <vector>

#include <unet/http.hpp>

struct RequestContext
{
    bool authenticated = false;
    std::string sub;
    std::string preferred_username;
    std::string issuer;
    std::string client_id;
    std::vector<std::string> roles;
    std::vector<std::string> scopes;
};

struct AuthConfig
{
    std::string expected_issuer;
    std::string jwks_url;
    bool require_audience = false;
    std::string expected_audience;
    std::string expected_azp;
    int clock_skew_seconds = 60;
};

struct AuthResult
{
    bool ok = false;
    int http_status = 500;
    std::string error;
};

inline RequestContext *get_request_context(usub::unet::http::Request &request)
{
    return std::any_cast<RequestContext>(&request.user_data);
}

inline const RequestContext *get_request_context(const usub::unet::http::Request &request)
{
    return std::any_cast<RequestContext>(&request.user_data);
}

inline void set_request_context(usub::unet::http::Request &request, RequestContext context)
{
    request.user_data = std::move(context);
}
