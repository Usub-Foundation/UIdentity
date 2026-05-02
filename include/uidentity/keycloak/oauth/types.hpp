#pragma once

#include <string>
#include <vector>

namespace keycloak
{
    struct TokenSet
    {
        std::string access_token;
        std::string id_token;
        std::string refresh_token;
        std::string token_type = "Bearer";
        std::string scope;
        int expires_in = 0;
        int refresh_expires_in = 0;
    };

    struct UserInfo
    {
        std::string sub;
        std::string preferred_username;
        std::string email;
        std::vector<std::string> roles;
    };

    struct OAuthResult
    {
        bool ok = false;
        int http_status = 500;
        std::string error;
        TokenSet tokens;
        UserInfo user_info;
    };
} // namespace keycloak
