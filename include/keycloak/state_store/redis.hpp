#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <string_view>

#include "uredis/RedisClusterClient.h"

namespace keycloak
{
    class RedisStateStore
    {
    public:
        // Example: prefix="kc:state:" so keys are kc:state:<state>
        RedisStateStore(usub::uredis::RedisClusterClient& redis,
                        std::string key_prefix = "kc:state:");

        std::string create_state(std::string_view code_verifier,
                                 std::chrono::seconds ttl);

        std::optional<std::string> consume_state(std::string_view state);

        void cleanup_expired_unsafe() {};
        std::string random_state_32();

    private:
        usub::uredis::RedisClusterClient& redis_;
        std::string key_prefix_;

        std::string make_key(std::string_view state) const;
    };
} // namespace keycloak
