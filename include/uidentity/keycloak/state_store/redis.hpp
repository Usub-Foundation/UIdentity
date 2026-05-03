#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <string_view>

#include <uvent/tasks/Awaitable.h>
#include <uvent/tasks/AwaitableFrame.h>

#include "uidentity/keycloak/state_store/state_store.hpp"
#include "uredis/RedisClusterClient.h"

namespace usub::uidentity::keycloak
{
    class RedisStateStore
    {
    public:
        // Example: prefix="kc:state:" so keys are kc:state:<state>
        RedisStateStore(usub::uredis::RedisClusterClient& redis,
                        std::string key_prefix = "kc:state:");

        usub::uvent::task::Awaitable<std::string> create_state(std::string_view code_verifier,
                                                               std::chrono::seconds ttl);

        usub::uvent::task::Awaitable<std::string> create_state_entry(const StateEntry &entry,
                                                                     std::chrono::seconds ttl);

        usub::uvent::task::Awaitable<std::optional<std::string>> consume_state(std::string_view state);
        usub::uvent::task::Awaitable<std::optional<StateEntry>> consume_state_entry(std::string_view state);

        void cleanup_expired_unsafe() {};
        std::string random_state_32();

    private:
        usub::uredis::RedisClusterClient& redis_;
        std::string key_prefix_;

        std::string make_key(std::string_view state) const;
    };
} // namespace usub::uidentity::keycloak
