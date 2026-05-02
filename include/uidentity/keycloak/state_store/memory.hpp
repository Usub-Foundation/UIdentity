#pragma once
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include <uvent/tasks/Awaitable.h>
#include <uvent/tasks/AwaitableFrame.h>

#include "uidentity/keycloak/state_store/state_store.hpp"

namespace keycloak
{

    class MemoryStateStore
    {
    public:
        usub::uvent::task::Awaitable<std::string> create_state(std::string_view code_verifier,
                                                               std::chrono::seconds ttl);

        usub::uvent::task::Awaitable<std::string> create_state_entry(const StateEntry &entry,
                                                                     std::chrono::seconds ttl);

        usub::uvent::task::Awaitable<std::optional<std::string>> consume_state(std::string_view state);
        usub::uvent::task::Awaitable<std::optional<StateEntry>> consume_state_entry(std::string_view state);
        std::string random_state_32();
        void cleanup_expired_unsafe();

    private:
        struct Entry
        {
            std::string verifier;
            std::string realm;
            std::chrono::steady_clock::time_point expires_at;
        };

        std::mutex m_;
        std::unordered_map<std::string, Entry> map_;
    };

} // namespace keycloak
