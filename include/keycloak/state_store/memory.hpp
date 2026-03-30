// TODO: this is a temporary in-memory state store for PKCE states. replace with Redis after.
#pragma once
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace keycloak
{

    class MemoryStateStore
    {
    public:
        std::string create_state(std::string_view code_verifier,
                                 std::chrono::seconds ttl);

        std::optional<std::string> consume_state(std::string_view state);
        std::string random_state_32();
        void cleanup_expired_unsafe();

    private:
        struct Entry
        {
            std::string verifier;
            std::chrono::steady_clock::time_point expires_at;
        };

        std::mutex m_;
        std::unordered_map<std::string, Entry> map_;
    };

} // namespace keycloak
