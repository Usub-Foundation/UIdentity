// TODO: this is a temporary in-memory state store for PKCE states. replace with Redis after.
#pragma once
#include "/home/dev_elseif/UIdentity/app/include/keycloak/state_store.hpp"

#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>

namespace keycloak
{

    class MemoryStateStore final : public IStateStore
    {
    public:
        std::string create_state(std::string_view code_verifier,
                                 std::chrono::seconds ttl) override;

        std::optional<std::string> consume_state(std::string_view state) override;

    private:
        struct Entry
        {
            std::string verifier;
            std::chrono::steady_clock::time_point expires_at;
        };

        std::mutex m_;
        std::unordered_map<std::string, Entry> map_;

        static std::string random_state_32();
        void cleanup_expired_unsafe();
    };

} // namespace keycloak
