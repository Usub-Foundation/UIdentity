#pragma once
#include <chrono>
#include <optional>
#include <string>
#include <string_view>

#include <uvent/tasks/Awaitable.h>
#include <uvent/tasks/AwaitableFrame.h>

namespace keycloak
{
    struct StateEntry
    {
        std::string code_verifier;
        std::string realm;
    };

    template <class StateStore>
    class KeycloakHandler
    {
    public:
        explicit KeycloakHandler(StateStore &store) : store_(store) {}

        usub::uvent::task::Awaitable<std::string> create_state(std::string_view code_verifier,
                                                               std::chrono::seconds ttl)
        {
            co_return co_await store_.create_state(code_verifier, ttl);
        }

        usub::uvent::task::Awaitable<std::string> create_state_entry(const StateEntry &entry,
                                                                     std::chrono::seconds ttl)
        {
            co_return co_await store_.create_state_entry(entry, ttl);
        }

        usub::uvent::task::Awaitable<std::optional<std::string>> consume_state(std::string_view state)
        {
            co_return co_await store_.consume_state(state);
        }

        usub::uvent::task::Awaitable<std::optional<StateEntry>> consume_state_entry(std::string_view state)
        {
            co_return co_await store_.consume_state_entry(state);
        }

        std::string random_state_32()
        {
            return store_.random_state_32();
        }

        void cleanup_expired_unsafe()
        {
            return store_.cleanup_expired_unsafe();
        }

    private:
        StateStore &store_;
    };

} // namespace keycloak
