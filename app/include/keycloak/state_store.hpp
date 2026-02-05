#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <chrono>

namespace keycloak
{

    // StateStore is responsible for:
    // - creating and storing (state -> code_verifier) with TTL
    // - consuming/verifying state once (single-use)
    class IStateStore
    {
    public:
        virtual ~IStateStore() = default;

        // Store verifier and return generated state.
        // Implementation should store with TTL and ideally single-use.
        virtual std::string create_state(std::string_view code_verifier,
                                         std::chrono::seconds ttl) = 0;

        // Consume state: returns code_verifier if valid; std::nullopt otherwise. TODO: implement our error handling
        // Should delete the state entry after successful read.
        virtual std::optional<std::string> consume_state(std::string_view state) = 0;
    };

} // namespace keycloak
