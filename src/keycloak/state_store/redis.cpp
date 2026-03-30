#include "keycloak/state_store/redis.hpp"

#include <random>
#include <stdexcept>
#include <utility>

namespace keycloak
{
    static constexpr char kHex[] = "0123456789abcdef";
    // TODO: Redis integration still needs a safe bridge from the coroutine client to this synchronous API.
    RedisStateStore::RedisStateStore(usub::uredis::RedisClusterClient& redis, std::string key_prefix)
        : redis_(redis), key_prefix_(std::move(key_prefix))
    {
        if (key_prefix_.empty())
            throw std::invalid_argument("key_prefix must not be empty");
    }

    std::string RedisStateStore::make_key(std::string_view state) const
    {
        return key_prefix_ + std::string(state);
    }

    std::string RedisStateStore::random_state_32()
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 15);

        std::string s;
        s.resize(32);
        for (auto &c : s)
            c = kHex[dist(gen)];
        return s;
    }

    // TODO: rewrite state store to the asynchrous so that i can implement uredis later
    std::string RedisStateStore::create_state(std::string_view code_verifier,
                                              std::chrono::seconds ttl)
    {
        (void)code_verifier;
        (void)ttl;
        throw std::runtime_error("RedisStateStore::create_state is not implemented yet");
    }

    std::optional<std::string> RedisStateStore::consume_state(std::string_view state)
    {
        (void)state;
        throw std::runtime_error("RedisStateStore::consume_state is not implemented yet");
    }

} // namespace keycloak
