#include "keycloak/state_store/memory.hpp"
#include <random>
#include <utility>

namespace keycloak
{

    static constexpr char kHex[] = "0123456789abcdef";

    std::string MemoryStateStore::random_state_32()
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

    void MemoryStateStore::cleanup_expired_unsafe()
    {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = map_.begin(); it != map_.end();)
        {
            if (it->second.expires_at <= now)
                it = map_.erase(it);
            else
                ++it;
        }
    }

    usub::uvent::task::Awaitable<std::string> MemoryStateStore::create_state(
        std::string_view code_verifier,
        std::chrono::seconds ttl)
    {
        std::lock_guard lk(m_);
        cleanup_expired_unsafe();

        std::string state = random_state_32();
        map_[state] = Entry{std::string(code_verifier),
                            std::chrono::steady_clock::now() + ttl};
        co_return state;
    }

    usub::uvent::task::Awaitable<std::optional<std::string>> MemoryStateStore::consume_state(
        std::string_view state)
    {
        std::lock_guard lk(m_);
        cleanup_expired_unsafe();

        auto it = map_.find(std::string(state));
        if (it == map_.end())
            co_return std::nullopt;

        std::string verifier = std::move(it->second.verifier);
        map_.erase(it);
        co_return verifier;
    }

} // namespace keycloak
