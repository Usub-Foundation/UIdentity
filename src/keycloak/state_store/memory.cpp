#include "uidentity/keycloak/state_store/memory.hpp"
#include <openssl/rand.h>
#include <stdexcept>
#include <utility>

namespace usub::uidentity::keycloak
{

    static constexpr char kHex[] = "0123456789abcdef";
    static constexpr std::size_t kStateBytes = 16;

    std::string MemoryStateStore::random_state_32()
    {
        unsigned char bytes[kStateBytes];
        if (RAND_bytes(bytes, static_cast<int>(sizeof(bytes))) != 1)
        {
            throw std::runtime_error("RAND_bytes failed while generating OAuth state");
        }

        std::string s;
        s.reserve(kStateBytes * 2);
        for (const unsigned char byte : bytes)
        {
            s.push_back(kHex[(byte >> 4) & 0x0F]);
            s.push_back(kHex[byte & 0x0F]);
        }
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
        co_return co_await create_state_entry(StateEntry{
                .code_verifier = std::string(code_verifier),
                .realm = "",
        },
                                              ttl);
    }

    usub::uvent::task::Awaitable<std::string> MemoryStateStore::create_state_entry(
        const StateEntry &entry,
        std::chrono::seconds ttl)
    {
        std::lock_guard lk(m_);
        cleanup_expired_unsafe();

        for (int attempt = 0; attempt < 8; ++attempt)
        {
            std::string state = random_state_32();
            if (map_.contains(state))
            {
                continue;
            }

            map_[state] = Entry{entry.code_verifier,
                                entry.realm,
                                std::chrono::steady_clock::now() + ttl};
            co_return state;
        }

        throw std::runtime_error("MemoryStateStore::create_state failed: unable to allocate unique state");
    }

    usub::uvent::task::Awaitable<std::optional<std::string>> MemoryStateStore::consume_state(
        std::string_view state)
    {
        const auto entry = co_await consume_state_entry(state);
        if (!entry.has_value())
            co_return std::nullopt;

        co_return entry->code_verifier;
    }

    usub::uvent::task::Awaitable<std::optional<StateEntry>> MemoryStateStore::consume_state_entry(
        std::string_view state)
    {
        std::lock_guard lk(m_);
        cleanup_expired_unsafe();

        auto it = map_.find(std::string(state));
        if (it == map_.end())
            co_return std::nullopt;

        StateEntry entry{
            .code_verifier = std::move(it->second.verifier),
            .realm = std::move(it->second.realm),
        };
        map_.erase(it);
        co_return entry;
    }

} // namespace usub::uidentity::keycloak
