#include "keycloak/state_store/redis.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <random>
#include <stdexcept>
#include <utility>

#include "utils/url_encode.hpp"

namespace keycloak
{
    static constexpr char kHex[] = "0123456789abcdef";
    RedisStateStore::RedisStateStore(usub::uredis::RedisClusterClient &redis, std::string key_prefix)
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

    namespace
    {
        std::runtime_error redis_failure(std::string_view operation, const usub::uredis::RedisError &error)
        {
            return std::runtime_error(
                std::string(operation) + " failed: " + error.message);
        }
    }

    usub::uvent::task::Awaitable<std::string> RedisStateStore::create_state(
        std::string_view code_verifier,
        std::chrono::seconds ttl)
    {
        co_return co_await create_state_entry(StateEntry{
                .code_verifier = std::string(code_verifier),
                .realm = "",
        },
                                              ttl);
    }

    namespace
    {
        std::string encode_state_entry(const StateEntry &entry)
        {
            return "verifier=" + url_encode(entry.code_verifier) + "&realm=" + url_encode(entry.realm);
        }

        std::optional<StateEntry> decode_state_entry(std::string_view raw)
        {
            StateEntry entry;
            std::size_t start = 0;

            while (start <= raw.size())
            {
                const std::size_t end = raw.find('&', start);
                const std::string_view part =
                    raw.substr(start, end == std::string_view::npos ? raw.size() - start : end - start);

                if (!part.empty())
                {
                    const std::size_t eq = part.find('=');
                    const std::string key = url_decode(part.substr(0, eq));
                    const std::string value =
                        eq == std::string_view::npos ? std::string{} : url_decode(part.substr(eq + 1));

                    if (key == "verifier")
                    {
                        entry.code_verifier = value;
                    }
                    else if (key == "realm")
                    {
                        entry.realm = value;
                    }
                }

                if (end == std::string_view::npos)
                {
                    break;
                }
                start = end + 1;
            }

            if (entry.code_verifier.empty())
            {
                return std::nullopt;
            }

            return entry;
        }
    }

    usub::uvent::task::Awaitable<std::string> RedisStateStore::create_state_entry(
        const StateEntry &entry,
        std::chrono::seconds ttl)
    {
        const int ttl_seconds = static_cast<int>(std::max<std::int64_t>(1, ttl.count()));
        const std::string ttl_text = std::to_string(ttl_seconds);
        const std::string value = encode_state_entry(entry);

        for (int attempt = 0; attempt < 8; ++attempt)
        {
            std::string state = random_state_32();
            std::string key = make_key(state);

            auto response = co_await redis_.command("SET",
                                                    key,
                                                    value,
                                                    "EX",
                                                    ttl_text,
                                                    "NX");
            if (!response)
            {
                throw redis_failure("RedisStateStore::create_state", response.error());
            }

            // SET NX returns a nil reply when the key already exists.
            if (response->is_null())
            {
                continue;
            }

            if (!response->is_simple_string() || response->as_string() != "OK")
            {
                throw std::runtime_error("RedisStateStore::create_state failed: unexpected Redis reply");
            }

            co_return state;
        }

        throw std::runtime_error("RedisStateStore::create_state failed: unable to allocate unique state");
    }

    usub::uvent::task::Awaitable<std::optional<std::string>> RedisStateStore::consume_state(
        std::string_view state)
    {
        const auto entry = co_await consume_state_entry(state);
        if (!entry.has_value())
        {
            co_return std::nullopt;
        }

        co_return entry->code_verifier;
    }

    usub::uvent::task::Awaitable<std::optional<StateEntry>> RedisStateStore::consume_state_entry(
        std::string_view state)
    {
        const std::string key = make_key(state);
        auto response = co_await redis_.command("GETDEL", key);
        if (!response)
        {
            throw redis_failure("RedisStateStore::consume_state", response.error());
        }

        if (response->is_null())
        {
            co_return std::nullopt;
        }

        if (!response->is_bulk_string() && !response->is_simple_string())
        {
            throw std::runtime_error("RedisStateStore::consume_state failed: unexpected Redis reply");
        }

        const auto raw = response->as_string();
        if (const auto entry = decode_state_entry(raw))
        {
            co_return entry;
        }

        // Backward-compatible fallback for any states written before the realm metadata existed.
        co_return StateEntry{
            .code_verifier = raw,
            .realm = "",
        };
    }

} // namespace keycloak
