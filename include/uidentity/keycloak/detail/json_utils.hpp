#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace usub::uidentity::keycloak::detail
{
    inline std::size_t skip_ws(std::string_view text, std::size_t pos)
    {
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos])))
        {
            ++pos;
        }
        return pos;
    }

    inline std::size_t skip_json_string(std::string_view text, std::size_t pos)
    {
        if (pos >= text.size() || text[pos] != '"')
        {
            return pos;
        }

        ++pos;
        bool escaped = false;
        while (pos < text.size())
        {
            const char ch = text[pos++];
            if (escaped)
            {
                escaped = false;
                continue;
            }

            if (ch == '\\')
            {
                escaped = true;
                continue;
            }

            if (ch == '"')
            {
                return pos;
            }
        }

        return text.size();
    }

    inline std::size_t skip_json_value(std::string_view text, std::size_t pos)
    {
        pos = skip_ws(text, pos);
        if (pos >= text.size())
        {
            return pos;
        }

        if (text[pos] == '"')
        {
            return skip_json_string(text, pos);
        }

        if (text[pos] == '{')
        {
            ++pos;
            while (pos < text.size())
            {
                pos = skip_ws(text, pos);
                if (pos < text.size() && text[pos] == '}')
                {
                    return pos + 1;
                }

                pos = skip_json_string(text, pos);
                pos = skip_ws(text, pos);
                if (pos < text.size() && text[pos] == ':')
                {
                    ++pos;
                }

                pos = skip_json_value(text, pos);
                pos = skip_ws(text, pos);
                if (pos < text.size() && text[pos] == ',')
                {
                    ++pos;
                    continue;
                }

                if (pos < text.size() && text[pos] == '}')
                {
                    return pos + 1;
                }
            }
            return text.size();
        }

        if (text[pos] == '[')
        {
            ++pos;
            while (pos < text.size())
            {
                pos = skip_ws(text, pos);
                if (pos < text.size() && text[pos] == ']')
                {
                    return pos + 1;
                }

                pos = skip_json_value(text, pos);
                pos = skip_ws(text, pos);
                if (pos < text.size() && text[pos] == ',')
                {
                    ++pos;
                    continue;
                }

                if (pos < text.size() && text[pos] == ']')
                {
                    return pos + 1;
                }
            }
            return text.size();
        }

        while (pos < text.size())
        {
            const char ch = text[pos];
            if (ch == ',' || ch == '}' || ch == ']')
            {
                break;
            }
            ++pos;
        }

        return pos;
    }

    inline std::optional<std::string_view> extract_json_value(std::string_view json,
                                                              std::string_view key)
    {
        const std::string quoted_key = "\"" + std::string(key) + "\"";
        std::size_t search_from = 0;

        while (search_from < json.size())
        {
            const auto key_pos = json.find(quoted_key, search_from);
            if (key_pos == std::string_view::npos)
            {
                return std::nullopt;
            }

            const auto colon_pos = json.find(':', key_pos + quoted_key.size());
            if (colon_pos == std::string_view::npos)
            {
                return std::nullopt;
            }

            const auto value_begin = skip_ws(json, colon_pos + 1);
            const auto value_end = skip_json_value(json, value_begin);
            if (value_begin < value_end)
            {
                return json.substr(value_begin, value_end - value_begin);
            }

            search_from = key_pos + quoted_key.size();
        }

        return std::nullopt;
    }

    inline std::optional<std::string> parse_json_string(std::string_view raw)
    {
        if (raw.size() < 2 || raw.front() != '"' || raw.back() != '"')
        {
            return std::nullopt;
        }

        std::string result;
        result.reserve(raw.size() - 2);

        bool escaped = false;
        for (std::size_t i = 1; i + 1 < raw.size(); ++i)
        {
            const char ch = raw[i];
            if (escaped)
            {
                switch (ch)
                {
                case '"':
                case '\\':
                case '/':
                    result.push_back(ch);
                    break;
                case 'b':
                    result.push_back('\b');
                    break;
                case 'f':
                    result.push_back('\f');
                    break;
                case 'n':
                    result.push_back('\n');
                    break;
                case 'r':
                    result.push_back('\r');
                    break;
                case 't':
                    result.push_back('\t');
                    break;
                default:
                    result.push_back(ch);
                    break;
                }
                escaped = false;
                continue;
            }

            if (ch == '\\')
            {
                escaped = true;
                continue;
            }

            result.push_back(ch);
        }

        return result;
    }

    inline std::optional<std::string> extract_json_string(std::string_view json,
                                                          std::string_view key)
    {
        const auto raw = extract_json_value(json, key);
        if (!raw.has_value())
        {
            return std::nullopt;
        }
        return parse_json_string(*raw);
    }

    inline std::optional<int> extract_json_int(std::string_view json,
                                               std::string_view key)
    {
        const auto raw = extract_json_value(json, key);
        if (!raw.has_value())
        {
            return std::nullopt;
        }

        try
        {
            return std::stoi(std::string(*raw));
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

    inline std::optional<std::int64_t> extract_json_int64(std::string_view json,
                                                          std::string_view key)
    {
        const auto raw = extract_json_value(json, key);
        if (!raw.has_value())
        {
            return std::nullopt;
        }

        try
        {
            return std::stoll(std::string(*raw));
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

    inline std::optional<bool> extract_json_bool(std::string_view json,
                                                 std::string_view key)
    {
        const auto raw = extract_json_value(json, key);
        if (!raw.has_value())
        {
            return std::nullopt;
        }

        if (*raw == "true")
        {
            return true;
        }
        if (*raw == "false")
        {
            return false;
        }
        return std::nullopt;
    }

    inline std::optional<std::string_view> extract_json_object(std::string_view json,
                                                               std::string_view key)
    {
        const auto raw = extract_json_value(json, key);
        if (!raw.has_value() || raw->empty() || raw->front() != '{')
        {
            return std::nullopt;
        }
        return raw;
    }

    inline std::optional<std::string_view> extract_json_array(std::string_view json,
                                                              std::string_view key)
    {
        const auto raw = extract_json_value(json, key);
        if (!raw.has_value() || raw->empty() || raw->front() != '[')
        {
            return std::nullopt;
        }
        return raw;
    }

    inline std::vector<std::string_view> split_json_array_elements(std::string_view array)
    {
        std::vector<std::string_view> out;
        if (array.size() < 2 || array.front() != '[' || array.back() != ']')
        {
            return out;
        }

        std::size_t pos = 1;
        while (pos + 1 < array.size())
        {
            pos = skip_ws(array, pos);
            if (pos >= array.size() - 1 || array[pos] == ']')
            {
                break;
            }

            const auto end = skip_json_value(array, pos);
            if (end <= pos)
            {
                break;
            }

            out.emplace_back(array.substr(pos, end - pos));
            pos = skip_ws(array, end);
            if (pos < array.size() && array[pos] == ',')
            {
                ++pos;
            }
        }

        return out;
    }

    inline std::vector<std::string> extract_json_string_array(std::string_view json,
                                                              std::string_view key)
    {
        std::vector<std::string> values;
        const auto raw = extract_json_array(json, key);
        if (!raw.has_value())
        {
            return values;
        }

        for (const auto element : split_json_array_elements(*raw))
        {
            if (const auto parsed = parse_json_string(element))
            {
                values.push_back(*parsed);
            }
        }

        return values;
    }

    inline std::vector<std::string> split_ws(std::string_view input)
    {
        std::vector<std::string> values;
        std::size_t pos = 0;

        while (pos < input.size())
        {
            pos = skip_ws(input, pos);
            if (pos >= input.size())
            {
                break;
            }

            const auto end = input.find_first_of(" \t\r\n", pos);
            if (end == std::string_view::npos)
            {
                values.emplace_back(input.substr(pos));
                break;
            }

            values.emplace_back(input.substr(pos, end - pos));
            pos = end + 1;
        }

        return values;
    }

    inline void append_unique(std::vector<std::string> &target,
                              const std::vector<std::string> &source)
    {
        for (const auto &value : source)
        {
            if (std::find(target.begin(), target.end(), value) == target.end())
            {
                target.push_back(value);
            }
        }
    }
} // namespace usub::uidentity::keycloak::detail
