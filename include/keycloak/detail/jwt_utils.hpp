#pragma once

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "keycloak/detail/json_utils.hpp"

namespace keycloak::detail
{
    struct DecodedJwt
    {
        std::string signing_input;
        std::string header_json;
        std::string payload_json;
        std::string signature;
    };

    struct Jwk
    {
        std::string kid;
        std::string kty;
        std::string alg;
        std::string n;
        std::string e;
    };

    inline std::optional<unsigned char> decode_base64url_char(char ch)
    {
        if (ch >= 'A' && ch <= 'Z')
        {
            return static_cast<unsigned char>(ch - 'A');
        }
        if (ch >= 'a' && ch <= 'z')
        {
            return static_cast<unsigned char>(26 + ch - 'a');
        }
        if (ch >= '0' && ch <= '9')
        {
            return static_cast<unsigned char>(52 + ch - '0');
        }
        if (ch == '-')
        {
            return 62;
        }
        if (ch == '_')
        {
            return 63;
        }
        return std::nullopt;
    }

    inline std::optional<std::string> base64url_decode(std::string_view input)
    {
        std::string out;
        out.reserve((input.size() * 3) / 4 + 3);

        int val = 0;
        int valb = -8;
        for (const char ch : input)
        {
            if (ch == '=')
            {
                break;
            }

            const auto decoded = decode_base64url_char(ch);
            if (!decoded.has_value())
            {
                return std::nullopt;
            }

            val = (val << 6) + *decoded;
            valb += 6;
            if (valb >= 0)
            {
                out.push_back(static_cast<char>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }

        return out;
    }

    inline std::optional<DecodedJwt> decode_jwt(std::string_view token)
    {
        const auto first_dot = token.find('.');
        const auto second_dot = token.find('.', first_dot == std::string_view::npos ? first_dot : first_dot + 1);
        if (first_dot == std::string_view::npos || second_dot == std::string_view::npos)
        {
            return std::nullopt;
        }

        const auto header_part = token.substr(0, first_dot);
        const auto payload_part = token.substr(first_dot + 1, second_dot - first_dot - 1);
        const auto signature_part = token.substr(second_dot + 1);

        const auto decoded_header = base64url_decode(header_part);
        const auto decoded_payload = base64url_decode(payload_part);
        const auto decoded_signature = base64url_decode(signature_part);
        if (!decoded_header.has_value() || !decoded_payload.has_value() || !decoded_signature.has_value())
        {
            return std::nullopt;
        }

        return DecodedJwt{
            .signing_input = std::string(token.substr(0, second_dot)),
            .header_json = *decoded_header,
            .payload_json = *decoded_payload,
            .signature = *decoded_signature,
        };
    }

    inline std::vector<Jwk> extract_jwks(std::string_view jwks_json)
    {
        std::vector<Jwk> keys;
        const auto array = extract_json_array(jwks_json, "keys");
        if (!array.has_value())
        {
            return keys;
        }

        for (const auto element : split_json_array_elements(*array))
        {
            if (element.empty() || element.front() != '{')
            {
                continue;
            }

            Jwk jwk;
            jwk.kid = extract_json_string(element, "kid").value_or("");
            jwk.kty = extract_json_string(element, "kty").value_or("");
            jwk.alg = extract_json_string(element, "alg").value_or("");
            jwk.n = extract_json_string(element, "n").value_or("");
            jwk.e = extract_json_string(element, "e").value_or("");
            if (!jwk.kty.empty())
            {
                keys.push_back(std::move(jwk));
            }
        }

        return keys;
    }

    inline const EVP_MD *evp_digest_for_alg(std::string_view alg)
    {
        if (alg == "RS256")
        {
            return EVP_sha256();
        }
        if (alg == "RS384")
        {
            return EVP_sha384();
        }
        if (alg == "RS512")
        {
            return EVP_sha512();
        }
        return nullptr;
    }

    inline std::vector<std::string> extract_audience_values(std::string_view payload_json)
    {
        auto values = extract_json_string_array(payload_json, "aud");
        if (values.empty())
        {
            if (const auto aud = extract_json_string(payload_json, "aud"))
            {
                values.push_back(*aud);
            }
        }
        return values;
    }

    inline std::vector<std::string> extract_all_roles(std::string_view payload_json)
    {
        std::vector<std::string> roles;

        if (const auto realm_access = extract_json_object(payload_json, "realm_access"))
        {
            append_unique(roles, extract_json_string_array(*realm_access, "roles"));
        }

        if (const auto resource_access = extract_json_object(payload_json, "resource_access"))
        {
            std::size_t pos = 1;
            while (pos + 1 < resource_access->size())
            {
                pos = skip_ws(*resource_access, pos);
                if (pos >= resource_access->size() - 1 || (*resource_access)[pos] == '}')
                {
                    break;
                }

                const auto key_end = skip_json_string(*resource_access, pos);
                if (key_end <= pos)
                {
                    break;
                }

                pos = skip_ws(*resource_access, key_end);
                if (pos < resource_access->size() && (*resource_access)[pos] == ':')
                {
                    ++pos;
                }

                pos = skip_ws(*resource_access, pos);
                const auto value_end = skip_json_value(*resource_access, pos);
                if (value_end <= pos)
                {
                    break;
                }

                const auto value = resource_access->substr(pos, value_end - pos);
                if (!value.empty() && value.front() == '{')
                {
                    append_unique(roles, extract_json_string_array(value, "roles"));
                }

                pos = skip_ws(*resource_access, value_end);
                if (pos < resource_access->size() && (*resource_access)[pos] == ',')
                {
                    ++pos;
                }
            }
        }

        return roles;
    }

    inline bool contains_string(const std::vector<std::string> &values,
                                std::string_view expected)
    {
        return std::find(values.begin(), values.end(), expected) != values.end();
    }

    inline std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> make_rsa_public_key(const Jwk &jwk)
    {
        auto pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(nullptr, &EVP_PKEY_free);
        if (jwk.kty != "RSA" || jwk.n.empty() || jwk.e.empty())
        {
            return pkey;
        }

        const auto n_bytes = base64url_decode(jwk.n);
        const auto e_bytes = base64url_decode(jwk.e);
        if (!n_bytes.has_value() || !e_bytes.has_value())
        {
            return pkey;
        }

        BIGNUM *n = BN_bin2bn(reinterpret_cast<const unsigned char *>(n_bytes->data()),
                             static_cast<int>(n_bytes->size()),
                             nullptr);
        BIGNUM *e = BN_bin2bn(reinterpret_cast<const unsigned char *>(e_bytes->data()),
                             static_cast<int>(e_bytes->size()),
                             nullptr);
        if (!n || !e)
        {
            if (n)
            {
                BN_free(n);
            }
            if (e)
            {
                BN_free(e);
            }
            return pkey;
        }

        RSA *rsa = RSA_new();
        if (!rsa)
        {
            BN_free(n);
            BN_free(e);
            return pkey;
        }

        if (RSA_set0_key(rsa, n, e, nullptr) != 1)
        {
            BN_free(n);
            BN_free(e);
            RSA_free(rsa);
            return pkey;
        }

        pkey.reset(EVP_PKEY_new());
        if (!pkey || EVP_PKEY_assign_RSA(pkey.get(), rsa) != 1)
        {
            RSA_free(rsa);
            pkey.reset();
            return pkey;
        }

        return pkey;
    }

    inline bool verify_rsa_signature(const Jwk &jwk,
                                     std::string_view alg,
                                     std::string_view signing_input,
                                     std::string_view signature)
    {
        const EVP_MD *digest = evp_digest_for_alg(alg);
        if (!digest)
        {
            return false;
        }

        auto pkey = make_rsa_public_key(jwk);
        if (!pkey)
        {
            return false;
        }

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            return false;
        }

        const bool ok =
            EVP_DigestVerifyInit(ctx, nullptr, digest, nullptr, pkey.get()) == 1 &&
            EVP_DigestVerifyUpdate(ctx, signing_input.data(), signing_input.size()) == 1 &&
            EVP_DigestVerifyFinal(ctx,
                                  reinterpret_cast<const unsigned char *>(signature.data()),
                                  signature.size()) == 1;

        EVP_MD_CTX_free(ctx);
        return ok;
    }
} // namespace keycloak::detail
