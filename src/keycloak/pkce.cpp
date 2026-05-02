#include "uidentity/keycloak/pkce.hpp"

#include <algorithm>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <string_view>

namespace
{

    // PKCE code_verifier allowed characters (RFC 7636 unreserved)
    constexpr std::string_view kCharset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

    std::string generate_random_string(std::size_t length)
    {
        std::string bytes(length, '\0');
        if (RAND_bytes(reinterpret_cast<unsigned char *>(bytes.data()),
                       static_cast<int>(bytes.size())) != 1)
        {
            throw std::runtime_error("RAND_bytes failed");
        }

        std::string result;
        result.reserve(length);
        for (unsigned char byte : bytes)
        {
            result.push_back(kCharset[byte % kCharset.size()]);
        }
        return result;
    }

    std::string sha256_raw(std::string_view input)
    {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int len = 0;

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
            throw std::runtime_error("EVP_MD_CTX_new failed");

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
            EVP_DigestFinal_ex(ctx, hash, &len) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA256 digest failed");
        }
        EVP_MD_CTX_free(ctx);

        return std::string(reinterpret_cast<char *>(hash), len);
    }

    std::string base64url_encode(std::string_view input)
    {
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO *mem = BIO_new(BIO_s_mem());
        if (!b64 || !mem)
        {
            if (b64)
                BIO_free(b64);
            if (mem)
                BIO_free(mem);
            throw std::runtime_error("BIO_new failed");
        }

        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64, mem);

        BIO_write(b64, input.data(), static_cast<int>(input.size()));
        BIO_flush(b64);

        BUF_MEM *buffer_ptr = nullptr;
        BIO_get_mem_ptr(b64, &buffer_ptr);
        std::string out(buffer_ptr->data, buffer_ptr->length);

        BIO_free_all(b64);

        // Convert to base64url
        std::replace(out.begin(), out.end(), '+', '-');
        std::replace(out.begin(), out.end(), '/', '_');
        while (!out.empty() && out.back() == '=')
            out.pop_back();

        return out;
    }

} // namespace

namespace keycloak
{

    PkcePair generate_pkce_pair(std::size_t verifier_len)
    {
        // RFC 7636: 43..128
        if (verifier_len < 43)
            verifier_len = 43;
        if (verifier_len > 128)
            verifier_len = 128;

        std::string verifier = generate_random_string(verifier_len);
        std::string challenge = base64url_encode(sha256_raw(verifier));

        return PkcePair{std::move(verifier), std::move(challenge)};
    }

} // namespace keycloak
