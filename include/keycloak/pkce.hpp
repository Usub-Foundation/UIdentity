#pragma once
#include <string>
#include <utility>
#include <cstddef>

namespace keycloak
{

    struct PkcePair
    {
        std::string code_verifier;
        std::string code_challenge;
    };

    // Generate (verifier, challenge) for S256.
    // verifier_len will be clamped to [43, 128].
    PkcePair generate_pkce_pair(std::size_t verifier_len = 64);

} // namespace keycloak
