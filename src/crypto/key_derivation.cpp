#include "crypto/key_derivation.hpp"

#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace winzox::crypto {

namespace {

void ValidatePbkdf2Iterations(uint32_t iterations) {
    if (iterations == 0) {
        throw std::runtime_error("KDF iterations must be greater than zero");
    }
    if (iterations < kMinKdfIterations && iterations != kLegacyKdfIterations) {
        throw std::runtime_error("PBKDF2 iteration count is below the minimum security threshold");
    }
}

void DecodeScryptParameters(uint32_t encoded, uint64_t& n, uint64_t& r, uint64_t& p) {
    const uint32_t logN = (encoded >> kScryptLogNShift) & kScryptByteMask;
    r = (encoded >> kScryptRShift) & kScryptByteMask;
    p = (encoded >> kScryptPShift) & kScryptByteMask;
    if (logN < 1 || logN > 20 || r == 0 || p == 0) {
        throw std::runtime_error("Invalid scrypt parameter encoding");
    }
    n = 1ULL << logN;
}

std::vector<unsigned char> DerivePbkdf2Key(const std::string& password,
                                           const std::vector<unsigned char>& salt,
                                           uint32_t iterations) {
    ValidatePbkdf2Iterations(iterations);

    std::vector<unsigned char> key(32);
    if (PKCS5_PBKDF2_HMAC(password.c_str(),
                         static_cast<int>(password.length()),
                         salt.data(),
                         static_cast<int>(salt.size()),
                         static_cast<int>(iterations),
                         EVP_sha256(),
                         static_cast<int>(key.size()),
                         key.data()) != 1) {
        throw std::runtime_error("Failed to derive encryption key");
    }

    return key;
}

std::vector<unsigned char> DeriveScryptKey(const std::string& password,
                                           const std::vector<unsigned char>& salt,
                                           uint32_t encodedParameters) {
    uint64_t n = 0;
    uint64_t r = 0;
    uint64_t p = 0;
    DecodeScryptParameters(encodedParameters, n, r, p);

    std::vector<unsigned char> key(32);
    constexpr uint64_t kMaxMemory = 128ULL * 1024ULL * 1024ULL;
    if (EVP_PBE_scrypt(password.c_str(),
                       password.length(),
                       salt.data(),
                       salt.size(),
                       n,
                       r,
                       p,
                       kMaxMemory,
                       key.data(),
                       key.size()) != 1) {
        throw std::runtime_error("Failed to derive scrypt key");
    }

    return key;
}

} // namespace

bool UsesMemoryHardKdf(uint32_t iterations) {
    return (iterations & kKdfSchemeMask) != 0;
}

bool IsSupportedKdfParameter(uint32_t iterations) {
    if (UsesMemoryHardKdf(iterations)) {
        try {
            uint64_t n = 0;
            uint64_t r = 0;
            uint64_t p = 0;
            DecodeScryptParameters(iterations, n, r, p);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    return iterations == kLegacyKdfIterations || iterations >= kMinKdfIterations;
}

uint32_t EncodeScryptParameters(uint8_t logN, uint8_t r, uint8_t p) {
    if (logN < 1 || logN > 20 || r == 0 || p == 0) {
        throw std::runtime_error("Invalid scrypt parameters");
    }

    return kKdfSchemeMask |
        (static_cast<uint32_t>(logN) << kScryptLogNShift) |
        (static_cast<uint32_t>(r) << kScryptRShift) |
        (static_cast<uint32_t>(p) << kScryptPShift);
}

std::vector<unsigned char> DeriveKey(const std::string& password,
                                     const std::vector<unsigned char>& salt,
                                     uint32_t iterations) {
    if (UsesMemoryHardKdf(iterations)) {
        return DeriveScryptKey(password, salt, iterations);
    }
    return DerivePbkdf2Key(password, salt, iterations);
}

std::vector<unsigned char> DeriveAuthenticationKey(const std::string& password,
                                                   const std::vector<unsigned char>& salt,
                                                   uint32_t iterations) {
    std::vector<unsigned char> authSalt = salt;
    for (size_t index = 0; index < authSalt.size(); ++index) {
        authSalt[index] ^= static_cast<unsigned char>(0xC3u + static_cast<unsigned char>((index * 13u) & 0xFFu));
    }
    return DeriveKey(password, authSalt, iterations);
}

} // namespace winzox::crypto
