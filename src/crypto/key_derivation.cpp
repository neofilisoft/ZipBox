#include "crypto/key_derivation.hpp"

#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace winzox::crypto {

namespace {

std::vector<unsigned char> DeriveKeyInternal(const std::string& password,
                                             const std::vector<unsigned char>& salt,
                                             uint32_t iterations) {
    if (iterations == 0) {
        throw std::runtime_error("KDF iterations must be greater than zero");
    }

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

} // namespace

std::vector<unsigned char> DeriveKey(const std::string& password,
                                     const std::vector<unsigned char>& salt,
                                     uint32_t iterations) {
    return DeriveKeyInternal(password, salt, iterations);
}

std::vector<unsigned char> DeriveAuthenticationKey(const std::string& password,
                                                   const std::vector<unsigned char>& salt,
                                                   uint32_t iterations) {
    std::vector<unsigned char> authSalt = salt;
    for (size_t index = 0; index < authSalt.size(); ++index) {
        authSalt[index] ^= static_cast<unsigned char>(0xC3u + static_cast<unsigned char>((index * 13u) & 0xFFu));
    }
    return DeriveKeyInternal(password, authSalt, iterations);
}

} // namespace winzox::crypto
