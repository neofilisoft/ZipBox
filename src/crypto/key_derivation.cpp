#include "crypto/key_derivation.hpp"

#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace zipbox::crypto {

std::vector<unsigned char> DeriveKey(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(32);
    if (PKCS5_PBKDF2_HMAC(password.c_str(),
                         static_cast<int>(password.length()),
                         salt.data(),
                         static_cast<int>(salt.size()),
                         10000,
                         EVP_sha256(),
                         static_cast<int>(key.size()),
                         key.data()) != 1) {
        throw std::runtime_error("Failed to derive encryption key");
    }

    return key;
}

} // namespace zipbox::crypto
