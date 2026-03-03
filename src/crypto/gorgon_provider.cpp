#include "crypto/gorgon_provider.hpp"

#include "crypto/gorgon.hpp"

#include <stdexcept>
#include <openssl/rand.h>

namespace zipbox::crypto {

EncryptionAlgorithm GorgonProvider::Algorithm() const {
    return EncryptionAlgorithm::Gorgon;
}

const char* GorgonProvider::Name() const {
    return "gorgon";
}

EncryptionMetadata GorgonProvider::CreateMetadata() const {
    EncryptionMetadata metadata;
    metadata.salt.resize(16);
    metadata.ivPrimary.resize(16);
    metadata.ivSecondary.resize(16);

    if (RAND_bytes(metadata.salt.data(), static_cast<int>(metadata.salt.size())) != 1 ||
        RAND_bytes(metadata.ivPrimary.data(), static_cast<int>(metadata.ivPrimary.size())) != 1 ||
        RAND_bytes(metadata.ivSecondary.data(), static_cast<int>(metadata.ivSecondary.size())) != 1) {
        throw std::runtime_error("Failed to generate Gorgon encryption metadata");
    }

    return metadata;
}

std::vector<uint8_t> GorgonProvider::Encrypt(const std::vector<uint8_t>& plainText,
                                             const std::string& password,
                                             const EncryptionMetadata& metadata) const {
    if (password.empty()) {
        throw std::runtime_error("Password is required to encrypt this .zox archive");
    }
    return EncryptGorgon(plainText, password, metadata);
}

std::vector<uint8_t> GorgonProvider::Decrypt(const std::vector<uint8_t>& cipherText,
                                             const std::string& password,
                                             const EncryptionMetadata& metadata,
                                             uint64_t plainTextSize) const {
    if (password.empty()) {
        throw std::runtime_error("Password is required to open this .zox archive");
    }
    return DecryptGorgon(cipherText, password, metadata, plainTextSize);
}

const IEncryptionProvider& GetGorgonProvider() {
    static const GorgonProvider provider;
    return provider;
}

} // namespace zipbox::crypto
