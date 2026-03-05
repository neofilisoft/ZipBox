#pragma once

#include "crypto/aes256.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace winzox::crypto {

class IEncryptionProvider {
public:
    virtual ~IEncryptionProvider() = default;

    virtual EncryptionAlgorithm Algorithm() const = 0;
    virtual const char* Name() const = 0;
    virtual EncryptionMetadata CreateMetadata() const = 0;
    virtual std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plainText,
                                         const std::string& password,
                                         const EncryptionMetadata& metadata) const = 0;
    virtual std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& cipherText,
                                         const std::string& password,
                                         const EncryptionMetadata& metadata,
                                         uint64_t plainTextSize) const = 0;
};

const IEncryptionProvider& GetEncryptionProvider(EncryptionAlgorithm algorithm);

} // namespace winzox::crypto
