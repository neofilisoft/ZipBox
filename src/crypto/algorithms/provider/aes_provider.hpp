#pragma once

#include "crypto/encryption_provider.hpp"

namespace winzox::crypto {

class AesProvider final : public IEncryptionProvider {
public:
    EncryptionAlgorithm Algorithm() const override;
    const char* Name() const override;
    EncryptionMetadata CreateMetadata() const override;
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plainText,
                                 const std::string& password,
                                 const EncryptionMetadata& metadata) const override;
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& cipherText,
                                 const std::string& password,
                                 const EncryptionMetadata& metadata,
                                 uint64_t plainTextSize) const override;
};

const IEncryptionProvider& GetAesProvider();

} // namespace winzox::crypto
