#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace winzox::crypto {

enum class EncryptionAlgorithm : uint8_t {
    None = 0,
    Aes256 = 1,
    Gorgon = 2,
};

struct EncryptionMetadata {
    std::vector<unsigned char> salt;
    std::vector<unsigned char> ivPrimary;
    std::vector<unsigned char> ivSecondary;
    uint32_t iterations = 100000;
};

EncryptionAlgorithm ParseEncryptionAlgorithmName(const std::string& value);
std::string EncryptionAlgorithmName(EncryptionAlgorithm algorithm);

EncryptionMetadata CreateEncryptionMetadata(EncryptionAlgorithm algorithm);
std::vector<uint8_t> EncryptPayload(const std::vector<uint8_t>& plainText,
                                    const std::string& password,
                                    const EncryptionMetadata& metadata,
                                    EncryptionAlgorithm algorithm);
std::vector<uint8_t> DecryptPayload(const std::vector<uint8_t>& cipherText,
                                    const std::string& password,
                                    const EncryptionMetadata& metadata,
                                    EncryptionAlgorithm algorithm,
                                    uint64_t plainTextSize);

} // namespace winzox::crypto
