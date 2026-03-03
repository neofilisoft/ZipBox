#pragma once

#include "crypto/aes256.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace zipbox::crypto {

std::vector<uint8_t> EncryptGorgon(const std::vector<uint8_t>& plainText,
                                   const std::string& password,
                                   const EncryptionMetadata& metadata);
std::vector<uint8_t> DecryptGorgon(const std::vector<uint8_t>& cipherText,
                                   const std::string& password,
                                   const EncryptionMetadata& metadata,
                                   uint64_t plainTextSize);

} // namespace zipbox::crypto
