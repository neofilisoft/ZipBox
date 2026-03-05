#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace winzox::crypto {

constexpr uint32_t kLegacyKdfIterations = 10000;
constexpr uint32_t kMinKdfIterations = 100000;
constexpr uint32_t kDefaultKdfIterations = 150000;

std::vector<unsigned char> DeriveKey(const std::string& password,
                                     const std::vector<unsigned char>& salt,
                                     uint32_t iterations);
std::vector<unsigned char> DeriveAuthenticationKey(const std::string& password,
                                                   const std::vector<unsigned char>& salt,
                                                   uint32_t iterations);

} // namespace winzox::crypto
