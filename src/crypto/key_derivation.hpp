#pragma once

#include <string>
#include <vector>

namespace zipbox::crypto {

std::vector<unsigned char> DeriveKey(const std::string& password, const std::vector<unsigned char>& salt);

} // namespace zipbox::crypto
