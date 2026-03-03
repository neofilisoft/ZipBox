#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace zipbox::io {

std::vector<std::filesystem::path> CollectInputFiles(const std::filesystem::path& inputPath);
std::vector<uint8_t> ReadFileBytes(const std::filesystem::path& path);

} // namespace zipbox::io
