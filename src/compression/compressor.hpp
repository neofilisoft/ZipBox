#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace winzox::compression {

enum class CompressionAlgorithm : uint8_t {
    Store = 0,
    Zstd = 1,
    Zlib = 2,
    Lz4 = 3,
    Lzma2 = 4,
};

CompressionAlgorithm ParseAlgorithmName(const std::string& value);
std::string AlgorithmName(CompressionAlgorithm algorithm);

std::vector<uint8_t> CompressBuffer(const std::vector<uint8_t>& data,
                                    CompressionAlgorithm algorithm,
                                    int zstdLevel,
                                    int zlibLevel,
                                    int lzmaLevel,
                                    uint32_t threadCount);
std::vector<uint8_t> DecompressBuffer(const std::vector<uint8_t>& data,
                                      CompressionAlgorithm algorithm,
                                      uint64_t expectedSize);

} // namespace winzox::compression
