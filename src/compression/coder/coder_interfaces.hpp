#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace winzox::compression::coder {

enum class CoderKind : uint8_t {
    Raw = 0,
    Huffman = 1,
    Range = 2,
};

struct EncodeOptions {
    size_t dictionarySize = 0;
};

struct DecodeOptions {
    size_t expectedSize = 0;
    size_t dictionarySize = 0;
};

class IEncoder {
public:
    virtual ~IEncoder() = default;
    [[nodiscard]] virtual CoderKind Kind() const = 0;
    [[nodiscard]] virtual std::vector<uint8_t> Encode(const std::vector<uint8_t>& input,
                                                      const EncodeOptions& options = {}) const = 0;
};

class IDecoder {
public:
    virtual ~IDecoder() = default;
    [[nodiscard]] virtual CoderKind Kind() const = 0;
    [[nodiscard]] virtual std::vector<uint8_t> Decode(const std::vector<uint8_t>& input,
                                                      const DecodeOptions& options = {}) const = 0;
};

} // namespace winzox::compression::coder

