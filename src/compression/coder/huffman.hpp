#pragma once

#include "compression/coder/coder_interfaces.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace winzox::compression::coder {

class HuffmanEncoder final : public IEncoder {
public:
    [[nodiscard]] CoderKind Kind() const override;
    [[nodiscard]] std::vector<uint8_t> Encode(const std::vector<uint8_t>& input,
                                              const EncodeOptions& options = {}) const override;
};

class HuffmanDecoder final : public IDecoder {
public:
    [[nodiscard]] CoderKind Kind() const override;
    [[nodiscard]] std::vector<uint8_t> Decode(const std::vector<uint8_t>& input,
                                              const DecodeOptions& options = {}) const override;
};

std::array<uint32_t, 256> BuildHuffmanFrequencyTable(const std::vector<uint8_t>& input);

} // namespace winzox::compression::coder

