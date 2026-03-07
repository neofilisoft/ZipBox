#pragma once

#include "compression/coder/coder_interfaces.hpp"

#include <vector>

namespace winzox::compression::coder {

class RangeEncoder final : public IEncoder {
public:
    [[nodiscard]] CoderKind Kind() const override;
    [[nodiscard]] std::vector<uint8_t> Encode(const std::vector<uint8_t>& input,
                                              const EncodeOptions& options = {}) const override;
};

class RangeDecoder final : public IDecoder {
public:
    [[nodiscard]] CoderKind Kind() const override;
    [[nodiscard]] std::vector<uint8_t> Decode(const std::vector<uint8_t>& input,
                                              const DecodeOptions& options = {}) const override;
};

} // namespace winzox::compression::coder

