#include "compression/coder/range_coder.hpp"

#include <stdexcept>

namespace winzox::compression::coder {

CoderKind RangeEncoder::Kind() const {
    return CoderKind::Range;
}

std::vector<uint8_t> RangeEncoder::Encode(const std::vector<uint8_t>&,
                                          const EncodeOptions&) const {
    throw std::runtime_error("Range coder backend is scaffolded but not implemented yet");
}

CoderKind RangeDecoder::Kind() const {
    return CoderKind::Range;
}

std::vector<uint8_t> RangeDecoder::Decode(const std::vector<uint8_t>&,
                                          const DecodeOptions&) const {
    throw std::runtime_error("Range coder backend is scaffolded but not implemented yet");
}

} // namespace winzox::compression::coder

