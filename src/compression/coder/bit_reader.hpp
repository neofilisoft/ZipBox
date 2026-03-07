#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace winzox::compression::coder {

class BitReader {
public:
    explicit BitReader(const std::vector<uint8_t>& buffer) : buffer_(buffer) {}

    [[nodiscard]] bool ReadBit();
    [[nodiscard]] uint32_t ReadBits(uint8_t bitCount);
    [[nodiscard]] uint8_t ReadByte();
    void AlignToByte();
    [[nodiscard]] size_t BitsRemaining() const;

private:
    const std::vector<uint8_t>& buffer_;
    size_t byteOffset_ = 0;
    uint8_t bitOffset_ = 0;
};

inline bool BitReader::ReadBit() {
    if (byteOffset_ >= buffer_.size()) {
        throw std::runtime_error("Bit stream is truncated");
    }

    const uint8_t value = buffer_[byteOffset_];
    const bool bit = ((value >> (7 - bitOffset_)) & 1u) != 0;
    ++bitOffset_;
    if (bitOffset_ == 8) {
        bitOffset_ = 0;
        ++byteOffset_;
    }
    return bit;
}

inline uint32_t BitReader::ReadBits(uint8_t bitCount) {
    uint32_t value = 0;
    for (uint8_t index = 0; index < bitCount; ++index) {
        value = static_cast<uint32_t>((value << 1) | (ReadBit() ? 1u : 0u));
    }
    return value;
}

inline uint8_t BitReader::ReadByte() {
    return static_cast<uint8_t>(ReadBits(8));
}

inline void BitReader::AlignToByte() {
    if (bitOffset_ == 0) {
        return;
    }

    bitOffset_ = 0;
    ++byteOffset_;
}

inline size_t BitReader::BitsRemaining() const {
    return (buffer_.size() - byteOffset_) * 8u - bitOffset_;
}

} // namespace winzox::compression::coder
