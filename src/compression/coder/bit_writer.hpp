#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace winzox::compression::coder {

class BitWriter {
public:
    void WriteBit(bool bit);
    void WriteBits(uint32_t value, uint8_t bitCount);
    void WriteByte(uint8_t value);
    void WriteBytes(const std::vector<uint8_t>& bytes);
    void AlignToByte(bool fillBit = false);
    [[nodiscard]] size_t BitSize() const;
    [[nodiscard]] const std::vector<uint8_t>& Buffer() const;
    [[nodiscard]] std::vector<uint8_t> TakeBuffer();

private:
    void FlushCurrentByte();

    std::vector<uint8_t> buffer_;
    uint8_t currentByte_ = 0;
    uint8_t bitsUsed_ = 0;
};

inline void BitWriter::WriteBit(bool bit) {
    currentByte_ = static_cast<uint8_t>((currentByte_ << 1) | (bit ? 1u : 0u));
    ++bitsUsed_;
    if (bitsUsed_ == 8) {
        FlushCurrentByte();
    }
}

inline void BitWriter::WriteBits(uint32_t value, uint8_t bitCount) {
    for (int bitIndex = bitCount - 1; bitIndex >= 0; --bitIndex) {
        WriteBit(((value >> bitIndex) & 1u) != 0);
    }
}

inline void BitWriter::WriteByte(uint8_t value) {
    if (bitsUsed_ == 0) {
        buffer_.push_back(value);
        return;
    }

    WriteBits(value, 8);
}

inline void BitWriter::WriteBytes(const std::vector<uint8_t>& bytes) {
    for (uint8_t value : bytes) {
        WriteByte(value);
    }
}

inline void BitWriter::AlignToByte(bool fillBit) {
    while (bitsUsed_ != 0) {
        WriteBit(fillBit);
    }
}

inline size_t BitWriter::BitSize() const {
    return buffer_.size() * 8u + bitsUsed_;
}

inline const std::vector<uint8_t>& BitWriter::Buffer() const {
    return buffer_;
}

inline std::vector<uint8_t> BitWriter::TakeBuffer() {
    AlignToByte(false);
    return std::move(buffer_);
}

inline void BitWriter::FlushCurrentByte() {
    if (bitsUsed_ == 0) {
        return;
    }

    if (bitsUsed_ < 8) {
        currentByte_ = static_cast<uint8_t>(currentByte_ << (8 - bitsUsed_));
    }

    buffer_.push_back(currentByte_);
    currentByte_ = 0;
    bitsUsed_ = 0;
}

} // namespace winzox::compression::coder

