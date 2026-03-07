#include "compression/coder/huffman.hpp"

#include "compression/coder/bit_reader.hpp"
#include "compression/coder/bit_writer.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <numeric>
#include <queue>
#include <stdexcept>
#include <utility>

namespace winzox::compression::coder {

namespace {

struct HuffmanNode {
    uint32_t frequency = 0;
    int symbol = -1;
    std::shared_ptr<HuffmanNode> left;
    std::shared_ptr<HuffmanNode> right;
};

struct QueueNode {
    uint32_t frequency = 0;
    std::shared_ptr<HuffmanNode> node;
};

struct QueueCompare {
    bool operator()(const QueueNode& lhs, const QueueNode& rhs) const {
        return lhs.frequency > rhs.frequency;
    }
};

struct Codeword {
    uint32_t bits = 0;
    uint8_t bitLength = 0;
};

std::shared_ptr<HuffmanNode> MakeLeaf(int symbol, uint32_t frequency) {
    auto node = std::make_shared<HuffmanNode>();
    node->symbol = symbol;
    node->frequency = frequency;
    return node;
}

std::shared_ptr<HuffmanNode> BuildTree(const std::array<uint32_t, 256>& frequencyTable) {
    std::priority_queue<QueueNode, std::vector<QueueNode>, QueueCompare> queue;
    for (size_t symbol = 0; symbol < frequencyTable.size(); ++symbol) {
        if (frequencyTable[symbol] == 0) {
            continue;
        }
        queue.push(QueueNode { frequencyTable[symbol], MakeLeaf(static_cast<int>(symbol), frequencyTable[symbol]) });
    }

    if (queue.empty()) {
        return {};
    }

    while (queue.size() > 1) {
        QueueNode first = queue.top();
        queue.pop();
        QueueNode second = queue.top();
        queue.pop();

        auto parent = std::make_shared<HuffmanNode>();
        parent->frequency = first.frequency + second.frequency;
        parent->left = std::move(first.node);
        parent->right = std::move(second.node);
        queue.push(QueueNode { parent->frequency, std::move(parent) });
    }

    QueueNode root = queue.top();
    queue.pop();
    return std::move(root.node);
}

void BuildCodeTable(const HuffmanNode* node,
                    uint32_t bits,
                    uint8_t bitLength,
                    std::array<Codeword, 256>& codeTable) {
    if (node == nullptr) {
        return;
    }

    if (node->symbol >= 0) {
        codeTable[static_cast<size_t>(node->symbol)] = Codeword { bits, static_cast<uint8_t>(std::max<uint8_t>(1, bitLength)) };
        return;
    }

    BuildCodeTable(node->left.get(), static_cast<uint32_t>(bits << 1), static_cast<uint8_t>(bitLength + 1), codeTable);
    BuildCodeTable(node->right.get(), static_cast<uint32_t>((bits << 1) | 1u), static_cast<uint8_t>(bitLength + 1), codeTable);
}

void AppendU32(std::vector<uint8_t>& output, uint32_t value) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
    output.insert(output.end(), bytes, bytes + sizeof(value));
}

uint32_t ReadU32(const std::vector<uint8_t>& input, size_t& offset) {
    if (offset + sizeof(uint32_t) > input.size()) {
        throw std::runtime_error("Huffman payload is truncated");
    }

    uint32_t value = 0;
    std::memcpy(&value, input.data() + offset, sizeof(value));
    offset += sizeof(value);
    return value;
}

} // namespace

CoderKind HuffmanEncoder::Kind() const {
    return CoderKind::Huffman;
}

std::vector<uint8_t> HuffmanEncoder::Encode(const std::vector<uint8_t>& input, const EncodeOptions&) const {
    std::vector<uint8_t> output;
    output.reserve(4 + 256 * sizeof(uint32_t) + input.size());
    output.insert(output.end(), { 'H', 'U', 'F', '0' });

    const auto frequencyTable = BuildHuffmanFrequencyTable(input);
    for (uint32_t frequency : frequencyTable) {
        AppendU32(output, frequency);
    }

    if (input.empty()) {
        return output;
    }

    const auto root = BuildTree(frequencyTable);
    std::array<Codeword, 256> codeTable {};
    BuildCodeTable(root.get(), 0, 0, codeTable);

    BitWriter writer;
    for (uint8_t value : input) {
        const Codeword code = codeTable[value];
        writer.WriteBits(code.bits, code.bitLength);
    }
    writer.AlignToByte(false);

    const std::vector<uint8_t> payload = writer.TakeBuffer();
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

CoderKind HuffmanDecoder::Kind() const {
    return CoderKind::Huffman;
}

std::vector<uint8_t> HuffmanDecoder::Decode(const std::vector<uint8_t>& input, const DecodeOptions& options) const {
    constexpr size_t kHeaderSize = 4 + 256 * sizeof(uint32_t);
    if (input.size() < kHeaderSize || std::memcmp(input.data(), "HUF0", 4) != 0) {
        throw std::runtime_error("Invalid Huffman payload header");
    }

    size_t offset = 4;
    std::array<uint32_t, 256> frequencyTable {};
    for (size_t index = 0; index < frequencyTable.size(); ++index) {
        frequencyTable[index] = ReadU32(input, offset);
    }

    const size_t expectedSize = options.expectedSize == 0
        ? std::accumulate(frequencyTable.begin(), frequencyTable.end(), static_cast<size_t>(0))
        : options.expectedSize;
    if (expectedSize == 0) {
        return {};
    }

    const auto root = BuildTree(frequencyTable);
    if (!root) {
        throw std::runtime_error("Huffman payload does not contain any symbols");
    }

    std::vector<uint8_t> payload(input.begin() + static_cast<std::ptrdiff_t>(offset), input.end());
    BitReader reader(payload);

    std::vector<uint8_t> output;
    output.reserve(expectedSize);
    while (output.size() < expectedSize) {
        const HuffmanNode* node = root.get();
        while (node->symbol < 0) {
            node = reader.ReadBit() ? node->right.get() : node->left.get();
            if (node == nullptr) {
                throw std::runtime_error("Huffman payload contains an invalid code");
            }
        }
        output.push_back(static_cast<uint8_t>(node->symbol));
    }

    return output;
}

std::array<uint32_t, 256> BuildHuffmanFrequencyTable(const std::vector<uint8_t>& input) {
    std::array<uint32_t, 256> frequencyTable {};
    for (uint8_t value : input) {
        ++frequencyTable[value];
    }
    return frequencyTable;
}

} // namespace winzox::compression::coder
