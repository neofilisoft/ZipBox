#include "compression/compressor.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <future>
#include <limits>
#include <stdexcept>
#include <thread>
#include <lz4.h>
#include <lzma.h>
#include <zlib.h>
#include <zstd.h>

namespace winzox::compression {

namespace {

uLong ToZlibSize(size_t size) {
    if (size > static_cast<size_t>(std::numeric_limits<uLong>::max())) {
        throw std::runtime_error("Data block is too large for zlib");
    }
    return static_cast<uLong>(size);
}

size_t ToSizeT(uint64_t value) {
    if (value > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        throw std::runtime_error("Data block is too large for this platform");
    }
    return static_cast<size_t>(value);
}

uint32_t ResolveThreadCount(uint32_t requestedThreads) {
    if (requestedThreads > 0) {
        return requestedThreads;
    }

    const unsigned int hardwareThreads = std::thread::hardware_concurrency();
    return hardwareThreads == 0 ? 1u : hardwareThreads;
}

void AppendU32(std::vector<uint8_t>& output, uint32_t value) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
    output.insert(output.end(), bytes, bytes + sizeof(value));
}

uint32_t ReadU32(const std::vector<uint8_t>& input, size_t& offset) {
    if (offset + sizeof(uint32_t) > input.size()) {
        throw std::runtime_error("LZ4 payload metadata is truncated");
    }

    uint32_t value = 0;
    std::memcpy(&value, input.data() + offset, sizeof(value));
    offset += sizeof(value);
    return value;
}

std::vector<uint8_t> CompressLz4MultiThreaded(const std::vector<uint8_t>& data, uint32_t requestedThreads) {
    if (data.empty()) {
        return {};
    }

    constexpr size_t kChunkSize = 1u << 20;
    const size_t chunkCount = (data.size() + kChunkSize - 1) / kChunkSize;
    if (chunkCount > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        throw std::runtime_error("LZ4 chunk count exceeds format limit");
    }

    struct ChunkResult {
        uint32_t originalSize = 0;
        std::vector<uint8_t> compressed;
    };

    std::vector<ChunkResult> chunks(chunkCount);
    const size_t maxWorkers = std::max<size_t>(1, ResolveThreadCount(requestedThreads));

    size_t nextChunk = 0;
    while (nextChunk < chunkCount) {
        const size_t workers = std::min(maxWorkers, chunkCount - nextChunk);
        std::vector<std::future<void>> jobs;
        jobs.reserve(workers);

        for (size_t worker = 0; worker < workers; ++worker) {
            const size_t chunkIndex = nextChunk++;
            jobs.push_back(std::async(std::launch::async, [&, chunkIndex]() {
                const size_t offset = chunkIndex * kChunkSize;
                const size_t remaining = data.size() - offset;
                const size_t chunkSize = std::min(kChunkSize, remaining);
                const int sourceSize = static_cast<int>(chunkSize);
                const int bound = LZ4_compressBound(sourceSize);
                if (bound <= 0) {
                    throw std::runtime_error("Failed to compute LZ4 compression bound");
                }

                std::vector<uint8_t> compressed(static_cast<size_t>(bound));
                const int written = LZ4_compress_default(
                    reinterpret_cast<const char*>(data.data() + offset),
                    reinterpret_cast<char*>(compressed.data()),
                    sourceSize,
                    bound);
                if (written <= 0) {
                    throw std::runtime_error("LZ4 compression failed");
                }

                compressed.resize(static_cast<size_t>(written));
                chunks[chunkIndex].originalSize = static_cast<uint32_t>(chunkSize);
                chunks[chunkIndex].compressed = std::move(compressed);
            }));
        }

        for (auto& job : jobs) {
            job.get();
        }
    }

    std::vector<uint8_t> output;
    output.reserve(data.size() / 2);
    output.insert(output.end(), {'L', '4', 'M', 'T'});
    AppendU32(output, static_cast<uint32_t>(chunkCount));
    for (const ChunkResult& chunk : chunks) {
        AppendU32(output, chunk.originalSize);
        AppendU32(output, static_cast<uint32_t>(chunk.compressed.size()));
    }
    for (const ChunkResult& chunk : chunks) {
        output.insert(output.end(), chunk.compressed.begin(), chunk.compressed.end());
    }
    return output;
}

std::vector<uint8_t> DecompressLz4MultiThreaded(const std::vector<uint8_t>& data,
                                                uint64_t expectedSize,
                                                uint32_t requestedThreads) {
    if (data.size() < 8 || std::memcmp(data.data(), "L4MT", 4) != 0) {
        throw std::runtime_error("Invalid LZ4 payload header");
    }

    size_t offset = 4;
    const uint32_t chunkCount = ReadU32(data, offset);

    struct ChunkDescriptor {
        uint32_t originalSize = 0;
        uint32_t compressedSize = 0;
        size_t compressedOffset = 0;
    };

    std::vector<ChunkDescriptor> descriptors(chunkCount);
    uint64_t totalOriginalSize = 0;
    for (uint32_t index = 0; index < chunkCount; ++index) {
        descriptors[index].originalSize = ReadU32(data, offset);
        descriptors[index].compressedSize = ReadU32(data, offset);
        totalOriginalSize += descriptors[index].originalSize;
    }

    if (totalOriginalSize != expectedSize) {
        throw std::runtime_error("LZ4 payload size does not match expected output size");
    }

    size_t payloadOffset = offset;
    for (uint32_t index = 0; index < chunkCount; ++index) {
        const uint32_t compressedSize = descriptors[index].compressedSize;
        if (payloadOffset + compressedSize > data.size()) {
            throw std::runtime_error("LZ4 payload is truncated");
        }
        descriptors[index].compressedOffset = payloadOffset;
        payloadOffset += compressedSize;
    }

    if (payloadOffset != data.size()) {
        throw std::runtime_error("LZ4 payload contains unexpected trailing data");
    }

    std::vector<std::vector<uint8_t>> plainChunks(chunkCount);
    const size_t maxWorkers = std::max<size_t>(1, ResolveThreadCount(requestedThreads));
    size_t nextChunk = 0;
    while (nextChunk < chunkCount) {
        const size_t workers = std::min(maxWorkers, static_cast<size_t>(chunkCount - nextChunk));
        std::vector<std::future<void>> jobs;
        jobs.reserve(workers);

        for (size_t worker = 0; worker < workers; ++worker) {
            const uint32_t chunkIndex = static_cast<uint32_t>(nextChunk++);
            jobs.push_back(std::async(std::launch::async, [&, chunkIndex]() {
                const ChunkDescriptor& descriptor = descriptors[chunkIndex];
                std::vector<uint8_t> plain(descriptor.originalSize);
                const int decoded = LZ4_decompress_safe(
                    reinterpret_cast<const char*>(data.data() + descriptor.compressedOffset),
                    reinterpret_cast<char*>(plain.data()),
                    static_cast<int>(descriptor.compressedSize),
                    static_cast<int>(descriptor.originalSize));
                if (decoded != static_cast<int>(descriptor.originalSize)) {
                    throw std::runtime_error("Failed to decompress an LZ4 chunk");
                }
                plainChunks[chunkIndex] = std::move(plain);
            }));
        }

        for (auto& job : jobs) {
            job.get();
        }
    }

    std::vector<uint8_t> output;
    output.reserve(ToSizeT(expectedSize));
    for (auto& chunk : plainChunks) {
        output.insert(output.end(), chunk.begin(), chunk.end());
    }
    return output;
}

std::vector<uint8_t> CompressLzma2MultiThreaded(const std::vector<uint8_t>& data,
                                                int lzmaLevel,
                                                uint32_t requestedThreads) {
    if (data.empty()) {
        return {};
    }
    if (lzmaLevel < 0 || lzmaLevel > 9) {
        throw std::runtime_error("LZMA2 level must be between 0 and 9");
    }

    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_mt multithreadConfig {};
    multithreadConfig.threads = ResolveThreadCount(requestedThreads);
    multithreadConfig.block_size = 0;
    multithreadConfig.timeout = 0;
    multithreadConfig.preset = static_cast<uint32_t>(lzmaLevel);
    multithreadConfig.check = LZMA_CHECK_CRC64;

    lzma_ret result = lzma_stream_encoder_mt(&stream, &multithreadConfig);
    if (result != LZMA_OK) {
        result = lzma_easy_encoder(&stream, static_cast<uint32_t>(lzmaLevel), LZMA_CHECK_CRC64);
    }
    if (result != LZMA_OK) {
        throw std::runtime_error("Failed to initialize LZMA2 encoder");
    }

    stream.next_in = data.data();
    stream.avail_in = data.size();

    std::vector<uint8_t> output(64 * 1024);
    while (true) {
        if (stream.total_out == output.size()) {
            output.resize(output.size() * 2);
        }

        stream.next_out = output.data() + stream.total_out;
        stream.avail_out = output.size() - stream.total_out;
        result = lzma_code(&stream, LZMA_FINISH);
        if (result == LZMA_STREAM_END) {
            break;
        }
        if (result != LZMA_OK) {
            lzma_end(&stream);
            throw std::runtime_error("LZMA2 compression failed");
        }
    }

    output.resize(stream.total_out);
    lzma_end(&stream);
    return output;
}

std::vector<uint8_t> DecompressLzma2(const std::vector<uint8_t>& data, uint64_t expectedSize) {
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_ret result = lzma_stream_decoder(&stream, UINT64_MAX, 0);
    if (result != LZMA_OK) {
        throw std::runtime_error("Failed to initialize LZMA2 decoder");
    }

    std::vector<uint8_t> output(ToSizeT(expectedSize));
    stream.next_in = data.data();
    stream.avail_in = data.size();
    stream.next_out = output.data();
    stream.avail_out = output.size();

    while (true) {
        result = lzma_code(&stream, LZMA_FINISH);
        if (result == LZMA_STREAM_END) {
            break;
        }
        if (result != LZMA_OK) {
            lzma_end(&stream);
            throw std::runtime_error("Failed to decompress an LZMA2 entry");
        }
        if (stream.avail_out == 0 && result == LZMA_OK) {
            lzma_end(&stream);
            throw std::runtime_error("LZMA2 output is larger than expected size");
        }
    }

    if (stream.total_out != output.size()) {
        lzma_end(&stream);
        throw std::runtime_error("LZMA2 output size does not match expected size");
    }

    lzma_end(&stream);
    return output;
}

} // namespace

CompressionAlgorithm ParseAlgorithmName(const std::string& value) {
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    if (lower == "store" || lower == "none") {
        return CompressionAlgorithm::Store;
    }
    if (lower == "zstd") {
        return CompressionAlgorithm::Zstd;
    }
    if (lower == "zlib") {
        return CompressionAlgorithm::Zlib;
    }
    if (lower == "lz4") {
        return CompressionAlgorithm::Lz4;
    }
    if (lower == "lzma2" || lower == "lzma") {
        return CompressionAlgorithm::Lzma2;
    }

    throw std::runtime_error("Unsupported compression algorithm: " + value);
}

std::string AlgorithmName(CompressionAlgorithm algorithm) {
    switch (algorithm) {
    case CompressionAlgorithm::Store:
        return "store";
    case CompressionAlgorithm::Zstd:
        return "zstd";
    case CompressionAlgorithm::Zlib:
        return "zlib";
    case CompressionAlgorithm::Lz4:
        return "lz4";
    case CompressionAlgorithm::Lzma2:
        return "lzma2";
    }

    throw std::runtime_error("Unknown compression algorithm id");
}

std::vector<uint8_t> CompressBuffer(const std::vector<uint8_t>& data,
                                    CompressionAlgorithm algorithm,
                                    int zstdLevel,
                                    int zlibLevel,
                                    int lzmaLevel,
                                    uint32_t threadCount) {
    switch (algorithm) {
    case CompressionAlgorithm::Store:
        return data;

    case CompressionAlgorithm::Zstd: {
        if (data.empty()) {
            return {};
        }

        const size_t bound = ZSTD_compressBound(data.size());
        std::vector<uint8_t> compressed(bound);
        const size_t written = ZSTD_compress(compressed.data(), compressed.size(), data.data(), data.size(), zstdLevel);
        if (ZSTD_isError(written) != 0) {
            throw std::runtime_error(std::string("Zstd compression failed: ") + ZSTD_getErrorName(written));
        }

        compressed.resize(written);
        return compressed;
    }

    case CompressionAlgorithm::Zlib: {
        if (zlibLevel < 0 || zlibLevel > 9) {
            throw std::runtime_error("Zlib level must be between 0 and 9");
        }

        if (data.empty()) {
            return {};
        }

        const uLong sourceLen = ToZlibSize(data.size());
        uLongf destLen = compressBound(sourceLen);
        std::vector<uint8_t> compressed(destLen);

        if (compress2(compressed.data(), &destLen, data.data(), sourceLen, zlibLevel) != Z_OK) {
            throw std::runtime_error("Zlib compression failed");
        }

        compressed.resize(destLen);
        return compressed;
    }

    case CompressionAlgorithm::Lz4:
        return CompressLz4MultiThreaded(data, threadCount);

    case CompressionAlgorithm::Lzma2:
        return CompressLzma2MultiThreaded(data, lzmaLevel, threadCount);
    }

    throw std::runtime_error("Unsupported compression algorithm");
}

std::vector<uint8_t> DecompressBuffer(const std::vector<uint8_t>& data,
                                      CompressionAlgorithm algorithm,
                                      uint64_t expectedSize) {
    if (expectedSize == 0) {
        if (!data.empty() && algorithm != CompressionAlgorithm::Store) {
            throw std::runtime_error("Archive stores unexpected payload for an empty file");
        }
        return {};
    }

    switch (algorithm) {
    case CompressionAlgorithm::Store:
        if (data.size() != ToSizeT(expectedSize)) {
            throw std::runtime_error("Stored entry size does not match expected size");
        }
        return data;

    case CompressionAlgorithm::Zstd: {
        std::vector<uint8_t> plain(ToSizeT(expectedSize));
        const size_t written = ZSTD_decompress(plain.data(), plain.size(), data.data(), data.size());
        if (ZSTD_isError(written) != 0 || written != plain.size()) {
            throw std::runtime_error("Failed to decompress a Zstd entry");
        }
        return plain;
    }

    case CompressionAlgorithm::Zlib: {
        std::vector<uint8_t> plain(ToSizeT(expectedSize));
        uLongf outputSize = static_cast<uLongf>(plain.size());
        const int result = uncompress(plain.data(), &outputSize, data.data(), ToZlibSize(data.size()));
        if (result != Z_OK || outputSize != plain.size()) {
            throw std::runtime_error("Failed to decompress a zlib entry");
        }
        return plain;
    }

    case CompressionAlgorithm::Lz4:
        return DecompressLz4MultiThreaded(data, expectedSize, 0);

    case CompressionAlgorithm::Lzma2:
        return DecompressLzma2(data, expectedSize);
    }

    throw std::runtime_error("Unsupported compression algorithm");
}

} // namespace winzox::compression
