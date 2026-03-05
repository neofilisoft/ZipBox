#pragma once

#include "compression/compressor.hpp"
#include "crypto/aes256.hpp"
#include "utils/progress.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace winzox::archive {

struct FileCompressionOverride {
    std::string relativePath;
    compression::CompressionAlgorithm algorithm = compression::CompressionAlgorithm::Zstd;
};

struct WinZOXConfig {
    std::string password;
    crypto::EncryptionAlgorithm encryptionAlgorithm = crypto::EncryptionAlgorithm::Aes256;
    size_t splitSize = 0;
    int zstdLevel = 9;
    int zlibLevel = 9;
    int lzmaLevel = 6;
    uint32_t threadCount = 0;
    compression::CompressionAlgorithm defaultAlgorithm = compression::CompressionAlgorithm::Zstd;
    bool solidMode = true;
    std::string comment;
    std::vector<FileCompressionOverride> fileOverrides;
};

struct ArchiveMetadata {
    bool encrypted = false;
    bool solid = false;
    bool authenticated = false;
    bool integritySha512 = false;
    bool integritySha3_256 = false;
    crypto::EncryptionAlgorithm encryptionAlgorithm = crypto::EncryptionAlgorithm::None;
    compression::CompressionAlgorithm defaultAlgorithm = compression::CompressionAlgorithm::Zstd;
    uint64_t createdUnixTime = 0;
    uint32_t payloadChecksum = 0;
    std::string comment;
};

struct ArchiveEntryInfo {
    std::string path;
    compression::CompressionAlgorithm algorithm = compression::CompressionAlgorithm::Store;
    uint64_t originalSize = 0;
    uint64_t storedSize = 0;
    uint64_t encodedSize = 0;
    uint32_t crc32 = 0;
};

struct ArchiveEntryData {
    ArchiveEntryInfo info;
    std::vector<uint8_t> storedData;
};

struct ArchiveContents {
    ArchiveMetadata metadata;
    std::vector<ArchiveEntryData> entries;
};

void CreateArchive(const std::string& inputPath,
                   const std::string& outputBase,
                   const WinZOXConfig& config,
                   const utils::ProgressCallback& progressCallback = {});
void CreateArchive(const std::vector<std::string>& inputPaths,
                   const std::string& outputBase,
                   const WinZOXConfig& config,
                   const utils::ProgressCallback& progressCallback = {});
void CreateZipArchive(const std::string& inputPath,
                      const std::string& outputPath,
                      const WinZOXConfig& config,
                      const utils::ProgressCallback& progressCallback = {});
void CreateZipArchive(const std::vector<std::string>& inputPaths,
                      const std::string& outputPath,
                      const WinZOXConfig& config,
                      const utils::ProgressCallback& progressCallback = {});
ArchiveMetadata ReadArchiveMetadata(const std::string& filename);
std::vector<ArchiveEntryInfo> ReadArchiveIndex(const std::string& filename, const std::string& password = "");
ArchiveContents ReadArchive(const std::string& filename, const std::string& password = "");
bool LooksLikeZoxArchive(const std::string& filename);

} // namespace winzox::archive
