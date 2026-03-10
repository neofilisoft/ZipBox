#include "archive/archive.hpp"
#include "archive/archive_integrity.hpp"

#include "crypto/aes256.hpp"
#include "crypto/auth/archive_authentication.hpp"
#include "crypto/key_derivation.hpp"
#include "io/file_reader.hpp"
#include "io/volume_reader.hpp"
#include "io/volume_writer.hpp"
#include "utils/checksum.hpp"
#include "utils/path_utils.hpp"

#include <archive.h>
#include <archive_entry.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <stdexcept>
#include <unordered_map>

namespace winzox::archive {

namespace fs = std::filesystem;

namespace {

constexpr char kLegacyMagic[] = "ZOX4";
constexpr char kPreviousMagicV5[] = "ZOX5";
constexpr char kPreviousMagicV6[] = "ZOX6";
constexpr char kCurrentMagic[] = "WZOX";
constexpr char kFooterMagic[] = "ZCDR";
constexpr uint8_t kEncryptedFlag = 0x01;
constexpr uint8_t kSolidFlag = 0x02;
constexpr uint8_t kAuthenticatedFlag = 0x04;
constexpr size_t kAuthenticationTagSize = 32;

struct LegacyHeader {
    ArchiveMetadata metadata;
    crypto::EncryptionMetadata cryptoMetadata;
    uint64_t plainPayloadSize = 0;
    uint64_t payloadSize = 0;
    size_t payloadOffset = 0;
};

struct CurrentHeader {
    ArchiveMetadata metadata;
    crypto::EncryptionMetadata cryptoMetadata;
    uint64_t dataSectionPlainSize = 0;
    size_t dataOffset = 0;
    bool usesExtendedFooter = false;
    bool hasIterationField = false;
};

struct DirectoryIndex {
    std::vector<ArchiveEntryInfo> entries;
    std::vector<uint64_t> dataOffsets;
    std::vector<uint64_t> encodedSizes;
    bool bulkEncryptedDataSection = false;
    bool solidArchive = false;
};

struct DirectoryFooter {
    uint64_t centralDirectoryOffset = 0;
    uint64_t centralDirectoryStoredSize = 0;
    uint64_t centralDirectoryPlainSize = 0;
    uint32_t centralDirectoryChecksum = 0;
    uint32_t entryCount = 0;
    std::vector<uint8_t> sha512Digest;
    std::vector<uint8_t> sha3_256Digest;
    std::vector<uint8_t> authenticationTag;
};

struct BuiltArchiveSections {
    std::vector<uint8_t> dataSection;
    std::vector<uint8_t> centralDirectory;
    uint64_t dataSectionPlainSize = 0;
    bool solidArchive = false;
};

template <typename T>
void AppendValue(std::vector<uint8_t>& buffer, T value) {
    const uint8_t* raw = reinterpret_cast<const uint8_t*>(&value);
    buffer.insert(buffer.end(), raw, raw + sizeof(T));
}

void AppendBytes(std::vector<uint8_t>& buffer, const void* data, size_t size) {
    const uint8_t* raw = static_cast<const uint8_t*>(data);
    buffer.insert(buffer.end(), raw, raw + size);
}

template <typename T>
T ReadValue(const std::vector<uint8_t>& data, size_t& offset) {
    if (offset + sizeof(T) > data.size()) {
        throw std::runtime_error("Archive is truncated");
    }

    T value {};
    std::memcpy(&value, data.data() + offset, sizeof(T));
    offset += sizeof(T);
    return value;
}

std::string ReadString(const std::vector<uint8_t>& data, size_t& offset, size_t length) {
    if (offset + length > data.size()) {
        throw std::runtime_error("Archive string field is truncated");
    }

    std::string value(reinterpret_cast<const char*>(data.data() + offset), length);
    offset += length;
    return value;
}

std::vector<uint8_t> ReadBytes(const std::vector<uint8_t>& data, size_t& offset, size_t length) {
    if (offset + length > data.size()) {
        throw std::runtime_error("Archive data field is truncated");
    }

    std::vector<uint8_t> value(length);
    if (length > 0) {
        std::memcpy(value.data(), data.data() + offset, length);
    }
    offset += length;
    return value;
}

size_t ToSizeT(uint64_t value, const char* label) {
    if (value > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        throw std::runtime_error(std::string(label) + " is too large for this platform");
    }
    return static_cast<size_t>(value);
}

std::vector<uint8_t> ComputeAuthenticationTag(const uint8_t* data,
                                              size_t dataSize,
                                              const std::string& password,
                                              const crypto::EncryptionMetadata& metadata) {
    return crypto::auth::ComputeArchiveAuthenticationTag(
        data,
        dataSize,
        password,
        metadata.salt,
        metadata.iterations);
}

bool AuthenticationTagsMatch(const std::vector<uint8_t>& expected, const std::vector<uint8_t>& actual) {
    if (expected.size() != actual.size()) {
        return false;
    }
    if (expected.empty()) {
        return true;
    }
    return integrity::DigestsEqual(expected.data(), actual.data(), expected.size());
}

uint64_t CurrentUnixTime() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

uint64_t CalculateTotalFileSize(const std::vector<fs::path>& files) {
    uint64_t totalSize = 0;
    for (const fs::path& filePath : files) {
        const uint64_t fileSize = fs::file_size(filePath);
        if (totalSize > (std::numeric_limits<uint64_t>::max)() - fileSize) {
            throw std::runtime_error("Total input size is too large");
        }
        totalSize += fileSize;
    }
    return totalSize;
}

void ReportProgress(const utils::ProgressCallback& progressCallback,
                    uint64_t completedUnits,
                    uint64_t totalUnits,
                    const std::string& currentItem,
                    const std::string& statusText) {
    if (!progressCallback) {
        return;
    }

    if (!progressCallback(utils::ProgressInfo { completedUnits, totalUnits, currentItem, statusText })) {
        throw std::runtime_error("Operation canceled");
    }
}

compression::CompressionAlgorithm ResolveAlgorithmForPath(
    const std::string& relativePath,
    compression::CompressionAlgorithm defaultAlgorithm,
    const std::unordered_map<std::string, compression::CompressionAlgorithm>& overrides) {
    const auto it = overrides.find(relativePath);
    if (it != overrides.end()) {
        return it->second;
    }
    return defaultAlgorithm;
}

std::unordered_map<std::string, compression::CompressionAlgorithm> BuildOverrideMap(
    const std::vector<FileCompressionOverride>& overrides) {
    std::unordered_map<std::string, compression::CompressionAlgorithm> map;
    for (const FileCompressionOverride& item : overrides) {
        map[item.relativePath] = item.algorithm;
    }
    return map;
}

std::vector<fs::path> NormalizeInputPaths(const std::vector<std::string>& inputPaths) {
    if (inputPaths.empty()) {
        throw std::runtime_error("No input paths were provided");
    }

    std::vector<fs::path> normalized;
    normalized.reserve(inputPaths.size());
    for (const std::string& inputPath : inputPaths) {
        normalized.push_back(fs::u8path(inputPath));
    }
    return normalized;
}

std::vector<fs::path> CollectFilesFromInputs(const std::vector<fs::path>& inputPaths) {
    std::vector<fs::path> files;
    for (const fs::path& inputPath : inputPaths) {
        std::vector<fs::path> currentFiles = io::CollectInputFiles(inputPath);
        files.insert(files.end(), currentFiles.begin(), currentFiles.end());
    }

    std::sort(files.begin(), files.end());
    files.erase(std::unique(files.begin(), files.end()), files.end());
    return files;
}

fs::path CommonBaseRoot(const std::vector<fs::path>& inputPaths) {
    std::vector<fs::path> parentPaths;
    parentPaths.reserve(inputPaths.size());
    for (const fs::path& inputPath : inputPaths) {
        fs::path parentPath = inputPath.parent_path();
        if (parentPath.empty()) {
            parentPath = ".";
        }
        parentPaths.push_back(fs::absolute(parentPath).lexically_normal());
    }

    std::vector<fs::path> sharedParts(parentPaths.front().begin(), parentPaths.front().end());
    for (size_t index = 1; index < parentPaths.size() && !sharedParts.empty(); ++index) {
        const std::vector<fs::path> currentParts(parentPaths[index].begin(), parentPaths[index].end());
        size_t sharedCount = 0;
        while (sharedCount < sharedParts.size() &&
               sharedCount < currentParts.size() &&
               sharedParts[sharedCount] == currentParts[sharedCount]) {
            ++sharedCount;
        }
        sharedParts.resize(sharedCount);
    }

    if (sharedParts.empty()) {
        return fs::current_path();
    }

    fs::path baseRoot;
    for (const fs::path& part : sharedParts) {
        baseRoot /= part;
    }

    if (baseRoot.empty()) {
        return fs::current_path();
    }

    return baseRoot.lexically_normal();
}

crypto::EncryptionMetadata ReadEncryptionMetadata(const std::vector<uint8_t>& raw,
                                                 size_t& offset,
                                                 crypto::EncryptionAlgorithm algorithm,
                                                 bool includeIterations) {
    crypto::EncryptionMetadata metadata;
    metadata.salt = ReadBytes(raw, offset, 16);
    metadata.ivPrimary = ReadBytes(raw, offset, 16);
    if (algorithm == crypto::EncryptionAlgorithm::Gorgon) {
        metadata.ivSecondary = ReadBytes(raw, offset, 16);
    }
    metadata.iterations = includeIterations
        ? ReadValue<uint32_t>(raw, offset)
        : crypto::kLegacyKdfIterations;
    if (includeIterations && !crypto::IsSupportedKdfParameter(metadata.iterations)) {
        throw std::runtime_error("Archive KDF parameters are invalid or below the minimum security threshold");
    }
    return metadata;
}

crypto::EncryptionMetadata DeriveDirectoryMetadata(const crypto::EncryptionMetadata& metadata,
                                                   crypto::EncryptionAlgorithm algorithm) {
    crypto::EncryptionMetadata derived = metadata;
    for (size_t index = 0; index < derived.ivPrimary.size(); ++index) {
        derived.ivPrimary[index] ^= static_cast<unsigned char>(0xA5u + static_cast<unsigned char>(index));
    }
    if (algorithm == crypto::EncryptionAlgorithm::Gorgon) {
        for (size_t index = 0; index < derived.ivSecondary.size(); ++index) {
            derived.ivSecondary[index] ^= static_cast<unsigned char>(0x3Cu + static_cast<unsigned char>(index));
        }
    }
    return derived;
}

crypto::EncryptionMetadata DeriveEntryMetadata(const crypto::EncryptionMetadata& metadata,
                                               crypto::EncryptionAlgorithm algorithm,
                                               uint32_t entryIndex) {
    crypto::EncryptionMetadata derived = metadata;
    for (size_t index = 0; index < derived.ivPrimary.size(); ++index) {
        const unsigned char mask = static_cast<unsigned char>(
            ((entryIndex >> ((index % sizeof(entryIndex)) * 8)) & 0xFFu) ^ (0x11u + static_cast<unsigned char>(index)));
        derived.ivPrimary[index] ^= mask;
    }

    if (algorithm == crypto::EncryptionAlgorithm::Gorgon) {
        for (size_t index = 0; index < derived.ivSecondary.size(); ++index) {
            const unsigned char mask = static_cast<unsigned char>(
                ((entryIndex >> (((index + 1) % sizeof(entryIndex)) * 8)) & 0xFFu) ^ (0x6Du + static_cast<unsigned char>(index)));
            derived.ivSecondary[index] ^= mask;
        }
    }

    return derived;
}

bool HasMagic(const std::vector<uint8_t>& raw, const char* magic) {
    return raw.size() >= 4 && std::memcmp(raw.data(), magic, 4) == 0;
}

LegacyHeader ParseLegacyHeader(const std::vector<uint8_t>& raw) {
    if (!HasMagic(raw, kLegacyMagic)) {
        throw std::runtime_error("Invalid legacy .zox archive header");
    }

    size_t offset = 4;
    LegacyHeader header;
    const uint8_t flags = ReadValue<uint8_t>(raw, offset);
    header.metadata.encrypted = (flags & kEncryptedFlag) != 0;
    header.metadata.solid = (flags & kSolidFlag) != 0;
    header.metadata.encryptionAlgorithm = static_cast<crypto::EncryptionAlgorithm>(ReadValue<uint8_t>(raw, offset));
    if (header.metadata.encrypted && header.metadata.encryptionAlgorithm == crypto::EncryptionAlgorithm::None) {
        throw std::runtime_error("Archive declares encryption but has no encryption mode");
    }
    header.metadata.defaultAlgorithm = static_cast<compression::CompressionAlgorithm>(ReadValue<uint8_t>(raw, offset));
    header.metadata.createdUnixTime = ReadValue<uint64_t>(raw, offset);
    header.plainPayloadSize = ReadValue<uint64_t>(raw, offset);
    header.metadata.payloadChecksum = ReadValue<uint32_t>(raw, offset);

    const uint32_t commentLength = ReadValue<uint32_t>(raw, offset);
    header.metadata.comment = ReadString(raw, offset, commentLength);

    if (header.metadata.encrypted) {
        header.cryptoMetadata = ReadEncryptionMetadata(
            raw,
            offset,
            header.metadata.encryptionAlgorithm,
            false);
    } else {
        header.metadata.encryptionAlgorithm = crypto::EncryptionAlgorithm::None;
    }

    header.payloadSize = ReadValue<uint64_t>(raw, offset);
    header.payloadOffset = offset;
    return header;
}

CurrentHeader ParseCurrentHeader(const std::vector<uint8_t>& raw) {
    const bool isCurrentFormat = HasMagic(raw, kCurrentMagic);
    const bool isPreviousFormatV6 = HasMagic(raw, kPreviousMagicV6);
    const bool isPreviousFormatV5 = HasMagic(raw, kPreviousMagicV5);
    if (!isCurrentFormat && !isPreviousFormatV6 && !isPreviousFormatV5) {
        throw std::runtime_error("Invalid .zox archive header");
    }

    size_t offset = 4;
    CurrentHeader header;
    header.usesExtendedFooter = isCurrentFormat;
    header.hasIterationField = isCurrentFormat;
    const uint8_t flags = ReadValue<uint8_t>(raw, offset);
    header.metadata.encrypted = (flags & kEncryptedFlag) != 0;
    header.metadata.solid = (flags & kSolidFlag) != 0;
    header.metadata.authenticated = (flags & kAuthenticatedFlag) != 0;
    header.metadata.integritySha512 = isCurrentFormat;
    header.metadata.integritySha3_256 = isCurrentFormat;
    if (header.metadata.authenticated && isPreviousFormatV5) {
        throw std::runtime_error("Archive authentication flag is not supported by this archive format");
    }
    if (header.metadata.authenticated && !header.metadata.encrypted) {
        throw std::runtime_error("Authenticated archives must be encrypted");
    }
    header.metadata.encryptionAlgorithm = static_cast<crypto::EncryptionAlgorithm>(ReadValue<uint8_t>(raw, offset));
    if (header.metadata.encrypted && header.metadata.encryptionAlgorithm == crypto::EncryptionAlgorithm::None) {
        throw std::runtime_error("Archive declares encryption but has no encryption mode");
    }
    header.metadata.defaultAlgorithm = static_cast<compression::CompressionAlgorithm>(ReadValue<uint8_t>(raw, offset));
    header.metadata.createdUnixTime = ReadValue<uint64_t>(raw, offset);
    header.metadata.payloadChecksum = ReadValue<uint32_t>(raw, offset);

    const uint32_t commentLength = ReadValue<uint32_t>(raw, offset);
    header.metadata.comment = ReadString(raw, offset, commentLength);

    if (header.metadata.encrypted) {
        header.cryptoMetadata = ReadEncryptionMetadata(
            raw,
            offset,
            header.metadata.encryptionAlgorithm,
            header.hasIterationField);
    } else {
        header.metadata.encryptionAlgorithm = crypto::EncryptionAlgorithm::None;
        header.cryptoMetadata.iterations = 0;
    }

    if (header.metadata.solid) {
        header.dataSectionPlainSize = ReadValue<uint64_t>(raw, offset);
    }

    header.dataOffset = offset;
    return header;
}

DirectoryFooter ParseDirectoryFooter(const std::vector<uint8_t>& raw, const CurrentHeader& header) {
    const size_t footerSize =
        4 + sizeof(uint64_t) * 3 + sizeof(uint32_t) * 2 +
        (header.metadata.integritySha512 ? integrity::kSha512DigestSize : 0) +
        (header.metadata.integritySha3_256 ? integrity::kSha3_256DigestSize : 0) +
        (header.metadata.authenticated ? kAuthenticationTagSize : 0);
    if (raw.size() < footerSize) {
        throw std::runtime_error("Archive is truncated");
    }

    size_t offset = raw.size() - footerSize;
    if (std::memcmp(raw.data() + offset, kFooterMagic, 4) != 0) {
        throw std::runtime_error("Archive central directory footer is missing");
    }
    offset += 4;

    DirectoryFooter footer;
    footer.centralDirectoryOffset = ReadValue<uint64_t>(raw, offset);
    footer.centralDirectoryStoredSize = ReadValue<uint64_t>(raw, offset);
    footer.centralDirectoryPlainSize = ReadValue<uint64_t>(raw, offset);
    footer.centralDirectoryChecksum = ReadValue<uint32_t>(raw, offset);
    footer.entryCount = ReadValue<uint32_t>(raw, offset);
    if (header.metadata.integritySha512) {
        footer.sha512Digest = ReadBytes(raw, offset, integrity::kSha512DigestSize);
    }
    if (header.metadata.integritySha3_256) {
        footer.sha3_256Digest = ReadBytes(raw, offset, integrity::kSha3_256DigestSize);
    }
    if (header.metadata.authenticated) {
        footer.authenticationTag = ReadBytes(raw, offset, kAuthenticationTagSize);
    }
    if (offset != raw.size()) {
        throw std::runtime_error("Archive footer metadata is inconsistent");
    }
    return footer;
}

void VerifyArchiveIntegrityDigests(const std::vector<uint8_t>& raw,
                                   const CurrentHeader& header,
                                   const DirectoryFooter& footer) {
    if (!header.metadata.integritySha512 && !header.metadata.integritySha3_256) {
        return;
    }

    const size_t digestBytes =
        (header.metadata.integritySha512 ? footer.sha512Digest.size() : 0) +
        (header.metadata.integritySha3_256 ? footer.sha3_256Digest.size() : 0);
    const size_t authenticationBytes = header.metadata.authenticated ? footer.authenticationTag.size() : 0;
    if (raw.size() < digestBytes + authenticationBytes) {
        throw std::runtime_error("Archive integrity metadata is truncated");
    }

    const size_t digestedSize = raw.size() - digestBytes - authenticationBytes;
    const integrity::ArchiveIntegrityDigests computed =
        integrity::ComputeArchiveIntegrityDigests(raw.data(), digestedSize);
    if (header.metadata.integritySha512 &&
        (footer.sha512Digest.size() != integrity::kSha512DigestSize ||
         !integrity::DigestsEqual(footer.sha512Digest.data(), computed.sha512.data(), integrity::kSha512DigestSize))) {
        throw std::runtime_error("Archive SHA-512 integrity check failed");
    }
    if (header.metadata.integritySha3_256 &&
        (footer.sha3_256Digest.size() != integrity::kSha3_256DigestSize ||
         !integrity::DigestsEqual(footer.sha3_256Digest.data(), computed.sha3_256.data(), integrity::kSha3_256DigestSize))) {
        throw std::runtime_error("Archive SHA3-256 integrity check failed");
    }
}

void VerifyArchiveAuthentication(const std::vector<uint8_t>& raw,
                                 const CurrentHeader& header,
                                 const DirectoryFooter& footer,
                                 const std::string& password) {
    if (!header.metadata.authenticated) {
        return;
    }
    if (footer.authenticationTag.size() != kAuthenticationTagSize) {
        throw std::runtime_error("Archive authentication tag is invalid");
    }
    if (raw.size() < footer.authenticationTag.size()) {
        throw std::runtime_error("Archive authentication tag is truncated");
    }

    const size_t authenticatedDataSize = raw.size() - footer.authenticationTag.size();
    const std::vector<uint8_t> computedTag = ComputeAuthenticationTag(
        raw.data(),
        authenticatedDataSize,
        password,
        header.cryptoMetadata);
    if (!AuthenticationTagsMatch(footer.authenticationTag, computedTag)) {
        throw std::runtime_error("Archive authentication failed (wrong password or modified data)");
    }
}

DirectoryIndex ParseDirectoryIndex(const std::vector<uint8_t>& raw,
                                   const CurrentHeader& header,
                                   const DirectoryFooter& footer,
                                   const std::string& password) {
    VerifyArchiveIntegrityDigests(raw, header, footer);
    VerifyArchiveAuthentication(raw, header, footer, password);

    if (footer.centralDirectoryOffset < header.dataOffset) {
        throw std::runtime_error("Archive central directory offset is invalid");
    }
    if (footer.centralDirectoryOffset > raw.size()) {
        throw std::runtime_error("Archive central directory offset is outside the file");
    }
    if (footer.centralDirectoryStoredSize > raw.size() - footer.centralDirectoryOffset) {
        throw std::runtime_error("Archive central directory is truncated");
    }

    size_t offset = ToSizeT(footer.centralDirectoryOffset, "Central directory offset");
    std::vector<uint8_t> directoryBytes = ReadBytes(
        raw,
        offset,
        ToSizeT(footer.centralDirectoryStoredSize, "Central directory size"));

    if (header.metadata.encrypted) {
        const crypto::EncryptionMetadata directoryMetadata =
            DeriveDirectoryMetadata(header.cryptoMetadata, header.metadata.encryptionAlgorithm);
        directoryBytes = crypto::DecryptPayload(
            directoryBytes,
            password,
            directoryMetadata,
            header.metadata.encryptionAlgorithm,
            footer.centralDirectoryPlainSize);
    }

    if (directoryBytes.size() != footer.centralDirectoryPlainSize) {
        throw std::runtime_error("Archive central directory size mismatch");
    }

    const uint32_t checksum = utils::ComputeCrc32(directoryBytes);
    if (checksum != footer.centralDirectoryChecksum || checksum != header.metadata.payloadChecksum) {
        throw std::runtime_error("Archive central directory checksum mismatch");
    }

    auto parseVariant = [&](bool withEncodedSize) {
        size_t cursor = 0;
        const uint32_t declaredCount = ReadValue<uint32_t>(directoryBytes, cursor);
        if (declaredCount != footer.entryCount) {
            throw std::runtime_error("Archive central directory entry count mismatch");
        }

        DirectoryIndex index;
        index.entries.reserve(declaredCount);
        index.dataOffsets.reserve(declaredCount);
        index.encodedSizes.reserve(declaredCount);
        index.bulkEncryptedDataSection = header.metadata.encrypted && !withEncodedSize && !header.metadata.solid;
        index.solidArchive = header.metadata.solid;

        for (uint32_t entryIndex = 0; entryIndex < declaredCount; ++entryIndex) {
            ArchiveEntryInfo entry;
            const uint16_t pathLength = ReadValue<uint16_t>(directoryBytes, cursor);
            entry.path = ReadString(directoryBytes, cursor, pathLength);
            if (entry.path.empty()) {
                throw std::runtime_error("Archive contains an empty entry name");
            }

            entry.algorithm = static_cast<compression::CompressionAlgorithm>(ReadValue<uint8_t>(directoryBytes, cursor));
            entry.originalSize = ReadValue<uint64_t>(directoryBytes, cursor);
            entry.storedSize = ReadValue<uint64_t>(directoryBytes, cursor);
            entry.encodedSize = withEncodedSize
                ? ReadValue<uint64_t>(directoryBytes, cursor)
                : entry.storedSize;
            entry.crc32 = ReadValue<uint32_t>(directoryBytes, cursor);
            index.dataOffsets.push_back(ReadValue<uint64_t>(directoryBytes, cursor));
            index.encodedSizes.push_back(entry.encodedSize);
            index.entries.push_back(std::move(entry));
        }

        if (cursor != directoryBytes.size()) {
            throw std::runtime_error("Archive central directory metadata is inconsistent");
        }

        return index;
    };

    try {
        return parseVariant(true);
    } catch (const std::exception&) {
        return parseVariant(false);
    }
}

ArchiveContents ReadArchiveLegacy(const std::vector<uint8_t>& raw, const std::string& password) {
    const LegacyHeader header = ParseLegacyHeader(raw);
    ArchiveContents contents;
    contents.metadata = header.metadata;

    size_t payloadOffset = header.payloadOffset;
    std::vector<uint8_t> payload = ReadBytes(raw, payloadOffset, ToSizeT(header.payloadSize, "Payload size"));
    if (payloadOffset != raw.size()) {
        throw std::runtime_error("Archive contains unexpected trailing data");
    }

    if (contents.metadata.encrypted) {
        payload = crypto::DecryptPayload(
            payload,
            password,
            header.cryptoMetadata,
            contents.metadata.encryptionAlgorithm,
            header.plainPayloadSize);
    }

    if (utils::ComputeCrc32(payload) != contents.metadata.payloadChecksum) {
        throw std::runtime_error("Archive payload checksum mismatch");
    }

    size_t cursor = 0;
    const uint32_t fileCount = ReadValue<uint32_t>(payload, cursor);
    contents.entries.reserve(fileCount);

    for (uint32_t entryIndex = 0; entryIndex < fileCount; ++entryIndex) {
        ArchiveEntryData entry;
        const uint16_t pathLength = ReadValue<uint16_t>(payload, cursor);
        entry.info.path = ReadString(payload, cursor, pathLength);
        if (entry.info.path.empty()) {
            throw std::runtime_error("Archive contains an empty entry name");
        }

        entry.info.algorithm = static_cast<compression::CompressionAlgorithm>(ReadValue<uint8_t>(payload, cursor));
        entry.info.originalSize = ReadValue<uint64_t>(payload, cursor);
        entry.info.storedSize = ReadValue<uint64_t>(payload, cursor);
        entry.info.encodedSize = entry.info.storedSize;
        entry.info.crc32 = ReadValue<uint32_t>(payload, cursor);
        entry.storedData = ReadBytes(payload, cursor, ToSizeT(entry.info.storedSize, "Stored file size"));
        contents.entries.push_back(std::move(entry));
    }

    if (cursor != payload.size()) {
        throw std::runtime_error("Archive payload metadata is inconsistent");
    }

    return contents;
}

std::vector<uint8_t> BuildLegacyPayload(const std::vector<fs::path>& files,
                                        const fs::path& baseRoot,
                                        const WinZOXConfig& config,
                                        const utils::ProgressCallback& progressCallback) {
    if (files.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        throw std::runtime_error("Archive contains too many files");
    }

    const auto overrideMap = BuildOverrideMap(config.fileOverrides);
    std::vector<uint8_t> payload;
    AppendValue<uint32_t>(payload, static_cast<uint32_t>(files.size()));
    const uint64_t totalSize = CalculateTotalFileSize(files);
    uint64_t completedSize = 0;

    ReportProgress(progressCallback, 0, totalSize, "", "Preparing archive");

    for (const fs::path& filePath : files) {
        const std::string relativePath = fs::relative(filePath, baseRoot).generic_string();
        if (relativePath.empty()) {
            throw std::runtime_error("Encountered an empty relative path");
        }
        if (relativePath.size() > static_cast<size_t>(std::numeric_limits<uint16_t>::max())) {
            throw std::runtime_error("File path is too long for the .zox format: " + relativePath);
        }

        const std::vector<uint8_t> rawData = io::ReadFileBytes(filePath);
        const compression::CompressionAlgorithm algorithm =
            ResolveAlgorithmForPath(relativePath, config.defaultAlgorithm, overrideMap);
        const std::vector<uint8_t> storedData = compression::CompressBuffer(
            rawData,
            algorithm,
            config.zstdLevel,
            config.zlibLevel,
            config.lzmaLevel,
            config.threadCount);

        AppendValue<uint16_t>(payload, static_cast<uint16_t>(relativePath.size()));
        AppendBytes(payload, relativePath.data(), relativePath.size());
        AppendValue<uint8_t>(payload, static_cast<uint8_t>(algorithm));
        AppendValue<uint64_t>(payload, static_cast<uint64_t>(rawData.size()));
        AppendValue<uint64_t>(payload, static_cast<uint64_t>(storedData.size()));
        AppendValue<uint32_t>(payload, utils::ComputeCrc32(rawData));
        if (!storedData.empty()) {
            AppendBytes(payload, storedData.data(), storedData.size());
        }

        completedSize += static_cast<uint64_t>(rawData.size());
        ReportProgress(progressCallback, completedSize, totalSize, relativePath, "Compressed");
    }

    return payload;
}

BuiltArchiveSections BuildArchiveSections(const std::vector<fs::path>& files,
                                         const fs::path& baseRoot,
                                         const WinZOXConfig& config,
                                         const crypto::EncryptionMetadata* cryptoMetadata,
                                         crypto::EncryptionAlgorithm encryptionAlgorithm,
                                         const utils::ProgressCallback& progressCallback) {
    if (files.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        throw std::runtime_error("Archive contains too many files");
    }

    const bool useSolidMode = config.solidMode && config.fileOverrides.empty();
    const auto overrideMap = BuildOverrideMap(config.fileOverrides);
    const uint64_t totalSize = CalculateTotalFileSize(files);
    uint64_t completedSize = 0;

    BuiltArchiveSections sections;
    sections.solidArchive = useSolidMode;
    AppendValue<uint32_t>(sections.centralDirectory, static_cast<uint32_t>(files.size()));
    ReportProgress(progressCallback, 0, totalSize, "", "Preparing archive");

    uint64_t dataOffset = 0;
    std::vector<uint8_t> solidPlainData;
    for (size_t entryIndex = 0; entryIndex < files.size(); ++entryIndex) {
        const fs::path& filePath = files[entryIndex];
        const std::string relativePath = fs::relative(filePath, baseRoot).generic_string();
        if (relativePath.empty()) {
            throw std::runtime_error("Encountered an empty relative path");
        }
        if (relativePath.size() > static_cast<size_t>(std::numeric_limits<uint16_t>::max())) {
            throw std::runtime_error("File path is too long for the .zox format: " + relativePath);
        }

        const std::vector<uint8_t> rawData = io::ReadFileBytes(filePath);
        compression::CompressionAlgorithm algorithm = compression::CompressionAlgorithm::Store;
        std::vector<uint8_t> storedData = rawData;
        std::vector<uint8_t> encodedData = storedData;
        if (!useSolidMode) {
            algorithm = ResolveAlgorithmForPath(relativePath, config.defaultAlgorithm, overrideMap);
            storedData = compression::CompressBuffer(
                rawData,
                algorithm,
                config.zstdLevel,
                config.zlibLevel,
                config.lzmaLevel,
                config.threadCount);
            encodedData = storedData;
            if (cryptoMetadata != nullptr) {
                const crypto::EncryptionMetadata entryMetadata =
                    DeriveEntryMetadata(*cryptoMetadata, encryptionAlgorithm, static_cast<uint32_t>(entryIndex));
                encodedData = crypto::EncryptPayload(storedData, config.password, entryMetadata, encryptionAlgorithm);
            }
        }

        AppendValue<uint16_t>(sections.centralDirectory, static_cast<uint16_t>(relativePath.size()));
        AppendBytes(sections.centralDirectory, relativePath.data(), relativePath.size());
        AppendValue<uint8_t>(sections.centralDirectory, static_cast<uint8_t>(algorithm));
        AppendValue<uint64_t>(sections.centralDirectory, static_cast<uint64_t>(rawData.size()));
        AppendValue<uint64_t>(sections.centralDirectory, static_cast<uint64_t>(storedData.size()));
        AppendValue<uint64_t>(sections.centralDirectory, static_cast<uint64_t>(encodedData.size()));
        AppendValue<uint32_t>(sections.centralDirectory, utils::ComputeCrc32(rawData));
        AppendValue<uint64_t>(sections.centralDirectory, dataOffset);

        if (useSolidMode) {
            if (!storedData.empty()) {
                AppendBytes(solidPlainData, storedData.data(), storedData.size());
            }
        } else if (!encodedData.empty()) {
            AppendBytes(sections.dataSection, encodedData.data(), encodedData.size());
        }

        const uint64_t offsetIncrement = useSolidMode
            ? static_cast<uint64_t>(storedData.size())
            : static_cast<uint64_t>(encodedData.size());
        if (dataOffset > (std::numeric_limits<uint64_t>::max)() - offsetIncrement) {
            throw std::runtime_error("Archive data section is too large");
        }
        dataOffset += offsetIncrement;

        completedSize += static_cast<uint64_t>(rawData.size());
        ReportProgress(progressCallback, completedSize, totalSize, relativePath, "Compressed");
    }

    if (useSolidMode) {
        const std::vector<uint8_t> compressedSolidData = compression::CompressBuffer(
            solidPlainData,
            config.defaultAlgorithm,
            config.zstdLevel,
            config.zlibLevel,
            config.lzmaLevel,
            config.threadCount);
        sections.dataSectionPlainSize = static_cast<uint64_t>(compressedSolidData.size());
        sections.dataSection = compressedSolidData;
        if (cryptoMetadata != nullptr) {
            sections.dataSection = crypto::EncryptPayload(
                compressedSolidData,
                config.password,
                *cryptoMetadata,
                encryptionAlgorithm);
        }
    }

    return sections;
}

std::string RelativePathForArchive(const fs::path& filePath, const fs::path& baseRoot) {
    const std::string relativePath = fs::relative(filePath, baseRoot).generic_string();
    if (relativePath.empty()) {
        throw std::runtime_error("Encountered an empty relative path");
    }
    return relativePath;
}

std::string EnsureZipExtension(const std::string& outputPath) {
    const fs::path path(outputPath);
    if (winzox::utils::ToLower(path.extension().string()) == ".zip") {
        return outputPath;
    }
    return outputPath + ".zip";
}

std::vector<uint8_t> ReadAllArchiveBytes(const std::string& filename) {
    return io::ReadAllVolumes(fs::path(filename));
}

} // namespace

bool LooksLikeZoxArchive(const std::string& filename) {
    const fs::path path(filename);
    const std::string extension = utils::ToLower(path.extension().string());
    const bool extensionSuggestsZox = extension == ".zox" || utils::IsSplitZoxExtension(extension);
    if (!fs::exists(path)) {
        return extensionSuggestsZox;
    }

    const std::vector<uint8_t> header = io::ReadFileBytes(path);
    return LooksLikeZoxArchiveBytes(header);
}

bool LooksLikeZoxArchiveBytes(const std::vector<uint8_t>& raw) {
    return HasMagic(raw, kLegacyMagic) ||
           HasMagic(raw, kPreviousMagicV5) ||
           HasMagic(raw, kPreviousMagicV6) ||
           HasMagic(raw, kCurrentMagic);
}

void CreateArchive(const std::string& inputPath,
                   const std::string& outputBase,
                   const WinZOXConfig& config,
                   const utils::ProgressCallback& progressCallback) {
    CreateArchive(std::vector<std::string> { inputPath }, outputBase, config, progressCallback);
}

void CreateArchive(const std::vector<std::string>& inputPaths,
                   const std::string& outputBase,
                   const WinZOXConfig& config,
                   const utils::ProgressCallback& progressCallback) {
    const std::vector<fs::path> normalizedInputs = NormalizeInputPaths(inputPaths);
    const fs::path baseRoot = CommonBaseRoot(normalizedInputs);
    const std::vector<fs::path> files = CollectFilesFromInputs(normalizedInputs);

    ArchiveMetadata metadata;
    metadata.encrypted = !config.password.empty();
    metadata.solid = false;
    metadata.authenticated = metadata.encrypted;
    metadata.integritySha512 = true;
    metadata.integritySha3_256 = true;
    metadata.encryptionAlgorithm = metadata.encrypted
        ? config.encryptionAlgorithm
        : crypto::EncryptionAlgorithm::None;
    metadata.defaultAlgorithm = config.defaultAlgorithm;
    metadata.createdUnixTime = CurrentUnixTime();
    metadata.payloadChecksum = 0;
    metadata.comment = config.comment;

    crypto::EncryptionMetadata cryptoMetadata;
    if (metadata.encrypted) {
        cryptoMetadata = crypto::CreateEncryptionMetadata(metadata.encryptionAlgorithm);
        if (!crypto::IsSupportedKdfParameter(cryptoMetadata.iterations)) {
            throw std::runtime_error("KDF parameters are invalid");
        }
    }

    BuiltArchiveSections sections = BuildArchiveSections(
        files,
        baseRoot,
        config,
        metadata.encrypted ? &cryptoMetadata : nullptr,
        metadata.encryptionAlgorithm,
        progressCallback);
    metadata.solid = sections.solidArchive;
    metadata.payloadChecksum = utils::ComputeCrc32(sections.centralDirectory);
    const uint64_t centralDirectoryPlainSize = static_cast<uint64_t>(sections.centralDirectory.size());

    if (metadata.encrypted) {
        const crypto::EncryptionMetadata directoryMetadata =
            DeriveDirectoryMetadata(cryptoMetadata, metadata.encryptionAlgorithm);
        sections.centralDirectory = crypto::EncryptPayload(
            sections.centralDirectory,
            config.password,
            directoryMetadata,
            metadata.encryptionAlgorithm);
    }

    io::VolumeWriter writer(outputBase, config.splitSize);
    integrity::ArchiveIntegrityAccumulator integrityContext;
    std::unique_ptr<crypto::auth::ArchiveAuthenticator> authenticationContext;
    if (metadata.authenticated) {
        authenticationContext = std::make_unique<crypto::auth::ArchiveAuthenticator>(
            config.password,
            cryptoMetadata.salt,
            cryptoMetadata.iterations);
    }

    auto writeWithContexts = [&](const void* data, size_t size, bool updateIntegrity, bool updateAuthentication) {
        writer.Write(reinterpret_cast<const char*>(data), size);
        if (size == 0) {
            return;
        }
        if (updateIntegrity) {
            integrityContext.Update(data, size);
        }
        if (updateAuthentication && authenticationContext != nullptr) {
            authenticationContext->Update(data, size);
        }
    };

    writeWithContexts(kCurrentMagic, 4, true, true);

    const uint8_t flags =
        (metadata.encrypted ? kEncryptedFlag : 0) |
        (metadata.solid ? kSolidFlag : 0) |
        (metadata.authenticated ? kAuthenticatedFlag : 0);
    writeWithContexts(&flags, sizeof(flags), true, true);

    const uint8_t encryptionAlgo = static_cast<uint8_t>(metadata.encryptionAlgorithm);
    writeWithContexts(&encryptionAlgo, sizeof(encryptionAlgo), true, true);

    const uint8_t defaultAlgo = static_cast<uint8_t>(metadata.defaultAlgorithm);
    writeWithContexts(&defaultAlgo, sizeof(defaultAlgo), true, true);

    writeWithContexts(&metadata.createdUnixTime, sizeof(metadata.createdUnixTime), true, true);
    writeWithContexts(&metadata.payloadChecksum, sizeof(metadata.payloadChecksum), true, true);

    const uint32_t commentLength = static_cast<uint32_t>(metadata.comment.size());
    writeWithContexts(&commentLength, sizeof(commentLength), true, true);
    if (commentLength > 0) {
        writeWithContexts(metadata.comment.data(), commentLength, true, true);
    }

    if (metadata.encrypted) {
        writeWithContexts(cryptoMetadata.salt.data(), cryptoMetadata.salt.size(), true, true);
        writeWithContexts(cryptoMetadata.ivPrimary.data(), cryptoMetadata.ivPrimary.size(), true, true);
        if (metadata.encryptionAlgorithm == crypto::EncryptionAlgorithm::Gorgon) {
            writeWithContexts(cryptoMetadata.ivSecondary.data(), cryptoMetadata.ivSecondary.size(), true, true);
        }
        writeWithContexts(&cryptoMetadata.iterations, sizeof(cryptoMetadata.iterations), true, true);
    }
    if (metadata.solid) {
        writeWithContexts(&sections.dataSectionPlainSize, sizeof(sections.dataSectionPlainSize), true, true);
    }

    const uint64_t headerSize =
        4 +
        sizeof(uint8_t) * 3 +
        sizeof(uint64_t) +
        sizeof(uint32_t) +
        sizeof(uint32_t) +
        static_cast<uint64_t>(commentLength) +
        static_cast<uint64_t>(metadata.encrypted
            ? cryptoMetadata.salt.size() + cryptoMetadata.ivPrimary.size() + cryptoMetadata.ivSecondary.size() + sizeof(uint32_t)
            : 0) +
        static_cast<uint64_t>(metadata.solid ? sizeof(uint64_t) : 0);
    const uint64_t dataSectionStoredSize = static_cast<uint64_t>(sections.dataSection.size());
    const uint64_t centralDirectoryStoredSize = static_cast<uint64_t>(sections.centralDirectory.size());
    const uint64_t centralDirectoryOffset = headerSize + dataSectionStoredSize;

    if (!sections.dataSection.empty()) {
        writeWithContexts(sections.dataSection.data(), sections.dataSection.size(), true, true);
    }
    if (!sections.centralDirectory.empty()) {
        writeWithContexts(sections.centralDirectory.data(), sections.centralDirectory.size(), true, true);
    }

    writeWithContexts(kFooterMagic, 4, true, true);
    writeWithContexts(&centralDirectoryOffset, sizeof(centralDirectoryOffset), true, true);
    writeWithContexts(&centralDirectoryStoredSize, sizeof(centralDirectoryStoredSize), true, true);
    writeWithContexts(&centralDirectoryPlainSize, sizeof(centralDirectoryPlainSize), true, true);
    writeWithContexts(&metadata.payloadChecksum, sizeof(metadata.payloadChecksum), true, true);

    const uint32_t entryCount = static_cast<uint32_t>(files.size());
    writeWithContexts(&entryCount, sizeof(entryCount), true, true);

    const integrity::ArchiveIntegrityDigests integrityDigests = integrityContext.Finalize();
    writeWithContexts(integrityDigests.sha512.data(), integrityDigests.sha512.size(), false, true);
    writeWithContexts(integrityDigests.sha3_256.data(), integrityDigests.sha3_256.size(), false, true);

    if (authenticationContext != nullptr) {
        const std::vector<uint8_t> authenticationTag = authenticationContext->Finalize();
        if (authenticationTag.size() != kAuthenticationTagSize) {
            throw std::runtime_error("Archive authentication tag length is invalid");
        }
        writer.Write(reinterpret_cast<const char*>(authenticationTag.data()), authenticationTag.size());
    }

    writer.Close();
    ReportProgress(progressCallback, 1, 1, fs::path(outputBase).filename().u8string(), "Archive created");
}

void CreateZipArchive(const std::string& inputPath,
                      const std::string& outputPath,
                      const WinZOXConfig& config,
                      const utils::ProgressCallback& progressCallback) {
    CreateZipArchive(std::vector<std::string> { inputPath }, outputPath, config, progressCallback);
}

void CreateZipArchive(const std::vector<std::string>& inputPaths,
                      const std::string& outputPath,
                      const WinZOXConfig& config,
                      const utils::ProgressCallback& progressCallback) {
    if (!config.password.empty()) {
        throw std::runtime_error("ZIP creation does not support encryption in this version");
    }
    if (config.splitSize != 0) {
        throw std::runtime_error("ZIP creation does not support split volumes in this version");
    }
    if (!config.comment.empty()) {
        throw std::runtime_error("ZIP creation does not support archive comments in this version");
    }
    if (!config.fileOverrides.empty()) {
        throw std::runtime_error("ZIP creation does not support per-file algorithm overrides in this version");
    }

    if (config.defaultAlgorithm != compression::CompressionAlgorithm::Store &&
        config.defaultAlgorithm != compression::CompressionAlgorithm::Zlib) {
        throw std::runtime_error("ZIP creation supports only store or zlib compression");
    }

    const std::vector<fs::path> normalizedInputs = NormalizeInputPaths(inputPaths);
    const fs::path baseRoot = CommonBaseRoot(normalizedInputs);
    const std::vector<fs::path> files = CollectFilesFromInputs(normalizedInputs);
    const uint64_t totalSize = CalculateTotalFileSize(files);
    uint64_t completedSize = 0;
    const std::string finalOutputPath = EnsureZipExtension(outputPath);

    struct archive* writer = archive_write_new();
    if (writer == nullptr) {
        throw std::runtime_error("Failed to allocate ZIP writer");
    }

    if (archive_write_set_format_zip(writer) != ARCHIVE_OK) {
        archive_write_free(writer);
        throw std::runtime_error("Failed to initialize ZIP format writer");
    }

    if (config.defaultAlgorithm == compression::CompressionAlgorithm::Store) {
        archive_write_set_options(writer, "compression=store");
    } else {
        archive_write_set_options(writer, "compression=deflate");
    }

    if (archive_write_open_filename(writer, finalOutputPath.c_str()) != ARCHIVE_OK) {
        const std::string message = archive_error_string(writer) ? archive_error_string(writer) : "unknown libarchive error";
        archive_write_free(writer);
        throw std::runtime_error("Failed to create ZIP archive: " + message);
    }

    ReportProgress(progressCallback, 0, totalSize, "", "Preparing archive");

    for (const fs::path& filePath : files) {
        const std::string relativePath = RelativePathForArchive(filePath, baseRoot);
        const std::vector<uint8_t> fileData = io::ReadFileBytes(filePath);

        archive_entry* entry = archive_entry_new();
        if (entry == nullptr) {
            archive_write_close(writer);
            archive_write_free(writer);
            throw std::runtime_error("Failed to allocate ZIP entry");
        }

        archive_entry_set_pathname(entry, relativePath.c_str());
        archive_entry_set_filetype(entry, AE_IFREG);
        archive_entry_set_perm(entry, 0644);
        archive_entry_set_size(entry, static_cast<la_int64_t>(fileData.size()));

        if (archive_write_header(writer, entry) != ARCHIVE_OK) {
            const std::string message = archive_error_string(writer) ? archive_error_string(writer) : "unknown libarchive error";
            archive_entry_free(entry);
            archive_write_close(writer);
            archive_write_free(writer);
            throw std::runtime_error("Failed to write ZIP header: " + message);
        }

        if (!fileData.empty()) {
            const la_ssize_t written = archive_write_data(writer, fileData.data(), fileData.size());
            if (written < 0 || static_cast<size_t>(written) != fileData.size()) {
                const std::string message = archive_error_string(writer) ? archive_error_string(writer) : "unknown libarchive error";
                archive_entry_free(entry);
                archive_write_close(writer);
                archive_write_free(writer);
                throw std::runtime_error("Failed to write ZIP entry: " + message);
            }
        }

        archive_entry_free(entry);
        completedSize += static_cast<uint64_t>(fileData.size());
        ReportProgress(progressCallback, completedSize, totalSize, relativePath, "Compressed");
    }

    archive_write_close(writer);
    archive_write_free(writer);
    ReportProgress(progressCallback, 1, 1, fs::path(finalOutputPath).filename().u8string(), "Archive created");
}

ArchiveMetadata ReadArchiveMetadataFromBytes(const std::vector<uint8_t>& raw) {
    if (HasMagic(raw, kCurrentMagic) || HasMagic(raw, kPreviousMagicV6) || HasMagic(raw, kPreviousMagicV5)) {
        CurrentHeader header = ParseCurrentHeader(raw);
        const DirectoryFooter footer = ParseDirectoryFooter(raw, header);
        VerifyArchiveIntegrityDigests(raw, header, footer);
        if (header.metadata.payloadChecksum != footer.centralDirectoryChecksum) {
            throw std::runtime_error("Archive central directory checksum metadata is inconsistent");
        }
        header.metadata.payloadChecksum = footer.centralDirectoryChecksum;
        return header.metadata;
    }

    if (HasMagic(raw, kLegacyMagic)) {
        return ParseLegacyHeader(raw).metadata;
    }

    throw std::runtime_error("Invalid .zox archive header");
}

ArchiveMetadata ReadArchiveMetadata(const std::string& filename) {
    return ReadArchiveMetadataFromBytes(ReadAllArchiveBytes(filename));
}

std::vector<ArchiveEntryInfo> ReadArchiveIndexFromBytes(const std::vector<uint8_t>& raw, const std::string& password) {
    if (HasMagic(raw, kCurrentMagic) || HasMagic(raw, kPreviousMagicV6) || HasMagic(raw, kPreviousMagicV5)) {
        const CurrentHeader header = ParseCurrentHeader(raw);
        const DirectoryFooter footer = ParseDirectoryFooter(raw, header);
        const DirectoryIndex index = ParseDirectoryIndex(raw, header, footer, password);
        return index.entries;
    }

    if (HasMagic(raw, kLegacyMagic)) {
        const ArchiveContents contents = ReadArchiveLegacy(raw, password);
        std::vector<ArchiveEntryInfo> entries;
        entries.reserve(contents.entries.size());
        for (const auto& entry : contents.entries) {
            entries.push_back(entry.info);
        }
        return entries;
    }

    throw std::runtime_error("Invalid .zox archive header");
}

std::vector<ArchiveEntryInfo> ReadArchiveIndex(const std::string& filename, const std::string& password) {
    return ReadArchiveIndexFromBytes(ReadAllArchiveBytes(filename), password);
}

ArchiveContents ReadArchiveFromBytes(const std::vector<uint8_t>& raw, const std::string& password) {
    if (HasMagic(raw, kLegacyMagic)) {
        return ReadArchiveLegacy(raw, password);
    }

    if (!HasMagic(raw, kCurrentMagic) &&
        !HasMagic(raw, kPreviousMagicV6) &&
        !HasMagic(raw, kPreviousMagicV5)) {
        throw std::runtime_error("Invalid .zox archive header");
    }

    const CurrentHeader header = ParseCurrentHeader(raw);
    const DirectoryFooter footer = ParseDirectoryFooter(raw, header);
    const DirectoryIndex directory = ParseDirectoryIndex(raw, header, footer, password);

    if (footer.centralDirectoryOffset < header.dataOffset) {
        throw std::runtime_error("Archive data section offset is invalid");
    }

    const uint64_t dataSectionStoredSize = footer.centralDirectoryOffset - static_cast<uint64_t>(header.dataOffset);
    ArchiveContents contents;
    contents.metadata = header.metadata;
    contents.metadata.payloadChecksum = footer.centralDirectoryChecksum;
    contents.entries.reserve(directory.entries.size());

    if (directory.solidArchive) {
        size_t dataOffset = header.dataOffset;
        std::vector<uint8_t> dataSection = ReadBytes(raw, dataOffset, ToSizeT(dataSectionStoredSize, "Data section size"));

        if (header.metadata.encrypted) {
            dataSection = crypto::DecryptPayload(
                dataSection,
                password,
                header.cryptoMetadata,
                header.metadata.encryptionAlgorithm,
                header.dataSectionPlainSize);
        }

        uint64_t solidPlainSize = 0;
        for (size_t index = 0; index < directory.entries.size(); ++index) {
            const uint64_t entryEnd = directory.dataOffsets[index] + directory.entries[index].storedSize;
            if (solidPlainSize < entryEnd) {
                solidPlainSize = entryEnd;
            }
        }

        const std::vector<uint8_t> solidPlainData = compression::DecompressBuffer(
            dataSection,
            header.metadata.defaultAlgorithm,
            solidPlainSize);

        for (size_t index = 0; index < directory.entries.size(); ++index) {
            const ArchiveEntryInfo& entryInfo = directory.entries[index];
            const size_t start = ToSizeT(directory.dataOffsets[index], "Entry data offset");
            const size_t length = ToSizeT(entryInfo.storedSize, "Entry stored size");
            if (start > solidPlainData.size() || length > solidPlainData.size() - start) {
                throw std::runtime_error("Archive entry data is truncated: " + entryInfo.path);
            }

            ArchiveEntryData entry;
            entry.info = entryInfo;
            entry.storedData.assign(
                solidPlainData.begin() + static_cast<std::ptrdiff_t>(start),
                solidPlainData.begin() + static_cast<std::ptrdiff_t>(start + length));
            contents.entries.push_back(std::move(entry));
        }

        return contents;
    }

    if (directory.bulkEncryptedDataSection) {
        size_t dataOffset = header.dataOffset;
        std::vector<uint8_t> dataSection = ReadBytes(raw, dataOffset, ToSizeT(dataSectionStoredSize, "Data section size"));

        uint64_t plainDataSectionSize = 0;
        for (size_t index = 0; index < directory.entries.size(); ++index) {
            const uint64_t entryEnd = directory.dataOffsets[index] + directory.entries[index].storedSize;
            if (plainDataSectionSize < entryEnd) {
                plainDataSectionSize = entryEnd;
            }
        }

        if (header.metadata.encrypted) {
            dataSection = crypto::DecryptPayload(
                dataSection,
                password,
                header.cryptoMetadata,
                header.metadata.encryptionAlgorithm,
                plainDataSectionSize);
        }

        if (dataSection.size() != plainDataSectionSize) {
            throw std::runtime_error("Archive data section size mismatch");
        }

        for (size_t index = 0; index < directory.entries.size(); ++index) {
            const ArchiveEntryInfo& entryInfo = directory.entries[index];
            const size_t start = ToSizeT(directory.dataOffsets[index], "Entry data offset");
            const size_t length = ToSizeT(entryInfo.storedSize, "Entry stored size");
            if (start > dataSection.size() || length > dataSection.size() - start) {
                throw std::runtime_error("Archive entry data is truncated: " + entryInfo.path);
            }

            ArchiveEntryData entry;
            entry.info = entryInfo;
            entry.storedData.assign(
                dataSection.begin() + static_cast<std::ptrdiff_t>(start),
                dataSection.begin() + static_cast<std::ptrdiff_t>(start + length));
            contents.entries.push_back(std::move(entry));
        }

        return contents;
    }

    for (size_t index = 0; index < directory.entries.size(); ++index) {
        const ArchiveEntryInfo& entryInfo = directory.entries[index];
        const uint64_t relativeOffset = directory.dataOffsets[index];
        const uint64_t encodedSize = directory.encodedSizes[index];
        if (relativeOffset > dataSectionStoredSize || encodedSize > dataSectionStoredSize - relativeOffset) {
            throw std::runtime_error("Archive entry data is truncated: " + entryInfo.path);
        }

        size_t start = header.dataOffset + ToSizeT(relativeOffset, "Entry data offset");
        size_t length = ToSizeT(encodedSize, "Encoded entry size");
        std::vector<uint8_t> entryBytes = ReadBytes(raw, start, length);

        if (header.metadata.encrypted) {
            const crypto::EncryptionMetadata entryMetadata =
                DeriveEntryMetadata(header.cryptoMetadata, header.metadata.encryptionAlgorithm, static_cast<uint32_t>(index));
            entryBytes = crypto::DecryptPayload(
                entryBytes,
                password,
                entryMetadata,
                header.metadata.encryptionAlgorithm,
                entryInfo.storedSize);
        }

        if (entryBytes.size() != entryInfo.storedSize) {
            throw std::runtime_error("Archive entry payload size mismatch: " + entryInfo.path);
        }

        ArchiveEntryData entry;
        entry.info = entryInfo;
        entry.storedData = std::move(entryBytes);
        contents.entries.push_back(std::move(entry));
    }

    return contents;
}

ArchiveContents ReadArchive(const std::string& filename, const std::string& password) {
    return ReadArchiveFromBytes(ReadAllArchiveBytes(filename), password);
}

} // namespace winzox::archive
