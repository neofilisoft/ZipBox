#include "extraction/api/unzox/unzox_api.hpp"

#include "compression/compressor.hpp"
#include "io/file_writer.hpp"
#include "utils/checksum.hpp"
#include "utils/path_utils.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <functional>
#include <limits>
#include <stdexcept>

namespace winzox::extraction::api::unzox {

namespace fs = std::filesystem;

namespace {

std::string ToLowerCopy(const std::string& value) {
    std::string result = value;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

Status MakeStatus(ErrorCode code, std::string message = {}) {
    return Status { code, std::move(message) };
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

uint64_t CalculateTotalEntryUnits(const std::vector<archive::ArchiveEntryData>& entries) {
    uint64_t totalUnits = 0;
    for (const auto& entry : entries) {
        const uint64_t increment = entry.info.originalSize > 0 ? entry.info.originalSize : 1;
        if (totalUnits > (std::numeric_limits<uint64_t>::max)() - increment) {
            throw std::runtime_error("Archive is too large");
        }
        totalUnits += increment;
    }
    return totalUnits;
}

void EnsurePasswordIfNeeded(const archive::ArchiveMetadata& metadata, const std::string& password) {
    if (metadata.encrypted && password.empty()) {
        throw std::runtime_error("Password is required for encrypted .zox archives");
    }
}

Status Execute(const std::function<void()>& operation) {
    try {
        operation();
        return MakeStatus(ErrorCode::WZOX_OK);
    } catch (const std::exception& error) {
        return MakeStatus(ClassifyError(error.what()), error.what());
    }
}

} // namespace

bool LooksLikeWzoxArchive(const std::vector<uint8_t>& archiveBytes) {
    return archive::LooksLikeZoxArchiveBytes(archiveBytes);
}

ErrorCode ClassifyError(const std::string& message) {
    const std::string lower = ToLowerCopy(message);

    if (lower.find("invalid .zox archive header") != std::string::npos ||
        lower.find("invalid legacy .zox archive header") != std::string::npos ||
        lower.find("invalid magic") != std::string::npos) {
        return ErrorCode::WZOX_ERR_INVALID_MAGIC;
    }

    if (lower.find("unsupported") != std::string::npos) {
        return ErrorCode::WZOX_ERR_UNSUPPORTED_FORMAT;
    }

    if (lower.find("truncated") != std::string::npos) {
        return ErrorCode::WZOX_ERR_TRUNCATED;
    }

    if (lower.find("password is required") != std::string::npos) {
        return ErrorCode::WZOX_ERR_PASSWORD_REQUIRED;
    }

    if (lower.find("authentication failed") != std::string::npos ||
        lower.find("wrong password") != std::string::npos) {
        return ErrorCode::WZOX_ERR_AUTH_FAILED;
    }

    if (lower.find("gorgon") != std::string::npos &&
        lower.find("decrypt") != std::string::npos) {
        return ErrorCode::WZOX_ERR_GORGON_DECRYPT;
    }

    if (lower.find("decrypt") != std::string::npos ||
        lower.find("decryption") != std::string::npos) {
        return ErrorCode::WZOX_ERR_DECRYPT_FAILED;
    }

    if (lower.find("integrity") != std::string::npos ||
        lower.find("checksum") != std::string::npos ||
        lower.find("crc32 mismatch") != std::string::npos) {
        return ErrorCode::WZOX_ERR_INTEGRITY_FAILED;
    }

    if (lower.find("out of range") != std::string::npos) {
        return ErrorCode::WZOX_ERR_ENTRY_OUT_OF_RANGE;
    }

    if (lower.find("canceled") != std::string::npos) {
        return ErrorCode::WZOX_ERR_CANCELED;
    }

    if (lower.find("cannot create output file") != std::string::npos ||
        lower.find("failed to open archive") != std::string::npos) {
        return ErrorCode::WZOX_ERR_IO;
    }

    return ErrorCode::WZOX_ERR_INTERNAL;
}

Status ProbeArchiveBytes(const std::vector<uint8_t>& archiveBytes,
                         const std::string& password,
                         archive::ArchiveMetadata* metadataOut,
                         std::vector<archive::ArchiveEntryInfo>* entriesOut) {
    if (metadataOut == nullptr || entriesOut == nullptr) {
        return MakeStatus(ErrorCode::WZOX_ERR_INVALID_ARGUMENT, "Output pointers must not be null");
    }

    return Execute([&]() {
        if (!LooksLikeWzoxArchive(archiveBytes)) {
            throw std::runtime_error("Invalid .zox archive header");
        }

        *metadataOut = archive::ReadArchiveMetadataFromBytes(archiveBytes);
        EnsurePasswordIfNeeded(*metadataOut, password);
        *entriesOut = archive::ReadArchiveIndexFromBytes(archiveBytes, password);
    });
}

Status ValidateAuthentication(const std::vector<uint8_t>& archiveBytes,
                              const std::string& password,
                              bool* requiresPasswordOut) {
    return Execute([&]() {
        if (!LooksLikeWzoxArchive(archiveBytes)) {
            throw std::runtime_error("Invalid .zox archive header");
        }

        const archive::ArchiveMetadata metadata = archive::ReadArchiveMetadataFromBytes(archiveBytes);
        if (requiresPasswordOut != nullptr) {
            *requiresPasswordOut = metadata.encrypted;
        }

        EnsurePasswordIfNeeded(metadata, password);
        (void)archive::ReadArchiveIndexFromBytes(archiveBytes, password);
    });
}

Status ExtractToDirectory(const std::vector<uint8_t>& archiveBytes,
                          const std::string& destination,
                          const std::string& password,
                          const utils::ProgressCallback& progressCallback) {
    if (destination.empty()) {
        return MakeStatus(ErrorCode::WZOX_ERR_INVALID_ARGUMENT, "Destination must not be empty");
    }

    return Execute([&]() {
        if (!LooksLikeWzoxArchive(archiveBytes)) {
            throw std::runtime_error("Invalid .zox archive header");
        }

        const archive::ArchiveMetadata metadata = archive::ReadArchiveMetadataFromBytes(archiveBytes);
        EnsurePasswordIfNeeded(metadata, password);
        const archive::ArchiveContents contents = archive::ReadArchiveFromBytes(archiveBytes, password);

        const fs::path destinationRoot(destination);
        fs::create_directories(destinationRoot);
        const uint64_t totalUnits = CalculateTotalEntryUnits(contents.entries);
        uint64_t completedUnits = 0;

        ReportProgress(progressCallback, 0, totalUnits, "", "Preparing extraction");
        for (const auto& entry : contents.entries) {
            const std::vector<uint8_t> plain = compression::DecompressBuffer(
                entry.storedData,
                entry.info.algorithm,
                entry.info.originalSize);
            if (utils::ComputeCrc32(plain) != entry.info.crc32) {
                throw std::runtime_error("CRC32 mismatch for entry: " + entry.info.path);
            }

            const fs::path outputPath = utils::ResolveSafeOutputPath(destinationRoot, entry.info.path);
            io::WriteFileBytes(outputPath, plain);

            completedUnits += entry.info.originalSize > 0 ? entry.info.originalSize : 1;
            ReportProgress(progressCallback, completedUnits, totalUnits, entry.info.path, "Extracting");
        }
        ReportProgress(progressCallback, 1, 1, destinationRoot.filename().u8string(), "Extraction complete");
    });
}

Status ReadEntryBytes(const std::vector<uint8_t>& archiveBytes,
                      size_t entryIndex,
                      std::vector<uint8_t>* entryDataOut,
                      const std::string& password) {
    if (entryDataOut == nullptr) {
        return MakeStatus(ErrorCode::WZOX_ERR_INVALID_ARGUMENT, "Output buffer must not be null");
    }

    return Execute([&]() {
        if (!LooksLikeWzoxArchive(archiveBytes)) {
            throw std::runtime_error("Invalid .zox archive header");
        }

        const archive::ArchiveMetadata metadata = archive::ReadArchiveMetadataFromBytes(archiveBytes);
        EnsurePasswordIfNeeded(metadata, password);
        const archive::ArchiveContents contents = archive::ReadArchiveFromBytes(archiveBytes, password);
        if (entryIndex >= contents.entries.size()) {
            throw std::runtime_error("Selected archive entry is out of range");
        }

        const auto& entry = contents.entries[entryIndex];
        std::vector<uint8_t> plain = compression::DecompressBuffer(
            entry.storedData,
            entry.info.algorithm,
            entry.info.originalSize);
        if (utils::ComputeCrc32(plain) != entry.info.crc32) {
            throw std::runtime_error("CRC32 mismatch for entry: " + entry.info.path);
        }

        *entryDataOut = std::move(plain);
    });
}

} // namespace winzox::extraction::api::unzox
