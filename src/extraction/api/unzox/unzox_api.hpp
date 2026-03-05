#pragma once

#include "archive/archive.hpp"
#include "utils/progress.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace winzox::extraction::api::unzox {

enum class ErrorCode : uint32_t {
    WZOX_OK = 0,
    WZOX_ERR_INVALID_ARGUMENT = 1,
    WZOX_ERR_INVALID_MAGIC = 2,
    WZOX_ERR_UNSUPPORTED_FORMAT = 3,
    WZOX_ERR_TRUNCATED = 4,
    WZOX_ERR_PASSWORD_REQUIRED = 5,
    WZOX_ERR_AUTH_FAILED = 6,
    WZOX_ERR_GORGON_DECRYPT = 7,
    WZOX_ERR_DECRYPT_FAILED = 8,
    WZOX_ERR_INTEGRITY_FAILED = 9,
    WZOX_ERR_ENTRY_OUT_OF_RANGE = 10,
    WZOX_ERR_CANCELED = 11,
    WZOX_ERR_IO = 12,
    WZOX_ERR_INTERNAL = 13
};

struct Status {
    ErrorCode code = ErrorCode::WZOX_OK;
    std::string message;

    [[nodiscard]] bool ok() const { return code == ErrorCode::WZOX_OK; }
    explicit operator bool() const { return ok(); }
};

bool LooksLikeWzoxArchive(const std::vector<uint8_t>& archiveBytes);
ErrorCode ClassifyError(const std::string& message);

Status ProbeArchiveBytes(const std::vector<uint8_t>& archiveBytes,
                         const std::string& password,
                         archive::ArchiveMetadata* metadataOut,
                         std::vector<archive::ArchiveEntryInfo>* entriesOut);

Status ValidateAuthentication(const std::vector<uint8_t>& archiveBytes,
                              const std::string& password,
                              bool* requiresPasswordOut = nullptr);

Status ExtractToDirectory(const std::vector<uint8_t>& archiveBytes,
                          const std::string& destination,
                          const std::string& password = "",
                          const utils::ProgressCallback& progressCallback = {});

Status ReadEntryBytes(const std::vector<uint8_t>& archiveBytes,
                      size_t entryIndex,
                      std::vector<uint8_t>* entryDataOut,
                      const std::string& password = "");

} // namespace winzox::extraction::api::unzox
