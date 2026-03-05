#include "crypto/gorgon/gorgon_api.h"

#include "crypto/gorgon/gorgon_provider.hpp"
#include "crypto/key_derivation.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

#ifndef WINZOX_GORGON_API_VERSION
#define WINZOX_GORGON_API_VERSION "2.01"
#endif

void SetError(char* errorBuffer, size_t errorBufferSize, const std::string& message) {
    if (errorBuffer == nullptr || errorBufferSize == 0) {
        return;
    }

    const size_t copyLength = std::min(errorBufferSize - 1, message.size());
    if (copyLength > 0) {
        std::memcpy(errorBuffer, message.data(), copyLength);
    }
    errorBuffer[copyLength] = '\0';
}

winzox::crypto::EncryptionMetadata ToInternalMetadata(const WinZOXGorgonMetadata& metadata) {
    winzox::crypto::EncryptionMetadata internal;
    internal.salt.assign(metadata.salt, metadata.salt + WINZOX_GORGON_SALT_SIZE);
    internal.ivPrimary.assign(metadata.iv_primary, metadata.iv_primary + WINZOX_GORGON_IV_SIZE);
    internal.ivSecondary.assign(metadata.iv_secondary, metadata.iv_secondary + WINZOX_GORGON_IV_SIZE);
    internal.iterations = winzox::crypto::kDefaultKdfIterations;
    return internal;
}

void FromInternalMetadata(const winzox::crypto::EncryptionMetadata& internal, WinZOXGorgonMetadata& metadata) {
    if (internal.salt.size() != WINZOX_GORGON_SALT_SIZE ||
        internal.ivPrimary.size() != WINZOX_GORGON_IV_SIZE ||
        internal.ivSecondary.size() != WINZOX_GORGON_IV_SIZE) {
        throw std::runtime_error("Unexpected Gorgon metadata size");
    }

    std::copy(internal.salt.begin(), internal.salt.end(), metadata.salt);
    std::copy(internal.ivPrimary.begin(), internal.ivPrimary.end(), metadata.iv_primary);
    std::copy(internal.ivSecondary.begin(), internal.ivSecondary.end(), metadata.iv_secondary);
}

WinZOXGorgonStatus ExportBuffer(const std::vector<uint8_t>& input,
                                WinZOXGorgonBuffer* output,
                                char* errorBuffer,
                                size_t errorBufferSize) {
    if (output == nullptr) {
        SetError(errorBuffer, errorBufferSize, "Output buffer pointer is required");
        return WINZOX_GORGON_STATUS_INVALID_ARGUMENT;
    }

    output->data = nullptr;
    output->size = 0;

    if (input.empty()) {
        return WINZOX_GORGON_STATUS_OK;
    }

    void* allocation = std::malloc(input.size());
    if (allocation == nullptr) {
        SetError(errorBuffer, errorBufferSize, "Failed to allocate output buffer");
        return WINZOX_GORGON_STATUS_OPERATION_FAILED;
    }

    std::memcpy(allocation, input.data(), input.size());
    output->data = static_cast<uint8_t*>(allocation);
    output->size = input.size();
    return WINZOX_GORGON_STATUS_OK;
}

std::vector<uint8_t> CopyInputBytes(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0) {
        return {};
    }

    return std::vector<uint8_t>(data, data + size);
}

} // namespace

extern "C" {

const char* winzox_gorgon_api_version(void) {
    return WINZOX_GORGON_API_VERSION;
}

WinZOXGorgonStatus winzox_gorgon_create_metadata(WinZOXGorgonMetadata* out_metadata,
                                                 char* error_buffer,
                                                 size_t error_buffer_size) {
    if (out_metadata == nullptr) {
        SetError(error_buffer, error_buffer_size, "Output metadata pointer is required");
        return WINZOX_GORGON_STATUS_INVALID_ARGUMENT;
    }

    try {
        const auto& provider = winzox::crypto::GetGorgonProvider();
        const winzox::crypto::EncryptionMetadata metadata = provider.CreateMetadata();
        FromInternalMetadata(metadata, *out_metadata);
        SetError(error_buffer, error_buffer_size, "");
        return WINZOX_GORGON_STATUS_OK;
    } catch (const std::exception& error) {
        SetError(error_buffer, error_buffer_size, error.what());
        return WINZOX_GORGON_STATUS_OPERATION_FAILED;
    }
}

WinZOXGorgonStatus winzox_gorgon_encrypt(const uint8_t* plain_data,
                                         size_t plain_size,
                                         const char* password,
                                         const WinZOXGorgonMetadata* metadata,
                                         WinZOXGorgonBuffer* out_cipher,
                                         char* error_buffer,
                                         size_t error_buffer_size) {
    if ((plain_data == nullptr && plain_size != 0) || password == nullptr || metadata == nullptr) {
        SetError(error_buffer, error_buffer_size, "Plain data, password, and metadata are required");
        return WINZOX_GORGON_STATUS_INVALID_ARGUMENT;
    }

    try {
        const std::vector<uint8_t> plain = CopyInputBytes(plain_data, plain_size);
        const auto& provider = winzox::crypto::GetGorgonProvider();
        const std::vector<uint8_t> cipher = provider.Encrypt(
            plain,
            password,
            ToInternalMetadata(*metadata));
        SetError(error_buffer, error_buffer_size, "");
        return ExportBuffer(cipher, out_cipher, error_buffer, error_buffer_size);
    } catch (const std::exception& error) {
        SetError(error_buffer, error_buffer_size, error.what());
        return WINZOX_GORGON_STATUS_OPERATION_FAILED;
    }
}

WinZOXGorgonStatus winzox_gorgon_decrypt(const uint8_t* cipher_data,
                                         size_t cipher_size,
                                         const char* password,
                                         const WinZOXGorgonMetadata* metadata,
                                         uint64_t expected_plain_size,
                                         WinZOXGorgonBuffer* out_plain,
                                         char* error_buffer,
                                         size_t error_buffer_size) {
    if ((cipher_data == nullptr && cipher_size != 0) || password == nullptr || metadata == nullptr) {
        SetError(error_buffer, error_buffer_size, "Cipher data, password, and metadata are required");
        return WINZOX_GORGON_STATUS_INVALID_ARGUMENT;
    }

    try {
        const std::vector<uint8_t> cipher = CopyInputBytes(cipher_data, cipher_size);
        const auto& provider = winzox::crypto::GetGorgonProvider();
        const std::vector<uint8_t> plain = provider.Decrypt(
            cipher,
            password,
            ToInternalMetadata(*metadata),
            expected_plain_size);
        SetError(error_buffer, error_buffer_size, "");
        return ExportBuffer(plain, out_plain, error_buffer, error_buffer_size);
    } catch (const std::exception& error) {
        SetError(error_buffer, error_buffer_size, error.what());
        return WINZOX_GORGON_STATUS_OPERATION_FAILED;
    }
}

void winzox_gorgon_free_buffer(WinZOXGorgonBuffer* buffer) {
    if (buffer == nullptr) {
        return;
    }

    if (buffer->data != nullptr) {
        std::free(buffer->data);
    }
    buffer->data = nullptr;
    buffer->size = 0;
}

} // extern "C"
