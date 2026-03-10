#include "winzox/extensions/chacha20/chacha20_api.h"

#include "crypto/key_derivation.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace {

#ifndef WINZOX_CHACHA20_API_VERSION
#define WINZOX_CHACHA20_API_VERSION "2.11.1"
#endif

int ToOpenSslSize(size_t size) {
    if (size > static_cast<size_t>((std::numeric_limits<int>::max)())) {
        throw std::runtime_error("Data block is too large for OpenSSL");
    }
    return static_cast<int>(size);
}

void WriteError(const std::string& message, char* errorBuffer, size_t errorBufferSize) {
    if (errorBuffer == nullptr || errorBufferSize == 0) {
        return;
    }

    const size_t copySize = std::min(message.size(), errorBufferSize - 1);
    std::memcpy(errorBuffer, message.data(), copySize);
    errorBuffer[copySize] = '\0';
}

void ValidateMetadata(const WinZOXChaCha20Metadata& metadata) {
    if (metadata.iterations == 0) {
        throw std::runtime_error("ChaCha20 iterations must be greater than zero");
    }
}

std::vector<uint8_t> ExportCipherWithTag(const std::vector<uint8_t>& cipher, const std::array<uint8_t, WINZOX_CHACHA20_TAG_SIZE>& tag) {
    std::vector<uint8_t> combined;
    combined.reserve(cipher.size() + tag.size());
    combined.insert(combined.end(), cipher.begin(), cipher.end());
    combined.insert(combined.end(), tag.begin(), tag.end());
    return combined;
}

std::vector<uint8_t> EncryptChaCha20Poly1305(const std::vector<uint8_t>& plainText,
                                             const std::string& password,
                                             const WinZOXChaCha20Metadata& metadata) {
    if (password.empty()) {
        throw std::runtime_error("Password is required for ChaCha20 encryption");
    }

    ValidateMetadata(metadata);
    const std::vector<unsigned char> salt(metadata.salt, metadata.salt + WINZOX_CHACHA20_SALT_SIZE);
    const std::vector<unsigned char> key = winzox::crypto::DeriveKey(password, salt, metadata.iterations);

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("Failed to create OpenSSL cipher context");
    }

    std::vector<uint8_t> cipher(plainText.size() + WINZOX_CHACHA20_TAG_SIZE);
    std::array<uint8_t, WINZOX_CHACHA20_TAG_SIZE> tag {};
    int produced = 0;
    int finalBytes = 0;

    if (EVP_EncryptInit_ex(context, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN, WINZOX_CHACHA20_NONCE_SIZE, nullptr) != 1 ||
        EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), metadata.nonce) != 1 ||
        EVP_EncryptUpdate(context, cipher.data(), &produced, plainText.data(), ToOpenSslSize(plainText.size())) != 1 ||
        EVP_EncryptFinal_ex(context, cipher.data() + produced, &finalBytes) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, WINZOX_CHACHA20_TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(context);
        throw std::runtime_error("ChaCha20 encryption failed");
    }

    EVP_CIPHER_CTX_free(context);
    cipher.resize(static_cast<size_t>(produced + finalBytes));
    return ExportCipherWithTag(cipher, tag);
}

std::vector<uint8_t> DecryptChaCha20Poly1305(const std::vector<uint8_t>& cipherText,
                                             const std::string& password,
                                             const WinZOXChaCha20Metadata& metadata,
                                             uint64_t expectedPlainSize) {
    if (password.empty()) {
        throw std::runtime_error("Password is required for ChaCha20 decryption");
    }
    ValidateMetadata(metadata);
    if (cipherText.size() < WINZOX_CHACHA20_TAG_SIZE) {
        throw std::runtime_error("ChaCha20 payload is truncated");
    }

    const size_t payloadSize = cipherText.size() - WINZOX_CHACHA20_TAG_SIZE;
    const uint8_t* payload = cipherText.data();
    const uint8_t* tag = cipherText.data() + payloadSize;
    const std::vector<unsigned char> salt(metadata.salt, metadata.salt + WINZOX_CHACHA20_SALT_SIZE);
    const std::vector<unsigned char> key = winzox::crypto::DeriveKey(password, salt, metadata.iterations);

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("Failed to create OpenSSL cipher context");
    }

    std::vector<uint8_t> plain(payloadSize);
    int produced = 0;
    int finalBytes = 0;

    const bool ok =
        EVP_DecryptInit_ex(context, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN, WINZOX_CHACHA20_NONCE_SIZE, nullptr) == 1 &&
        EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), metadata.nonce) == 1 &&
        EVP_DecryptUpdate(context, plain.data(), &produced, payload, ToOpenSslSize(payloadSize)) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, WINZOX_CHACHA20_TAG_SIZE, const_cast<uint8_t*>(tag)) == 1 &&
        EVP_DecryptFinal_ex(context, plain.data() + produced, &finalBytes) == 1;

    EVP_CIPHER_CTX_free(context);

    if (!ok) {
        throw std::runtime_error("ChaCha20 authentication failed");
    }

    plain.resize(static_cast<size_t>(produced + finalBytes));
    if (expectedPlainSize != 0 && plain.size() != expectedPlainSize) {
        throw std::runtime_error("ChaCha20 plaintext length mismatch");
    }
    return plain;
}

WinZOXChaCha20Status ExportBuffer(const std::vector<uint8_t>& input,
                                  WinZOXChaCha20Buffer* output,
                                  char* errorBuffer,
                                  size_t errorBufferSize) {
    if (output == nullptr) {
        WriteError("Output buffer is null", errorBuffer, errorBufferSize);
        return WINZOX_CHACHA20_STATUS_INVALID_ARGUMENT;
    }

    output->data = nullptr;
    output->size = 0;
    if (input.empty()) {
        return WINZOX_CHACHA20_STATUS_OK;
    }

    auto* buffer = static_cast<uint8_t*>(std::malloc(input.size()));
    if (buffer == nullptr) {
        WriteError("Failed to allocate output buffer", errorBuffer, errorBufferSize);
        return WINZOX_CHACHA20_STATUS_OPERATION_FAILED;
    }

    std::memcpy(buffer, input.data(), input.size());
    output->data = buffer;
    output->size = input.size();
    return WINZOX_CHACHA20_STATUS_OK;
}

} // namespace

extern "C" {

const char* winzox_chacha20_api_version(void) {
    return WINZOX_CHACHA20_API_VERSION;
}

WinZOXChaCha20Status winzox_chacha20_create_metadata(WinZOXChaCha20Metadata* out_metadata,
                                                     char* error_buffer,
                                                     size_t error_buffer_size) {
    if (out_metadata == nullptr) {
        WriteError("Metadata output is null", error_buffer, error_buffer_size);
        return WINZOX_CHACHA20_STATUS_INVALID_ARGUMENT;
    }

    try {
        out_metadata->iterations = winzox::crypto::kDefaultKdfIterations;
        if (RAND_bytes(out_metadata->salt, WINZOX_CHACHA20_SALT_SIZE) != 1 ||
            RAND_bytes(out_metadata->nonce, WINZOX_CHACHA20_NONCE_SIZE) != 1) {
            throw std::runtime_error("Failed to generate ChaCha20 metadata");
        }
        return WINZOX_CHACHA20_STATUS_OK;
    } catch (const std::exception& error) {
        WriteError(error.what(), error_buffer, error_buffer_size);
        return WINZOX_CHACHA20_STATUS_OPERATION_FAILED;
    }
}

WinZOXChaCha20Status winzox_chacha20_encrypt(const uint8_t* plain_data,
                                             size_t plain_size,
                                             const char* password,
                                             const WinZOXChaCha20Metadata* metadata,
                                             WinZOXChaCha20Buffer* out_cipher,
                                             char* error_buffer,
                                             size_t error_buffer_size) {
    if ((plain_data == nullptr && plain_size != 0) || password == nullptr || metadata == nullptr || out_cipher == nullptr) {
        WriteError("Invalid ChaCha20 encryption arguments", error_buffer, error_buffer_size);
        return WINZOX_CHACHA20_STATUS_INVALID_ARGUMENT;
    }

    try {
        const std::vector<uint8_t> plain(plain_data, plain_data + plain_size);
        const std::vector<uint8_t> cipher = EncryptChaCha20Poly1305(plain, password, *metadata);
        return ExportBuffer(cipher, out_cipher, error_buffer, error_buffer_size);
    } catch (const std::exception& error) {
        WriteError(error.what(), error_buffer, error_buffer_size);
        return WINZOX_CHACHA20_STATUS_OPERATION_FAILED;
    }
}

WinZOXChaCha20Status winzox_chacha20_decrypt(const uint8_t* cipher_data,
                                             size_t cipher_size,
                                             const char* password,
                                             const WinZOXChaCha20Metadata* metadata,
                                             uint64_t expected_plain_size,
                                             WinZOXChaCha20Buffer* out_plain,
                                             char* error_buffer,
                                             size_t error_buffer_size) {
    if ((cipher_data == nullptr && cipher_size != 0) || password == nullptr || metadata == nullptr || out_plain == nullptr) {
        WriteError("Invalid ChaCha20 decryption arguments", error_buffer, error_buffer_size);
        return WINZOX_CHACHA20_STATUS_INVALID_ARGUMENT;
    }

    try {
        const std::vector<uint8_t> cipher(cipher_data, cipher_data + cipher_size);
        const std::vector<uint8_t> plain = DecryptChaCha20Poly1305(cipher, password, *metadata, expected_plain_size);
        return ExportBuffer(plain, out_plain, error_buffer, error_buffer_size);
    } catch (const std::exception& error) {
        const WinZOXChaCha20Status status = std::string(error.what()).find("authentication failed") != std::string::npos
            ? WINZOX_CHACHA20_STATUS_AUTH_FAILED
            : WINZOX_CHACHA20_STATUS_OPERATION_FAILED;
        WriteError(error.what(), error_buffer, error_buffer_size);
        return status;
    }
}

void winzox_chacha20_free_buffer(WinZOXChaCha20Buffer* buffer) {
    if (buffer == nullptr) {
        return;
    }

    if (buffer->data != nullptr) {
        std::free(buffer->data);
        buffer->data = nullptr;
    }
    buffer->size = 0;
}

} // extern "C"
