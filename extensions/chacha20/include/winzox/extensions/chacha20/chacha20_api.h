#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  ifdef WINZOX_CHACHA20_BUILD_SHARED
#    define WINZOX_CHACHA20_API __declspec(dllexport)
#  else
#    define WINZOX_CHACHA20_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define WINZOX_CHACHA20_API __attribute__((visibility("default")))
#else
#  define WINZOX_CHACHA20_API
#endif

#define WINZOX_CHACHA20_SALT_SIZE 16u
#define WINZOX_CHACHA20_NONCE_SIZE 12u
#define WINZOX_CHACHA20_TAG_SIZE 16u

#ifdef __cplusplus
extern "C" {
#endif

typedef enum WinZOXChaCha20Status {
    WINZOX_CHACHA20_STATUS_OK = 0,
    WINZOX_CHACHA20_STATUS_INVALID_ARGUMENT = 1,
    WINZOX_CHACHA20_STATUS_AUTH_FAILED = 2,
    WINZOX_CHACHA20_STATUS_OPERATION_FAILED = 3
} WinZOXChaCha20Status;

typedef struct WinZOXChaCha20Metadata {
    uint8_t salt[WINZOX_CHACHA20_SALT_SIZE];
    uint8_t nonce[WINZOX_CHACHA20_NONCE_SIZE];
    uint32_t iterations;
} WinZOXChaCha20Metadata;

typedef struct WinZOXChaCha20Buffer {
    uint8_t* data;
    size_t size;
} WinZOXChaCha20Buffer;

WINZOX_CHACHA20_API const char* winzox_chacha20_api_version(void);

WINZOX_CHACHA20_API WinZOXChaCha20Status winzox_chacha20_create_metadata(
    WinZOXChaCha20Metadata* out_metadata,
    char* error_buffer,
    size_t error_buffer_size);

WINZOX_CHACHA20_API WinZOXChaCha20Status winzox_chacha20_encrypt(
    const uint8_t* plain_data,
    size_t plain_size,
    const char* password,
    const WinZOXChaCha20Metadata* metadata,
    WinZOXChaCha20Buffer* out_cipher,
    char* error_buffer,
    size_t error_buffer_size);

WINZOX_CHACHA20_API WinZOXChaCha20Status winzox_chacha20_decrypt(
    const uint8_t* cipher_data,
    size_t cipher_size,
    const char* password,
    const WinZOXChaCha20Metadata* metadata,
    uint64_t expected_plain_size,
    WinZOXChaCha20Buffer* out_plain,
    char* error_buffer,
    size_t error_buffer_size);

WINZOX_CHACHA20_API void winzox_chacha20_free_buffer(WinZOXChaCha20Buffer* buffer);

#ifdef __cplusplus
}
#endif
