#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  ifdef WINZOX_GORGON_BUILD_SHARED
#    define WINZOX_GORGON_API __declspec(dllexport)
#  else
#    define WINZOX_GORGON_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define WINZOX_GORGON_API __attribute__((visibility("default")))
#else
#  define WINZOX_GORGON_API
#endif

#define WINZOX_GORGON_SALT_SIZE 16u
#define WINZOX_GORGON_IV_SIZE 16u

#ifdef __cplusplus
extern "C" {
#endif

typedef enum WinZOXGorgonStatus {
    WINZOX_GORGON_STATUS_OK = 0,
    WINZOX_GORGON_STATUS_INVALID_ARGUMENT = 1,
    WINZOX_GORGON_STATUS_OPERATION_FAILED = 2
} WinZOXGorgonStatus;

typedef struct WinZOXGorgonMetadata {
    uint8_t salt[WINZOX_GORGON_SALT_SIZE];
    uint8_t iv_primary[WINZOX_GORGON_IV_SIZE];
    uint8_t iv_secondary[WINZOX_GORGON_IV_SIZE];
} WinZOXGorgonMetadata;

typedef struct WinZOXGorgonBuffer {
    uint8_t* data;
    size_t size;
} WinZOXGorgonBuffer;

WINZOX_GORGON_API const char* winzox_gorgon_api_version(void);

WINZOX_GORGON_API WinZOXGorgonStatus winzox_gorgon_create_metadata(
    WinZOXGorgonMetadata* out_metadata,
    char* error_buffer,
    size_t error_buffer_size);

WINZOX_GORGON_API WinZOXGorgonStatus winzox_gorgon_encrypt(
    const uint8_t* plain_data,
    size_t plain_size,
    const char* password,
    const WinZOXGorgonMetadata* metadata,
    WinZOXGorgonBuffer* out_cipher,
    char* error_buffer,
    size_t error_buffer_size);

WINZOX_GORGON_API WinZOXGorgonStatus winzox_gorgon_decrypt(
    const uint8_t* cipher_data,
    size_t cipher_size,
    const char* password,
    const WinZOXGorgonMetadata* metadata,
    uint64_t expected_plain_size,
    WinZOXGorgonBuffer* out_plain,
    char* error_buffer,
    size_t error_buffer_size);

WINZOX_GORGON_API void winzox_gorgon_free_buffer(WinZOXGorgonBuffer* buffer);

#ifdef __cplusplus
}
#endif
