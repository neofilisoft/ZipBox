#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  ifdef ZIPBOX_GORGON_BUILD_SHARED
#    define ZIPBOX_GORGON_API __declspec(dllexport)
#  else
#    define ZIPBOX_GORGON_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define ZIPBOX_GORGON_API __attribute__((visibility("default")))
#else
#  define ZIPBOX_GORGON_API
#endif

#define ZIPBOX_GORGON_SALT_SIZE 16u
#define ZIPBOX_GORGON_IV_SIZE 16u

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ZipBoxGorgonStatus {
    ZIPBOX_GORGON_STATUS_OK = 0,
    ZIPBOX_GORGON_STATUS_INVALID_ARGUMENT = 1,
    ZIPBOX_GORGON_STATUS_OPERATION_FAILED = 2
} ZipBoxGorgonStatus;

typedef struct ZipBoxGorgonMetadata {
    uint8_t salt[ZIPBOX_GORGON_SALT_SIZE];
    uint8_t iv_primary[ZIPBOX_GORGON_IV_SIZE];
    uint8_t iv_secondary[ZIPBOX_GORGON_IV_SIZE];
} ZipBoxGorgonMetadata;

typedef struct ZipBoxGorgonBuffer {
    uint8_t* data;
    size_t size;
} ZipBoxGorgonBuffer;

ZIPBOX_GORGON_API const char* zipbox_gorgon_api_version(void);

ZIPBOX_GORGON_API ZipBoxGorgonStatus zipbox_gorgon_create_metadata(
    ZipBoxGorgonMetadata* out_metadata,
    char* error_buffer,
    size_t error_buffer_size);

ZIPBOX_GORGON_API ZipBoxGorgonStatus zipbox_gorgon_encrypt(
    const uint8_t* plain_data,
    size_t plain_size,
    const char* password,
    const ZipBoxGorgonMetadata* metadata,
    ZipBoxGorgonBuffer* out_cipher,
    char* error_buffer,
    size_t error_buffer_size);

ZIPBOX_GORGON_API ZipBoxGorgonStatus zipbox_gorgon_decrypt(
    const uint8_t* cipher_data,
    size_t cipher_size,
    const char* password,
    const ZipBoxGorgonMetadata* metadata,
    uint64_t expected_plain_size,
    ZipBoxGorgonBuffer* out_plain,
    char* error_buffer,
    size_t error_buffer_size);

ZIPBOX_GORGON_API void zipbox_gorgon_free_buffer(ZipBoxGorgonBuffer* buffer);

#ifdef __cplusplus
}
#endif
