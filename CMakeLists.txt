cmake_minimum_required(VERSION 3.10)
set(WINZOX_VERSION_STRING "2.11.2")
project(WinZOX VERSION ${WINZOX_VERSION_STRING} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(WINZOX_SRC_DIR src)
set(WINZOX_EXTENSIONS_DIR extensions)
option(WINZOX_ENABLE_EXTENSIONS "Build extension targets discovered under extensions/" ON)
set(WINZOX_ARCHIVE_DIR ${WINZOX_SRC_DIR}/archive)
set(WINZOX_COMPRESSION_DIR ${WINZOX_SRC_DIR}/compression)
set(WINZOX_COMPRESSION_CODER_DIR ${WINZOX_COMPRESSION_DIR}/coder)
set(WINZOX_COMPRESSION_DICTIONARY_DIR ${WINZOX_COMPRESSION_DIR}/dictionary)
set(WINZOX_CRYPTO_DIR ${WINZOX_SRC_DIR}/crypto)
set(WINZOX_CRYPTO_ALGORITHMS_DIR ${WINZOX_CRYPTO_DIR}/algorithms)
set(WINZOX_CRYPTO_PROVIDERS_DIR ${WINZOX_CRYPTO_ALGORITHMS_DIR}/provider)
set(WINZOX_EXTRACTION_DIR ${WINZOX_SRC_DIR}/extraction)
set(WINZOX_EXTRACTION_DECODER_DIR ${WINZOX_EXTRACTION_DIR}/decoder)
set(WINZOX_IO_DIR ${WINZOX_SRC_DIR}/io)
set(WINZOX_UTILS_DIR ${WINZOX_SRC_DIR}/utils)

if (WIN32)
    set(MSYS2_UCRT64_ROOT "C:/msys64/ucrt64")
    if (EXISTS "${MSYS2_UCRT64_ROOT}")
        list(APPEND CMAKE_PREFIX_PATH "${MSYS2_UCRT64_ROOT}")

        if (NOT DEFINED OPENSSL_ROOT_DIR)
            set(OPENSSL_ROOT_DIR "${MSYS2_UCRT64_ROOT}")
        endif()
    endif()
endif()

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(LibArchive REQUIRED)
find_path(ZSTD_INCLUDE_DIR zstd.h
    PATHS
        "${MSYS2_UCRT64_ROOT}/include"
)
find_library(ZSTD_LIBRARY NAMES zstd libzstd
    PATHS
        "${MSYS2_UCRT64_ROOT}/lib"
)
find_library(NETTLE_LIBRARY NAMES nettle libnettle
    PATHS
        "${MSYS2_UCRT64_ROOT}/lib"
)
find_path(LZ4_INCLUDE_DIR lz4.h
    PATHS
        "${MSYS2_UCRT64_ROOT}/include"
)
find_library(LZ4_LIBRARY NAMES lz4 liblz4
    PATHS
        "${MSYS2_UCRT64_ROOT}/lib"
)
find_path(LZMA_INCLUDE_DIR lzma.h
    PATHS
        "${MSYS2_UCRT64_ROOT}/include"
)
find_library(LZMA_LIBRARY NAMES lzma liblzma
    PATHS
        "${MSYS2_UCRT64_ROOT}/lib"
)

if (NOT ZSTD_INCLUDE_DIR OR NOT ZSTD_LIBRARY)
    message(FATAL_ERROR "Could not find Zstd. Install the Zstd development package or set ZSTD_INCLUDE_DIR/ZSTD_LIBRARY.")
endif()

if (NOT NETTLE_LIBRARY)
    message(FATAL_ERROR "Could not find Nettle. Install the Nettle development package or set NETTLE_LIBRARY.")
endif()
if (NOT LZ4_INCLUDE_DIR OR NOT LZ4_LIBRARY)
    message(FATAL_ERROR "Could not find LZ4. Install the LZ4 development package or set LZ4_INCLUDE_DIR/LZ4_LIBRARY.")
endif()
if (NOT LZMA_INCLUDE_DIR OR NOT LZMA_LIBRARY)
    message(FATAL_ERROR "Could not find LZMA. Install the XZ/LZMA development package or set LZMA_INCLUDE_DIR/LZMA_LIBRARY.")
endif()

set(SOURCES
    ${WINZOX_SRC_DIR}/app/main.cpp
    ${WINZOX_ARCHIVE_DIR}/archive.cpp
    ${WINZOX_ARCHIVE_DIR}/archive_integrity.cpp
    ${WINZOX_COMPRESSION_DIR}/compressor.cpp
    ${WINZOX_COMPRESSION_CODER_DIR}/huffman.cpp
    ${WINZOX_COMPRESSION_CODER_DIR}/range_coder.cpp
    ${WINZOX_COMPRESSION_DICTIONARY_DIR}/dictionary_manager.cpp
    ${WINZOX_CRYPTO_ALGORITHMS_DIR}/aes/aes256.cpp
    ${WINZOX_CRYPTO_PROVIDERS_DIR}/aes_provider.cpp
    ${WINZOX_CRYPTO_DIR}/auth/archive_authentication.cpp
    ${WINZOX_CRYPTO_PROVIDERS_DIR}/gorgon_provider.cpp
    ${WINZOX_CRYPTO_ALGORITHMS_DIR}/gorgon/gorgon.cpp
    ${WINZOX_CRYPTO_DIR}/key_derivation.cpp
    ${WINZOX_EXTRACTION_DIR}/extractor.cpp
    ${WINZOX_EXTRACTION_DECODER_DIR}/decode_pipeline.cpp
    ${WINZOX_EXTRACTION_DIR}/api/unzox/unzox_api.cpp
    ${WINZOX_IO_DIR}/file_reader.cpp
    ${WINZOX_IO_DIR}/file_writer.cpp
    ${WINZOX_SRC_DIR}/shell/windows_shell.cpp
    ${WINZOX_SRC_DIR}/shell/windows_shell_add_dialog.cpp
    ${WINZOX_SRC_DIR}/shell/windows_shell_browse_dialog.cpp
    ${WINZOX_IO_DIR}/volume_reader.cpp
    ${WINZOX_IO_DIR}/volume_writer.cpp
    ${WINZOX_UTILS_DIR}/checksum.cpp
    ${WINZOX_UTILS_DIR}/path_utils.cpp
)

set(GORGON_LIBRARY_SOURCES
    ${WINZOX_CRYPTO_ALGORITHMS_DIR}/gorgon/gorgon_api.cpp
    ${WINZOX_CRYPTO_PROVIDERS_DIR}/gorgon_provider.cpp
    ${WINZOX_CRYPTO_ALGORITHMS_DIR}/gorgon/gorgon.cpp
    ${WINZOX_CRYPTO_DIR}/key_derivation.cpp
)

set(UNZOX_LIBRARY_SOURCES
    ${WINZOX_ARCHIVE_DIR}/archive.cpp
    ${WINZOX_ARCHIVE_DIR}/archive_integrity.cpp
    ${WINZOX_COMPRESSION_DIR}/compressor.cpp
    ${WINZOX_COMPRESSION_CODER_DIR}/huffman.cpp
    ${WINZOX_COMPRESSION_CODER_DIR}/range_coder.cpp
    ${WINZOX_COMPRESSION_DICTIONARY_DIR}/dictionary_manager.cpp
    ${WINZOX_CRYPTO_ALGORITHMS_DIR}/aes/aes256.cpp
    ${WINZOX_CRYPTO_PROVIDERS_DIR}/aes_provider.cpp
    ${WINZOX_CRYPTO_DIR}/auth/archive_authentication.cpp
    ${WINZOX_CRYPTO_PROVIDERS_DIR}/gorgon_provider.cpp
    ${WINZOX_CRYPTO_ALGORITHMS_DIR}/gorgon/gorgon.cpp
    ${WINZOX_CRYPTO_DIR}/key_derivation.cpp
    ${WINZOX_EXTRACTION_DIR}/extractor.cpp
    ${WINZOX_EXTRACTION_DECODER_DIR}/decode_pipeline.cpp
    ${WINZOX_EXTRACTION_DIR}/api/unzox/unzox_api.cpp
    ${WINZOX_EXTRACTION_DIR}/api/unzox/unzox_c_api.cpp
    ${WINZOX_IO_DIR}/file_reader.cpp
    ${WINZOX_IO_DIR}/file_writer.cpp
    ${WINZOX_IO_DIR}/volume_reader.cpp
    ${WINZOX_IO_DIR}/volume_writer.cpp
    ${WINZOX_UTILS_DIR}/checksum.cpp
    ${WINZOX_UTILS_DIR}/path_utils.cpp
)

if (WIN32)
    add_executable(winzox WIN32 ${SOURCES})
else()
    add_executable(winzox ${SOURCES})
endif()
set_target_properties(winzox PROPERTIES OUTPUT_NAME "zox")

add_library(winzox_gorgon SHARED ${GORGON_LIBRARY_SOURCES})
target_compile_definitions(winzox_gorgon PRIVATE
    WINZOX_GORGON_BUILD_SHARED
    WINZOX_GORGON_API_VERSION="${WINZOX_VERSION_STRING}"
)
target_include_directories(winzox_gorgon PUBLIC
    src
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(winzox_gorgon PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${NETTLE_LIBRARY}
)
if (WIN32)
    set_target_properties(winzox_gorgon PROPERTIES PREFIX "")
endif()

add_library(winzox_unzox SHARED ${UNZOX_LIBRARY_SOURCES})
target_compile_definitions(winzox_unzox PRIVATE
    WINZOX_UNZOX_BUILD_SHARED
    WINZOX_UNZOX_API_VERSION="${WINZOX_VERSION_STRING}"
)
target_include_directories(winzox_unzox PUBLIC
    src
    ${OPENSSL_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
    ${LibArchive_INCLUDE_DIRS}
    ${ZSTD_INCLUDE_DIR}
    ${LZ4_INCLUDE_DIR}
    ${LZMA_INCLUDE_DIR}
)
target_link_libraries(winzox_unzox PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    ${LibArchive_LIBRARIES}
    ${ZSTD_LIBRARY}
    ${NETTLE_LIBRARY}
    ${LZ4_LIBRARY}
    ${LZMA_LIBRARY}
)
if (WIN32)
    set_target_properties(winzox_unzox PROPERTIES PREFIX "" OUTPUT_NAME "UnZOX")
else()
    set_target_properties(winzox_unzox PROPERTIES OUTPUT_NAME "UnZOX")
endif()

target_include_directories(winzox PRIVATE
    src
    ${OPENSSL_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
    ${LibArchive_INCLUDE_DIRS}
    ${ZSTD_INCLUDE_DIR}
    ${LZ4_INCLUDE_DIR}
    ${LZMA_INCLUDE_DIR}
)

target_link_libraries(winzox PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    ${LibArchive_LIBRARIES}
    ${ZSTD_LIBRARY}
    ${NETTLE_LIBRARY}
    ${LZ4_LIBRARY}
    ${LZMA_LIBRARY}
)

if (WIN32)
    target_link_libraries(winzox PRIVATE comdlg32 comctl32 shell32 user32 ole32 uuid)
    add_custom_command(
        TARGET winzox POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/windows/winzox.manifest"
            "$<TARGET_FILE_DIR:winzox>/zox.exe.manifest"
    )
endif()

install(TARGETS winzox
        RUNTIME DESTINATION bin)
install(TARGETS winzox_gorgon
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
install(TARGETS winzox_unzox
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
install(FILES
    ${WINZOX_CRYPTO_ALGORITHMS_DIR}/gorgon/gorgon_api.h
    DESTINATION include/crypto
)
install(FILES
    ${WINZOX_EXTRACTION_DIR}/api/unzox/unzox_api.hpp
    DESTINATION include/extraction/api/unzox
)
install(FILES
    ${WINZOX_EXTRACTION_DIR}/api/unzox/unzox_c_api.h
    DESTINATION include/extraction/api/unzox
)
install(FILES
    windows/install-shell-integration.ps1
    windows/shell-dispatch.ps1
    windows/uninstall-shell-integration.ps1
    DESTINATION tools
)

if (WINZOX_ENABLE_EXTENSIONS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${WINZOX_EXTENSIONS_DIR}")
    file(GLOB WINZOX_EXTENSION_CMAKE_FILES
        RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
        "${WINZOX_EXTENSIONS_DIR}/*/CMakeLists.txt"
    )

    foreach(extension_cmake IN LISTS WINZOX_EXTENSION_CMAKE_FILES)
        get_filename_component(extension_dir "${extension_cmake}" DIRECTORY)
        add_subdirectory(
            "${CMAKE_CURRENT_SOURCE_DIR}/${extension_dir}"
            "${CMAKE_CURRENT_BINARY_DIR}/${extension_dir}"
        )
    endforeach()
endif()
