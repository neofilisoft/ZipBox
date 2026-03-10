set(WINZOX_CHACHA20_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/chacha20.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto/key_derivation.cpp
)

add_library(winzox_chacha20 SHARED ${WINZOX_CHACHA20_SOURCES})
target_compile_definitions(winzox_chacha20 PRIVATE
    WINZOX_CHACHA20_BUILD_SHARED
    WINZOX_CHACHA20_API_VERSION="${WINZOX_VERSION_STRING}"
)
target_include_directories(winzox_chacha20 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(winzox_chacha20 PRIVATE
    OpenSSL::Crypto
)

if (WIN32)
    set_target_properties(winzox_chacha20 PROPERTIES PREFIX "" OUTPUT_NAME "WinZOXChaCha20")
else()
    set_target_properties(winzox_chacha20 PROPERTIES OUTPUT_NAME "WinZOXChaCha20")
endif()
