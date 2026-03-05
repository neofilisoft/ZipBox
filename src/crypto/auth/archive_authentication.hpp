#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace winzox::crypto::auth {

class ArchiveAuthenticator {
public:
    ArchiveAuthenticator(const std::string& password,
                         const std::vector<unsigned char>& salt,
                         uint32_t iterations);
    ~ArchiveAuthenticator();

    ArchiveAuthenticator(const ArchiveAuthenticator&) = delete;
    ArchiveAuthenticator& operator=(const ArchiveAuthenticator&) = delete;
    ArchiveAuthenticator(ArchiveAuthenticator&&) noexcept;
    ArchiveAuthenticator& operator=(ArchiveAuthenticator&&) noexcept;

    void Update(const void* data, size_t size);
    std::vector<uint8_t> Finalize();

private:
    struct Impl;
    Impl* impl_;
};

std::vector<uint8_t> ComputeArchiveAuthenticationTag(const uint8_t* data,
                                                     size_t dataSize,
                                                     const std::string& password,
                                                     const std::vector<unsigned char>& salt,
                                                     uint32_t iterations);

} // namespace winzox::crypto::auth
