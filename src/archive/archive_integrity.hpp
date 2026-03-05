#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace winzox::archive::integrity {

constexpr size_t kSha512DigestSize = 64;
constexpr size_t kSha3_256DigestSize = 32;

struct ArchiveIntegrityDigests {
    std::array<uint8_t, kSha512DigestSize> sha512 {};
    std::array<uint8_t, kSha3_256DigestSize> sha3_256 {};
};

class ArchiveIntegrityAccumulator {
public:
    ArchiveIntegrityAccumulator();
    ~ArchiveIntegrityAccumulator();

    ArchiveIntegrityAccumulator(const ArchiveIntegrityAccumulator&) = delete;
    ArchiveIntegrityAccumulator& operator=(const ArchiveIntegrityAccumulator&) = delete;

    void Update(const void* data, size_t size);
    ArchiveIntegrityDigests Finalize();

private:
    struct Impl;
    Impl* impl_;
};

ArchiveIntegrityDigests ComputeArchiveIntegrityDigests(const uint8_t* data, size_t size);
bool DigestsEqual(const uint8_t* left, const uint8_t* right, size_t size);

} // namespace winzox::archive::integrity
