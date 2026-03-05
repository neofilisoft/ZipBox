#include "archive/archive_integrity.hpp"

#include <stdexcept>
#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace winzox::archive::integrity {

struct ArchiveIntegrityAccumulator::Impl {
    EVP_MD_CTX* sha512 = nullptr;
    EVP_MD_CTX* sha3_256 = nullptr;
    bool finalized = false;

    ~Impl() {
        if (sha512 != nullptr) {
            EVP_MD_CTX_free(sha512);
        }
        if (sha3_256 != nullptr) {
            EVP_MD_CTX_free(sha3_256);
        }
    }
};

ArchiveIntegrityAccumulator::ArchiveIntegrityAccumulator()
    : impl_(new Impl()) {
    impl_->sha512 = EVP_MD_CTX_new();
    impl_->sha3_256 = EVP_MD_CTX_new();
    if (impl_->sha512 == nullptr || impl_->sha3_256 == nullptr) {
        throw std::runtime_error("Failed to initialize archive integrity context");
    }

    if (EVP_DigestInit_ex(impl_->sha512, EVP_sha512(), nullptr) != 1 ||
        EVP_DigestInit_ex(impl_->sha3_256, EVP_sha3_256(), nullptr) != 1) {
        throw std::runtime_error("Failed to initialize archive integrity digests");
    }
}

ArchiveIntegrityAccumulator::~ArchiveIntegrityAccumulator() {
    delete impl_;
    impl_ = nullptr;
}

void ArchiveIntegrityAccumulator::Update(const void* data, size_t size) {
    if (impl_ == nullptr || impl_->finalized) {
        throw std::runtime_error("Archive integrity context is not available");
    }
    if (size == 0) {
        return;
    }

    if (EVP_DigestUpdate(impl_->sha512, data, size) != 1 ||
        EVP_DigestUpdate(impl_->sha3_256, data, size) != 1) {
        throw std::runtime_error("Failed to update archive integrity digests");
    }
}

ArchiveIntegrityDigests ArchiveIntegrityAccumulator::Finalize() {
    if (impl_ == nullptr || impl_->finalized) {
        throw std::runtime_error("Archive integrity was already finalized");
    }

    ArchiveIntegrityDigests digests;
    unsigned int sha512Length = 0;
    unsigned int sha3Length = 0;
    if (EVP_DigestFinal_ex(impl_->sha512, digests.sha512.data(), &sha512Length) != 1 ||
        EVP_DigestFinal_ex(impl_->sha3_256, digests.sha3_256.data(), &sha3Length) != 1) {
        throw std::runtime_error("Failed to finalize archive integrity digests");
    }
    if (sha512Length != kSha512DigestSize || sha3Length != kSha3_256DigestSize) {
        throw std::runtime_error("Archive integrity digest size is invalid");
    }

    impl_->finalized = true;
    return digests;
}

ArchiveIntegrityDigests ComputeArchiveIntegrityDigests(const uint8_t* data, size_t size) {
    ArchiveIntegrityAccumulator accumulator;
    if (size > 0) {
        accumulator.Update(data, size);
    }
    return accumulator.Finalize();
}

bool DigestsEqual(const uint8_t* left, const uint8_t* right, size_t size) {
    if (size == 0) {
        return true;
    }
    return CRYPTO_memcmp(left, right, size) == 0;
}

} // namespace winzox::archive::integrity
