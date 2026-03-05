#include "crypto/auth/archive_authentication.hpp"

#include "crypto/key_derivation.hpp"

#include <stdexcept>
#include <utility>
#include <openssl/core_names.h>
#include <openssl/evp.h>

namespace winzox::crypto::auth {

namespace {

constexpr size_t kAuthenticationTagSize = 32;

} // namespace

struct ArchiveAuthenticator::Impl {
    EVP_MAC* mac = nullptr;
    EVP_MAC_CTX* ctx = nullptr;
    bool finalized = false;

    ~Impl() {
        if (ctx != nullptr) {
            EVP_MAC_CTX_free(ctx);
        }
        if (mac != nullptr) {
            EVP_MAC_free(mac);
        }
    }
};

ArchiveAuthenticator::ArchiveAuthenticator(const std::string& password,
                                           const std::vector<unsigned char>& salt,
                                           uint32_t iterations)
    : impl_(new Impl()) {
    if (password.empty()) {
        throw std::runtime_error("Password is required to verify archive authentication");
    }
    if (salt.empty()) {
        throw std::runtime_error("Archive authentication metadata is missing");
    }

    const std::vector<unsigned char> macKey = DeriveAuthenticationKey(password, salt, iterations);
    impl_->mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (impl_->mac == nullptr) {
        throw std::runtime_error("Failed to load HMAC provider");
    }

    impl_->ctx = EVP_MAC_CTX_new(impl_->mac);
    if (impl_->ctx == nullptr) {
        throw std::runtime_error("Failed to initialize archive authentication context");
    }

    char digestName[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digestName, 0),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_MAC_init(impl_->ctx, macKey.data(), macKey.size(), params) != 1) {
        throw std::runtime_error("Failed to initialize archive authentication key");
    }
}

ArchiveAuthenticator::~ArchiveAuthenticator() {
    delete impl_;
    impl_ = nullptr;
}

ArchiveAuthenticator::ArchiveAuthenticator(ArchiveAuthenticator&& other) noexcept
    : impl_(other.impl_) {
    other.impl_ = nullptr;
}

ArchiveAuthenticator& ArchiveAuthenticator::operator=(ArchiveAuthenticator&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    delete impl_;
    impl_ = other.impl_;
    other.impl_ = nullptr;
    return *this;
}

void ArchiveAuthenticator::Update(const void* data, size_t size) {
    if (impl_ == nullptr || impl_->ctx == nullptr) {
        throw std::runtime_error("Archive authentication context is not initialized");
    }
    if (impl_->finalized) {
        throw std::runtime_error("Archive authentication was already finalized");
    }
    if (size == 0) {
        return;
    }
    if (EVP_MAC_update(impl_->ctx, static_cast<const uint8_t*>(data), size) != 1) {
        throw std::runtime_error("Failed to update archive authentication state");
    }
}

std::vector<uint8_t> ArchiveAuthenticator::Finalize() {
    if (impl_ == nullptr || impl_->ctx == nullptr) {
        throw std::runtime_error("Archive authentication context is not initialized");
    }
    if (impl_->finalized) {
        throw std::runtime_error("Archive authentication was already finalized");
    }

    std::vector<uint8_t> tag(kAuthenticationTagSize);
    size_t tagLength = 0;
    if (EVP_MAC_final(impl_->ctx, tag.data(), &tagLength, tag.size()) != 1) {
        throw std::runtime_error("Failed to finalize archive authentication tag");
    }
    if (tagLength != kAuthenticationTagSize) {
        throw std::runtime_error("Archive authentication tag length is invalid");
    }

    impl_->finalized = true;
    return tag;
}

std::vector<uint8_t> ComputeArchiveAuthenticationTag(const uint8_t* data,
                                                     size_t dataSize,
                                                     const std::string& password,
                                                     const std::vector<unsigned char>& salt,
                                                     uint32_t iterations) {
    ArchiveAuthenticator authenticator(password, salt, iterations);
    if (dataSize > 0) {
        authenticator.Update(data, dataSize);
    }
    return authenticator.Finalize();
}

} // namespace winzox::crypto::auth
