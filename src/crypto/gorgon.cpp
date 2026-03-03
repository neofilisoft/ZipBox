#include "crypto/gorgon.hpp"

#include "crypto/key_derivation.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <openssl/evp.h>
#include <nettle/serpent.h>

namespace zipbox::crypto {

namespace {

constexpr size_t kBlockSize = 16;

int ToOpenSslSize(size_t size) {
    if (size > static_cast<size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("Data block is too large for OpenSSL");
    }
    return static_cast<int>(size);
}

std::vector<uint8_t> TransformAes256Cbc(const std::vector<uint8_t>& input,
                                        const std::vector<unsigned char>& key,
                                        const std::vector<unsigned char>& iv,
                                        bool encrypt) {
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("Failed to create OpenSSL cipher context");
    }

    std::vector<uint8_t> output(input.size() + EVP_MAX_BLOCK_LENGTH);
    int produced = 0;
    int finalBytes = 0;

    const int initResult = encrypt
        ? EVP_EncryptInit_ex(context, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())
        : EVP_DecryptInit_ex(context, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    if (initResult != 1) {
        EVP_CIPHER_CTX_free(context);
        throw std::runtime_error("Failed to initialize cipher");
    }

    const int updateResult = encrypt
        ? EVP_EncryptUpdate(context, output.data(), &produced, input.data(), ToOpenSslSize(input.size()))
        : EVP_DecryptUpdate(context, output.data(), &produced, input.data(), ToOpenSslSize(input.size()));
    if (updateResult != 1) {
        EVP_CIPHER_CTX_free(context);
        throw std::runtime_error(encrypt ? "Encryption update failed" : "Decryption update failed");
    }

    const int finalResult = encrypt
        ? EVP_EncryptFinal_ex(context, output.data() + produced, &finalBytes)
        : EVP_DecryptFinal_ex(context, output.data() + produced, &finalBytes);
    if (finalResult != 1) {
        EVP_CIPHER_CTX_free(context);
        throw std::runtime_error(encrypt ? "Encryption finalization failed" : "Failed to decrypt archive payload");
    }

    EVP_CIPHER_CTX_free(context);
    output.resize(static_cast<size_t>(produced + finalBytes));
    return output;
}

std::vector<uint8_t> AddPkcs7Padding(const std::vector<uint8_t>& input) {
    const uint8_t paddingSize = static_cast<uint8_t>(kBlockSize - (input.size() % kBlockSize));
    std::vector<uint8_t> output = input;
    output.insert(output.end(), paddingSize, paddingSize);
    return output;
}

std::vector<uint8_t> RemovePkcs7Padding(const std::vector<uint8_t>& input) {
    if (input.empty() || input.size() % kBlockSize != 0) {
        throw std::runtime_error("Invalid PKCS#7 padded block");
    }

    const uint8_t paddingSize = input.back();
    if (paddingSize == 0 || paddingSize > kBlockSize || paddingSize > input.size()) {
        throw std::runtime_error("Invalid PKCS#7 padding");
    }

    for (size_t index = input.size() - paddingSize; index < input.size(); ++index) {
        if (input[index] != paddingSize) {
            throw std::runtime_error("Invalid PKCS#7 padding");
        }
    }

    return std::vector<uint8_t>(input.begin(), input.end() - paddingSize);
}

void XorBlock(std::array<uint8_t, kBlockSize>& block, const std::array<uint8_t, kBlockSize>& mask) {
    for (size_t index = 0; index < kBlockSize; ++index) {
        block[index] ^= mask[index];
    }
}

std::vector<uint8_t> TransformSerpent256Cbc(const std::vector<uint8_t>& input,
                                            const std::vector<unsigned char>& key,
                                            const std::vector<unsigned char>& iv,
                                            bool encrypt) {
    if (key.size() != SERPENT_KEY_SIZE || iv.size() != SERPENT_BLOCK_SIZE) {
        throw std::runtime_error("Invalid Serpent-256-CBC key or IV size");
    }

    serpent_ctx context {};
    serpent256_set_key(&context, key.data());

    if (encrypt) {
        const std::vector<uint8_t> padded = AddPkcs7Padding(input);
        std::vector<uint8_t> output(padded.size());

        std::array<uint8_t, kBlockSize> previous {};
        std::copy(iv.begin(), iv.end(), previous.begin());

        for (size_t offset = 0; offset < padded.size(); offset += kBlockSize) {
            std::array<uint8_t, kBlockSize> block {};
            std::copy(padded.begin() + static_cast<std::ptrdiff_t>(offset),
                      padded.begin() + static_cast<std::ptrdiff_t>(offset + kBlockSize),
                      block.begin());
            XorBlock(block, previous);
            serpent_encrypt(&context, kBlockSize, output.data() + offset, block.data());
            std::copy(output.begin() + static_cast<std::ptrdiff_t>(offset),
                      output.begin() + static_cast<std::ptrdiff_t>(offset + kBlockSize),
                      previous.begin());
        }

        return output;
    }

    if (input.empty() || input.size() % kBlockSize != 0) {
        throw std::runtime_error("Invalid Serpent-256-CBC payload size");
    }

    std::vector<uint8_t> output(input.size());
    std::array<uint8_t, kBlockSize> previous {};
    std::copy(iv.begin(), iv.end(), previous.begin());

    for (size_t offset = 0; offset < input.size(); offset += kBlockSize) {
        std::array<uint8_t, kBlockSize> plainBlock {};
        serpent_decrypt(&context, kBlockSize, plainBlock.data(), input.data() + offset);
        XorBlock(plainBlock, previous);
        std::copy(plainBlock.begin(), plainBlock.end(), output.begin() + static_cast<std::ptrdiff_t>(offset));
        std::copy(input.begin() + static_cast<std::ptrdiff_t>(offset),
                  input.begin() + static_cast<std::ptrdiff_t>(offset + kBlockSize),
                  previous.begin());
    }

    return RemovePkcs7Padding(output);
}

size_t PaddedCipherSize(size_t plainSize) {
    return ((plainSize / kBlockSize) + 1) * kBlockSize;
}

std::vector<unsigned char> SecondarySalt(const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> derived = salt;
    std::reverse(derived.begin(), derived.end());
    for (size_t index = 0; index < derived.size(); ++index) {
        derived[index] ^= static_cast<unsigned char>(0x5Au + static_cast<unsigned char>(index));
    }
    return derived;
}

} // namespace

std::vector<uint8_t> EncryptGorgon(const std::vector<uint8_t>& plainText,
                                   const std::string& password,
                                   const EncryptionMetadata& metadata) {
    const size_t midpoint = plainText.size() / 2;
    const std::vector<uint8_t> firstHalf(plainText.begin(), plainText.begin() + static_cast<std::ptrdiff_t>(midpoint));
    const std::vector<uint8_t> secondHalf(plainText.begin() + static_cast<std::ptrdiff_t>(midpoint), plainText.end());

    const std::vector<unsigned char> aesKey = DeriveKey(password, metadata.salt);
    const std::vector<unsigned char> serpentKey = DeriveKey(password, SecondarySalt(metadata.salt));

    const std::vector<uint8_t> firstCipher = TransformAes256Cbc(firstHalf, aesKey, metadata.ivPrimary, true);
    const std::vector<uint8_t> secondCipher = TransformSerpent256Cbc(secondHalf, serpentKey, metadata.ivSecondary, true);

    std::vector<uint8_t> joined;
    joined.reserve(firstCipher.size() + secondCipher.size());
    joined.insert(joined.end(), firstCipher.begin(), firstCipher.end());
    joined.insert(joined.end(), secondCipher.begin(), secondCipher.end());
    return joined;
}

std::vector<uint8_t> DecryptGorgon(const std::vector<uint8_t>& cipherText,
                                   const std::string& password,
                                   const EncryptionMetadata& metadata,
                                   uint64_t plainTextSize) {
    const size_t firstPlainSize = static_cast<size_t>(plainTextSize / 2);
    const size_t firstCipherSize = PaddedCipherSize(firstPlainSize);
    if (cipherText.size() < firstCipherSize) {
        throw std::runtime_error("Gorgon payload is truncated");
    }

    const std::vector<uint8_t> firstCipher(cipherText.begin(), cipherText.begin() + static_cast<std::ptrdiff_t>(firstCipherSize));
    const std::vector<uint8_t> secondCipher(cipherText.begin() + static_cast<std::ptrdiff_t>(firstCipherSize), cipherText.end());

    const std::vector<unsigned char> aesKey = DeriveKey(password, metadata.salt);
    const std::vector<unsigned char> serpentKey = DeriveKey(password, SecondarySalt(metadata.salt));

    const std::vector<uint8_t> firstPlain = TransformAes256Cbc(firstCipher, aesKey, metadata.ivPrimary, false);
    const std::vector<uint8_t> secondPlain = TransformSerpent256Cbc(secondCipher, serpentKey, metadata.ivSecondary, false);

    if (firstPlain.size() + secondPlain.size() != plainTextSize) {
        throw std::runtime_error("Gorgon payload length mismatch");
    }

    std::vector<uint8_t> joined;
    joined.reserve(firstPlain.size() + secondPlain.size());
    joined.insert(joined.end(), firstPlain.begin(), firstPlain.end());
    joined.insert(joined.end(), secondPlain.begin(), secondPlain.end());
    return joined;
}

} // namespace zipbox::crypto
