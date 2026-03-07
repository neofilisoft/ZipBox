#include "compression/dictionary/dictionary_manager.hpp"

#include <algorithm>

namespace winzox::compression::dictionary {

namespace {

size_t RoundUpToPowerOfTwo(size_t value) {
    if (value <= 1) {
        return 1;
    }

    size_t rounded = 1;
    while (rounded < value) {
        rounded <<= 1;
    }
    return rounded;
}

} // namespace

size_t NormalizeDictionarySize(size_t requestedSize, size_t inputSize) {
    if (requestedSize == 0 || inputSize == 0) {
        return 0;
    }

    constexpr size_t kMinDictionarySize = 4 * 1024;
    constexpr size_t kMaxDictionarySize = 64 * 1024 * 1024;
    const size_t clamped = std::min(std::max(requestedSize, kMinDictionarySize), kMaxDictionarySize);
    return std::min(RoundUpToPowerOfTwo(clamped), inputSize);
}

DictionaryWindow::DictionaryWindow(size_t requestedSize)
    : capacity_(NormalizeDictionarySize(requestedSize, requestedSize == 0 ? 0 : requestedSize)) {
}

size_t DictionaryWindow::Capacity() const {
    return capacity_;
}

bool DictionaryWindow::Empty() const {
    return history_.empty();
}

std::vector<uint8_t> DictionaryWindow::Snapshot() const {
    return history_;
}

void DictionaryWindow::Reset() {
    history_.clear();
}

void DictionaryWindow::Append(const std::vector<uint8_t>& bytes) {
    if (capacity_ == 0 || bytes.empty()) {
        return;
    }

    if (bytes.size() >= capacity_) {
        history_.assign(bytes.end() - static_cast<std::ptrdiff_t>(capacity_), bytes.end());
        return;
    }

    if (history_.size() + bytes.size() > capacity_) {
        const size_t overflow = history_.size() + bytes.size() - capacity_;
        history_.erase(history_.begin(), history_.begin() + static_cast<std::ptrdiff_t>(overflow));
    }

    history_.insert(history_.end(), bytes.begin(), bytes.end());
}

} // namespace winzox::compression::dictionary

