#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace winzox::compression::dictionary {

size_t NormalizeDictionarySize(size_t requestedSize, size_t inputSize);

class DictionaryWindow {
public:
    explicit DictionaryWindow(size_t requestedSize = 0);

    [[nodiscard]] size_t Capacity() const;
    [[nodiscard]] bool Empty() const;
    [[nodiscard]] std::vector<uint8_t> Snapshot() const;
    void Reset();
    void Append(const std::vector<uint8_t>& bytes);

private:
    size_t capacity_ = 0;
    std::vector<uint8_t> history_;
};

} // namespace winzox::compression::dictionary

