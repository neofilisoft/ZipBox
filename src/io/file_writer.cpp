#include "io/file_writer.hpp"

#include <fstream>
#include <stdexcept>

namespace zipbox::io {

void WriteFileBytes(const std::filesystem::path& path, const std::vector<uint8_t>& data) {
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }

    std::ofstream output(path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("Cannot create output file: " + path.string());
    }

    if (!data.empty()) {
        output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
}

} // namespace zipbox::io
