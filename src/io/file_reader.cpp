#include "io/file_reader.hpp"

#include <algorithm>
#include <fstream>
#include <stdexcept>

namespace zipbox::io {

std::vector<std::filesystem::path> CollectInputFiles(const std::filesystem::path& inputPath) {
    namespace fs = std::filesystem;

    if (!fs::exists(inputPath)) {
        throw std::runtime_error("Input path does not exist: " + inputPath.string());
    }

    std::vector<fs::path> files;
    if (fs::is_regular_file(inputPath)) {
        files.push_back(inputPath);
    } else if (fs::is_directory(inputPath)) {
        for (const auto& entry : fs::recursive_directory_iterator(inputPath)) {
            if (entry.is_regular_file()) {
                files.push_back(entry.path());
            }
        }
    } else {
        throw std::runtime_error("Input path is neither a file nor a directory");
    }

    std::sort(files.begin(), files.end());
    return files;
}

std::vector<uint8_t> ReadFileBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw std::runtime_error("Cannot open file: " + path.string());
    }

    const std::streamsize rawSize = input.tellg();
    if (rawSize < 0) {
        throw std::runtime_error("Failed to determine file size: " + path.string());
    }

    const size_t size = static_cast<size_t>(rawSize);
    std::vector<uint8_t> data(size);
    input.seekg(0, std::ios::beg);
    if (size > 0) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));
        if (!input) {
            throw std::runtime_error("Failed to read file: " + path.string());
        }
    }

    return data;
}

} // namespace zipbox::io
