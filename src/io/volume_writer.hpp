#pragma once

#include <cstddef>
#include <fstream>
#include <string>

namespace zipbox::io {

class VolumeWriter {
public:
    VolumeWriter(const std::string& basePath, size_t splitSize);
    ~VolumeWriter();

    void Write(const char* data, size_t size);
    void Close();

private:
    std::string NextFileName() const;
    void OpenNextVolume();

    std::string basePath_;
    size_t splitSize_;
    size_t currentSize_;
    int volumeIndex_;
    std::ofstream output_;
};

} // namespace zipbox::io
