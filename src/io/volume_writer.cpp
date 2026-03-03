#include "io/volume_writer.hpp"

#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace zipbox::io {

VolumeWriter::VolumeWriter(const std::string& basePath, size_t splitSize)
    : basePath_(basePath), splitSize_(splitSize), currentSize_(0), volumeIndex_(0) {
    OpenNextVolume();
}

VolumeWriter::~VolumeWriter() {
    Close();
}

std::string VolumeWriter::NextFileName() const {
    if (volumeIndex_ == 0) {
        return basePath_ + ".zox";
    }

    std::ostringstream name;
    name << basePath_ << ".z" << std::setw(2) << std::setfill('0') << volumeIndex_;
    return name.str();
}

void VolumeWriter::OpenNextVolume() {
    if (output_.is_open()) {
        output_.close();
    }

    const std::string name = NextFileName();
    output_.open(name, std::ios::binary);
    if (!output_) {
        throw std::runtime_error("Cannot create volume file: " + name);
    }

    currentSize_ = 0;
    ++volumeIndex_;
}

void VolumeWriter::Write(const char* data, size_t size) {
    if (splitSize_ > 0 && currentSize_ + size > splitSize_) {
        const size_t spaceLeft = splitSize_ - currentSize_;
        if (spaceLeft > 0) {
            output_.write(data, static_cast<std::streamsize>(spaceLeft));
        }

        OpenNextVolume();
        Write(data + spaceLeft, size - spaceLeft);
        return;
    }

    output_.write(data, static_cast<std::streamsize>(size));
    currentSize_ += size;
}

void VolumeWriter::Close() {
    if (output_.is_open()) {
        output_.close();
    }
}

} // namespace zipbox::io
