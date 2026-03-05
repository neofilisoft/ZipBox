#include "archive/archive.hpp"
#include "compression/compressor.hpp"
#include "extraction/extractor.hpp"
#include "shell/windows_shell.hpp"
#include "utils/path_utils.hpp"

#include <cctype>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

namespace {

enum class ArchiveFormat {
    Zox,
    Zip,
};

struct Args {
    std::string command;
    std::vector<std::string> positional;
    std::string password;
    winzox::crypto::EncryptionAlgorithm encryptionAlgorithm = winzox::crypto::EncryptionAlgorithm::Aes256;
    bool encryptionAlgorithmExplicit = false;
    ArchiveFormat archiveFormat = ArchiveFormat::Zox;
    size_t splitSize = 0;
    int zstdLevel = 9;
    int zlibLevel = 9;
    int lzmaLevel = 6;
    uint32_t threadCount = 0;
    bool speedPresetExplicit = false;
    winzox::compression::CompressionAlgorithm defaultAlgorithm = winzox::compression::CompressionAlgorithm::Zstd;
    bool defaultAlgorithmExplicit = false;
    std::string comment;
    std::vector<winzox::archive::FileCompressionOverride> fileOverrides;
    bool valid = false;
    std::string error;
};

#ifdef _WIN32
bool g_hasConsole = false;

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return std::wstring();
    }

    const int wideLength = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (wideLength <= 0) {
        throw std::runtime_error("Unable to convert UTF-8 text to UTF-16");
    }

    std::wstring wide(static_cast<size_t>(wideLength), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, wide.data(), wideLength);
    wide.pop_back();
    return wide;
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return std::string();
    }

    const int utf8Length = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8Length <= 0) {
        throw std::runtime_error("Unable to convert UTF-16 text to UTF-8");
    }

    std::string utf8(static_cast<size_t>(utf8Length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, utf8.data(), utf8Length, nullptr, nullptr);
    utf8.pop_back();
    return utf8;
}

void TryAttachParentConsole() {
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        return;
    }

    g_hasConsole = true;
    std::freopen("CONIN$", "r", stdin);
    std::freopen("CONOUT$", "w", stdout);
    std::freopen("CONOUT$", "w", stderr);
    std::ios::sync_with_stdio();
}

std::vector<std::string> CollectWindowsArgs() {
    int argc = 0;
    LPWSTR* argvWide = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argvWide == nullptr) {
        throw std::runtime_error("Unable to read the Windows command line");
    }

    std::vector<std::string> argv;
    argv.reserve(static_cast<size_t>(argc));
    for (int index = 0; index < argc; ++index) {
        argv.push_back(WideToUtf8(argvWide[index]));
    }

    LocalFree(argvWide);
    return argv;
}

void ShowMessage(const std::string& title, const std::string& message, UINT icon) {
    MessageBoxW(nullptr,
                Utf8ToWide(message).c_str(),
                Utf8ToWide(title).c_str(),
                MB_OK | icon);
}
#endif

std::string NormalizeCommand(const std::string& value) {
    const std::string lower = winzox::utils::ToLower(value);
    if (lower == "add" || lower == "a" || lower == "c-zox") return "add";
    if (lower == "extract" || lower == "x") return "extract";
    if (lower == "list" || lower == "l") return "list";
    if (lower == "test" || lower == "t") return "test";
    if (lower == "shell-add") return "shell-add";
    if (lower == "shell-quick-zox") return "shell-quick-zox";
    if (lower == "shell-browse") return "shell-browse";
    if (lower == "shell-extract-files") return "shell-extract-files";
    if (lower == "shell-extract") return "shell-extract";
    if (lower == "shell-extract-here") return "shell-extract-here";
    if (lower == "help" || lower == "-h" || lower == "--help") return "help";
    return lower;
}

size_t ParseSplitSize(const std::string& value) {
    if (value.empty()) {
        throw std::runtime_error("Split size cannot be empty");
    }

    unsigned long long multiplier = 1;
    std::string numberPart = value;
    const char suffix = static_cast<char>(std::tolower(static_cast<unsigned char>(value.back())));
    if (std::isalpha(static_cast<unsigned char>(suffix))) {
        numberPart.pop_back();
        switch (suffix) {
        case 'k':
            multiplier = 1024ULL;
            break;
        case 'm':
            multiplier = 1024ULL * 1024ULL;
            break;
        case 'g':
            multiplier = 1024ULL * 1024ULL * 1024ULL;
            break;
        default:
            throw std::runtime_error("Unsupported split size suffix. Use k, m, or g");
        }
    }

    const unsigned long long amount = std::stoull(numberPart);
    if (amount > (std::numeric_limits<size_t>::max)() / multiplier) {
        throw std::runtime_error("Split size is too large");
    }

    return static_cast<size_t>(amount * multiplier);
}

ArchiveFormat ParseArchiveFormat(const std::string& value) {
    const std::string lower = winzox::utils::ToLower(value);
    if (lower == "zox") {
        return ArchiveFormat::Zox;
    }
    if (lower == "zip") {
        return ArchiveFormat::Zip;
    }
    throw std::runtime_error("Unsupported archive format: " + value);
}

winzox::archive::FileCompressionOverride ParseFileOverride(const std::string& value) {
    const size_t separator = value.find('=');
    if (separator == std::string::npos || separator == 0 || separator + 1 >= value.size()) {
        throw std::runtime_error("Invalid --file-algo format. Use <relative_path>=<algorithm>");
    }

    winzox::archive::FileCompressionOverride overrideEntry;
    overrideEntry.relativePath = value.substr(0, separator);
    overrideEntry.algorithm = winzox::compression::ParseAlgorithmName(value.substr(separator + 1));
    return overrideEntry;
}

int ParseZstdSpeedPreset(const std::string& value) {
    std::string lower = value;
    for (char& ch : lower) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }

    if (lower == "fast") {
        return 4;
    }
    if (lower == "normal") {
        return 10;
    }
    if (lower == "maximum" || lower == "max") {
        return 18;
    }
    if (lower == "ultra") {
        return 26;
    }

    throw std::runtime_error("Unsupported speed preset: " + value);
}

std::string FormatTimestamp(uint64_t unixTime) {
    if (unixTime == 0) {
        return "n/a";
    }

    const std::time_t raw = static_cast<std::time_t>(unixTime);
    std::tm* local = std::localtime(&raw);
    if (local == nullptr) {
        return "n/a";
    }

    std::ostringstream out;
    out << std::put_time(local, "%Y-%m-%d %H:%M:%S");
    return out.str();
}

bool IsCanceledError(const std::exception& error) {
    return std::string(error.what()) == "Operation canceled";
}

void PrintUsage() {
    std::cout << "WinZOX v2.02.1 - Modular Archiver\n";
    std::cout << "Usage:\n";
    std::cout << "  zox add <input_path> <output_base> [options]\n";
    std::cout << "  zox extract <archive_file> <output_folder> [-p password]\n";
    std::cout << "  zox list <archive_file> [-p password]\n";
    std::cout << "  zox test <archive_file> [-p password]\n";
    std::cout << "  zox shell-add <target_path>\n";
    std::cout << "  zox shell-browse <archive_file>\n";
    std::cout << "  zox shell-extract-files <archive_file>\n";
    std::cout << "\n";
    std::cout << "Options for add:\n";
    std::cout << "  --format <zox|zip>         Output archive format (default: zox)\n";
    std::cout << "  -p <password>              Encrypt the archive\n";
    std::cout << "  --encrypt <aes|gorgon>     Select the encryption algorithm when -p is used\n";
    std::cout << "  -s <size>                  Split size in bytes or with k/m/g suffix\n";
    std::cout << "  --algo <zstd|zlib|lz4|lzma2|store>   Default algorithm for the whole archive\n";
    std::cout << "  --preset <fast|normal|maximum|ultra>  Zstd speed preset ranges: 3-5 / 8-12 / 15-20 / 22-30\n";
    std::cout << "  --file-algo <path=algo>    Override the algorithm for one relative path\n";
    std::cout << "  --zstd-level <int>         Zstd compression level (default: 9)\n";
    std::cout << "  --zlib-level <0-9>         Zlib compression level (default: 9)\n";
    std::cout << "  --lzma-level <0-9>         LZMA2 compression level (default: 6)\n";
    std::cout << "  --threads <n>              Thread count for LZ4/LZMA2 (0 = auto)\n";
    std::cout << "  --comment <text>           Archive comment / metadata note\n";
}

void PrintArchiveInfo(const winzox::archive::ArchiveMetadata& metadata) {
    std::cout << "Format: .zox\n";
    std::cout << "Encrypted: " << (metadata.encrypted ? "yes" : "no") << "\n";
    std::cout << "Authenticated: " << (metadata.authenticated ? "yes" : "no") << "\n";
    std::cout << "Integrity SHA-512: " << (metadata.integritySha512 ? "yes" : "no") << "\n";
    std::cout << "Integrity SHA3-256: " << (metadata.integritySha3_256 ? "yes" : "no") << "\n";
    std::cout << "Solid: " << (metadata.solid ? "yes" : "no") << "\n";
    std::cout << "Encryption mode: " << winzox::crypto::EncryptionAlgorithmName(metadata.encryptionAlgorithm) << "\n";
    std::cout << "Default algorithm: " << winzox::compression::AlgorithmName(metadata.defaultAlgorithm) << "\n";
    std::cout << "Created: " << FormatTimestamp(metadata.createdUnixTime) << "\n";
    if (!metadata.comment.empty()) {
        std::cout << "Comment: " << metadata.comment << "\n";
    }
}

void PrintArchiveEntries(const std::vector<winzox::archive::ArchiveEntryInfo>& entries) {
    if (entries.empty()) {
        std::cout << "Archive is empty.\n";
        return;
    }

    std::cout << std::left
              << std::setw(10) << "Algo"
              << std::setw(14) << "Stored"
              << std::setw(14) << "Original"
              << std::setw(12) << "CRC32"
              << "Path\n";

    for (const auto& entry : entries) {
        std::ostringstream crc;
        crc << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << entry.crc32;
        std::cout << std::left
                  << std::setfill(' ')
                  << std::setw(10) << winzox::compression::AlgorithmName(entry.algorithm)
                  << std::setw(14) << entry.storedSize
                  << std::setw(14) << entry.originalSize
                  << std::setw(12) << crc.str()
                  << entry.path << "\n";
    }
}

Args ParseArgs(const std::vector<std::string>& argv) {
    Args args;
    if (argv.size() < 2) {
        args.error = "Missing command.";
        return args;
    }

    args.command = NormalizeCommand(argv[1]);
    if (args.command == "help") {
        args.valid = true;
        return args;
    }

    try {
        for (size_t index = 2; index < argv.size(); ++index) {
            const std::string token = argv[index];

            if (token == "-p") {
                if (index + 1 >= argv.size()) {
                    args.error = "Missing value for -p";
                    return args;
                }
                args.password = argv[++index];
            } else if (token == "--encrypt") {
                if (index + 1 >= argv.size()) {
                    args.error = "Missing value for --encrypt";
                    return args;
                }
                args.encryptionAlgorithm = winzox::crypto::ParseEncryptionAlgorithmName(argv[++index]);
                args.encryptionAlgorithmExplicit = true;
            } else if (token == "--format") {
                if (index + 1 >= argv.size()) {
                    args.error = "Missing value for --format";
                    return args;
                }
                args.archiveFormat = ParseArchiveFormat(argv[++index]);
            } else if (token == "-s") {
                if (index + 1 >= argv.size()) {
                    args.error = "Missing value for -s";
                    return args;
                }
                args.splitSize = ParseSplitSize(argv[++index]);
            } else if (token == "--algo") {
                if (index + 1 >= argv.size()) {
                    args.error = "Missing value for --algo";
                    return args;
                }
                args.defaultAlgorithm = winzox::compression::ParseAlgorithmName(argv[++index]);
                args.defaultAlgorithmExplicit = true;
            } else if (token == "--preset") {
                if (index + 1 >= argv.size()) {
                    args.error = "Missing value for --preset";
                    return args;
                }
                args.zstdLevel = ParseZstdSpeedPreset(argv[++index]);
                args.speedPresetExplicit = true;
            } else if (token == "--file-algo") {
                if (index + 1 >= argv.size()) {
                    args.error = "Missing value for --file-algo";
                    return args;
                }
                args.fileOverrides.push_back(ParseFileOverride(argv[++index]));
            } else if (token == "--zstd-level") {
                if (index + 1 >= argv.size()) {
                    args.error = "Missing value for --zstd-level";
                    return args;
                }
                args.zstdLevel = std::stoi(argv[++index]);
            } else if (token == "--zlib-level") {
                if (index + 1 >= argv.size()) {
                    args.error = "Missing value for --zlib-level";
                    return args;
                }
                args.zlibLevel = std::stoi(argv[++index]);
            } else if (token == "--lzma-level") {
                if (index + 1 >= argv.size()) {
                    args.error = "Missing value for --lzma-level";
                    return args;
                }
                args.lzmaLevel = std::stoi(argv[++index]);
            } else if (token == "--threads") {
                if (index + 1 >= argv.size()) {
                    args.error = "Missing value for --threads";
                    return args;
                }
                args.threadCount = static_cast<uint32_t>(std::stoul(argv[++index]));
            } else if (token == "--comment") {
                if (index + 1 >= argv.size()) {
                    args.error = "Missing value for --comment";
                    return args;
                }
                args.comment = argv[++index];
            } else if (!token.empty() && token.front() == '-') {
                args.error = "Unknown option: " + token;
                return args;
            } else {
                args.positional.push_back(token);
            }
        }
    } catch (const std::exception& error) {
        args.error = error.what();
        return args;
    }

    const size_t positionalCount = args.positional.size();
    if (args.command == "add" || args.command == "extract") {
        args.valid = positionalCount == 2;
    } else if (args.command == "shell-add" ||
               args.command == "shell-quick-zox" ||
               args.command == "shell-browse") {
        args.valid = positionalCount >= 1;
    } else if (args.command == "shell-extract-files") {
        args.valid = positionalCount == 1;
    } else if (args.command == "shell-extract" ||
               args.command == "shell-extract-here") {
        args.valid = positionalCount == 1;
    } else if (args.command == "list" || args.command == "test") {
        args.valid = positionalCount == 1;
    } else {
        args.error = "Unknown command: " + args.command;
        return args;
    }

    if (!args.valid) {
        args.error = "Invalid arguments for command: " + args.command;
    }

    if (args.zlibLevel < 0 || args.zlibLevel > 9) {
        args.valid = false;
        args.error = "Zlib level must be between 0 and 9";
    }
    if (args.lzmaLevel < 0 || args.lzmaLevel > 9) {
        args.valid = false;
        args.error = "LZMA2 level must be between 0 and 9";
    }

    if (args.command == "add" && args.password.empty() && args.encryptionAlgorithmExplicit) {
        args.valid = false;
        args.error = "--encrypt requires -p <password>";
    }

    if (args.command == "add" &&
        !args.password.empty() &&
        args.encryptionAlgorithm == winzox::crypto::EncryptionAlgorithm::None) {
        args.valid = false;
        args.error = "--encrypt must be aes or gorgon when -p is used";
    }

    if (args.command != "add" && args.encryptionAlgorithmExplicit) {
        args.valid = false;
        args.error = "--encrypt is only valid with the add command";
    }

    if (args.command != "add" && args.speedPresetExplicit) {
        args.valid = false;
        args.error = "--preset is only valid with the add command";
    }

    if (args.command == "add" && args.archiveFormat == ArchiveFormat::Zip) {
        if (!args.defaultAlgorithmExplicit) {
            args.defaultAlgorithm = winzox::compression::CompressionAlgorithm::Zlib;
        }

        if (args.defaultAlgorithm != winzox::compression::CompressionAlgorithm::Store &&
            args.defaultAlgorithm != winzox::compression::CompressionAlgorithm::Zlib) {
            args.valid = false;
            args.error = "ZIP supports only --algo zlib or --algo store";
        }

        if (!args.password.empty()) {
            args.valid = false;
            args.error = "ZIP creation does not support -p/--encrypt in this version";
        }

        if (args.splitSize != 0) {
            args.valid = false;
            args.error = "ZIP creation does not support split volumes in this version";
        }

        if (!args.comment.empty()) {
            args.valid = false;
            args.error = "ZIP creation does not support --comment in this version";
        }

        if (!args.fileOverrides.empty()) {
            args.valid = false;
            args.error = "ZIP creation does not support --file-algo in this version";
        }

        if (args.speedPresetExplicit) {
            args.valid = false;
            args.error = "ZIP creation does not use zstd speed presets";
        }
    }

    if (args.command == "add" &&
        args.speedPresetExplicit &&
        args.defaultAlgorithm != winzox::compression::CompressionAlgorithm::Zstd) {
        args.valid = false;
        args.error = "--preset requires --algo zstd";
    }

    return args;
}

} // namespace

int RunApp(const std::vector<std::string>& argv) {
    const Args args = ParseArgs(argv);

    if (!args.valid || args.command == "help") {
        if (!args.error.empty()) {
#ifdef _WIN32
            if (!g_hasConsole) {
                ShowMessage("WinZOX", args.error + "\n\nUse the command line for help output.", MB_ICONERROR);
                return 1;
            }
#endif
            std::cerr << args.error << "\n\n";
        }
        PrintUsage();
        return args.command == "help" ? 0 : 1;
    }

    try {
        if (args.command == "add") {
            winzox::archive::WinZOXConfig config;
            config.password = args.password;
            config.encryptionAlgorithm = args.encryptionAlgorithm;
            config.splitSize = args.splitSize;
            config.zstdLevel = args.zstdLevel;
            config.zlibLevel = args.zlibLevel;
            config.lzmaLevel = args.lzmaLevel;
            config.threadCount = args.threadCount;
            config.defaultAlgorithm = args.defaultAlgorithm;
            config.comment = args.comment;
            config.fileOverrides = args.fileOverrides;

            if (args.archiveFormat == ArchiveFormat::Zip) {
                winzox::archive::CreateZipArchive(args.positional[0], args.positional[1], config);
            } else {
                winzox::archive::CreateArchive(args.positional[0], args.positional[1], config);
            }
        } else if (args.command == "extract") {
            winzox::extraction::ExtractArchive(args.positional[0], args.positional[1], args.password);
        } else if (args.command == "list") {
            if (winzox::archive::LooksLikeZoxArchive(args.positional[0])) {
                PrintArchiveInfo(winzox::extraction::GetArchiveMetadata(args.positional[0], args.password));
            }
            PrintArchiveEntries(winzox::extraction::ListArchiveEntries(args.positional[0], args.password));
        } else if (args.command == "test") {
            winzox::extraction::TestArchive(args.positional[0], args.password);
            std::cout << "Archive passed integrity checks.\n";
        } else if (args.command == "shell-add") {
            winzox::shell::RunShellAddDialog(args.positional);
        } else if (args.command == "shell-quick-zox") {
            winzox::shell::RunQuickAddZox(args.positional);
        } else if (args.command == "shell-browse") {
            winzox::shell::RunShellBrowse(args.positional[0]);
        } else if (args.command == "shell-extract-files") {
            winzox::shell::RunShellExtractFiles(args.positional[0]);
        } else if (args.command == "shell-extract") {
            winzox::shell::RunShellExtract(args.positional[0], false);
        } else if (args.command == "shell-extract-here") {
            winzox::shell::RunShellExtract(args.positional[0], true);
        }
    } catch (const std::exception& error) {
#ifdef _WIN32
        if (IsCanceledError(error)) {
            return 1;
        }
        if (!g_hasConsole) {
            ShowMessage("WinZOX", "Error: " + std::string(error.what()), MB_ICONERROR);
            return 1;
        }
#endif
        std::cerr << "Error: " << error.what() << "\n";
        return 1;
    }

    return 0;
}

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    try {
        TryAttachParentConsole();
        return RunApp(CollectWindowsArgs());
    } catch (const std::exception& error) {
        if (IsCanceledError(error)) {
            return 1;
        }
        if (!g_hasConsole) {
            ShowMessage("WinZOX", "Error: " + std::string(error.what()), MB_ICONERROR);
            return 1;
        }

        std::cerr << "Error: " << error.what() << "\n";
        return 1;
    }
}
#else
int main(int argc, char* argv[]) {
    std::vector<std::string> argvValues;
    argvValues.reserve(static_cast<size_t>(argc));
    for (int index = 0; index < argc; ++index) {
        argvValues.emplace_back(argv[index]);
    }
    return RunApp(argvValues);
}
#endif
