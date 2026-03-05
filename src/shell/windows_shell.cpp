#include "shell/windows_shell_internal.hpp"

#ifdef _WIN32

#include "io/file_reader.hpp"

#include <algorithm>
#include <commctrl.h>

namespace winzox::shell::internal {

namespace {

std::wstring DefaultArchiveStem(const fs::path& targetPath) {
    if (fs::is_directory(targetPath)) {
        return targetPath.filename().wstring();
    }
    return targetPath.stem().wstring();
}

fs::path CommonSelectionParent(const std::vector<fs::path>& targets) {
    std::vector<fs::path> parents;
    parents.reserve(targets.size());
    for (const fs::path& target : targets) {
        fs::path parent = target.parent_path();
        if (parent.empty()) {
            parent = ".";
        }
        parents.push_back(fs::absolute(parent).lexically_normal());
    }

    std::vector<fs::path> sharedParts(parents.front().begin(), parents.front().end());
    for (size_t index = 1; index < parents.size() && !sharedParts.empty(); ++index) {
        const std::vector<fs::path> currentParts(parents[index].begin(), parents[index].end());
        size_t sharedCount = 0;
        while (sharedCount < sharedParts.size() &&
               sharedCount < currentParts.size() &&
               sharedParts[sharedCount] == currentParts[sharedCount]) {
            ++sharedCount;
        }
        sharedParts.resize(sharedCount);
    }

    fs::path result;
    for (const fs::path& part : sharedParts) {
        result /= part;
    }

    return result.empty() ? fs::current_path() : result;
}

bool TryAcquireArchivePassword(const std::string& archivePath, HWND owner, std::string& password) {
    if (!winzox::archive::LooksLikeZoxArchive(archivePath)) {
        password.clear();
        return true;
    }

    const winzox::archive::ArchiveMetadata metadata = winzox::archive::ReadArchiveMetadata(archivePath);
    if (!metadata.encrypted) {
        password.clear();
        return true;
    }

    return PromptForArchivePassword(owner, archivePath, password);
}

fs::path BuildAutoRenamePath(const fs::path& existingPath) {
    const fs::path parent = existingPath.parent_path();
    const std::wstring stem = existingPath.stem().wstring();
    const std::wstring extension = existingPath.extension().wstring();
    for (size_t index = 1; index <= 100000; ++index) {
        const fs::path candidate = parent / (stem + L" (" + std::to_wstring(index) + L")" + extension);
        if (!fs::exists(candidate)) {
            return candidate;
        }
    }

    throw std::runtime_error("Unable to generate a unique file name for renamed extraction");
}

int RunOverwritePrompt(HWND owner, const std::wstring& contentText) {
    TASKDIALOGCONFIG config {};
    config.cbSize = sizeof(config);
    config.hwndParent = owner;
    config.pszWindowTitle = L"WinZOX";
    config.pszMainInstruction = L"File already exists";
    config.pszContent = contentText.c_str();

    constexpr int kButtonReplace = 1001;
    constexpr int kButtonRename = 1002;
    constexpr int kButtonReplaceAll = 1003;
    TASKDIALOG_BUTTON buttons[] = {
        { kButtonReplace, L"Yes" },
        { kButtonRename, L"Rename" },
        { kButtonReplaceAll, L"Replace all" },
        { IDCANCEL, L"Cancel" },
    };

    config.cButtons = ARRAYSIZE(buttons);
    config.pButtons = buttons;
    config.nDefaultButton = kButtonReplace;
    config.dwFlags = TDF_POSITION_RELATIVE_TO_WINDOW;

    int selectedButton = IDCANCEL;
    using TaskDialogIndirectFn = HRESULT (WINAPI*)(const TASKDIALOGCONFIG*, int*, int*, BOOL*);
    HMODULE commonControls = LoadLibraryW(L"comctl32.dll");
    if (commonControls != nullptr) {
        const auto taskDialogIndirect =
            reinterpret_cast<TaskDialogIndirectFn>(GetProcAddress(commonControls, "TaskDialogIndirect"));
        if (taskDialogIndirect != nullptr &&
            SUCCEEDED(taskDialogIndirect(&config, &selectedButton, nullptr, nullptr))) {
            FreeLibrary(commonControls);
            return selectedButton;
        }
        FreeLibrary(commonControls);
    }

    const int fallback = MessageBoxW(owner,
                                     contentText.c_str(),
                                     L"WinZOX",
                                     MB_ICONWARNING | MB_YESNOCANCEL);
    if (fallback == IDYES) {
        return kButtonReplace;
    }
    if (fallback == IDNO) {
        return kButtonRename;
    }
    return IDCANCEL;
}

} // namespace

TargetCompressionStats AnalyzeInputTargets(const std::vector<fs::path>& targets) {
    TargetCompressionStats stats;
    std::vector<fs::path> files;

    for (const fs::path& target : targets) {
        std::vector<fs::path> targetFiles = io::CollectInputFiles(target);
        files.insert(files.end(), targetFiles.begin(), targetFiles.end());
    }

    std::sort(files.begin(), files.end());
    files.erase(std::unique(files.begin(), files.end()), files.end());

    stats.fileCount = files.size();
    for (const fs::path& file : files) {
        stats.totalBytes += fs::file_size(file);
    }
    return stats;
}

int ResolveAutoZstdLevel(ShellSpeedPreset preset, uint64_t totalBytes, size_t fileCount) {
    int minLevel = 8;
    int maxLevel = 12;
    switch (preset) {
    case ShellSpeedPreset::Fast:
        minLevel = 3;
        maxLevel = 5;
        break;
    case ShellSpeedPreset::Normal:
        minLevel = 8;
        maxLevel = 12;
        break;
    case ShellSpeedPreset::Maximum:
        minLevel = 15;
        maxLevel = 20;
        break;
    case ShellSpeedPreset::Ultra:
        minLevel = 22;
        maxLevel = 30;
        break;
    }

    size_t score = 0;
    if (totalBytes >= 16ULL * 1024ULL * 1024ULL) {
        ++score;
    }
    if (totalBytes >= 128ULL * 1024ULL * 1024ULL) {
        ++score;
    }
    if (totalBytes >= 1024ULL * 1024ULL * 1024ULL) {
        ++score;
    }
    if (totalBytes >= 8ULL * 1024ULL * 1024ULL * 1024ULL) {
        ++score;
    }
    if (fileCount >= 200) {
        ++score;
    }
    if (fileCount >= 2000) {
        ++score;
    }
    if (score > 5) {
        score = 5;
    }

    const int width = maxLevel - minLevel;
    const int level = minLevel + static_cast<int>((static_cast<double>(width) * static_cast<double>(score)) / 5.0 + 0.5);
    return std::clamp(level, minLevel, maxLevel);
}

winzox::extraction::OverwriteDecision PromptForOverwriteDecision(HWND owner,
                                                                 const fs::path& destinationRoot,
                                                                 const fs::path& existingPath,
                                                                 const std::string& archiveEntryPath) {
    (void)destinationRoot;
    (void)archiveEntryPath;
    const std::wstring content = L"\"" + existingPath.filename().wstring() +
        L"\" already exists in destination.\nChoose an action.";
    const int selectedButton = RunOverwritePrompt(owner, content);

    switch (selectedButton) {
    case 1001:
        return { winzox::extraction::OverwriteAction::Replace, {} };
    case 1002:
        return { winzox::extraction::OverwriteAction::Rename, BuildAutoRenamePath(existingPath).u8string() };
    case 1003:
        return { winzox::extraction::OverwriteAction::ReplaceAll, {} };
    default:
        return { winzox::extraction::OverwriteAction::Cancel, {} };
    }
}

std::vector<fs::path> NormalizeTargets(const std::vector<std::string>& targetPaths) {
    if (targetPaths.empty()) {
        throw std::runtime_error("Shell target list is empty");
    }

    std::vector<fs::path> targets;
    targets.reserve(targetPaths.size());
    for (const std::string& targetPath : targetPaths) {
        const fs::path target = fs::u8path(targetPath);
        if (!fs::exists(target)) {
            throw std::runtime_error("Shell target does not exist: " + targetPath);
        }
        targets.push_back(target);
    }

    return targets;
}

std::string DefaultZoxBasePath(const fs::path& targetPath) {
    if (fs::is_directory(targetPath)) {
        return targetPath.u8string();
    }

    return (targetPath.parent_path() / targetPath.stem()).u8string();
}

std::string DefaultZoxBasePath(const std::vector<fs::path>& targets) {
    if (targets.size() == 1) {
        return DefaultZoxBasePath(targets.front());
    }

    return (CommonSelectionParent(targets) / "Archive").u8string();
}

std::string DefaultExtractDestination(const fs::path& targetPath) {
    return (targetPath.parent_path() / targetPath.stem()).u8string();
}

void ExecuteShellExtraction(const std::string& archivePath,
                           const std::string& destination,
                           HWND owner) {
    std::string password;
    if (!TryAcquireArchivePassword(archivePath, owner, password)) {
        return;
    }

    ProgressDialog progressDialog(L"WinZOX - Extracting archive");
    const auto progressCallback = [&progressDialog](const winzox::utils::ProgressInfo& info) {
        return progressDialog.Update(info);
    };
    const fs::path destinationRoot = fs::u8path(destination);
    const auto overwriteCallback =
        [owner, destinationRoot](const std::string& existingPath, const std::string& archiveEntryPath) {
            return PromptForOverwriteDecision(owner, destinationRoot, fs::u8path(existingPath), archiveEntryPath);
        };
    winzox::extraction::ExtractArchive(archivePath, destination, password, progressCallback, overwriteCallback);
}

} // namespace winzox::shell::internal

namespace winzox::shell {

bool RunShellAddDialog(const std::vector<std::string>& targetPaths) {
    internal::VisualStylesActivationContext visualStyles;
    const std::vector<internal::fs::path> targets = internal::NormalizeTargets(targetPaths);

    const internal::ShellAddDialogResult dialogResult = internal::ShowShellAddDialog(targets);
    if (!dialogResult.accepted) {
        return false;
    }

    winzox::archive::WinZOXConfig config;
    config.defaultAlgorithm = dialogResult.algorithm;
    config.zstdLevel = dialogResult.zstdLevel;
    config.solidMode = dialogResult.solidMode;
    config.password = dialogResult.password;
    config.encryptionAlgorithm = dialogResult.encryption;
    config.splitSize = dialogResult.splitSize;
    internal::ProgressDialog progressDialog(L"WinZOX - Creating archive");
    const auto progressCallback = [&progressDialog](const winzox::utils::ProgressInfo& info) {
        return progressDialog.Update(info);
    };

    if (dialogResult.format == internal::ShellArchiveFormat::Zip) {
        winzox::archive::CreateZipArchive(targetPaths, internal::fs::path(dialogResult.outputPath).u8string(), config, progressCallback);
    } else {
        winzox::archive::CreateArchive(
            targetPaths,
            [&]() {
                internal::fs::path outputPath(dialogResult.outputPath);
                if (winzox::utils::ToLower(outputPath.extension().u8string()) == ".zox") {
                    outputPath.replace_extension("");
                }
                return outputPath.u8string();
            }(),
            config,
            progressCallback);
    }

    return true;
}

void RunQuickAddZox(const std::vector<std::string>& targetPaths) {
    const std::vector<internal::fs::path> targets = internal::NormalizeTargets(targetPaths);
    const internal::TargetCompressionStats stats = internal::AnalyzeInputTargets(targets);

    winzox::archive::WinZOXConfig config;
    config.defaultAlgorithm = winzox::compression::CompressionAlgorithm::Zstd;
    config.solidMode = true;
    config.zstdLevel = internal::ResolveAutoZstdLevel(
        internal::ShellSpeedPreset::Normal,
        stats.totalBytes,
        stats.fileCount);
    internal::ProgressDialog progressDialog(L"WinZOX - Creating archive");
    const auto progressCallback = [&progressDialog](const winzox::utils::ProgressInfo& info) {
        return progressDialog.Update(info);
    };
    winzox::archive::CreateArchive(targetPaths, internal::DefaultZoxBasePath(targets), config, progressCallback);
}

void RunShellBrowse(const std::string& targetPath) {
    internal::VisualStylesActivationContext visualStyles;
    const internal::fs::path target = internal::fs::u8path(targetPath);
    if (!internal::fs::exists(target)) {
        throw std::runtime_error("Shell target does not exist: " + targetPath);
    }

    internal::ShowBrowseDialog(targetPath);
}

void RunShellExtractFiles(const std::string& targetPath) {
    const internal::fs::path target = internal::fs::u8path(targetPath);
    if (!internal::fs::exists(target)) {
        throw std::runtime_error("Shell target does not exist: " + targetPath);
    }

    const std::wstring selectedFolder =
        internal::PromptForFolder(nullptr, internal::fs::u8path(internal::DefaultExtractDestination(target)));
    if (selectedFolder.empty()) {
        return;
    }

    internal::ExecuteShellExtraction(target.u8string(), internal::fs::path(selectedFolder).u8string(), nullptr);
}

void RunShellExtract(const std::string& targetPath, bool extractHere) {
    const internal::fs::path target = internal::fs::u8path(targetPath);
    if (!internal::fs::exists(target)) {
        throw std::runtime_error("Shell target does not exist: " + targetPath);
    }

    const std::string destination = extractHere
        ? target.parent_path().u8string()
        : internal::DefaultExtractDestination(target);
    internal::ExecuteShellExtraction(target.u8string(), destination, nullptr);
}

} // namespace winzox::shell

#else

namespace winzox::shell {

bool RunShellAddDialog(const std::vector<std::string>& targetPaths) {
    (void)targetPaths;
    throw std::runtime_error("Native Windows shell actions are only available on Windows");
}

void RunQuickAddZox(const std::vector<std::string>& targetPaths) {
    (void)targetPaths;
    throw std::runtime_error("Native Windows shell actions are only available on Windows");
}

void RunShellBrowse(const std::string& targetPath) {
    (void)targetPath;
    throw std::runtime_error("Native Windows shell actions are only available on Windows");
}

void RunShellExtractFiles(const std::string& targetPath) {
    (void)targetPath;
    throw std::runtime_error("Native Windows shell actions are only available on Windows");
}

void RunShellExtract(const std::string& targetPath, bool extractHere) {
    (void)targetPath;
    (void)extractHere;
    throw std::runtime_error("Native Windows shell actions are only available on Windows");
}

} // namespace winzox::shell

#endif
