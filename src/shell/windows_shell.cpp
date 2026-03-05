#include "shell/windows_shell_internal.hpp"

#ifdef _WIN32

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

} // namespace

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
    winzox::extraction::ExtractArchive(archivePath, destination, password, progressCallback);
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

    winzox::archive::WinZOXConfig config;
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
