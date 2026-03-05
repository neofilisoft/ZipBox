#pragma once

#include "shell/windows_shell.hpp"

#include "archive/archive.hpp"
#include "compression/compressor.hpp"
#include "extraction/extractor.hpp"
#include "utils/path_utils.hpp"

#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#endif

namespace winzox::shell::internal {

namespace fs = std::filesystem;

#ifdef _WIN32

enum class ShellArchiveFormat {
    Zip,
    Zox,
};

enum class ShellSpeedPreset {
    Fast,
    Normal,
    Maximum,
    Ultra,
};

struct ShellAddDialogResult {
    bool accepted = false;
    std::wstring outputPath;
    ShellArchiveFormat format = ShellArchiveFormat::Zox;
    winzox::compression::CompressionAlgorithm algorithm = winzox::compression::CompressionAlgorithm::Zstd;
    ShellSpeedPreset speedPreset = ShellSpeedPreset::Normal;
    int zstdLevel = 8;
    std::string password;
    winzox::crypto::EncryptionAlgorithm encryption = winzox::crypto::EncryptionAlgorithm::Aes256;
    size_t splitSize = 0;
};

inline std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return std::wstring();
    }

    const int wideLength = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (wideLength <= 0) {
        throw std::runtime_error("Failed to convert text to UTF-16");
    }

    std::wstring wide(static_cast<size_t>(wideLength), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, wide.data(), wideLength);
    wide.pop_back();
    return wide;
}

inline std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return std::string();
    }

    const int utf8Length = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8Length <= 0) {
        throw std::runtime_error("Failed to convert text to UTF-8");
    }

    std::string utf8(static_cast<size_t>(utf8Length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, utf8.data(), utf8Length, nullptr, nullptr);
    utf8.pop_back();
    return utf8;
}

class ProgressDialog {
public:
    explicit ProgressDialog(const std::wstring& title) {
        const HRESULT initResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        comInitialized_ = SUCCEEDED(initResult);
        if (FAILED(initResult) && initResult != RPC_E_CHANGED_MODE) {
            throw std::runtime_error("Failed to initialize COM for the progress dialog");
        }

        const HRESULT createResult = CoCreateInstance(
            CLSID_ProgressDialog,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IProgressDialog,
            reinterpret_cast<void**>(&dialog_));
        if (FAILED(createResult) || dialog_ == nullptr) {
            if (comInitialized_) {
                CoUninitialize();
            }
            throw std::runtime_error("Failed to create the native progress dialog");
        }

        dialog_->SetTitle(title.c_str());
        dialog_->SetLine(1, L"Preparing...", FALSE, nullptr);
        dialog_->SetCancelMsg(L"Canceling WinZOX operation...", nullptr);
        dialog_->StartProgressDialog(nullptr, nullptr, PROGDLG_NORMAL | PROGDLG_AUTOTIME, nullptr);
    }

    ~ProgressDialog() {
        if (dialog_ != nullptr) {
            dialog_->StopProgressDialog();
            dialog_->Release();
        }

        if (comInitialized_) {
            CoUninitialize();
        }
    }

    bool Update(const winzox::utils::ProgressInfo& info) {
        const ULONGLONG totalUnits = info.totalUnits == 0 ? 1ULL : static_cast<ULONGLONG>(info.totalUnits);
        const ULONGLONG completedUnits = info.completedUnits > totalUnits
            ? totalUnits
            : static_cast<ULONGLONG>(info.completedUnits);

        dialog_->SetProgress64(completedUnits, totalUnits);

        const std::wstring statusLine = info.statusText.empty()
            ? L"Working..."
            : Utf8ToWide(info.statusText);
        dialog_->SetLine(1, statusLine.c_str(), FALSE, nullptr);

        const std::wstring itemLine = info.currentItem.empty()
            ? L""
            : Utf8ToWide(info.currentItem);
        dialog_->SetLine(2, itemLine.c_str(), FALSE, nullptr);

        return dialog_->HasUserCancelled() == FALSE;
    }

private:
    IProgressDialog* dialog_ = nullptr;
    bool comInitialized_ = false;
};

class VisualStylesActivationContext {
public:
    VisualStylesActivationContext() {
        wchar_t modulePath[MAX_PATH] = {};
        const DWORD pathLength = GetModuleFileNameW(nullptr, modulePath, static_cast<DWORD>(std::size(modulePath)));
        if (pathLength == 0 || pathLength >= std::size(modulePath)) {
            return;
        }

        std::wstring manifestPath(modulePath);
        manifestPath += L".manifest";
        if (GetFileAttributesW(manifestPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            return;
        }

        ACTCTXW context {};
        context.cbSize = sizeof(context);
        context.lpSource = manifestPath.c_str();
        handle_ = CreateActCtxW(&context);
        if (handle_ == INVALID_HANDLE_VALUE) {
            handle_ = INVALID_HANDLE_VALUE;
            return;
        }

        if (!ActivateActCtx(handle_, &cookie_)) {
            ReleaseActCtx(handle_);
            handle_ = INVALID_HANDLE_VALUE;
            cookie_ = 0;
        }
    }

    ~VisualStylesActivationContext() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            if (cookie_ != 0) {
                DeactivateActCtx(0, cookie_);
            }
            ReleaseActCtx(handle_);
        }
    }

    VisualStylesActivationContext(const VisualStylesActivationContext&) = delete;
    VisualStylesActivationContext& operator=(const VisualStylesActivationContext&) = delete;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    ULONG_PTR cookie_ = 0;
};

std::vector<fs::path> NormalizeTargets(const std::vector<std::string>& targetPaths);
std::string DefaultZoxBasePath(const fs::path& targetPath);
std::string DefaultZoxBasePath(const std::vector<fs::path>& targets);
std::string DefaultExtractDestination(const fs::path& targetPath);
bool PromptForArchivePassword(HWND owner, const std::string& archivePath, std::string& passwordOut);
std::wstring PromptForFolder(HWND owner, const fs::path& initialPath);
ShellAddDialogResult ShowShellAddDialog(const std::vector<fs::path>& targets);
void ShowBrowseDialog(const std::string& archivePath);
void ExecuteShellExtraction(const std::string& archivePath,
                           const std::string& destination,
                           HWND owner);

#endif

} // namespace winzox::shell::internal
