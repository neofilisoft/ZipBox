#include "shell/windows_shell_internal.hpp"

#ifdef _WIN32

#include <cwctype>
#include <limits>

namespace winzox::shell::internal {

namespace {

enum : int {
    kArchivePathEditId = 1001,
    kBrowseButtonId = 1002,
    kFormatComboId = 1003,
    kCompressionComboId = 1004,
    kPresetComboId = 1005,
    kPasswordEditId = 1006,
    kEncryptionComboId = 1007,
    kSplitEditId = 1008,
};

struct ShellAddDialogState {
    std::vector<fs::path> targets;
    HWND window = nullptr;
    HWND archivePathEdit = nullptr;
    HWND formatCombo = nullptr;
    HWND compressionCombo = nullptr;
    HWND presetCombo = nullptr;
    HWND passwordEdit = nullptr;
    HWND encryptionCombo = nullptr;
    HWND splitEdit = nullptr;
    HFONT font = nullptr;
    bool done = false;
    ShellAddDialogResult result;
};

std::wstring DefaultArchiveStem(const fs::path& targetPath) {
    if (fs::is_directory(targetPath)) {
        return targetPath.filename().wstring();
    }
    return targetPath.stem().wstring();
}

fs::path DefaultOutputDirectory(const fs::path& targetPath) {
    return targetPath.parent_path();
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

std::wstring DefaultArchiveStem(const std::vector<fs::path>& targets) {
    if (targets.size() == 1) {
        return DefaultArchiveStem(targets.front());
    }
    return L"Archive";
}

fs::path DefaultOutputDirectory(const std::vector<fs::path>& targets) {
    if (targets.size() == 1) {
        return DefaultOutputDirectory(targets.front());
    }
    return CommonSelectionParent(targets);
}

std::wstring DefaultArchivePath(const std::vector<fs::path>& targets, ShellArchiveFormat format) {
    const std::wstring extension = format == ShellArchiveFormat::Zip ? L".zip" : L".zox";
    return (DefaultOutputDirectory(targets) / (DefaultArchiveStem(targets) + extension)).wstring();
}

std::wstring GetControlText(HWND control) {
    const int length = GetWindowTextLengthW(control);
    std::wstring value(static_cast<size_t>(length + 1), L'\0');
    if (length > 0) {
        GetWindowTextW(control, value.data(), length + 1);
        value.pop_back();
    } else {
        value.clear();
    }
    return value;
}

void SetControlFont(HWND control, HFONT font) {
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

void AddComboEntry(HWND combo, const wchar_t* label, LPARAM value) {
    const LRESULT index = SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    if (index >= 0) {
        SendMessageW(combo, CB_SETITEMDATA, static_cast<WPARAM>(index), value);
    }
}

LPARAM GetSelectedComboValue(HWND combo) {
    const LRESULT selection = SendMessageW(combo, CB_GETCURSEL, 0, 0);
    if (selection == CB_ERR) {
        throw std::runtime_error("A dialog selection is invalid");
    }
    return SendMessageW(combo, CB_GETITEMDATA, static_cast<WPARAM>(selection), 0);
}

ShellArchiveFormat GetSelectedFormat(HWND combo) {
    return static_cast<ShellArchiveFormat>(GetSelectedComboValue(combo));
}

void SetSelectedFormat(HWND combo, ShellArchiveFormat format) {
    const int count = static_cast<int>(SendMessageW(combo, CB_GETCOUNT, 0, 0));
    for (int index = 0; index < count; ++index) {
        if (static_cast<ShellArchiveFormat>(
                SendMessageW(combo, CB_GETITEMDATA, static_cast<WPARAM>(index), 0)) == format) {
            SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(index), 0);
            return;
        }
    }
}

void PopulateCompressionCombo(HWND combo,
                              ShellArchiveFormat format,
                              winzox::compression::CompressionAlgorithm preferred) {
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);

    if (format == ShellArchiveFormat::Zip) {
        AddComboEntry(combo, L"zlib", static_cast<LPARAM>(winzox::compression::CompressionAlgorithm::Zlib));
        AddComboEntry(combo, L"store", static_cast<LPARAM>(winzox::compression::CompressionAlgorithm::Store));
    } else {
        AddComboEntry(combo, L"zstd", static_cast<LPARAM>(winzox::compression::CompressionAlgorithm::Zstd));
        AddComboEntry(combo, L"zlib", static_cast<LPARAM>(winzox::compression::CompressionAlgorithm::Zlib));
        AddComboEntry(combo, L"store", static_cast<LPARAM>(winzox::compression::CompressionAlgorithm::Store));
    }

    const int count = static_cast<int>(SendMessageW(combo, CB_GETCOUNT, 0, 0));
    int selectedIndex = 0;
    for (int index = 0; index < count; ++index) {
        if (static_cast<winzox::compression::CompressionAlgorithm>(
                SendMessageW(combo, CB_GETITEMDATA, static_cast<WPARAM>(index), 0)) == preferred) {
            selectedIndex = index;
            break;
        }
    }

    SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(selectedIndex), 0);
}

int ZstdLevelForPreset(ShellSpeedPreset preset) {
    switch (preset) {
    case ShellSpeedPreset::Fast:
        return 5;
    case ShellSpeedPreset::Normal:
        return 8;
    case ShellSpeedPreset::Maximum:
        return 14;
    case ShellSpeedPreset::Ultra:
        return 20;
    }

    throw std::runtime_error("Invalid Zstd speed preset");
}

void PopulatePresetCombo(HWND combo, ShellSpeedPreset preferred) {
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);
    AddComboEntry(combo, L"Fast (zstd 5)", static_cast<LPARAM>(ShellSpeedPreset::Fast));
    AddComboEntry(combo, L"Normal (zstd 8)", static_cast<LPARAM>(ShellSpeedPreset::Normal));
    AddComboEntry(combo, L"Maximum (zstd 14)", static_cast<LPARAM>(ShellSpeedPreset::Maximum));
    AddComboEntry(combo, L"Ultra (zstd 20)", static_cast<LPARAM>(ShellSpeedPreset::Ultra));

    const int count = static_cast<int>(SendMessageW(combo, CB_GETCOUNT, 0, 0));
    int selectedIndex = 0;
    for (int index = 0; index < count; ++index) {
        if (static_cast<ShellSpeedPreset>(
                SendMessageW(combo, CB_GETITEMDATA, static_cast<WPARAM>(index), 0)) == preferred) {
            selectedIndex = index;
            break;
        }
    }

    SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(selectedIndex), 0);
}

bool IsZstdCompressionSelected(HWND combo) {
    return static_cast<winzox::compression::CompressionAlgorithm>(GetSelectedComboValue(combo)) ==
        winzox::compression::CompressionAlgorithm::Zstd;
}

size_t ParseSplitSizeValue(const std::wstring& value) {
    if (value.empty()) {
        return 0;
    }

    std::wstring numberPart = value;
    unsigned long long multiplier = 1;
    const wchar_t suffix = static_cast<wchar_t>(std::towlower(numberPart.back()));
    if (std::iswalpha(suffix)) {
        numberPart.pop_back();
        switch (suffix) {
        case L'k':
            multiplier = 1024ULL;
            break;
        case L'm':
            multiplier = 1024ULL * 1024ULL;
            break;
        case L'g':
            multiplier = 1024ULL * 1024ULL * 1024ULL;
            break;
        default:
            throw std::runtime_error("Split size suffix must be k, m, or g");
        }
    }

    const unsigned long long amount = std::stoull(numberPart);
    if (amount > (std::numeric_limits<size_t>::max)() / multiplier) {
        throw std::runtime_error("Split size is too large");
    }

    return static_cast<size_t>(amount * multiplier);
}

std::wstring EnsureArchiveExtension(const std::wstring& value, ShellArchiveFormat format) {
    fs::path path(value);
    std::wstring extension = path.extension().wstring();
    for (wchar_t& ch : extension) {
        ch = static_cast<wchar_t>(std::towlower(ch));
    }

    const std::wstring desiredExtension = format == ShellArchiveFormat::Zip ? L".zip" : L".zox";
    if (extension != desiredExtension) {
        path.replace_extension(desiredExtension);
    }

    return path.wstring();
}

void AdjustArchivePathExtension(ShellAddDialogState& state) {
    const std::wstring currentText = GetControlText(state.archivePathEdit);
    if (currentText.empty()) {
        SetWindowTextW(state.archivePathEdit, DefaultArchivePath(state.targets, GetSelectedFormat(state.formatCombo)).c_str());
        return;
    }

    SetWindowTextW(state.archivePathEdit, EnsureArchiveExtension(currentText, GetSelectedFormat(state.formatCombo)).c_str());
}

void RefreshArchiveDialog(ShellAddDialogState& state) {
    const ShellArchiveFormat format = GetSelectedFormat(state.formatCombo);
    const auto preferred = format == ShellArchiveFormat::Zip
        ? winzox::compression::CompressionAlgorithm::Zlib
        : winzox::compression::CompressionAlgorithm::Zstd;
    PopulateCompressionCombo(state.compressionCombo, format, preferred);

    const BOOL enableZoxOptions = format == ShellArchiveFormat::Zox ? TRUE : FALSE;
    const BOOL enablePreset = enableZoxOptions && IsZstdCompressionSelected(state.compressionCombo) ? TRUE : FALSE;
    EnableWindow(state.presetCombo, enablePreset);
    EnableWindow(state.passwordEdit, enableZoxOptions);
    EnableWindow(state.encryptionCombo, enableZoxOptions);
    EnableWindow(state.splitEdit, enableZoxOptions);
    AdjustArchivePathExtension(state);
}

bool BrowseArchivePath(ShellAddDialogState& state) {
    wchar_t buffer[4096] = {};
    const std::wstring initialValue = GetControlText(state.archivePathEdit).empty()
        ? DefaultArchivePath(state.targets, GetSelectedFormat(state.formatCombo))
        : GetControlText(state.archivePathEdit);
    initialValue.copy(buffer, initialValue.size());
    buffer[initialValue.size()] = L'\0';

    const ShellArchiveFormat format = GetSelectedFormat(state.formatCombo);
    const wchar_t* filter = format == ShellArchiveFormat::Zip
        ? L"ZIP archive (*.zip)\0*.zip\0\0"
        : L"WinZOX archive (*.zox)\0*.zox\0\0";

    OPENFILENAMEW dialog {};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = state.window;
    dialog.lpstrFilter = filter;
    dialog.nFilterIndex = 1;
    dialog.lpstrFile = buffer;
    dialog.nMaxFile = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
    const std::wstring initialDirectory = DefaultOutputDirectory(state.targets).wstring();
    dialog.lpstrInitialDir = initialDirectory.c_str();
    dialog.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    dialog.lpstrDefExt = format == ShellArchiveFormat::Zip ? L"zip" : L"zox";
    dialog.lpstrTitle = L"WinZOX - Select archive destination";

    if (!GetSaveFileNameW(&dialog)) {
        const DWORD error = CommDlgExtendedError();
        if (error == 0) {
            return false;
        }
        throw std::runtime_error("Failed to open the archive destination dialog");
    }

    SetWindowTextW(state.archivePathEdit, EnsureArchiveExtension(std::wstring(buffer), format).c_str());
    return true;
}

LRESULT CALLBACK ShellAddDialogProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<ShellAddDialogState*>(GetWindowLongPtrW(window, GWLP_USERDATA));

    switch (message) {
    case WM_NCCREATE: {
        auto* createStruct = reinterpret_cast<CREATESTRUCTW*>(lParam);
        auto* newState = reinterpret_cast<ShellAddDialogState*>(createStruct->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(newState));
        newState->window = window;
        return TRUE;
    }

    case WM_CREATE: {
        if (state == nullptr) {
            return -1;
        }

        state->font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

        const int labelX = 14;
        const int controlX = 136;
        const int buttonX = 426;
        const int rowWidth = 282;
        const int rowHeight = 24;
        int y = 16;

        auto createLabel = [&](const wchar_t* text, int top) {
            HWND label = CreateWindowExW(
                0, L"STATIC", text,
                WS_CHILD | WS_VISIBLE,
                labelX, top + 4, 116, 20,
                window, nullptr, nullptr, nullptr);
            SetControlFont(label, state->font);
        };

        createLabel(L"Archive name", y);
        state->archivePathEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", DefaultArchivePath(state->targets, ShellArchiveFormat::Zox).c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            controlX, y, rowWidth, rowHeight,
            window, reinterpret_cast<HMENU>(kArchivePathEditId), nullptr, nullptr);
        SetControlFont(state->archivePathEdit, state->font);

        HWND browseButton = CreateWindowExW(
            0, L"BUTTON", L"Browse...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            buttonX, y - 1, 88, 26,
            window, reinterpret_cast<HMENU>(kBrowseButtonId), nullptr, nullptr);
        SetControlFont(browseButton, state->font);
        y += 36;

        createLabel(L"Archive format", y);
        state->formatCombo = CreateWindowExW(
            0, L"COMBOBOX", nullptr,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
            controlX, y, 160, 200,
            window, reinterpret_cast<HMENU>(kFormatComboId), nullptr, nullptr);
        SetControlFont(state->formatCombo, state->font);
        AddComboEntry(state->formatCombo, L"ZOX", static_cast<LPARAM>(ShellArchiveFormat::Zox));
        AddComboEntry(state->formatCombo, L"ZIP", static_cast<LPARAM>(ShellArchiveFormat::Zip));
        SetSelectedFormat(state->formatCombo, ShellArchiveFormat::Zox);
        y += 36;

        createLabel(L"Compression", y);
        state->compressionCombo = CreateWindowExW(
            0, L"COMBOBOX", nullptr,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
            controlX, y, 160, 200,
            window, reinterpret_cast<HMENU>(kCompressionComboId), nullptr, nullptr);
        SetControlFont(state->compressionCombo, state->font);
        y += 36;

        createLabel(L"Speed level", y);
        state->presetCombo = CreateWindowExW(
            0, L"COMBOBOX", nullptr,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
            controlX, y, 180, 200,
            window, reinterpret_cast<HMENU>(kPresetComboId), nullptr, nullptr);
        SetControlFont(state->presetCombo, state->font);
        PopulatePresetCombo(state->presetCombo, ShellSpeedPreset::Normal);
        y += 36;

        createLabel(L"Password", y);
        state->passwordEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", nullptr,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD,
            controlX, y, 160, rowHeight,
            window, reinterpret_cast<HMENU>(kPasswordEditId), nullptr, nullptr);
        SetControlFont(state->passwordEdit, state->font);
        y += 36;

        createLabel(L"Encryption", y);
        state->encryptionCombo = CreateWindowExW(
            0, L"COMBOBOX", nullptr,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
            controlX, y, 160, 200,
            window, reinterpret_cast<HMENU>(kEncryptionComboId), nullptr, nullptr);
        SetControlFont(state->encryptionCombo, state->font);
        AddComboEntry(state->encryptionCombo, L"AES256", static_cast<LPARAM>(winzox::crypto::EncryptionAlgorithm::Aes256));
        AddComboEntry(state->encryptionCombo, L"Gorgon", static_cast<LPARAM>(winzox::crypto::EncryptionAlgorithm::Gorgon));
        SendMessageW(state->encryptionCombo, CB_SETCURSEL, 0, 0);
        y += 36;

        createLabel(L"Split size", y);
        state->splitEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", nullptr,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            controlX, y, 160, rowHeight,
            window, reinterpret_cast<HMENU>(kSplitEditId), nullptr, nullptr);
        SetControlFont(state->splitEdit, state->font);

        HWND splitHint = CreateWindowExW(
            0, L"STATIC", L"Examples: 100m, 700m, 1g",
            WS_CHILD | WS_VISIBLE,
            304, y + 4, 210, 20,
            window, nullptr, nullptr, nullptr);
        SetControlFont(splitHint, state->font);

        HWND okButton = CreateWindowExW(
            0, L"BUTTON", L"OK",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            324, 274, 90, 28,
            window, reinterpret_cast<HMENU>(IDOK), nullptr, nullptr);
        SetControlFont(okButton, state->font);

        HWND cancelButton = CreateWindowExW(
            0, L"BUTTON", L"Cancel",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            424, 274, 90, 28,
            window, reinterpret_cast<HMENU>(IDCANCEL), nullptr, nullptr);
        SetControlFont(cancelButton, state->font);

        RefreshArchiveDialog(*state);
        return 0;
    }

    case WM_COMMAND:
        if (state == nullptr) {
            break;
        }

        switch (LOWORD(wParam)) {
        case kBrowseButtonId:
            try {
                BrowseArchivePath(*state);
            } catch (const std::exception& error) {
                MessageBoxW(window, Utf8ToWide(error.what()).c_str(), L"WinZOX", MB_OK | MB_ICONERROR);
            }
            return 0;

        case kFormatComboId:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                RefreshArchiveDialog(*state);
            }
            return 0;

        case kCompressionComboId:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                const BOOL enablePreset =
                    GetSelectedFormat(state->formatCombo) == ShellArchiveFormat::Zox &&
                    IsZstdCompressionSelected(state->compressionCombo)
                    ? TRUE
                    : FALSE;
                EnableWindow(state->presetCombo, enablePreset);
            }
            return 0;

        case IDOK:
            try {
                state->result.format = GetSelectedFormat(state->formatCombo);
                state->result.outputPath = EnsureArchiveExtension(GetControlText(state->archivePathEdit), state->result.format);
                if (state->result.outputPath.empty()) {
                    throw std::runtime_error("Archive name is required");
                }

                state->result.algorithm = static_cast<winzox::compression::CompressionAlgorithm>(
                    GetSelectedComboValue(state->compressionCombo));
                state->result.speedPreset = static_cast<ShellSpeedPreset>(GetSelectedComboValue(state->presetCombo));
                state->result.zstdLevel = state->result.algorithm == winzox::compression::CompressionAlgorithm::Zstd &&
                        state->result.format == ShellArchiveFormat::Zox
                    ? ZstdLevelForPreset(state->result.speedPreset)
                    : 9;
                if (state->result.format == ShellArchiveFormat::Zox) {
                    state->result.password = WideToUtf8(GetControlText(state->passwordEdit));
                    state->result.encryption = static_cast<winzox::crypto::EncryptionAlgorithm>(
                        GetSelectedComboValue(state->encryptionCombo));
                    state->result.splitSize = ParseSplitSizeValue(GetControlText(state->splitEdit));
                } else {
                    state->result.password.clear();
                    state->result.encryption = winzox::crypto::EncryptionAlgorithm::None;
                    state->result.splitSize = 0;
                }

                state->result.accepted = true;
                state->done = true;
                DestroyWindow(window);
            } catch (const std::exception& error) {
                MessageBoxW(window, Utf8ToWide(error.what()).c_str(), L"WinZOX", MB_OK | MB_ICONERROR);
            }
            return 0;

        case IDCANCEL:
            state->done = true;
            DestroyWindow(window);
            return 0;
        }
        break;

    case WM_CLOSE:
        if (state != nullptr) {
            state->done = true;
        }
        DestroyWindow(window);
        return 0;

    case WM_DESTROY:
        if (state != nullptr) {
            state->done = true;
        }
        return 0;
    }

    return DefWindowProcW(window, message, wParam, lParam);
}

} // namespace

ShellAddDialogResult ShowShellAddDialog(const std::vector<fs::path>& targets) {
    const wchar_t* className = L"WinZOXShellAddDialog";
    static bool classRegistered = false;

    if (!classRegistered) {
        WNDCLASSEXW windowClass {};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = ShellAddDialogProc;
        windowClass.hInstance = GetModuleHandleW(nullptr);
        windowClass.hCursor = LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_ARROW));
        windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
        windowClass.lpszClassName = className;
        if (RegisterClassExW(&windowClass) == 0) {
            throw std::runtime_error("Failed to register the WinZOX dialog window class");
        }
        classRegistered = true;
    }

    ShellAddDialogState state;
    state.targets = targets;

    HWND window = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        className,
        L"WinZOX - Add to archive",
        WS_CAPTION | WS_SYSMENU | WS_POPUP | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 534, 346,
        nullptr, nullptr, GetModuleHandleW(nullptr), &state);

    if (window == nullptr) {
        throw std::runtime_error("Failed to create the WinZOX add dialog");
    }

    RECT rect {};
    GetWindowRect(window, &rect);
    const int width = rect.right - rect.left;
    const int height = rect.bottom - rect.top;
    SetWindowPos(
        window,
        nullptr,
        (GetSystemMetrics(SM_CXSCREEN) - width) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - height) / 2,
        0, 0,
        SWP_NOSIZE | SWP_NOZORDER | SWP_SHOWWINDOW);

    MSG message {};
    while (!state.done && GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    return state.result;
}

} // namespace winzox::shell::internal

#endif
