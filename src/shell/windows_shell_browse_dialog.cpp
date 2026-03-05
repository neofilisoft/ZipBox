#include "shell/windows_shell_internal.hpp"

#ifdef _WIN32

#include "io/file_writer.hpp"
#include "utils/checksum.hpp"

#include <sstream>

namespace winzox::shell::internal {

namespace {

enum : int {
    kBrowseListId = 3001,
    kBrowseViewId = 3002,
    kBrowseExtractId = 3003,
    kBrowseExtractHereId = 3004,
};

enum : int {
    kBrowseMenuFileOpen = 3101,
    kBrowseMenuFileExtract = 3102,
    kBrowseMenuFileExtractHere = 3103,
    kBrowseMenuFileClose = 3104,
    kBrowseMenuOptionsRefresh = 3201,
    kBrowseMenuToolsTest = 3301,
    kBrowseMenuHelpAbout = 3401,
};

constexpr UINT kBrowseInitializeMessage = WM_APP + 1;

enum : int {
    kPasswordPromptEditId = 4001,
};

struct PasswordPromptState {
    std::string archivePath;
    HWND window = nullptr;
    HWND passwordEdit = nullptr;
    HFONT font = nullptr;
    bool done = false;
    bool accepted = false;
    std::string password;
};

struct BrowseDialogState {
    std::string archivePath;
    std::string defaultDestination;
    std::string password;
    std::vector<winzox::archive::ArchiveEntryInfo> entries;
    HWND window = nullptr;
    HWND listBox = nullptr;
    HFONT font = nullptr;
    bool done = false;
};

void ShowAboutDialog(HWND owner) {
    MessageBoxW(
        owner,
        L"WinZOX Archive Browser\n\nBrowse, test, and extract supported archives.\n\n"
        L"Gorgon\n"
        L"(Guarded Oversight for Resilient Granular Obfuscation Network)",
        L"About WinZOX",
        MB_OK | MB_ICONINFORMATION);
}

void CreateBrowseMenu(HWND window) {
    HMENU menuBar = CreateMenu();
    HMENU fileMenu = CreatePopupMenu();
    HMENU optionsMenu = CreatePopupMenu();
    HMENU toolsMenu = CreatePopupMenu();
    HMENU helpMenu = CreatePopupMenu();

    AppendMenuW(fileMenu, MF_STRING, kBrowseMenuFileOpen, L"Open");
    AppendMenuW(fileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(fileMenu, MF_STRING, kBrowseMenuFileExtract, L"Extract Files...");
    AppendMenuW(fileMenu, MF_STRING, kBrowseMenuFileExtractHere, L"Extract Here");
    AppendMenuW(fileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(fileMenu, MF_STRING, kBrowseMenuFileClose, L"Close");

    AppendMenuW(optionsMenu, MF_STRING, kBrowseMenuOptionsRefresh, L"Refresh");

    AppendMenuW(toolsMenu, MF_STRING, kBrowseMenuToolsTest, L"Test Archive");

    AppendMenuW(helpMenu, MF_STRING, kBrowseMenuHelpAbout, L"About WinZOX");

    AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"File");
    AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(optionsMenu), L"Options");
    AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(toolsMenu), L"Tools");
    AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(helpMenu), L"Help");

    SetMenu(window, menuBar);
    DrawMenuBar(window);
}

void ExecuteBrowseExtractToFolder(BrowseDialogState& state, HWND window) {
    const std::wstring selectedFolder = PromptForFolder(window, fs::u8path(state.defaultDestination));
    if (selectedFolder.empty()) {
        return;
    }

    ProgressDialog progressDialog(L"WinZOX - Extracting archive");
    const auto progressCallback = [&progressDialog](const winzox::utils::ProgressInfo& info) {
        return progressDialog.Update(info);
    };
    winzox::extraction::ExtractArchive(
        state.archivePath,
        fs::path(selectedFolder).u8string(),
        state.password,
        progressCallback);
    MessageBoxW(window, L"Extraction completed.", L"WinZOX", MB_OK | MB_ICONINFORMATION);
}

void ExecuteBrowseExtractHere(BrowseDialogState& state, HWND window) {
    ProgressDialog progressDialog(L"WinZOX - Extracting archive");
    const auto progressCallback = [&progressDialog](const winzox::utils::ProgressInfo& info) {
        return progressDialog.Update(info);
    };
    winzox::extraction::ExtractArchive(
        state.archivePath,
        state.defaultDestination,
        state.password,
        progressCallback);
    MessageBoxW(window, L"Extraction completed.", L"WinZOX", MB_OK | MB_ICONINFORMATION);
}

void ExecuteBrowseTest(BrowseDialogState& state, HWND window) {
    winzox::extraction::TestArchive(state.archivePath, state.password);
    MessageBoxW(window, L"Archive passed integrity checks.", L"WinZOX", MB_OK | MB_ICONINFORMATION);
}

int GetSelectedBrowseIndex(const BrowseDialogState& state) {
    const LRESULT selection = SendMessageW(state.listBox, LB_GETCURSEL, 0, 0);
    if (selection == LB_ERR) {
        return -1;
    }
    return static_cast<int>(selection);
}

void OpenSelectedEntry(BrowseDialogState& state, HWND window) {
    const int selectedIndex = GetSelectedBrowseIndex(state);
    if (selectedIndex < 0 || static_cast<size_t>(selectedIndex) >= state.entries.size()) {
        MessageBoxW(window, L"Select a file first.", L"WinZOX", MB_OK | MB_ICONINFORMATION);
        return;
    }

    const auto& selected = state.entries[static_cast<size_t>(selectedIndex)];
    const std::vector<uint8_t> plain = winzox::extraction::ReadArchiveEntry(
        state.archivePath,
        static_cast<size_t>(selectedIndex),
        state.password);

    fs::path outputPath = fs::temp_directory_path() / "WinZOXPreview" / fs::path(selected.path).filename();
    fs::create_directories(outputPath.parent_path());
    winzox::io::WriteFileBytes(outputPath, plain);

    const HINSTANCE result = ShellExecuteW(window, L"open", outputPath.wstring().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(result) <= 32) {
        throw std::runtime_error("Failed to open the selected file");
    }
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

LRESULT CALLBACK PasswordPromptProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<PasswordPromptState*>(GetWindowLongPtrW(window, GWLP_USERDATA));

    switch (message) {
    case WM_NCCREATE: {
        auto* createStruct = reinterpret_cast<CREATESTRUCTW*>(lParam);
        auto* newState = reinterpret_cast<PasswordPromptState*>(createStruct->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(newState));
        newState->window = window;
        return TRUE;
    }

    case WM_CREATE: {
        if (state == nullptr) {
            return -1;
        }

        state->font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

        const std::wstring prompt = L"Enter the password for " +
            Utf8ToWide(fs::path(state->archivePath).filename().u8string());
        HWND label = CreateWindowExW(
            0, L"STATIC", prompt.c_str(),
            WS_CHILD | WS_VISIBLE,
            12, 16, 356, 20,
            window, nullptr, nullptr, nullptr);
        SetControlFont(label, state->font);

        state->passwordEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", nullptr,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD,
            12, 46, 356, 24,
            window, reinterpret_cast<HMENU>(kPasswordPromptEditId), nullptr, nullptr);
        SetControlFont(state->passwordEdit, state->font);

        HWND okButton = CreateWindowExW(
            0, L"BUTTON", L"OK",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            190, 84, 84, 28,
            window, reinterpret_cast<HMENU>(IDOK), nullptr, nullptr);
        SetControlFont(okButton, state->font);

        HWND cancelButton = CreateWindowExW(
            0, L"BUTTON", L"Cancel",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            284, 84, 84, 28,
            window, reinterpret_cast<HMENU>(IDCANCEL), nullptr, nullptr);
        SetControlFont(cancelButton, state->font);

        SetFocus(state->passwordEdit);
        return 0;
    }

    case WM_COMMAND:
        if (state == nullptr) {
            break;
        }

        if (LOWORD(wParam) == IDOK) {
            state->password = WideToUtf8(GetControlText(state->passwordEdit));
            if (state->password.empty()) {
                MessageBoxW(window, L"Password is required.", L"WinZOX", MB_OK | MB_ICONERROR);
                return 0;
            }

            state->accepted = true;
            state->done = true;
            DestroyWindow(window);
            return 0;
        }

        if (LOWORD(wParam) == IDCANCEL) {
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

std::wstring BuildBrowseLine(const winzox::archive::ArchiveEntryInfo& entry) {
    std::ostringstream line;
    line << entry.path << "  (" << entry.originalSize << " bytes)";
    return Utf8ToWide(line.str());
}

void LoadBrowseEntries(BrowseDialogState& state) {
    SendMessageW(state.listBox, LB_RESETCONTENT, 0, 0);
    state.entries.clear();

    const winzox::archive::ArchiveMetadata metadata = winzox::extraction::GetArchiveMetadata(state.archivePath);
    if (!metadata.encrypted) {
        state.password.clear();
        state.entries = winzox::extraction::ListArchiveEntries(state.archivePath);
    } else {
        while (true) {
            std::string candidatePassword;
            if (!PromptForArchivePassword(state.window, state.archivePath, candidatePassword)) {
                throw std::runtime_error("Password entry canceled");
            }

            try {
                state.entries = winzox::extraction::ListArchiveEntries(state.archivePath, candidatePassword);
                state.password = std::move(candidatePassword);
                break;
            } catch (const std::exception& error) {
                const std::wstring message = Utf8ToWide(std::string(error.what()) + "\n\nTry again?");
                if (MessageBoxW(state.window, message.c_str(), L"WinZOX", MB_YESNO | MB_ICONERROR) != IDYES) {
                    throw std::runtime_error("Password entry canceled");
                }
            }
        }
    }

    for (const auto& entry : state.entries) {
        SendMessageW(state.listBox, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(BuildBrowseLine(entry).c_str()));
    }

    if (state.entries.empty()) {
        SendMessageW(state.listBox, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"(empty archive)"));
    }
}

LRESULT CALLBACK BrowseDialogProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<BrowseDialogState*>(GetWindowLongPtrW(window, GWLP_USERDATA));

    switch (message) {
    case WM_NCCREATE: {
        auto* createStruct = reinterpret_cast<CREATESTRUCTW*>(lParam);
        auto* newState = reinterpret_cast<BrowseDialogState*>(createStruct->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(newState));
        newState->window = window;
        return TRUE;
    }

    case WM_CREATE: {
        if (state == nullptr) {
            return -1;
        }

        state->font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        CreateBrowseMenu(window);

        HWND infoLabel = CreateWindowExW(
            0, L"STATIC", Utf8ToWide(fs::path(state->archivePath).filename().u8string()).c_str(),
            WS_CHILD | WS_VISIBLE,
            12, 12, 636, 20,
            window, nullptr, nullptr, nullptr);
        SetControlFont(infoLabel, state->font);

        state->listBox = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"LISTBOX", nullptr,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
            12, 40, 636, 260,
            window, reinterpret_cast<HMENU>(kBrowseListId), nullptr, nullptr);
        SetControlFont(state->listBox, state->font);

        HWND viewButton = CreateWindowExW(
            0, L"BUTTON", L"Open",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            266, 314, 90, 28,
            window, reinterpret_cast<HMENU>(kBrowseViewId), nullptr, nullptr);
        SetControlFont(viewButton, state->font);

        HWND extractButton = CreateWindowExW(
            0, L"BUTTON", L"Extract...",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            364, 314, 90, 28,
            window, reinterpret_cast<HMENU>(kBrowseExtractId), nullptr, nullptr);
        SetControlFont(extractButton, state->font);

        HWND extractHereButton = CreateWindowExW(
            0, L"BUTTON", L"Extract Here",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            462, 314, 90, 28,
            window, reinterpret_cast<HMENU>(kBrowseExtractHereId), nullptr, nullptr);
        SetControlFont(extractHereButton, state->font);

        HWND closeButton = CreateWindowExW(
            0, L"BUTTON", L"Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            560, 314, 88, 28,
            window, reinterpret_cast<HMENU>(IDCANCEL), nullptr, nullptr);
        SetControlFont(closeButton, state->font);

        PostMessageW(window, kBrowseInitializeMessage, 0, 0);
        return 0;
    }

    case kBrowseInitializeMessage:
        if (state == nullptr) {
            return 0;
        }

        try {
            LoadBrowseEntries(*state);
        } catch (const std::exception& error) {
            if (std::string(error.what()) != "Password entry canceled") {
                MessageBoxW(window, Utf8ToWide(error.what()).c_str(), L"WinZOX", MB_OK | MB_ICONERROR);
            }
            state->done = true;
            DestroyWindow(window);
        }
        return 0;

    case WM_COMMAND:
        if (state == nullptr) {
            break;
        }

        if (LOWORD(wParam) == kBrowseListId && HIWORD(wParam) == LBN_DBLCLK) {
            try {
                OpenSelectedEntry(*state, window);
            } catch (const std::exception& error) {
                MessageBoxW(window, Utf8ToWide(error.what()).c_str(), L"WinZOX", MB_OK | MB_ICONERROR);
            }
            return 0;
        }

        if (LOWORD(wParam) == kBrowseViewId || LOWORD(wParam) == kBrowseMenuFileOpen) {
            try {
                OpenSelectedEntry(*state, window);
            } catch (const std::exception& error) {
                MessageBoxW(window, Utf8ToWide(error.what()).c_str(), L"WinZOX", MB_OK | MB_ICONERROR);
            }
            return 0;
        }

        if (LOWORD(wParam) == kBrowseExtractId || LOWORD(wParam) == kBrowseMenuFileExtract) {
            try {
                ExecuteBrowseExtractToFolder(*state, window);
            } catch (const std::exception& error) {
                MessageBoxW(window, Utf8ToWide(error.what()).c_str(), L"WinZOX", MB_OK | MB_ICONERROR);
            }
            return 0;
        }

        if (LOWORD(wParam) == kBrowseExtractHereId || LOWORD(wParam) == kBrowseMenuFileExtractHere) {
            try {
                ExecuteBrowseExtractHere(*state, window);
            } catch (const std::exception& error) {
                MessageBoxW(window, Utf8ToWide(error.what()).c_str(), L"WinZOX", MB_OK | MB_ICONERROR);
            }
            return 0;
        }

        if (LOWORD(wParam) == kBrowseMenuOptionsRefresh) {
            try {
                LoadBrowseEntries(*state);
            } catch (const std::exception& error) {
                MessageBoxW(window, Utf8ToWide(error.what()).c_str(), L"WinZOX", MB_OK | MB_ICONERROR);
            }
            return 0;
        }

        if (LOWORD(wParam) == kBrowseMenuToolsTest) {
            try {
                ExecuteBrowseTest(*state, window);
            } catch (const std::exception& error) {
                MessageBoxW(window, Utf8ToWide(error.what()).c_str(), L"WinZOX", MB_OK | MB_ICONERROR);
            }
            return 0;
        }

        if (LOWORD(wParam) == kBrowseMenuHelpAbout) {
            ShowAboutDialog(window);
            return 0;
        }

        if (LOWORD(wParam) == kBrowseMenuFileClose) {
            state->done = true;
            DestroyWindow(window);
            return 0;
        }

        if (LOWORD(wParam) == IDCANCEL) {
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

bool PromptForArchivePassword(HWND owner, const std::string& archivePath, std::string& passwordOut) {
    VisualStylesActivationContext visualStyles;
    const wchar_t* className = L"WinZOXPasswordPrompt";
    static bool classRegistered = false;

    if (!classRegistered) {
        WNDCLASSEXW windowClass {};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = PasswordPromptProc;
        windowClass.hInstance = GetModuleHandleW(nullptr);
        windowClass.hCursor = LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_ARROW));
        windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
        windowClass.lpszClassName = className;
        if (RegisterClassExW(&windowClass) == 0) {
            throw std::runtime_error("Failed to register the WinZOX password prompt");
        }
        classRegistered = true;
    }

    PasswordPromptState state;
    state.archivePath = archivePath;

    HWND window = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        className,
        L"WinZOX - Password Required",
        WS_CAPTION | WS_SYSMENU | WS_POPUP | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 388, 152,
        owner, nullptr, GetModuleHandleW(nullptr), &state);

    if (window == nullptr) {
        throw std::runtime_error("Failed to create the WinZOX password prompt");
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

    if (!state.accepted) {
        return false;
    }

    passwordOut = state.password;
    return true;
}

std::wstring PromptForFolder(HWND owner, const fs::path& initialPath) {
    BROWSEINFOW browseInfo {};
    browseInfo.hwndOwner = owner;
    browseInfo.lpszTitle = L"Select extraction folder";
    browseInfo.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    PIDLIST_ABSOLUTE selected = SHBrowseForFolderW(&browseInfo);
    if (selected == nullptr) {
        return {};
    }

    wchar_t pathBuffer[MAX_PATH] = {};
    const BOOL ok = SHGetPathFromIDListW(selected, pathBuffer);
    CoTaskMemFree(selected);
    if (!ok) {
        throw std::runtime_error("Failed to read the selected folder");
    }

    (void)initialPath;
    return std::wstring(pathBuffer);
}

void ShowBrowseDialog(const std::string& archivePath) {
    const wchar_t* className = L"WinZOXBrowseDialog";
    static bool classRegistered = false;

    if (!classRegistered) {
        WNDCLASSEXW windowClass {};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = BrowseDialogProc;
        windowClass.hInstance = GetModuleHandleW(nullptr);
        windowClass.hCursor = LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_ARROW));
        windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
        windowClass.lpszClassName = className;
        if (RegisterClassExW(&windowClass) == 0) {
            throw std::runtime_error("Failed to register the WinZOX browser window class");
        }
        classRegistered = true;
    }

    BrowseDialogState state;
    state.archivePath = archivePath;
    state.defaultDestination = DefaultExtractDestination(fs::u8path(archivePath));

    HWND window = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        className,
        Utf8ToWide("WinZOX - " + fs::path(archivePath).filename().u8string()).c_str(),
        WS_CAPTION | WS_SYSMENU | WS_POPUP | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 670, 390,
        nullptr, nullptr, GetModuleHandleW(nullptr), &state);

    if (window == nullptr) {
        throw std::runtime_error("Failed to create the WinZOX browser window");
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
}

} // namespace winzox::shell::internal

#endif
