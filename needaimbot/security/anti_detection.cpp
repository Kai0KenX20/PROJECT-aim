#include "anti_detection.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <algorithm>

AntiDetection& AntiDetection::getInstance() {
    static AntiDetection instance;
    return instance;
}

void AntiDetection::initialize() {
    if (m_initialized.exchange(true)) return;

    std::lock_guard<std::mutex> lock(m_mutex);

    seedRandomGenerator();
    initializePatterns();
    enableProcessProtection();
    createLegitimateArtifacts();

    std::cout << "[AntiDetection] System initialized successfully" << std::endl;
}

void AntiDetection::seedRandomGenerator() {
    // Use multiple entropy sources for better randomization
    auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    seed ^= GetCurrentProcessId();
    seed ^= GetTickCount64();
    seed ^= reinterpret_cast<uintptr_t>(&seed); // Memory address entropy
    m_rng.seed(static_cast<unsigned int>(seed));
}

void AntiDetection::initializePatterns() {
    // Real Windows system component patterns
    m_windowClasses = {
        L"MsctfimeUIElementWnd",        // Microsoft IME
        L"IME",                         // Input Method Editor
        L"MSCTFIME UI",                 // Microsoft Text Framework
        L"Default IME",                 // Default Input Method
        L"Chrome_RenderWidgetHostHWND", // Chrome renderer
        L"Edge_WidgetWin_1",           // Edge browser
        L"ApplicationFrameWindow",      // UWP apps
        L"Windows.UI.Core.CoreWindow",  // Windows 10 apps
        L"Shell_TrayWnd",              // System tray
        L"WorkerW",                    // Desktop worker
        L"Progman"                     // Program Manager
    };

    m_windowTitles = {
        L"Microsoft Text Input Application",
        L"Windows Input Experience",
        L"Microsoft IME",
        L"Settings",
        L"System",
        L"",                           // Empty title (common)
        L"Background Application Host",
        L"Desktop Window Manager"
    };
}

std::wstring AntiDetection::generateLegitimateWindowClass() {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Select random base class
    std::uniform_int_distribution<> dis(0, static_cast<int>(m_windowClasses.size() - 1));
    std::wstring baseClass = m_windowClasses[dis(m_rng)];

    // Add randomized but realistic suffix
    std::wstring suffix = generateRandomHex(4);
    return baseClass + L"_" + suffix;
}

std::wstring AntiDetection::generateLegitimateWindowTitle() {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::uniform_int_distribution<> dis(0, static_cast<int>(m_windowTitles.size() - 1));
    return m_windowTitles[dis(m_rng)];
}

std::wstring AntiDetection::generateRandomHex(size_t length) {
    const wchar_t* hex_chars = L"0123456789ABCDEF";
    std::wstring result;
    result.reserve(length);

    std::uniform_int_distribution<> dis(0, 15);
    for (size_t i = 0; i < length; ++i) {
        result += hex_chars[dis(m_rng)];
    }
    return result;
}

void AntiDetection::applyWindowStealth(HWND hwnd) {
    if (!hwnd) return;

    // Remove from Alt+Tab and task manager
    LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
    exStyle |= WS_EX_TOOLWINDOW;
    exStyle &= ~WS_EX_APPWINDOW;
    SetWindowLongPtr(hwnd, GWL_EXSTYLE, exStyle);

    // Set legitimate window properties that system components have
    SetProp(hwnd, L"ApplicationViewState", reinterpret_cast<HANDLE>(1));
    SetProp(hwnd, L"IsProcessTrusted", reinterpret_cast<HANDLE>(1));

    // Slight position randomization to avoid static signatures
    RECT rect;
    GetWindowRect(hwnd, &rect);
    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;

    std::uniform_int_distribution<> posDis(-5, 5);
    int offsetX = posDis(m_rng);
    int offsetY = posDis(m_rng);

    SetWindowPos(hwnd, nullptr, rect.left + offsetX, rect.top + offsetY,
        width, height, SWP_NOZORDER | SWP_NOACTIVATE);
}

void AntiDetection::enableProcessProtection() {
    // Enable Data Execution Prevention
    SetProcessDEPPolicy(PROCESS_DEP_ENABLE | PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION);

    // Apply modern Windows security mitigations
    setProcessMitigation();

    // Randomize process priority to avoid static fingerprinting
    randomizeProcessPriority();
}

void AntiDetection::setProcessMitigation() {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) return;

    typedef BOOL(WINAPI* SetProcessMitigationPolicyProc)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
    auto SetProcessMitigationPolicyFunc = reinterpret_cast<SetProcessMitigationPolicyProc>(
        GetProcAddress(kernel32, "SetProcessMitigationPolicy"));

    if (SetProcessMitigationPolicyFunc) {
        // Enable ASLR (makes memory layout unpredictable)
        PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = {};
        aslrPolicy.EnableBottomUpRandomization = 1;
        aslrPolicy.EnableForceRelocateImages = 1;
        aslrPolicy.EnableHighEntropy = 1;
        SetProcessMitigationPolicyFunc(ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy));

        // Enable strict handle checking
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy = {};
        handlePolicy.RaiseExceptionOnInvalidHandleReference = 1;
        handlePolicy.HandleExceptionsPermanentlyEnabled = 1;
        SetProcessMitigationPolicyFunc(ProcessStrictHandleCheckPolicy, &handlePolicy, sizeof(handlePolicy));
    }
}

void AntiDetection::randomizeProcessPriority() {
    std::uniform_int_distribution<> priorityDis(0, 2);
    DWORD priorities[] = {
        NORMAL_PRIORITY_CLASS,
        ABOVE_NORMAL_PRIORITY_CLASS,
        BELOW_NORMAL_PRIORITY_CLASS
    };

    SetPriorityClass(GetCurrentProcess(), priorities[priorityDis(m_rng)]);

    // Also randomize thread priority
    int threadPriority = THREAD_PRIORITY_NORMAL + (priorityDis(m_rng) - 1);
    SetThreadPriority(GetCurrentThread(), threadPriority);
}

std::chrono::milliseconds AntiDetection::getRandomizedDelay(int baseMs, int varianceMs) {
    std::uniform_int_distribution<> dis(-varianceMs, varianceMs);
    return std::chrono::milliseconds(baseMs + dis(m_rng));
}

void AntiDetection::simulateHumanBehavior() {
    // Add small random delays to simulate human timing
    std::this_thread::sleep_for(getRandomizedDelay(20, 10));

    // Occasionally perform legitimate Windows operations
    std::uniform_int_distribution<> dis(1, 100);
    if (dis(m_rng) <= 3) { // 3% chance
        // Query system information (legitimate operation)
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        // Check system metrics (normal application behavior)
        GetSystemMetrics(SM_CXSCREEN);
        GetSystemMetrics(SM_CYSCREEN);

        // Check if we're the foreground window
        GetForegroundWindow();
    }
}

bool AntiDetection::detectAPIHooks() {
    struct APICheck {
        const char* module;
        const char* function;
    };

    // Check critical APIs for hooks
    APICheck apis[] = {
        {"kernel32.dll", "WriteFile"},          // RawHID communication
        {"kernel32.dll", "CreateProcessW"},     // Process creation
        {"user32.dll", "SetWindowsHookExW"},    // Hook installation
        {"ntdll.dll", "NtQueryInformationProcess"}, // Process queries
        {"kernel32.dll", "VirtualProtect"},     // Memory protection
        {"user32.dll", "GetAsyncKeyState"},     // Keyboard state
        {"user32.dll", "mouse_event"},          // Mouse events
        {"user32.dll", "SendInput"}             // Input simulation
    };

    for (const auto& api : apis) {
        HMODULE hMod = GetModuleHandleA(api.module);
        if (!hMod) continue;

        FARPROC proc = GetProcAddress(hMod, api.function);
        if (!proc) continue;

        BYTE* funcBytes = reinterpret_cast<BYTE*>(proc);

        // Check for common hook signatures
        if (funcBytes[0] == 0xE9) {  // JMP rel32 (inline hook)
            std::cout << "[AntiDetection] Inline hook detected in "
                << api.module << "::" << api.function << std::endl;
            return true;
        }

        if (funcBytes[0] == 0xFF && funcBytes[1] == 0x25) { // JMP [mem] (trampoline)
            std::cout << "[AntiDetection] Trampoline hook detected in "
                << api.module << "::" << api.function << std::endl;
            return true;
        }

        // Check for x64 hooks
        if (funcBytes[0] == 0x48 && funcBytes[1] == 0xB8) { // MOV RAX, imm64
            std::cout << "[AntiDetection] x64 hook detected in "
                << api.module << "::" << api.function << std::endl;
            return true;
        }
    }

    return false;
}

bool AntiDetection::isAntiCheatPresent() {
    std::vector<std::wstring> acProcesses = {
        L"EasyAntiCheat.exe",
        L"EasyAntiCheat_EOS.exe",
        L"BEService.exe",           // BattlEye
        L"BEServices.exe",
        L"FACEIT.exe",
        L"FACEITService.exe",
        L"vgtray.exe",             // Vanguard
        L"vgc.exe",
        L"steamservice.exe",
        L"VAC.exe",
        L"PnkBstrA.exe",           // PunkBuster
        L"PnkBstrB.exe"
    };

    for (const auto& processName : acProcesses) {
        if (isProcessRunning(processName)) {
            std::cout << "[AntiDetection] Anti-cheat detected: "
                << std::string(processName.begin(), processName.end()) << std::endl;
            return true;
        }
    }

    return false;
}

bool AntiDetection::isProcessRunning(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    bool found = false;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return found;
}

bool AntiDetection::isDebuggingEnvironment() {
    // Check for debugger presence
    if (IsDebuggerPresent()) return true;

    // Check for remote debugger
    BOOL remoteDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
    if (remoteDebugger) return true;

    // Check for common debugging tools
    std::vector<std::wstring> debuggers = {
        L"x64dbg.exe",
        L"x32dbg.exe",
        L"ollydbg.exe",
        L"windbg.exe",
        L"ida.exe",
        L"ida64.exe",
        L"cheatengine-x86_64.exe",
        L"processhacker.exe"
    };

    for (const auto& debugger : debuggers) {
        if (isProcessRunning(debugger)) {
            return true;
        }
    }

    return false;
}

bool AntiDetection::isVirtualMachine() {
    // Check for VM-specific registry keys
    HKEY hKey = nullptr; // ✅ Initialize to nullptr
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxService",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true; // VirtualBox
    }

    // Check for VMware
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true; // VMware
    }

    // Check system manufacturer
    wchar_t manufacturer[256] = {}; // ✅ Initialize the array
    DWORD size = sizeof(manufacturer);
    if (RegGetValueW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
        L"SystemManufacturer", RRF_RT_REG_SZ, nullptr,
        manufacturer, &size) == ERROR_SUCCESS) {

        std::wstring mfg(manufacturer);
        if (mfg.find(L"VMware") != std::wstring::npos ||
            mfg.find(L"VirtualBox") != std::wstring::npos ||
            mfg.find(L"QEMU") != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

void AntiDetection::createLegitimateArtifacts() {
    // Create temporary files that look like legitimate Windows operations
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    std::vector<std::wstring> legitimateFiles = {
        L"Microsoft.Windows.ShellHost.tmp",
        L"Windows.ApplicationModel.tmp",
        L"SystemSettings.tmp",
        L"WinStore.tmp"
    };

    for (const auto& filename : legitimateFiles) {
        std::wstring fullPath = std::wstring(tempPath) + filename;
        std::ofstream file(fullPath, std::ios::binary);
        if (file) {
            // Write legitimate-looking data
            file << "Microsoft Windows Temporary File\n";
            file << "Generated: " << GetTickCount64() << "\n";
            file << "Process: " << GetCurrentProcessId() << "\n";
            file.close();
        }
    }
}

void AntiDetection::cleanupTraces() {
    // Clean up temporary files
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    std::vector<std::wstring> patterns = {
        L"Microsoft.Windows.ShellHost.tmp",
        L"Windows.ApplicationModel.tmp",
        L"SystemSettings.tmp",
        L"WinStore.tmp"
    };

    for (const auto& pattern : patterns) {
        std::wstring fullPath = std::wstring(tempPath) + pattern;
        DeleteFileW(fullPath.c_str());
    }
}

void AntiDetection::cleanup() {
    std::lock_guard<std::mutex> lock(m_mutex);
    cleanupTraces();
    std::cout << "[AntiDetection] Cleanup completed" << std::endl;
}