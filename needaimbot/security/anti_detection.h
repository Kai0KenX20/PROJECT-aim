#ifndef ANTI_DETECTION_H
#define ANTI_DETECTION_H

#include <Windows.h>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <atomic>
#include <mutex>
#include <unordered_map>

class AntiDetection {
public:
    static AntiDetection& getInstance();

    // Core initialization
    void initialize();
    void cleanup();

    // Window obfuscation methods
    std::wstring generateLegitimateWindowClass();
    std::wstring generateLegitimateWindowTitle();
    void applyWindowStealth(HWND hwnd);

    // Process protection
    void enableProcessProtection();
    void randomizeProcessPriority();

    // Timing obfuscation
    std::chrono::milliseconds getRandomizedDelay(int baseMs, int varianceMs);
    void simulateHumanBehavior();

    // Detection systems
    bool detectAPIHooks();
    bool isAntiCheatPresent();
    bool isDebuggingEnvironment();
    bool isVirtualMachine();

    // Cleanup and stealth
    void cleanupTraces();
    void createLegitimateArtifacts();

private:
    AntiDetection() = default;
    ~AntiDetection() = default;
    AntiDetection(const AntiDetection&) = delete;
    AntiDetection& operator=(const AntiDetection&) = delete;

    // Internal state
    std::atomic<bool> m_initialized{ false };
    std::mt19937 m_rng;
    std::mutex m_mutex;

    // Cached patterns
    std::vector<std::wstring> m_windowClasses;
    std::vector<std::wstring> m_windowTitles;

    // Helper methods
    void initializePatterns();
    void seedRandomGenerator();
    std::wstring generateRandomHex(size_t length);
    bool isProcessRunning(const std::wstring& processName);
    void setProcessMitigation();
};

#endif // ANTI_DETECTION_H