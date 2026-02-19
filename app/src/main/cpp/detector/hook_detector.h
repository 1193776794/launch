#ifndef LAUNCH_HOOK_DETECTOR_H
#define LAUNCH_HOOK_DETECTOR_H

#include <string>
#include <vector>

struct MultiLayerResult;

class HookDetector {
public:
    // Xposed paths
    static const std::vector<std::string>& getXposedPaths();

    // Frida related paths
    static const std::vector<std::string>& getFridaPaths();

    // LSPosed/EdXposed paths
    static const std::vector<std::string>& getLSPosedPaths();

    // Common Frida ports
    static const std::vector<int>& getFridaPorts();

    // Native layer detection
    static bool checkXposedNative();
    static bool checkFridaNative();
    static bool checkFridaPortsNative();
    static bool checkFridaMemoryNative();
    static bool checkLSPosedNative();
    static bool checkLSPosedMemoryNative();
    static bool checkRiruZygiskNative();
    static bool checkMapsForHooks();

    // Syscall layer detection
    static bool checkXposedSyscall();
    static bool checkFridaSyscall();
    static bool checkFridaMemorySyscall();
    static bool checkLSPosedSyscall();
    static bool checkLSPosedMemorySyscall();
    static bool checkRiruZygiskSyscall();
    static bool checkMapsForHooksSyscall();

    // Thread name detection for Frida
    static bool checkFridaThreads();

    // Get detailed info about LSPosed injection
    static std::string getLSPosedDetails();

    // System-wide LSPosed detection (scans all processes)
    static bool checkLSPosedSystemWide();

    // Check for anonymous executable memory (rwxp with no file backing)
    static bool checkAnonymousExecutableMemory();

    // SMAPS Integrity Check - 高级内存取证技术
    // 检测代码段 (r-xp) 的 Private_Dirty 来发现 Inline Hook
    static bool checkSmapsIntegrity();

    // Zygisk detection (通用检测: Magisk Zygisk, ReZygisk, Zygisk Next)
    static bool checkZygiskNative();
    static bool checkZygiskSyscall();

    // Combined detection
    static MultiLayerResult detectXposed();
    static MultiLayerResult detectFrida();
    static MultiLayerResult detectLSPosed();
    static MultiLayerResult detectZygisk();  // 改为通用 Zygisk 检测
    static MultiLayerResult detectSmapsHook();  // SMAPS 内存取证检测
    static MultiLayerResult detectMemoryHooks();
    static MultiLayerResult detectDumpArtMethodHook();  // DumpArtMethod Hook 检测

    // DumpArtMethod Hook Detection
    // Scans /proc/self/maps for dumpArtMethod symbol - indicates ART method dumping tools
    static bool checkDumpArtMethodHookNative();
    static bool checkDumpArtMethodHookSyscall();
};

#endif // LAUNCH_HOOK_DETECTOR_H
