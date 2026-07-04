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

    // [XFF] 自读进程内存原始字节,扫 Xposed/LSPosed 类名串(DetectEvilFrameworks 技术)。
    // 读 /proc/self/maps 拿匿名/dalvik 区地址 → 直接指针 memmem 找 needle。
    // 进程内自读(V3),不经 /proc/self/mem·ptrace,内核 proc-mem 伪装拦不住;
    // 唯一能拦=exec-only(无 EPAN 硬件不行)或类名串根本不存在(混淆)。
    static bool checkXposedMemoryStrings();
    static std::string getXposedMemStringsDetails();

    // [XFF-T2/T3] 模块注入痕迹:扫 /proc/self/maps 外来 apk/dex/oat 映射 + /proc/self/fd 外来 fd。
    // 宿主进程正常只 mmap 自己包的 base.apk/split;任何外来包的 apk/dex/oat 被映射进本进程 = 注入模块。
    // dex 必须被 ART mmap 才能执行、模块 fd 必须常开 → 就算把 maps 行文本里的 lspd/lsposed 藏了,
    // dex/apk 文件本体路径仍在;传入 hostPkg + hostApkDir 用于排除宿主自身与系统 framework。
    // 返回多行报告(MAPS_FOREIGN=... / FD_FOREIGN=...),无命中返回 "CLEAN\n"。
    static std::string getModuleInjectionReport(const std::string& hostPkg,
                                                const std::string& hostApkDir);

    // [XFF-T5] Hook 引擎 .so 探测:dlopen(RTLD_NOLOAD) 命中已加载到本进程的框架库。
    // 走 loader 的"已加载库表",比扫 maps 行文本更难伪装(改 maps 文本骗不过 dlopen 内部记账);
    // liblspd.so / libxposed_art.so 只要 LSPosed 注入了本进程就必在表内。返回多行,无命中 "CLEAN\n"。
    static std::string getArtHookLibReport();

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
};

#endif // LAUNCH_HOOK_DETECTOR_H
