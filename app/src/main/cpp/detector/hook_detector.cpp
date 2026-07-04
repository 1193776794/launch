#include "hook_detector.h"
#include "root_detector.h"
#include "../syscall/syscall_wrapper.h"
#include <unistd.h>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>
#include <algorithm>
#include <set>
#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include <linux/limits.h>
#include <fcntl.h>

// [XFF] 经 /proc/self/mem 的 pread 安全读进程自身内存(读到不可访问页返 -1/EIO,不 SIGSEGV;
// 而直接指针 memmem 遇到 maps 标 r 但实际 fault 的页会崩)。返回实际读入字节数,块内复用缓冲。
static size_t xffPreadRegion(int memfd, unsigned long start, size_t len,
                             std::vector<char>& buf, size_t cap) {
    size_t toRead = len < cap ? len : cap;
    if (buf.size() < toRead) buf.resize(toRead);
    size_t done = 0;
    while (done < toRead) {
        ssize_t got = pread(memfd, buf.data() + done, toRead - done, (off_t)(start + done));
        if (got <= 0) break;   // 不可读页 → 停在此,返回已读前缀
        done += (size_t) got;
    }
    return done;
}

#define LOG_TAG "HookDetector"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

const std::vector<std::string>& HookDetector::getXposedPaths() {
    static std::vector<std::string> paths = {
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/system/xposed.prop",
        "/data/data/de.robv.android.xposed.installer"
    };
    return paths;
}

const std::vector<std::string>& HookDetector::getFridaPaths() {
    static std::vector<std::string> paths = {
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida",
        "/sdcard/frida-server"
    };
    return paths;
}

const std::vector<std::string>& HookDetector::getLSPosedPaths() {
    static std::vector<std::string> paths = {
        "/data/adb/lspd",
        "/data/adb/edxp",
        "/data/adb/modules/lsposed",
        "/data/adb/modules/edxposed",
        "/data/adb/modules/zygisk_lsposed",
        "/data/adb/modules/riru_lsposed",
        "/system/framework/lspd.dex"
    };
    return paths;
}

const std::vector<int>& HookDetector::getFridaPorts() {
    static std::vector<int> ports = {
        27042, // Default Frida server port
        27043  // Alternative port
    };
    return ports;
}

// Native layer detection
bool HookDetector::checkXposedNative() {
    for (const auto& path : getXposedPaths()) {
        if (access(path.c_str(), F_OK) == 0) {
            LOGD("Xposed path found (native): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool HookDetector::checkFridaNative() {
    for (const auto& path : getFridaPaths()) {
        if (access(path.c_str(), F_OK) == 0) {
            LOGD("Frida path found (native): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool HookDetector::checkFridaPortsNative() {
    for (int port : getFridaPorts()) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        // Set timeout
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms timeout
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        int result = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
        close(sockfd);

        if (result == 0) {
            LOGD("Frida port %d is open (native)", port);
            return true;
        }
    }
    return false;
}

bool HookDetector::checkFridaMemoryNative() {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("frida") != std::string::npos ||
            line.find("gadget") != std::string::npos ||
            line.find("gum-js-loop") != std::string::npos ||
            line.find("LIBFRIDA") != std::string::npos) {
            LOGD("Frida memory signature found (native): %s", line.c_str());
            return true;
        }
    }
    return false;
}

bool HookDetector::checkLSPosedNative() {
    // 1. Check file paths
    for (const auto& path : getLSPosedPaths()) {
        if (access(path.c_str(), F_OK) == 0) {
            LOGD("LSPosed path found (native): %s", path.c_str());
            return true;
        }
    }

    // 2. Check memory maps for LSPosed signatures
    if (checkLSPosedMemoryNative()) {
        LOGD("LSPosed detected in memory (native)");
        return true;
    }

    // 3. Check for Riru/Zygisk (LSPosed dependencies)
    if (checkRiruZygiskNative()) {
        LOGD("Riru/Zygisk detected (LSPosed dependency)");
        return true;
    }

    return false;
}

bool HookDetector::checkLSPosedMemoryNative() {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;

    std::string line;
    while (std::getline(maps, line)) {
        // Convert to uppercase for case-insensitive comparison
        std::string upper_line = line;
        std::transform(upper_line.begin(), upper_line.end(), upper_line.begin(), ::toupper);

        // Check for LSPosed/Xposed memory signatures (case-insensitive)
        if (upper_line.find("LIBXPOSED_ART.SO") != std::string::npos ||
            upper_line.find("XPOSEDBRIDGE.JAR") != std::string::npos ||
            upper_line.find("XPOSEDBRIDGE") != std::string::npos) {
            LOGD("Xposed/LSPosed JAR/SO found (native): %s", line.c_str());
            return true;
        }

        // Check for LSPlant (LSPosed's ART hooking library)
        if (upper_line.find("LSPLANT") != std::string::npos ||
            upper_line.find("LIBLSPLANT") != std::string::npos) {
            LOGD("LSPlant hooking library found (native): %s", line.c_str());
            return true;
        }

        // Check for LSPosed daemon and framework
        if (line.find("lspd") != std::string::npos ||
            line.find("lsposed") != std::string::npos ||
            line.find("edxposed") != std::string::npos ||
            line.find("EdXposed") != std::string::npos) {
            LOGD("LSPosed memory signature found (native): %s", line.c_str());
            return true;
        }

        // Check for Zygisk LSPosed module paths
        // Pattern: /data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so
        // or: /data/adb/modules/zygisk lsposed/zygisk/arm64-v8a.so (with space)
        if (line.find("/data/adb/modules/") != std::string::npos &&
            line.find("/zygisk/") != std::string::npos) {
            // Check if it contains lsposed/edxposed keywords
            if (line.find("lsposed") != std::string::npos ||
                line.find("edxposed") != std::string::npos) {
                LOGD("LSPosed Zygisk module found (native): %s", line.c_str());
                return true;
            }
        }

        // Check for Riru LSPosed
        if (line.find("/system/lib") != std::string::npos &&
            line.find("libriru") != std::string::npos) {
            LOGD("Riru library found (LSPosed dependency): %s", line.c_str());
            return true;
        }

        // Check for module dex files (common pattern)
        if (line.find("/data/misc/riru/modules") != std::string::npos ||
            line.find("/data/adb/modules") != std::string::npos) {
            if (line.find(".dex") != std::string::npos || line.find(".so") != std::string::npos) {
                LOGD("Suspicious module file in memory (native): %s", line.c_str());
                return true;
            }
        }
    }
    return false;
}

bool HookDetector::checkRiruZygiskNative() {
    // Check for Riru
    if (access("/data/adb/riru", F_OK) == 0 ||
        access("/system/lib/libriru.so", F_OK) == 0 ||
        access("/system/lib64/libriru.so", F_OK) == 0) {
        LOGD("Riru detected (native)");
        return true;
    }

    // Check memory for Riru/Zygisk
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("riru") != std::string::npos ||
            line.find("zygisk") != std::string::npos) {
            LOGD("Riru/Zygisk memory signature found (native): %s", line.c_str());
            return true;
        }
    }

    return false;
}

bool HookDetector::checkMapsForHooks() {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("substrate") != std::string::npos ||
            line.find("xposed") != std::string::npos ||
            line.find("riru") != std::string::npos) {
            LOGD("Hook framework signature found (native): %s", line.c_str());
            return true;
        }
    }
    return false;
}

// Syscall layer detection
bool HookDetector::checkXposedSyscall() {
    for (const auto& path : getXposedPaths()) {
        if (syscall_file_exists(path.c_str())) {
            LOGD("Xposed path found (syscall): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool HookDetector::checkFridaSyscall() {
    for (const auto& path : getFridaPaths()) {
        if (syscall_file_exists(path.c_str())) {
            LOGD("Frida path found (syscall): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool HookDetector::checkFridaMemorySyscall() {
    std::string content = syscall_read_file("/proc/self/maps", 65536);
    if (content.find("frida") != std::string::npos ||
        content.find("gadget") != std::string::npos ||
        content.find("gum-js-loop") != std::string::npos ||
        content.find("LIBFRIDA") != std::string::npos) {
        LOGD("Frida memory signature found (syscall)");
        return true;
    }
    return false;
}

bool HookDetector::checkLSPosedSyscall() {
    // 1. Check file paths via syscall
    for (const auto& path : getLSPosedPaths()) {
        if (syscall_file_exists(path.c_str())) {
            LOGD("LSPosed path found (syscall): %s", path.c_str());
            return true;
        }
    }

    // 2. Check memory maps via syscall
    if (checkLSPosedMemorySyscall()) {
        LOGD("LSPosed detected in memory (syscall)");
        return true;
    }

    // 3. Check for Riru/Zygisk via syscall
    if (checkRiruZygiskSyscall()) {
        LOGD("Riru/Zygisk detected (syscall)");
        return true;
    }

    return false;
}

bool HookDetector::checkLSPosedMemorySyscall() {
    std::string content = syscall_read_file("/proc/self/maps", 131072);

    // Convert to uppercase for case-insensitive search
    std::string upper_content = content;
    std::transform(upper_content.begin(), upper_content.end(), upper_content.begin(), ::toupper);

    // Check for Xposed/LSPosed classic signatures (case-insensitive)
    if (upper_content.find("LIBXPOSED_ART.SO") != std::string::npos ||
        upper_content.find("XPOSEDBRIDGE.JAR") != std::string::npos ||
        upper_content.find("XPOSEDBRIDGE") != std::string::npos) {
        LOGD("Xposed/LSPosed JAR/SO found (syscall)");
        return true;
    }

    // Check for LSPlant (LSPosed's ART hooking library)
    if (upper_content.find("LSPLANT") != std::string::npos ||
        upper_content.find("LIBLSPLANT") != std::string::npos) {
        LOGD("LSPlant hooking library found (syscall)");
        return true;
    }

    // Check for LSPosed daemon and framework
    if (content.find("lspd") != std::string::npos ||
        content.find("lsposed") != std::string::npos ||
        content.find("edxposed") != std::string::npos ||
        content.find("EdXposed") != std::string::npos) {
        LOGD("LSPosed memory signature found (syscall)");
        return true;
    }

    // Check for Zygisk LSPosed module paths in maps
    if (content.find("/data/adb/modules/") != std::string::npos &&
        content.find("/zygisk/") != std::string::npos) {
        if (content.find("lsposed") != std::string::npos ||
            content.find("edxposed") != std::string::npos) {
            LOGD("LSPosed Zygisk module found (syscall)");
            return true;
        }
    }

    // Check for Riru LSPosed
    if (content.find("/system/lib") != std::string::npos &&
        content.find("libriru") != std::string::npos) {
        LOGD("Riru library found (syscall)");
        return true;
    }

    // Check for module files
    if ((content.find("/data/misc/riru/modules") != std::string::npos ||
         content.find("/data/adb/modules") != std::string::npos) &&
        (content.find(".dex") != std::string::npos || content.find(".so") != std::string::npos)) {
        LOGD("Suspicious module file found (syscall)");
        return true;
    }

    return false;
}

bool HookDetector::checkRiruZygiskSyscall() {
    // Check Riru paths
    if (syscall_file_exists("/data/adb/riru") ||
        syscall_file_exists("/system/lib/libriru.so") ||
        syscall_file_exists("/system/lib64/libriru.so")) {
        LOGD("Riru detected (syscall)");
        return true;
    }

    // Check memory for Riru/Zygisk
    std::string content = syscall_read_file("/proc/self/maps", 131072);
    if (content.find("riru") != std::string::npos ||
        content.find("zygisk") != std::string::npos) {
        LOGD("Riru/Zygisk memory signature found (syscall)");
        return true;
    }

    return false;
}

bool HookDetector::checkMapsForHooksSyscall() {
    std::string content = syscall_read_file("/proc/self/maps", 65536);
    if (content.find("substrate") != std::string::npos ||
        content.find("xposed") != std::string::npos ||
        content.find("riru") != std::string::npos) {
        LOGD("Hook framework signature found (syscall)");
        return true;
    }
    return false;
}

bool HookDetector::checkFridaThreads() {
    DIR* dir = opendir("/proc/self/task");
    if (!dir) return false;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        std::string statusPath = "/proc/self/task/" + std::string(entry->d_name) + "/comm";
        std::ifstream comm(statusPath);
        if (comm.is_open()) {
            std::string threadName;
            std::getline(comm, threadName);
            if (threadName.find("gmain") != std::string::npos ||
                threadName.find("gdbus") != std::string::npos ||
                threadName.find("gum-js-loop") != std::string::npos ||
                threadName.find("pool-frida") != std::string::npos) {
                LOGD("Frida thread found: %s", threadName.c_str());
                closedir(dir);
                return true;
            }
        }
    }
    closedir(dir);
    return false;
}

// Get detailed LSPosed injection information
std::string HookDetector::getLSPosedDetails() {
    std::string details;
    std::string content = syscall_read_file("/proc/self/maps", 131072);
    if (content.empty()) return "";

    std::stringstream ss(content);
    std::string line;
    int injectionCount = 0;
    int rwxpAnonCount = 0;
    std::set<std::string> foundPaths;  // To avoid duplicates

    while (std::getline(ss, line)) {
        bool isLSPosedRelated = false;
        std::string modulePath;

        // Convert to uppercase for case-insensitive comparison
        std::string upper_line = line;
        std::transform(upper_line.begin(), upper_line.end(), upper_line.begin(), ::toupper);

        // Check for anonymous executable memory (rwxp with no backing file)
        if (line.find(" rwxp ") != std::string::npos) {
            size_t pathStart = line.rfind(' ');
            std::string path;
            if (pathStart != std::string::npos && pathStart < line.length() - 1) {
                path = line.substr(pathStart + 1);
            }

            bool isAnonymous = path.empty() || path == "[anon]" || path == "?" ||
                              line.find(" 00:00 0 ") != std::string::npos;

            if (isAnonymous) {
                rwxpAnonCount++;
                if (rwxpAnonCount <= 5) { // Limit output
                    details += "• [可疑可执行内存] " + line.substr(0, line.find(' ')) + " rwxp\n";
                }
                continue; // Don't double-count as LSPosed module
            }
        }

        // Check for Xposed/LSPosed classic signatures
        if (upper_line.find("LIBXPOSED_ART.SO") != std::string::npos ||
            upper_line.find("XPOSEDBRIDGE.JAR") != std::string::npos ||
            upper_line.find("XPOSEDBRIDGE") != std::string::npos) {
            isLSPosedRelated = true;
        }

        // Check for LSPlant
        if (upper_line.find("LSPLANT") != std::string::npos ||
            upper_line.find("LIBLSPLANT") != std::string::npos) {
            isLSPosedRelated = true;
        }

        // Check for LSPosed signatures
        if (line.find("lspd") != std::string::npos ||
            line.find("lsposed") != std::string::npos ||
            line.find("edxposed") != std::string::npos) {
            isLSPosedRelated = true;
        }

        // Check for Zygisk LSPosed modules
        if (line.find("/data/adb/modules/") != std::string::npos &&
            line.find("/zygisk/") != std::string::npos) {
            isLSPosedRelated = true;
        }

        // Check for Riru modules
        if (line.find("/data/misc/riru/modules/") != std::string::npos ||
            (line.find("/system/lib") != std::string::npos && line.find("libriru") != std::string::npos)) {
            isLSPosedRelated = true;
        }

        if (isLSPosedRelated) {
            // Extract the file path from the maps line
            // Format: address-address perm offset dev:inode path
            size_t pathStart = line.rfind(' ');
            if (pathStart != std::string::npos && pathStart < line.length() - 1) {
                modulePath = line.substr(pathStart + 1);

                // Skip if already recorded or is a system library not related
                if (foundPaths.find(modulePath) == foundPaths.end() &&
                    !modulePath.empty() && modulePath != "[anon]") {
                    foundPaths.insert(modulePath);
                    injectionCount++;
                    details += "• " + modulePath + "\n";
                    LOGD("LSPosed injection found: %s", modulePath.c_str());
                }
            }
        }
    }

    if (injectionCount > 0 || rwxpAnonCount > 0) {
        std::stringstream result;
        if (injectionCount > 0) {
            result << "检测到 " << injectionCount << " 个注入模块:\n";
        }
        if (rwxpAnonCount > 0) {
            if (injectionCount > 0) result << "\n";
            result << "检测到 " << rwxpAnonCount << " 个匿名可执行内存区域 (rwxp)\n";
        }
        result << details;
        return result.str();
    }

    return "";
}

// Check for suspicious anonymous executable memory (rwxp with no file backing)
// This is a strong indicator of code injection (LSPosed, Frida, etc.)
bool HookDetector::checkAnonymousExecutableMemory() {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;

    std::string line;
    int rwxp_count = 0;

    while (std::getline(maps, line)) {
        // Check for rwxp permission
        if (line.find(" rwxp ") == std::string::npos) {
            continue;
        }

        // Extract the path part (last field after spaces)
        size_t pathStart = line.rfind(' ');
        std::string path;
        if (pathStart != std::string::npos && pathStart < line.length() - 1) {
            path = line.substr(pathStart + 1);
        }

        // Anonymous memory has no path, or path is empty, or inode is 0
        // Check if this is anonymous memory (no file backing)
        bool isAnonymous = path.empty() ||
                          path == "[anon]" ||
                          path == "[anon:libc_malloc]" ||
                          path == "?" ||
                          line.find(" 00:00 0 ") != std::string::npos; // inode 0

        if (isAnonymous) {
            rwxp_count++;
            LOGD("Suspicious anonymous rwxp memory found: %s", line.c_str());

            // Even one anonymous rwxp region is highly suspicious
            // LSPosed/Frida often create small rwxp regions for hooks
            if (rwxp_count >= 1) {
                return true;
            }
        }
    }

    return false;
}

// System-wide LSPosed process detection
// Scans all processes for LSPosed-related names (works even if app not in LSPosed scope)
bool HookDetector::checkLSPosedSystemWide() {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return false;

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Check if directory name is numeric (PID)
        if (entry->d_type != DT_DIR) continue;

        bool is_pid = true;
        for (int i = 0; entry->d_name[i] != '\0'; i++) {
            if (!isdigit(entry->d_name[i])) {
                is_pid = false;
                break;
            }
        }
        if (!is_pid) continue;

        // Read /proc/[pid]/cmdline
        std::string cmdline_path = std::string("/proc/") + entry->d_name + "/cmdline";
        std::ifstream cmdline_file(cmdline_path);
        if (!cmdline_file.is_open()) continue;

        std::string cmdline;
        std::getline(cmdline_file, cmdline, '\0');
        cmdline_file.close();

        // Convert to lowercase for case-insensitive matching
        std::string lower_cmdline = cmdline;
        std::transform(lower_cmdline.begin(), lower_cmdline.end(), lower_cmdline.begin(), ::tolower);

        // Check for LSPosed-related process names
        if (lower_cmdline.find("lsposed") != std::string::npos ||
            lower_cmdline.find("lspd") != std::string::npos ||
            lower_cmdline.find("edxposed") != std::string::npos ||
            lower_cmdline.find("xposed") != std::string::npos) {
            LOGD("LSPosed-related process found: PID=%s, cmdline=%s", entry->d_name, cmdline.c_str());
            closedir(proc_dir);
            return true;
        }

        // Also check /proc/[pid]/comm (short process name)
        std::string comm_path = std::string("/proc/") + entry->d_name + "/comm";
        std::ifstream comm_file(comm_path);
        if (comm_file.is_open()) {
            std::string comm;
            std::getline(comm_file, comm);
            comm_file.close();

            std::string lower_comm = comm;
            std::transform(lower_comm.begin(), lower_comm.end(), lower_comm.begin(), ::tolower);

            if (lower_comm.find("lsposed") != std::string::npos ||
                lower_comm.find("lspd") != std::string::npos ||
                lower_comm.find("xposed") != std::string::npos) {
                LOGD("LSPosed-related comm found: PID=%s, comm=%s", entry->d_name, comm.c_str());
                closedir(proc_dir);
                return true;
            }
        }
    }

    closedir(proc_dir);
    return false;
}

// ===================== SMAPS Memory Integrity Detection =====================

/**
 * 高级内存取证技术 - 检测代码段篡改
 * 通过分析 /proc/self/smaps 文件检测 Inline Hook
 * 原理: 对只读代码段（r-xp）进行修改会触发 Copy-on-Write，产生 Private_Dirty 页
 */
bool HookDetector::checkSmapsIntegrity() {
    LOGD("=== checkSmapsIntegrity() START ===");

    // 关键库列表 - 这些是 Hook 框架的主要目标
    const char* CRITICAL_LIBS[] = {
        "libart.so",        // Android Runtime (Xposed/LSPosed 主要 Hook 点)
        "libc.so",          // C 标准库 (Frida 常 Hook)
        "libandroid_runtime.so",  // Android Runtime JNI
        "liblaunch.so",     // [XFF-C] 检测器自身:自己代码段被 inline-patch/hook 也要能发现
        nullptr
    };

    // 使用 syscall 直接读取（避免被 Hook）
    int fd = syscall(__NR_openat, AT_FDCWD, "/proc/self/smaps", O_RDONLY);
    if (fd < 0) {
        LOGD("Failed to open /proc/self/smaps");
        return false;
    }

    char buf[8192];
    std::string current_lib;
    bool is_executable = false;
    bool detected = false;
    std::string line_buffer;

    while (true) {
        ssize_t n = syscall(__NR_read, fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = '\0';

        // 逐行解析
        line_buffer += buf;
        size_t pos;

        while ((pos = line_buffer.find('\n')) != std::string::npos) {
            std::string line = line_buffer.substr(0, pos);
            line_buffer.erase(0, pos + 1);

            // 1. 检测可执行段映射行 (r-xp) - 这是代码段
            if (line.find("r-xp") != std::string::npos) {
                is_executable = true;
                current_lib.clear();

                // 检查是否是关键库
                for (int i = 0; CRITICAL_LIBS[i]; i++) {
                    if (line.find(CRITICAL_LIBS[i]) != std::string::npos) {
                        current_lib = CRITICAL_LIBS[i];
                        LOGD("Found executable section of %s", current_lib.c_str());
                        break;
                    }
                }
            }
            // 遇到新映射段，重置标志
            else if (line.find('-') != std::string::npos &&
                     (line.find("rw-p") != std::string::npos ||
                      line.find("r--p") != std::string::npos)) {
                is_executable = false;
            }

            // 2. 检查 Private_Dirty 字段 - 关键检测点！
            if (is_executable && !current_lib.empty() &&
                line.find("Private_Dirty:") != std::string::npos) {

                // 提取数值
                size_t colon_pos = line.find(':');
                if (colon_pos != std::string::npos) {
                    std::string value_str = line.substr(colon_pos + 1);
                    // 去除空格
                    value_str.erase(0, value_str.find_first_not_of(" \t"));
                    int dirty_kb = atoi(value_str.c_str());

                    // 代码段的 Private_Dirty > 0 说明被修改过！
                    if (dirty_kb > 0) {
                        LOGD("🚨 SMAPS: %s executable segment has Private_Dirty: %d kB (code patched!)",
                             current_lib.c_str(), dirty_kb);
                        detected = true;
                        // 继续检测其他库
                    }
                }
            }
        }
    }

    syscall(__NR_close, fd);

    if (detected) {
        LOGD("=== checkSmapsIntegrity() END - Inline Hook DETECTED ===");
    } else {
        LOGD("=== checkSmapsIntegrity() END - No Hook detected ===");
    }

    return detected;
}

// ===================== Zygisk Detection (通用) =====================
// 检测所有 Zygisk 变体: Magisk Zygisk, ReZygisk, Zygisk Next, Zygisk Assistant

bool HookDetector::checkZygiskNative() {
    LOGD("=== checkZygiskNative() START ===");
    LOGD("[Zygisk检测] Native层检测开始 - 使用 libc access/opendir/dlopen");

    int detectionPoints = 0;
    bool detected = false;

    // 1. Check Magisk Zygisk marker
    LOGD("[1/8] 检测 Magisk Zygisk 标记文件...");
    if (access("/data/adb/modules/.zygisk", F_OK) == 0) {
        LOGD("✅ [DETECTED] Magisk Zygisk marker: /data/adb/modules/.zygisk");
        detectionPoints++;
        detected = true;
    } else {
        LOGD("❌ Magisk Zygisk 标记文件不存在");
    }

    // 2. Check ReZygisk module directory
    LOGD("[2/8] 检测 ReZygisk 模块目录...");
    if (access("/data/adb/modules/rezygisk", F_OK) == 0) {
        LOGD("✅ [DETECTED] ReZygisk module: /data/adb/modules/rezygisk");
        detectionPoints++;
        detected = true;

        // 检查模块文件
        if (access("/data/adb/modules/rezygisk/module.prop", F_OK) == 0) {
            LOGD("  ├─ module.prop 存在");
        }
        if (access("/data/adb/modules/rezygisk/zygisk", F_OK) == 0) {
            LOGD("  ├─ zygisk 标记文件存在");
        }
    } else {
        LOGD("❌ ReZygisk 模块目录不存在");
    }

    // 3. Check Zygisk Next module
    LOGD("[3/8] 检测 Zygisk Next 模块...");
    if (access("/data/adb/modules/zygiskNext", F_OK) == 0) {
        LOGD("✅ [DETECTED] Zygisk Next module: /data/adb/modules/zygiskNext");
        detectionPoints++;
        detected = true;
    } else {
        LOGD("❌ Zygisk Next 模块不存在");
    }

    // 4. Check for zygiskd daemon process
    LOGD("[4/8] 扫描 /proc 检测 Zygisk 守护进程...");
    int processScanned = 0;
    int zygiskProcessFound = 0;
    DIR* procDir = opendir("/proc");
    if (procDir != nullptr) {
        struct dirent* entry;
        while ((entry = readdir(procDir)) != nullptr) {
            if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
                processScanned++;
                std::string cmdlinePath = "/proc/" + std::string(entry->d_name) + "/cmdline";
                std::string commPath = "/proc/" + std::string(entry->d_name) + "/comm";

                // Check cmdline
                std::ifstream cmdfile(cmdlinePath);
                if (cmdfile.is_open()) {
                    std::string cmdline;
                    std::getline(cmdfile, cmdline);
                    cmdfile.close();

                    if (cmdline.find("zygiskd") != std::string::npos ||
                        cmdline.find("rezygiskd") != std::string::npos) {
                        LOGD("✅ [DETECTED] Zygisk daemon process [PID:%s]: %s",
                             entry->d_name, cmdline.c_str());
                        zygiskProcessFound++;
                        detectionPoints++;
                        detected = true;
                    }
                }

                // Check comm
                std::ifstream commfile(commPath);
                if (commfile.is_open()) {
                    std::string comm;
                    std::getline(commfile, comm);
                    commfile.close();

                    if (comm.find("zygiskd") != std::string::npos) {
                        LOGD("✅ [DETECTED] Zygisk daemon via comm [PID:%s]: %s",
                             entry->d_name, comm.c_str());
                        if (zygiskProcessFound == 0) {  // 避免重复计数
                            zygiskProcessFound++;
                            detectionPoints++;
                            detected = true;
                        }
                    }
                }
            }
        }
        closedir(procDir);
        LOGD("  ├─ 已扫描进程数: %d", processScanned);
        if (zygiskProcessFound > 0) {
            LOGD("  └─ 发现 Zygisk 守护进程: %d 个", zygiskProcessFound);
        } else {
            LOGD("  └─ ❌ 未发现 Zygisk 守护进程");
        }
    } else {
        LOGD("❌ 无法打开 /proc 目录 (SELinux限制?)");
    }

    // 5. Check /proc/self/maps for Zygisk libraries
    LOGD("[5/8] 分析 /proc/self/maps 内存映射...");
    int mapsLineScanned = 0;
    int zygiskMapsFound = 0;
    std::ifstream maps("/proc/self/maps");
    if (maps.is_open()) {
        std::string line;
        while (std::getline(maps, line)) {
            mapsLineScanned++;
            std::string lower = line;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            // Zygisk core library
            if (lower.find("libzygisk.so") != std::string::npos) {
                LOGD("✅ [DETECTED] libzygisk.so in maps:");
                LOGD("  └─ %s", line.c_str());
                zygiskMapsFound++;
                detectionPoints++;
                detected = true;
            }

            // Generic zygisk string (but not zygote)
            else if (lower.find("zygisk") != std::string::npos &&
                     lower.find("zygote") == std::string::npos) {
                LOGD("✅ [DETECTED] Zygisk-related in maps:");
                LOGD("  └─ %s", line.c_str());
                if (zygiskMapsFound == 0) {  // 只计数一次
                    zygiskMapsFound++;
                    detectionPoints++;
                    detected = true;
                }
            }

            // Zygisk dependencies
            else if (lower.find("lsplt") != std::string::npos ||
                     lower.find("csoloader") != std::string::npos) {
                LOGD("✅ [DETECTED] ReZygisk dependency in maps:");
                LOGD("  └─ %s", line.c_str());
                if (zygiskMapsFound == 0) {
                    zygiskMapsFound++;
                    detectionPoints++;
                    detected = true;
                }
            }

            // Zygisk module paths
            else if (lower.find("/data/adb/modules/") != std::string::npos &&
                     lower.find("/zygisk/") != std::string::npos) {
                LOGD("✅ [DETECTED] Zygisk module path in maps:");
                LOGD("  └─ %s", line.c_str());
                if (zygiskMapsFound == 0) {
                    zygiskMapsFound++;
                    detectionPoints++;
                    detected = true;
                }
            }
        }
        maps.close();
        LOGD("  ├─ 已扫描内存映射行数: %d", mapsLineScanned);
        if (zygiskMapsFound > 0) {
            LOGD("  └─ 发现 Zygisk 相关映射: %d 处", zygiskMapsFound);
        } else {
            LOGD("  └─ ❌ 未在内存映射中发现 Zygisk");
        }
    } else {
        LOGD("❌ 无法读取 /proc/self/maps");
    }

    // 6. Check for Zygisk library files
    LOGD("[6/8] 检测 Zygisk 库文件...");
    const char* lib_paths[] = {
        "/data/adb/modules/rezygisk/zygisk/arm64-v8a.so",
        "/data/adb/modules/rezygisk/zygisk/armeabi-v7a.so",
        "/data/adb/modules/zygiskNext/zygisk/arm64-v8a.so",
        "/data/adb/modules/zygiskNext/zygisk/armeabi-v7a.so",
        "/system/lib64/libzygisk.so",
        "/system/lib/libzygisk.so"
    };
    int libsChecked = 0;
    int libsFound = 0;
    for (const char* path : lib_paths) {
        libsChecked++;
        if (access(path, F_OK) == 0) {
            LOGD("✅ [DETECTED] Zygisk library: %s", path);
            libsFound++;
            if (detectionPoints < 5) {  // 避免重复计数过多
                detectionPoints++;
                detected = true;
            }
        }
    }
    LOGD("  ├─ 已检查库路径: %d 个", libsChecked);
    if (libsFound > 0) {
        LOGD("  └─ 发现库文件: %d 个", libsFound);
    } else {
        LOGD("  └─ ❌ 未发现 Zygisk 库文件");
    }

    // 7. Check dlopen handles
    LOGD("[7/8] 检测内存中的 libzygisk.so...");
    void* handle = dlopen("libzygisk.so", RTLD_NOLOAD | RTLD_NOW);
    if (handle != nullptr) {
        LOGD("✅ [DETECTED] libzygisk.so 已加载到内存中");
        LOGD("  └─ Handle: %p", handle);
        dlclose(handle);
        detectionPoints++;
        detected = true;
    } else {
        LOGD("❌ libzygisk.so 未在内存中");
    }

    // 8. Additional checks
    LOGD("[8/8] 额外检测项...");

    // Check /dev/zygisk
    if (access("/dev/zygisk", F_OK) == 0) {
        LOGD("✅ [DETECTED] Device node: /dev/zygisk");
        detectionPoints++;
        detected = true;
    } else {
        LOGD("❌ /dev/zygisk 设备节点不存在");
    }

    // Summary
    LOGD("=== checkZygiskNative() SUMMARY ===");
    LOGD("检测方法: Native (libc)");
    LOGD("检测点总数: %d", detectionPoints);
    LOGD("最终结果: %s", detected ? "✅ DETECTED" : "❌ NOT DETECTED");
    LOGD("=== checkZygiskNative() END ===");

    return detected;
}

bool HookDetector::checkZygiskSyscall() {
    LOGD("=== checkZygiskSyscall() START ===");
    LOGD("[Zygisk检测] Syscall层检测开始 - 使用直接系统调用 (绕过libc)");

    int detectionPoints = 0;
    bool detected = false;

    // 1. Check Magisk Zygisk marker via syscall
    LOGD("[1/7] 检测 Magisk Zygisk 标记 (syscall faccessat)...");
    if (syscall_file_exists("/data/adb/modules/.zygisk")) {
        LOGD("✅ [DETECTED] Magisk Zygisk marker: /data/adb/modules/.zygisk");
        detectionPoints++;
        detected = true;
    } else {
        LOGD("❌ Magisk Zygisk 标记不存在");
    }

    // 2. Check ReZygisk module directory via syscall
    LOGD("[2/7] 检测 ReZygisk 模块 (syscall faccessat)...");
    if (syscall_file_exists("/data/adb/modules/rezygisk")) {
        LOGD("✅ [DETECTED] ReZygisk module: /data/adb/modules/rezygisk");
        detectionPoints++;
        detected = true;

        // Check additional ReZygisk files
        if (syscall_file_exists("/data/adb/modules/rezygisk/module.prop")) {
            LOGD("  ├─ module.prop 存在 (syscall验证)");
        }
        if (syscall_file_exists("/data/adb/modules/rezygisk/zygisk")) {
            LOGD("  ├─ zygisk 标记存在 (syscall验证)");
        }
    } else {
        LOGD("❌ ReZygisk 模块不存在");
    }

    // 3. Check Zygisk Next module via syscall
    LOGD("[3/7] 检测 Zygisk Next 模块 (syscall faccessat)...");
    if (syscall_file_exists("/data/adb/modules/zygiskNext")) {
        LOGD("✅ [DETECTED] Zygisk Next module: /data/adb/modules/zygiskNext");
        detectionPoints++;
        detected = true;
    } else {
        LOGD("❌ Zygisk Next 模块不存在");
    }

    // 4. Check /proc/self/maps via syscall
    LOGD("[4/7] 分析 /proc/self/maps (syscall openat+read)...");
    std::string maps = syscall_read_file("/proc/self/maps", 131072);  // 128KB buffer
    int mapsSize = maps.size();
    LOGD("  ├─ 成功读取 maps 文件: %d 字节", mapsSize);

    if (!maps.empty()) {
        std::string lower = maps;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        // Count lines
        int lineCount = 0;
        for (char c : maps) {
            if (c == '\n') lineCount++;
        }
        LOGD("  ├─ 内存映射条目数: %d 行", lineCount);

        int zygiskMapsCount = 0;

        // Check for libzygisk.so
        if (lower.find("libzygisk.so") != std::string::npos) {
            size_t pos = lower.find("libzygisk.so");
            size_t lineStart = maps.rfind('\n', pos) + 1;
            size_t lineEnd = maps.find('\n', pos);
            std::string matchedLine = maps.substr(lineStart, lineEnd - lineStart);
            LOGD("✅ [DETECTED] libzygisk.so in maps:");
            LOGD("  └─ %s", matchedLine.c_str());
            zygiskMapsCount++;
            detectionPoints++;
            detected = true;
        }

        // Check for generic zygisk (not zygote)
        else if (lower.find("zygisk") != std::string::npos &&
                 lower.find("zygote") == std::string::npos) {
            size_t pos = lower.find("zygisk");
            size_t lineStart = maps.rfind('\n', pos) + 1;
            size_t lineEnd = maps.find('\n', pos);
            std::string matchedLine = maps.substr(lineStart, lineEnd - lineStart);
            LOGD("✅ [DETECTED] Zygisk-related string in maps:");
            LOGD("  └─ %s", matchedLine.c_str());
            zygiskMapsCount++;
            detectionPoints++;
            detected = true;
        }

        // Check for Zygisk dependencies
        if (lower.find("lsplt") != std::string::npos) {
            LOGD("✅ [DETECTED] LSPlt library (ReZygisk dependency)");
            if (zygiskMapsCount == 0) {
                zygiskMapsCount++;
                detectionPoints++;
                detected = true;
            }
        }
        if (lower.find("csoloader") != std::string::npos) {
            LOGD("✅ [DETECTED] CSOLoader library (ReZygisk dependency)");
            if (zygiskMapsCount == 0) {
                zygiskMapsCount++;
                detectionPoints++;
                detected = true;
            }
        }

        // Check for module paths
        if (lower.find("/data/adb/modules/") != std::string::npos &&
            lower.find("/zygisk/") != std::string::npos) {
            size_t pos = lower.find("/zygisk/");
            size_t lineStart = maps.rfind('\n', pos) + 1;
            size_t lineEnd = maps.find('\n', pos);
            std::string matchedLine = maps.substr(lineStart, lineEnd - lineStart);
            LOGD("✅ [DETECTED] Zygisk module path:");
            LOGD("  └─ %s", matchedLine.c_str());
            if (zygiskMapsCount == 0) {
                zygiskMapsCount++;
                detectionPoints++;
                detected = true;
            }
        }

        if (zygiskMapsCount == 0) {
            LOGD("  └─ ❌ 未在内存映射中发现 Zygisk");
        } else {
            LOGD("  └─ 发现 Zygisk 映射: %d 处", zygiskMapsCount);
        }
    } else {
        LOGD("❌ 无法读取 /proc/self/maps (syscall)");
    }

    // 5. Check Zygisk library files via syscall
    LOGD("[5/7] 检测 Zygisk 库文件 (syscall faccessat)...");
    const char* lib_paths[] = {
        "/data/adb/modules/rezygisk/zygisk/arm64-v8a.so",
        "/data/adb/modules/rezygisk/zygisk/armeabi-v7a.so",
        "/data/adb/modules/zygiskNext/zygisk/arm64-v8a.so",
        "/data/adb/modules/zygiskNext/zygisk/armeabi-v7a.so",
        "/system/lib64/libzygisk.so",
        "/system/lib/libzygisk.so"
    };
    int libsChecked = 0;
    int libsFound = 0;
    for (const char* path : lib_paths) {
        libsChecked++;
        if (syscall_file_exists(path)) {
            LOGD("✅ [DETECTED] Zygisk library: %s", path);
            libsFound++;
            if (detectionPoints < 5) {
                detectionPoints++;
                detected = true;
            }
        }
    }
    LOGD("  ├─ 已检查库路径: %d 个", libsChecked);
    if (libsFound > 0) {
        LOGD("  └─ 发现库文件: %d 个", libsFound);
    } else {
        LOGD("  └─ ❌ 未发现 Zygisk 库文件");
    }

    // 6. Check parent process (Zygote injection detection)
    LOGD("[6/7] 检测 Zygote 注入 (分析父进程)...");
    std::string statContent = syscall_read_file("/proc/self/stat", 1024);
    if (!statContent.empty()) {
        LOGD("  ├─ 成功读取 /proc/self/stat: %lu 字节", statContent.size());

        // Parse PPID
        std::istringstream iss(statContent);
        std::string token;
        int field = 0;
        int ppid = 0;
        while (iss >> token && field < 4) {
            field++;
            if (field == 4) {
                ppid = std::atoi(token.c_str());
                break;
            }
        }

        if (ppid > 0) {
            LOGD("  ├─ 父进程 PID: %d", ppid);
            std::string ppidCmdline = "/proc/" + std::to_string(ppid) + "/cmdline";
            std::string cmdline = syscall_read_file(ppidCmdline.c_str(), 1024);

            if (!cmdline.empty()) {
                LOGD("  ├─ 父进程名称: %s", cmdline.c_str());

                if (cmdline.find("zygote") != std::string::npos ||
                    cmdline.find("zygote64") != std::string::npos) {
                    LOGD("  ├─ 父进程是 Zygote! 检查注入痕迹...");

                    // Check for Zygisk traces
                    if (maps.find("zygisk") != std::string::npos ||
                        maps.find("lsplt") != std::string::npos) {
                        LOGD("✅ [DETECTED] Zygote 注入 + Zygisk 痕迹");
                        detectionPoints++;
                        detected = true;
                    } else {
                        LOGD("  └─ 父进程是 Zygote，但未发现 Zygisk 注入痕迹");
                    }
                } else {
                    LOGD("  └─ 父进程不是 Zygote");
                }
            } else {
                LOGD("  └─ 无法读取父进程 cmdline");
            }
        } else {
            LOGD("  └─ 无法解析父进程 PID");
        }
    } else {
        LOGD("❌ 无法读取 /proc/self/stat");
    }

    // 7. Additional checks
    LOGD("[7/7] 额外检测 (syscall)...");
    if (syscall_file_exists("/dev/zygisk")) {
        LOGD("✅ [DETECTED] Device node: /dev/zygisk");
        detectionPoints++;
        detected = true;
    } else {
        LOGD("❌ /dev/zygisk 不存在");
    }

    // Summary
    LOGD("=== checkZygiskSyscall() SUMMARY ===");
    LOGD("检测方法: Direct Syscall (openat/read/faccessat)");
    LOGD("检测点总数: %d", detectionPoints);
    LOGD("最终结果: %s", detected ? "✅ DETECTED" : "❌ NOT DETECTED");
    LOGD("=== checkZygiskSyscall() END ===");

    return detected;
}

// Combined multi-layer detection
MultiLayerResult HookDetector::detectXposed() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkXposedNative() || checkMapsForHooks();
    result.syscallResult = checkXposedSyscall() || checkMapsForHooksSyscall();
    return result;
}

MultiLayerResult HookDetector::detectFrida() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkFridaNative() || checkFridaPortsNative() ||
                          checkFridaMemoryNative() || checkFridaThreads();
    result.syscallResult = checkFridaSyscall() || checkFridaMemorySyscall();
    return result;
}

MultiLayerResult HookDetector::detectLSPosed() {
    MultiLayerResult result;
    result.javaResult = false;
    // Include system-wide process scan and anonymous executable memory check
    // These work even if app is not in LSPosed scope
    result.nativeResult = checkLSPosedNative() || checkLSPosedMemoryNative() ||
                          checkRiruZygiskNative() || checkLSPosedSystemWide() ||
                          checkAnonymousExecutableMemory();
    result.syscallResult = checkLSPosedSyscall() || checkLSPosedMemorySyscall() || checkRiruZygiskSyscall();
    return result;
}

MultiLayerResult HookDetector::detectZygisk() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkZygiskNative();
    result.syscallResult = checkZygiskSyscall();
    return result;
}

// 为了向后兼容，保留 detectSmapsHook 的别名
MultiLayerResult HookDetector::detectSmapsHook() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkSmapsIntegrity();
    result.syscallResult = checkSmapsIntegrity();  // SMAPS uses same syscall-based method
    return result;
}

MultiLayerResult HookDetector::detectMemoryHooks() {
    MultiLayerResult result;
    result.javaResult = false;
    // Anonymous executable memory is a strong indicator of hooks
    result.nativeResult = checkMapsForHooks() || checkFridaMemoryNative() || checkAnonymousExecutableMemory();
    result.syscallResult = checkMapsForHooksSyscall() || checkFridaMemorySyscall();
    return result;
}

// ================= [XFF] 自读内存原始字节 · Xposed 类名串扫描 =================
// 现有 checkLSPosedMemoryNative 只看 /proc/self/maps 的“行文本(文件名)”,注入已把
// lspd/lsposed/lsplant 等文件痕迹全藏 → 漏检。本函数改扫内存“字节内容”:
// 读 maps 拿匿名/dalvik 区地址,直接指针 memmem 找加载进本进程的模块/框架类名串。
// 这是 Risk Detector DetectEvilFrameworks 的核心技术;no-hook 模块实测证明:只要有
// 模块被 scope 进来(哪怕不 hook),这些类名串就在 dalvik 区,必被扫到。
static std::string s_xposedMemDetails;

bool HookDetector::checkXposedMemoryStrings() {
    // 只用“注入特有”needle:框架/现代API 加载进被注入进程才有的类名。app 自己的字符串字面量在
    // 文件映射的 dex 串池里(本扫描只扫匿名/dalvik 区,跳过 file-backed),不会自命中;只有注入进
    // 匿名内存的框架 dex / native 串才被扫到 → 可放心放框架类名。覆盖各 Xposed 变体 + hook 引擎。
    static const char* kNeedles[] = {
        // —— LSPosed 框架(Zygisk/Riru)——
        "org.lsposed.lspd",                        // 框架 service 类
        "org.lsposed.lspd.service",
        "org.lsposed.lspd.core",                   // 框架核心
        "org.lsposed.lspd.nativebridge",           // native 桥
        "org.lsposed.lspd.hooker",                 // 内建 hooker
        "LspModuleClassLoader",                    // 模块专用 classloader
        "ILSPInjectedModule",                      // 框架注入 service
        "LSPHooker_",                              // LSPlant 生成的 hook 桥类名前缀
        // —— 现代 libxposed API ——
        "XposedModuleInterface",
        "XposedModuleInterface$ModuleLoadedParam",
        "io.github.libxposed.api",                 // 新版 libxposed 接口
        "io.github.libxposed.service",
        // —— 经典 Xposed API(EdXposed/太极/VirtualXposed 都用)——
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XposedHelpers",
        "de.robv.android.xposed.XC_MethodHook",    // hook 回调基类
        "de.robv.android.xposed.IXposedHookLoadPackage",
        "de.robv.android.xposed.callbacks.XC_LoadPackage",
        // —— EdXposed / Riru 系 ——
        "com.elderdrivers.riru",                   // EdXposed riru 实现
        "org.meowcat.edxposed",                    // EdXposed manager
        // —— LSPatch(免 root 重打包注入)——
        "org.lsposed.lspatch",
        // —— 太极 / 免 root Xposed ——
        "me.weishu.exp",                           // TaiChi exposed
        "me.weishu.epic",                          // Epic hook 引擎
        // —— native hook 引擎 ——
        "com.swift.sandhook",                      // SandHook
        "top.canyie.pine",                         // Pine
        "lab.galaxy.yahfa",                        // YAHFA
        "com.taobao.android.dexposed",             // Dexposed
    };
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return false;
    int memfd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);   // 经 pread 安全读,防野读崩
    if (memfd < 0) return false;
    s_xposedMemDetails.clear();
    bool found = false;
    std::string line;
    std::vector<char> rbuf;
    while (std::getline(maps, line)) {
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        char path[512] = {0};
        int n = sscanf(line.c_str(), "%lx-%lx %7s %*x %*x:%*x %*u %511[^\n]",
                       &start, &end, perms, path);
        if (n < 3 || perms[0] != 'r') continue;   // 必须可读
        std::string p = (n >= 4) ? std::string(path) : std::string();
        // 只扫匿名区(heap/dalvik)与 dalvik-* 命名区——加载的模块类/dex 串所在处。
        // 跳过 file-backed(含本 .so 的 .rodata,避免自己的 needle 常量自命中)。
        bool isTarget = p.empty()
                     || p.find("dalvik") != std::string::npos
                     || p.rfind("[anon:", 0) == 0;
        if (!isTarget || end <= start) continue;
        size_t len = end - start;
        if (len > 128UL * 1024 * 1024) continue;   // 跳过异常大区
        size_t got = xffPreadRegion(memfd, start, len, rbuf, 64UL * 1024 * 1024);
        if (got == 0) continue;
        for (const char* needle : kNeedles) {
            size_t nlen = strlen(needle);
            if (nlen == 0 || nlen > got) continue;
            if (memmem(rbuf.data(), got, needle, nlen) != nullptr) {
                LOGD("Xposed mem-string HIT: %s @ %s", needle, p.empty() ? "[anon]" : p.c_str());
                s_xposedMemDetails += std::string(needle) + " @ " + (p.empty() ? "[anon]" : p) + "\n";
                found = true;
            }
        }
    }
    close(memfd);
    return found;
}

std::string HookDetector::getXposedMemStringsDetails() {
    return s_xposedMemDetails.empty() ? std::string("未命中") : s_xposedMemDetails;
}

// ================= [XFF-T2/T3] 模块注入痕迹 · 外来 dex/apk 映射 + fd 扫描 =================
// 现有检测只认识 lspd/lsposed/xposed 这些"框架关键词",模块自身的 apk/dex 路径它不查。
// 思路反过来:宿主进程本该只 mmap 自己包的 base.apk/split + 系统 framework。任何一个
//   /data/app/~~xxx==/<别的包>/base.apk、外来 .dex/.oat/.vdex、或内存 dex 被映射进来
// 就是有模块被加载进本进程。dex 要执行必须被 ART mmap、模块 apk 的 fd 必须常开 →
// 这两处痕迹比 maps 行里的关键词更硬,藏不掉。
namespace {
    // 系统合法容器前缀/特征——命中即排除,避免误报
    bool isSystemContainer(const std::string& p) {
        return p.rfind("/system/", 0) == 0 ||
               p.rfind("/system_ext/", 0) == 0 ||
               p.rfind("/apex/", 0) == 0 ||
               p.rfind("/vendor/", 0) == 0 ||
               p.rfind("/product/", 0) == 0 ||
               p.find("/dalvik-cache/") != std::string::npos ||   // 系统 AOT 缓存
               p.find("boot.oat") != std::string::npos ||
               p.find("boot.art") != std::string::npos ||
               p.find("boot-framework") != std::string::npos;
    }
    // 是否是"代码容器"文件(apk/dex/jar/oat/odex/vdex)
    bool isCodeContainer(const std::string& p) {
        static const char* kExt[] = {".apk", ".dex", ".jar", ".oat", ".odex", ".vdex"};
        for (const char* ext : kExt) {
            size_t el = strlen(ext);
            if (p.size() >= el && p.compare(p.size() - el, el, ext) == 0) return true;
            // 兼容 "xxx.dex (deleted)" / "xxx.apk!classes.dex" 这类后缀带尾巴的写法
            if (p.find(std::string(ext) + " ") != std::string::npos ||
                p.find(std::string(ext) + "!") != std::string::npos) return true;
        }
        return false;
    }
    // 内存 dex 特征(InMemoryDexClassLoader / ashmem dex),排除正常 JIT/boot 缓存
    bool isInMemoryDex(const std::string& p) {
        bool memBacked = p.rfind("/memfd:", 0) == 0 ||
                         p.find("/dev/ashmem/") != std::string::npos ||
                         p.find("(deleted)") != std::string::npos;
        if (!memBacked) return false;
        // 只认带 dex/classes/vdex 字样的,排除 jit-cache / jit-zygote / boot
        bool looksDex = p.find("dex") != std::string::npos ||
                        p.find("classes") != std::string::npos ||
                        p.find("vdex") != std::string::npos;
        bool jit = p.find("jit-cache") != std::string::npos ||
                   p.find("jit-zygote") != std::string::npos ||
                   p.find("boot") != std::string::npos;
        return looksDex && !jit;
    }
    bool belongsToHost(const std::string& p, const std::string& hostPkg,
                       const std::string& hostApkDir) {
        if (!hostPkg.empty() && p.find(hostPkg) != std::string::npos) return true;
        if (!hostApkDir.empty() && p.find(hostApkDir) != std::string::npos) return true;
        return false;
    }
    // 已知会合法映射进普通 app 进程的系统包(WebView provider / Chrome / GMS dynamite),
    // 命中即排除,避免把系统 WebView 的 base.apk 误报成注入模块。
    bool isKnownSystemInjector(const std::string& p) {
        static const char* kInj[] = {
            "com.google.android.webview",
            "com.android.webview",
            "com.google.android.trichromelibrary",
            "com.android.chrome",
            "org.chromium",
            "com.google.android.gms",           // GMS dynamite 模块
        };
        for (const char* s : kInj) {
            if (p.find(s) != std::string::npos) return true;
        }
        return false;
    }
}

std::string HookDetector::getModuleInjectionReport(const std::string& hostPkg,
                                                   const std::string& hostApkDir) {
    std::string report;
    std::set<std::string> seen;

    // ---- T2: /proc/self/maps 外来代码容器映射 ----
    std::string maps = syscall_read_file_full("/proc/self/maps");
    std::stringstream ss(maps);
    std::string line;
    while (std::getline(ss, line)) {
        // 取最后一个字段(路径)。maps 路径可能含空格,取第 6 列到行尾更稳:
        // addr perm off dev inode path —— 前 5 列无空格,找到第 5 个空白后即为路径起点。
        int spaces = 0; size_t i = 0;
        for (; i < line.size() && spaces < 5; ++i) {
            if (line[i] == ' ') { spaces++; while (i + 1 < line.size() && line[i + 1] == ' ') ++i; }
        }
        if (spaces < 5 || i >= line.size()) continue;
        std::string path = line.substr(i);
        if (path.empty() || path[0] == '[') continue;   // 匿名/[stack]/[heap]

        bool foreign = false;
        const char* kind = nullptr;
        if (isCodeContainer(path) && !isSystemContainer(path) &&
            !belongsToHost(path, hostPkg, hostApkDir) && !isKnownSystemInjector(path)) {
            foreign = true; kind = "MAPS_FOREIGN";
        } else if (isInMemoryDex(path) && !belongsToHost(path, hostPkg, hostApkDir) &&
                   !isKnownSystemInjector(path)) {
            foreign = true; kind = "MAPS_MEMDEX";
        }
        if (!foreign) continue;
        if (seen.count(path)) continue;
        seen.insert(path);
        report += std::string(kind) + "=" + path + "\n";
        LOGD("[T2] foreign container in maps: %s", path.c_str());
    }

    // ---- T3: /proc/self/fd 外来打开文件 ----
    DIR* d = opendir("/proc/self/fd");
    if (d) {
        struct dirent* e;
        char target[PATH_MAX];
        while ((e = readdir(d)) != nullptr) {
            if (e->d_name[0] == '.') continue;
            std::string linkp = std::string("/proc/self/fd/") + e->d_name;
            ssize_t n = readlink(linkp.c_str(), target, sizeof(target) - 1);
            if (n <= 0) continue;
            target[n] = '\0';
            std::string t(target);

            bool suspicious = isCodeContainer(t) || isInMemoryDex(t) ||
                              t.rfind("/memfd:", 0) == 0;   // memfd 承载的 dex/apk
            if (!suspicious) continue;
            if (isSystemContainer(t) || belongsToHost(t, hostPkg, hostApkDir) ||
                isKnownSystemInjector(t)) continue;
            // 排除正常 JIT/boot memfd
            if (t.find("jit-cache") != std::string::npos ||
                t.find("jit-zygote") != std::string::npos ||
                t.find("boot") != std::string::npos) continue;

            std::string key = "fd:" + t;
            if (seen.count(key)) continue;
            seen.insert(key);
            report += "FD_FOREIGN=" + t + "\n";
            LOGD("[T3] foreign fd: %s -> %s", e->d_name, t.c_str());
        }
        closedir(d);
    }

    // ---- T2b: 匿名内存 DEX 内容扫描(抓 InMemoryDexClassLoader 注入的框架 dex) ----
    // 现代 LSPosed 把模块/框架 dex 读进 [anon:dalvik-DEX data] 匿名内存,无文件路径 → 上面的
    // maps/fd 文件扫描全抓不到。这里直接读匿名内存 dex 区的*字节*,memmem 找框架特征串。
    // 关键防自命中:**只扫 dalvik-DEX 内存 dex 区**,不扫 Java 堆(dalvik-main space 等)——
    // app 自己的 dex 是文件映射的,任何 [anon:dalvik-DEX data] 都是 InMemoryDexClassLoader 加载的
    // 内存 dex,里面绝不含本 app 的 Java 字面量(那些在文件 dex + Java 堆里,已被排除)。
    // needle 用框架专有简单名/接口名(经内存 CompactDex 编码后 slash 全描述符可能不连续,故用简单名)。
    static const char* kFwDescriptors[] = {
        "LspModuleClassLoader",           // LSPosed 模块专用 loader(框架专有)
        "IXposedHookLoadPackage",         // 经典 Xposed 模块入口接口
        "de.robv.android.xposed",         // 经典 Xposed API 包名
        "org.lsposed.lspd",               // LSPosed 框架包名
        "Lorg/lsposed/",                  // slash 描述符(若未编码)
        "Lde/robv/android/xposed/",
    };
    std::stringstream ssd(maps);
    std::string dline;
    int anonScanned = 0;
    int memfd2 = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);   // 经 pread 安全读,防野读崩
    std::vector<char> dbuf;
    while (memfd2 >= 0 && std::getline(ssd, dline)) {
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        char dpath[512] = {0};
        int n = sscanf(dline.c_str(), "%lx-%lx %7s %*x %*x:%*x %*u %511[^\n]",
                       &start, &end, perms, dpath);
        if (n < 3 || perms[0] != 'r') continue;   // 必须可读才能自读
        std::string p = (n >= 4) ? std::string(dpath) : std::string();
        // 只扫内存 dex 数据区(排除 Java 堆 dalvik-main/large-object/zygote space,防自命中)
        bool isMemDexRegion = (p.find("dalvik-DEX") != std::string::npos);
        if (!isMemDexRegion || end <= start) continue;
        size_t len = end - start;
        if (len > 96UL * 1024 * 1024) continue;    // 跳过异常大区
        anonScanned++;
        size_t got = xffPreadRegion(memfd2, start, len, dbuf, 64UL * 1024 * 1024);
        if (got == 0) continue;
        for (const char* desc : kFwDescriptors) {
            size_t dl = strlen(desc);
            if (dl > got) continue;
            if (memmem(dbuf.data(), got, desc, dl) != nullptr) {
                std::string keyd = std::string("anon:") + desc;
                if (seen.count(keyd)) break;
                seen.insert(keyd);
                report += std::string("ANON_DEX_FW=") + desc + " @ " + p + "\n";
                LOGD("[T2b] framework dex descriptor in anon memory: %s @ %s", desc, p.c_str());
                break;   // 该区命中一个框架特征即够,不重复
            }
        }
    }
    if (memfd2 >= 0) close(memfd2);
    LOGD("[T2b] in-memory dex regions scanned: %d", anonScanned);

    if (report.empty()) report = "CLEAN\n";
    return report;
}

// ================= [XFF-T5] Hook 引擎 .so dlopen 探测 =================
// dlopen(RTLD_NOLOAD) 只在库"已加载"时返回非空 handle——它查的是 linker 内部的已加载库链表,
// 不是 /proc/self/maps 文本。改 maps 行文本能骗过 checkLSPosedMemoryNative,但骗不过 linker 记账。
// liblspd.so / libxposed_art.so 只要 LSPosed 把框架注入了本进程,必在链表里。
std::string HookDetector::getArtHookLibReport() {
    static const char* kEngineLibs[] = {
        // LSPosed / EdXposed / 经典 Xposed 框架核心
        "liblspd.so", "libxposed_art.so", "libedxp.so", "libriru_edxp.so",
        "libriru_lsposed.so", "libriruloader.so",
        // LSPlant / Pine / YAHFA / SandHook —— ART 方法 hook 引擎
        "liblsplant.so", "libpine.so", "libyahfa.so", "libsandhook.so",
        "libSandHook.so", "libwhale.so",
        // Substrate / Cydia 系
        "libsubstrate.so", "libsubstrate-dvm.so",
        // Zygisk 注入器本体
        "libzygisk.so",
    };
    std::string report;
    std::set<std::string> reported;
    for (const char* lib : kEngineLibs) {
        void* h = dlopen(lib, RTLD_NOLOAD | RTLD_NOW);
        if (h != nullptr) {
            report += std::string("LIB_LOADED=") + lib + "\n";
            reported.insert(lib);
            LOGD("[T5] hook engine lib loaded (dlopen): %s", lib);
            dlclose(h);   // NOLOAD 不增加真实引用,dlclose 抵消本次 dlopen 的计数
        }
    }

    // maps 兜底:Android 10+ zygisk 注入的引擎库常在独立 linker namespace,
    // dlopen(RTLD_NOLOAD) 从 app namespace 看不到 → 直接扫 /proc/self/maps 的库名。
    std::string maps = syscall_read_file_full("/proc/self/maps");
    for (const char* lib : kEngineLibs) {
        if (reported.count(lib)) continue;
        if (maps.find(lib) != std::string::npos) {
            report += std::string("LIB_MAPPED=") + lib + "\n";
            reported.insert(lib);
            LOGD("[T5] hook engine lib in maps: %s", lib);
        }
    }

    if (report.empty()) report = "CLEAN\n";
    return report;
}
