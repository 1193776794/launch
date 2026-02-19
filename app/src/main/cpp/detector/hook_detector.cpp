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

// ===================== DumpArtMethod Hook Detection =====================
//
// The dumpArtMethod symbol is used by ART method dumping/hooking tools:
//   - FDex2: Dumps DEX files from memory
//   - DexDump: ART method dumping
//   - Various ART hooking frameworks that patch ArtMethod structures
//
// Detection: Read /proc/self/maps and search for "dumpArtMethod" symbol
// If found, it means a hooking tool has injected a library that exports
// (or references) the dumpArtMethod function.

bool HookDetector::checkDumpArtMethodHookNative() {
    LOGD("=== checkDumpArtMethodHookNative() START ===");

    // Read /proc/self/maps using libc
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) {
        LOGD("Failed to open /proc/self/maps (native)");
        return false;
    }

    std::string line;
    while (std::getline(maps, line)) {
        // Search for dumpArtMethod symbol in memory maps
        if (line.find("dumpArtMethod") != std::string::npos) {
            LOGD("🚨 [DETECTED] dumpArtMethod found in maps (native): %s", line.c_str());
            maps.close();
            return true;
        }

        // Also check for related dumping tool signatures
        if (line.find("libdexdump") != std::string::npos ||
            line.find("libFDex2") != std::string::npos ||
            line.find("fdex2") != std::string::npos ||
            line.find("dexdump") != std::string::npos ||
            line.find("libdexhunter") != std::string::npos ||
            line.find("dexhunter") != std::string::npos ||
            line.find("libunpacker") != std::string::npos) {
            LOGD("🚨 [DETECTED] ART dumping tool found in maps (native): %s", line.c_str());
            maps.close();
            return true;
        }
    }

    maps.close();
    LOGD("=== checkDumpArtMethodHookNative() END - Clean ===");
    return false;
}

bool HookDetector::checkDumpArtMethodHookSyscall() {
    LOGD("=== checkDumpArtMethodHookSyscall() START ===");

    // Read /proc/self/maps using direct syscall (bypass libc hooks)
    std::string maps = syscall_read_file("/proc/self/maps", 131072);  // 128KB
    if (maps.empty()) {
        LOGD("Failed to read /proc/self/maps (syscall)");
        return false;
    }

    // Search for dumpArtMethod symbol
    if (maps.find("dumpArtMethod") != std::string::npos) {
        LOGD("🚨 [DETECTED] dumpArtMethod found in maps (syscall)");
        return true;
    }

    // Also check for related dumping tool signatures
    if (maps.find("libdexdump") != std::string::npos ||
        maps.find("libFDex2") != std::string::npos ||
        maps.find("fdex2") != std::string::npos ||
        maps.find("dexdump") != std::string::npos ||
        maps.find("libdexhunter") != std::string::npos ||
        maps.find("dexhunter") != std::string::npos ||
        maps.find("libunpacker") != std::string::npos) {
        LOGD("🚨 [DETECTED] ART dumping tool found in maps (syscall)");
        return true;
    }

    LOGD("=== checkDumpArtMethodHookSyscall() END - Clean ===");
    return false;
}

MultiLayerResult HookDetector::detectDumpArtMethodHook() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkDumpArtMethodHookNative();
    result.syscallResult = checkDumpArtMethodHookSyscall();
    return result;
}
