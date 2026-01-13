#include "root_detector.h"
#include "../syscall/syscall_wrapper.h"
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <fstream>
#include <android/log.h>

#define LOG_TAG "RootDetector"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

const std::vector<std::string>& RootDetector::getSuPaths() {
    static std::vector<std::string> paths = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/vendor/bin/su",
        "/su/bin/su",
        "/system/xbin/busybox",
        "/system/bin/busybox"
    };
    return paths;
}

const std::vector<std::string>& RootDetector::getMagiskPaths() {
    static std::vector<std::string> paths = {
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/data/adb/magisk.img",
        "/data/adb/magisk.db",
        "/cache/magisk.log",
        "/cache/.disable_magisk",
        "/dev/.magisk.unblock",
        "/data/adb/modules"
    };
    return paths;
}

const std::vector<std::string>& RootDetector::getKernelSUPaths() {
    static std::vector<std::string> paths = {
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/data/adb/ksu/bin/busybox",
        "/data/adb/ksu/bin/resetprop"
    };
    return paths;
}

const std::vector<std::string>& RootDetector::getAPatchPaths() {
    static std::vector<std::string> paths = {
        "/data/adb/ap",
        "/data/adb/apd",
        "/data/adb/ap/bin"
    };
    return paths;
}

const std::vector<std::string>& RootDetector::getSukiSUPaths() {
    static std::vector<std::string> paths = {
        "/data/adb/sukisu",
        "/data/adb/ksu" // SukiSU is based on KernelSU
    };
    return paths;
}

const std::vector<std::string>& RootDetector::getRootManagerPackages() {
    static std::vector<std::string> packages = {
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        "me.bmax.apatch",
        "org.sukisu.manager",
        "com.noshufou.android.su",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "me.phh.superuser"
    };
    return packages;
}

const std::vector<std::string>& RootDetector::getRootHidingPaths() {
    static std::vector<std::string> paths = {
        "/data/adb/modules/shamiko",
        "/data/adb/modules/zygisk-assistant",
        "/data/adb/modules/playintegrityfix",
        "/data/adb/modules/zygiskNext",
        "/data/adb/modules/rezygisk",
        "/data/adb/modules/lsposed"
    };
    return paths;
}

// Native layer detection using libc
bool RootDetector::checkFileNative(const char* path) {
    return access(path, F_OK) == 0;
}

bool RootDetector::checkSuFilesNative() {
    for (const auto& path : getSuPaths()) {
        if (checkFileNative(path.c_str())) {
            LOGD("SU file found (native): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool RootDetector::checkMagiskNative() {
    for (const auto& path : getMagiskPaths()) {
        if (checkFileNative(path.c_str())) {
            LOGD("Magisk path found (native): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool RootDetector::checkKernelSUNative() {
    for (const auto& path : getKernelSUPaths()) {
        if (checkFileNative(path.c_str())) {
            LOGD("KernelSU path found (native): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool RootDetector::checkAPatchNative() {
    for (const auto& path : getAPatchPaths()) {
        if (checkFileNative(path.c_str())) {
            LOGD("APatch path found (native): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool RootDetector::checkSukiSUNative() {
    for (const auto& path : getSukiSUPaths()) {
        if (checkFileNative(path.c_str())) {
            LOGD("SukiSU path found (native): %s", path.c_str());
            return true;
        }
    }

    // Check SUSFS feature in /proc/filesystems
    std::ifstream file("/proc/filesystems");
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            if (line.find("susfs") != std::string::npos) {
                LOGD("SUSFS detected in /proc/filesystems (native)");
                return true;
            }
        }
    }
    return false;
}

bool RootDetector::checkMountInfoNative() {
    std::ifstream file("/proc/self/mountinfo");
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        if (line.find("magisk") != std::string::npos ||
            line.find("overlay") != std::string::npos) {
            LOGD("Suspicious mount found (native): %s", line.c_str());
            return true;
        }
    }
    return false;
}

bool RootDetector::checkSuspiciousMountsNative() {
    std::ifstream file("/proc/self/mountinfo");
    if (!file.is_open()) return false;

    std::string line;
    const std::vector<std::string> suspiciousPatterns = {
        "magisk",
        "zygisk",
        "zygisksu",
        "overlay",
        "tmpfs",
        "debug_ramdisk",
        "module.prop",
        "/data/adb/modules",
        "cacerts"
    };

    while (std::getline(file, line)) {
        // Convert to lowercase for case-insensitive matching
        std::string lowerLine = line;
        std::transform(lowerLine.begin(), lowerLine.end(), lowerLine.begin(), ::tolower);

        for (const auto& pattern : suspiciousPatterns) {
            if (lowerLine.find(pattern) != std::string::npos) {
                LOGD("Suspicious mount detected (native): %s in line: %s", pattern.c_str(), line.c_str());
                return true;
            }
        }

        // Check for repeated cacerts mounts (sign of certificate hijacking)
        size_t cacertsCount = 0;
        size_t pos = 0;
        while ((pos = line.find("cacerts", pos)) != std::string::npos) {
            cacertsCount++;
            pos += 7; // length of "cacerts"
        }
        if (cacertsCount > 2) {
            LOGD("Repeated cacerts mounts detected (native): %zu occurrences", cacertsCount);
            return true;
        }
    }
    return false;
}

bool RootDetector::checkRootHidingNative() {
    for (const auto& path : getRootHidingPaths()) {
        if (checkFileNative(path.c_str())) {
            LOGD("Root hiding module found (native): %s", path.c_str());
            return true;
        }
    }
    return false;
}

// Syscall layer detection
bool RootDetector::checkFileSyscall(const char* path) {
    return syscall_file_exists(path);
}

bool RootDetector::checkSuFilesSyscall() {
    for (const auto& path : getSuPaths()) {
        if (checkFileSyscall(path.c_str())) {
            LOGD("SU file found (syscall): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool RootDetector::checkMagiskSyscall() {
    for (const auto& path : getMagiskPaths()) {
        if (checkFileSyscall(path.c_str())) {
            LOGD("Magisk path found (syscall): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool RootDetector::checkKernelSUSyscall() {
    for (const auto& path : getKernelSUPaths()) {
        if (checkFileSyscall(path.c_str())) {
            LOGD("KernelSU path found (syscall): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool RootDetector::checkAPatchSyscall() {
    for (const auto& path : getAPatchPaths()) {
        if (checkFileSyscall(path.c_str())) {
            LOGD("APatch path found (syscall): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool RootDetector::checkSukiSUSyscall() {
    for (const auto& path : getSukiSUPaths()) {
        if (checkFileSyscall(path.c_str())) {
            LOGD("SukiSU path found (syscall): %s", path.c_str());
            return true;
        }
    }

    // Check SUSFS using syscall
    std::string content = syscall_read_file("/proc/filesystems");
    if (content.find("susfs") != std::string::npos) {
        LOGD("SUSFS detected (syscall)");
        return true;
    }
    return false;
}

bool RootDetector::checkMountInfoSyscall() {
    std::string content = syscall_read_file("/proc/self/mountinfo", 8192);
    if (content.find("magisk") != std::string::npos ||
        content.find("overlay") != std::string::npos) {
        LOGD("Suspicious mount found (syscall)");
        return true;
    }
    return false;
}

bool RootDetector::checkSuspiciousMountsSyscall() {
    // Read mountinfo via direct syscall (harder to hook)
    std::string content = syscall_read_file("/proc/self/mountinfo", 16384);
    if (content.empty()) return false;

    const std::vector<std::string> suspiciousPatterns = {
        "magisk",
        "zygisk",
        "zygisksu",
        "zygisk_su",
        "overlay",
        "tmpfs",
        "debug_ramdisk",
        "module.prop",
        "/data/adb/modules",
        "cacerts"
    };

    // Convert to lowercase for case-insensitive matching
    std::string lowerContent = content;
    std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);

    for (const auto& pattern : suspiciousPatterns) {
        if (lowerContent.find(pattern) != std::string::npos) {
            LOGD("Suspicious mount detected (syscall): %s", pattern.c_str());
            return true;
        }
    }

    // Check for repeated cacerts mounts (line by line)
    size_t pos = 0;
    std::string line;
    while (pos < content.length()) {
        size_t nextPos = content.find('\n', pos);
        if (nextPos == std::string::npos) {
            line = content.substr(pos);
            pos = content.length();
        } else {
            line = content.substr(pos, nextPos - pos);
            pos = nextPos + 1;
        }

        // Count "cacerts" occurrences in this line
        size_t cacertsCount = 0;
        size_t searchPos = 0;
        while ((searchPos = line.find("cacerts", searchPos)) != std::string::npos) {
            cacertsCount++;
            searchPos += 7;
        }

        if (cacertsCount > 2) {
            LOGD("Repeated cacerts mounts detected (syscall): %zu occurrences in one line", cacertsCount);
            return true;
        }
    }

    return false;
}

bool RootDetector::checkRootHidingSyscall() {
    for (const auto& path : getRootHidingPaths()) {
        if (checkFileSyscall(path.c_str())) {
            LOGD("Root hiding module found (syscall): %s", path.c_str());
            return true;
        }
    }
    return false;
}

bool RootDetector::checkBuildTags() {
    std::string content = syscall_read_file("/system/build.prop", 16384);
    return content.find("ro.build.tags=test-keys") != std::string::npos;
}

bool RootDetector::checkSelinuxStatus() {
    std::string content = syscall_read_file("/sys/fs/selinux/enforce");
    return !content.empty() && content[0] == '0';
}

// Combined multi-layer detection
MultiLayerResult RootDetector::detectSu() {
    MultiLayerResult result;
    result.javaResult = false; // Will be set from Java layer
    result.nativeResult = checkSuFilesNative();
    result.syscallResult = checkSuFilesSyscall();
    return result;
}

MultiLayerResult RootDetector::detectMagisk() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkMagiskNative();
    result.syscallResult = checkMagiskSyscall();
    return result;
}

MultiLayerResult RootDetector::detectKernelSU() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkKernelSUNative();
    result.syscallResult = checkKernelSUSyscall();
    return result;
}

MultiLayerResult RootDetector::detectAPatch() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkAPatchNative();
    result.syscallResult = checkAPatchSyscall();
    return result;
}

MultiLayerResult RootDetector::detectSukiSU() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkSukiSUNative();
    result.syscallResult = checkSukiSUSyscall();
    return result;
}

MultiLayerResult RootDetector::detectRootHiding() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkRootHidingNative();
    result.syscallResult = checkRootHidingSyscall();
    return result;
}
