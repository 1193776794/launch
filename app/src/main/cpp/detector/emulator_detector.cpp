#include "emulator_detector.h"
#include "root_detector.h"
#include "../syscall/syscall_wrapper.h"
#include <unistd.h>
#include <fstream>
#include <android/log.h>

#define LOG_TAG "EmulatorDetector"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

const std::vector<std::string>& EmulatorDetector::getEmulatorFiles() {
    static std::vector<std::string> files = {
        // QEMU
        "/dev/qemu_pipe",
        "/dev/qemu_trace",
        "/dev/goldfish_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/init.goldfish.rc",
        "/init.ranchu.rc",
        // Genymotion
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd",
        // Nox
        "/data/data/com.bignox.app.store.hd",
        "/system/bin/nox",
        "/system/bin/nox-prop",
        "/fstab.nox",
        // LDPlayer
        "/system/bin/ldinit",
        "/system/bin/ldmountsf",
        "/fstab.andy",
        // MEmu
        "/data/data/com.microvirt.guide",
        "/system/bin/microvirt",
        "/fstab.vbox86",
        // BlueStacks
        "/data/data/com.bluestacks.settings"
    };
    return files;
}

const std::vector<std::string>& EmulatorDetector::getEmulatorProperties() {
    static std::vector<std::string> props = {
        "goldfish",
        "ranchu",
        "generic",
        "vbox86",
        "nox",
        "genymotion",
        "andy",
        "ttVM_Hdragon",
        "sdk",
        "google_sdk",
        "Emulator",
        "Android SDK built for x86"
    };
    return props;
}

bool EmulatorDetector::checkEmulatorFilesNative() {
    for (const auto& file : getEmulatorFiles()) {
        if (access(file.c_str(), F_OK) == 0) {
            LOGD("Emulator file found (native): %s", file.c_str());
            return true;
        }
    }
    return false;
}

bool EmulatorDetector::checkQemuNative() {
    // Check QEMU specific files
    if (access("/dev/qemu_pipe", F_OK) == 0 ||
        access("/dev/goldfish_pipe", F_OK) == 0) {
        LOGD("QEMU detected via pipe (native)");
        return true;
    }

    // Check /proc/cpuinfo for QEMU
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("QEMU") != std::string::npos ||
                line.find("Goldfish") != std::string::npos) {
                LOGD("QEMU detected in cpuinfo (native)");
                return true;
            }
        }
    }
    return false;
}

bool EmulatorDetector::checkGenyMotionNative() {
    return access("/dev/socket/genyd", F_OK) == 0 ||
           access("/dev/socket/baseband_genyd", F_OK) == 0;
}

bool EmulatorDetector::checkNoxNative() {
    return access("/data/data/com.bignox.app.store.hd", F_OK) == 0 ||
           access("/system/bin/nox", F_OK) == 0 ||
           access("/fstab.nox", F_OK) == 0;
}

bool EmulatorDetector::checkLdPlayerNative() {
    return access("/system/bin/ldinit", F_OK) == 0 ||
           access("/system/bin/ldmountsf", F_OK) == 0;
}

bool EmulatorDetector::checkMemuNative() {
    return access("/data/data/com.microvirt.guide", F_OK) == 0 ||
           access("/fstab.vbox86", F_OK) == 0;
}

bool EmulatorDetector::checkBlueprintsNative() {
    // Check for VirtualBox blueprints
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.find("VirtualBox") != std::string::npos) {
                LOGD("VirtualBox detected in cpuinfo (native)");
                return true;
            }
        }
    }
    return false;
}

bool EmulatorDetector::checkEmulatorFilesSyscall() {
    for (const auto& file : getEmulatorFiles()) {
        if (syscall_file_exists(file.c_str())) {
            LOGD("Emulator file found (syscall): %s", file.c_str());
            return true;
        }
    }
    return false;
}

bool EmulatorDetector::checkQemuSyscall() {
    if (syscall_file_exists("/dev/qemu_pipe") ||
        syscall_file_exists("/dev/goldfish_pipe")) {
        LOGD("QEMU detected via pipe (syscall)");
        return true;
    }

    std::string cpuinfo = syscall_read_file("/proc/cpuinfo", 8192);
    if (cpuinfo.find("QEMU") != std::string::npos ||
        cpuinfo.find("Goldfish") != std::string::npos) {
        LOGD("QEMU detected in cpuinfo (syscall)");
        return true;
    }
    return false;
}

bool EmulatorDetector::checkSensorAnomalies() {
    // Real devices typically have 10+ sensors
    // This would need to be called from Java layer
    return false;
}

bool EmulatorDetector::checkBatteryAnomalies() {
    // Check battery status - emulators often show abnormal values
    std::ifstream status("/sys/class/power_supply/battery/status");
    if (!status.is_open()) {
        LOGD("No battery found - possible emulator");
        return true;
    }
    return false;
}

// Combined multi-layer detection
MultiLayerResult EmulatorDetector::detectEmulator() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkEmulatorFilesNative() || checkQemuNative() ||
                          checkGenyMotionNative() || checkNoxNative() ||
                          checkLdPlayerNative() || checkMemuNative();
    result.syscallResult = checkEmulatorFilesSyscall() || checkQemuSyscall();
    return result;
}

MultiLayerResult EmulatorDetector::detectQemu() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkQemuNative();
    result.syscallResult = checkQemuSyscall();
    return result;
}

MultiLayerResult EmulatorDetector::detectVirtualMachine() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkBlueprintsNative() || checkMemuNative();
    result.syscallResult = false;
    return result;
}
