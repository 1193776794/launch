#include "debug_detector.h"
#include "root_detector.h"
#include "../syscall/syscall_wrapper.h"
#include <unistd.h>
#include <sys/ptrace.h>
#include <fstream>
#include <sstream>
#include <android/log.h>

#define LOG_TAG "DebugDetector"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

int DebugDetector::getTracerPid() {
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) return -1;

    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            std::istringstream iss(line);
            std::string key;
            int pid;
            iss >> key >> pid;
            return pid;
        }
    }
    return 0;
}

bool DebugDetector::checkTracerPidNative() {
    int tracerPid = getTracerPid();
    if (tracerPid > 0) {
        LOGD("TracerPid is non-zero: %d (native)", tracerPid);
        return true;
    }
    return false;
}

bool DebugDetector::checkPtraceNative() {
    // Try to ptrace ourselves - if we're being traced, this will fail
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
        LOGD("PTRACE_TRACEME failed - possibly being traced (native)");
        return true;
    }
    // Detach
    ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
    return false;
}

bool DebugDetector::checkDebuggerNative() {
    // Check /proc/self/wchan for debugging related wait channels
    std::ifstream wchan("/proc/self/wchan");
    if (wchan.is_open()) {
        std::string content;
        std::getline(wchan, content);
        if (content.find("ptrace") != std::string::npos) {
            LOGD("ptrace found in wchan (native)");
            return true;
        }
    }
    return false;
}

bool DebugDetector::checkTracerPidSyscall() {
    std::string content = syscall_read_file("/proc/self/status", 4096);
    size_t pos = content.find("TracerPid:");
    if (pos != std::string::npos) {
        std::string line = content.substr(pos);
        size_t endPos = line.find('\n');
        if (endPos != std::string::npos) {
            line = line.substr(0, endPos);
        }
        // Parse TracerPid value
        std::istringstream iss(line);
        std::string key;
        int pid;
        iss >> key >> pid;
        if (pid > 0) {
            LOGD("TracerPid is non-zero: %d (syscall)", pid);
            return true;
        }
    }
    return false;
}

MultiLayerResult DebugDetector::detectDebugger() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkTracerPidNative() || checkDebuggerNative();
    result.syscallResult = checkTracerPidSyscall();
    return result;
}

MultiLayerResult DebugDetector::detectPtrace() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkPtraceNative();
    result.syscallResult = false; // Can't check ptrace via syscall reliably
    return result;
}

// ===================== Suspicious Tool Path Detection =====================
// Iterates over suspicious tool path array, using access() to check file existence

// Suspicious tool path entries with descriptions
struct ToolPathEntry {
    const char* path;
    const char* description;
};

static const ToolPathEntry SUSPICIOUS_TOOL_PATHS[] = {
    {"/data/local/tmp/android_server",                              "IDA debugger (32-bit)"},
    {"/data/local/tmp/android_server64",                            "IDA debugger (64-bit)"},
    {"/data/local/tmp/gdbserver",                                   "GDB debugger"},
    {"/data/local/tmp/inject",                                      "Injection tool"},
    {"/data/local/tmp/libhello.so",                                 "Frida gadget"},
    {"/sdcard/xxxx/",                                               "Unpacker (FART etc.)"},
    {"/sdcard/ooxx/",                                               "Unpacker"},
    {"/sdcard/fart/",                                               "FART unpacker"},
    {"/sdcard/Download/dexDump/",                                   "DEX dump tool"},
    {"/sdcard/Download/top.niunaijun.blackdexa32_logcat.txt",       "BlackDex log (32-bit)"},
    {"/sdcard/Download/top.niunaijun.blackdexa64_logcat.txt",       "BlackDex log (64-bit)"},
    {"/data/data/top.niunaijun.blackdexa32",                        "BlackDex app (32-bit)"},
    {"/data/data/top.niunaijun.blackdexa64",                        "BlackDex app (64-bit)"},
};
static const int SUSPICIOUS_TOOL_PATHS_COUNT = sizeof(SUSPICIOUS_TOOL_PATHS) / sizeof(SUSPICIOUS_TOOL_PATHS[0]);

bool DebugDetector::checkSuspiciousToolPathsNative() {
    for (int i = 0; i < SUSPICIOUS_TOOL_PATHS_COUNT; i++) {
        if (access(SUSPICIOUS_TOOL_PATHS[i].path, F_OK) == 0) {
            LOGD("Suspicious tool path found (native): %s [%s]",
                 SUSPICIOUS_TOOL_PATHS[i].path, SUSPICIOUS_TOOL_PATHS[i].description);
            return true;
        }
    }
    return false;
}

bool DebugDetector::checkSuspiciousToolPathsSyscall() {
    for (int i = 0; i < SUSPICIOUS_TOOL_PATHS_COUNT; i++) {
        if (syscall_file_exists(SUSPICIOUS_TOOL_PATHS[i].path)) {
            LOGD("Suspicious tool path found (syscall): %s [%s]",
                 SUSPICIOUS_TOOL_PATHS[i].path, SUSPICIOUS_TOOL_PATHS[i].description);
            return true;
        }
    }
    return false;
}

std::string DebugDetector::getDetectedSuspiciousToolPaths() {
    std::string result = "[";
    bool first = true;

    for (int i = 0; i < SUSPICIOUS_TOOL_PATHS_COUNT; i++) {
        bool nativeExists = (access(SUSPICIOUS_TOOL_PATHS[i].path, F_OK) == 0);
        bool syscallExists = syscall_file_exists(SUSPICIOUS_TOOL_PATHS[i].path);

        if (nativeExists || syscallExists) {
            if (!first) result += ",";
            first = false;

            result += "{\"path\":\"";
            result += SUSPICIOUS_TOOL_PATHS[i].path;
            result += "\",\"desc\":\"";
            result += SUSPICIOUS_TOOL_PATHS[i].description;
            result += "\",\"native\":";
            result += nativeExists ? "true" : "false";
            result += ",\"syscall\":";
            result += syscallExists ? "true" : "false";
            result += "}";

            LOGD("Detected suspicious tool: %s [%s] (native:%d, syscall:%d)",
                 SUSPICIOUS_TOOL_PATHS[i].path, SUSPICIOUS_TOOL_PATHS[i].description,
                 nativeExists, syscallExists);
        }
    }

    result += "]";
    return result;
}

MultiLayerResult DebugDetector::detectSuspiciousToolPaths() {
    MultiLayerResult result;
    result.javaResult = false; // Not checked at Java layer
    result.nativeResult = checkSuspiciousToolPathsNative();
    result.syscallResult = checkSuspiciousToolPathsSyscall();
    return result;
}
