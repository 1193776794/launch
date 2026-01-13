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
