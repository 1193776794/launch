#ifndef LAUNCH_DEBUG_DETECTOR_H
#define LAUNCH_DEBUG_DETECTOR_H

#include <string>
#include <vector>

struct MultiLayerResult;

class DebugDetector {
public:
    // Native layer detection
    static bool checkTracerPidNative();
    static bool checkPtraceNative();
    static bool checkDebuggerNative();

    // Syscall layer detection
    static bool checkTracerPidSyscall();

    // Combined detection
    static MultiLayerResult detectDebugger();
    static MultiLayerResult detectPtrace();

    // Get TracerPid value
    static int getTracerPid();

    // JDWP-specific detection (bypass Java/libc hooks)
    // 全部走 syscall_open + syscall_read，避免 libc / Java 反射被 hook 时漏报
    static bool checkJdwpAdbConnectionLoaded();   // /proc/self/maps 命中 libadbconnection.so
    static bool checkJdwpJvmtiLoaded();           // /proc/self/maps 命中 libopenjdkjvmti.so / libjdwp.so
    static int  countJdwpAbstractSockets();       // /proc/net/unix 中 @jdwp 抽象 socket 数量
    static int  countJdwpAbstractSocketsForSelf();// /proc/net/unix 中 @jdwp-<self_pid> 数 (区分 attach vs 系统可用)
    // 一次性聚合报告，多行 KEY=VALUE，Java 端 parseKeyValueReport
    static std::string getJdwpDetectionReport();
};

#endif // LAUNCH_DEBUG_DETECTOR_H
