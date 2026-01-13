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
};

#endif // LAUNCH_DEBUG_DETECTOR_H
