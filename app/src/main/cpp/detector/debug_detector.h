#ifndef LAUNCH_DEBUG_DETECTOR_H
#define LAUNCH_DEBUG_DETECTOR_H

#include <string>
#include <vector>
#include <ctime>

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

    // Anti-timing attack detection
    // Measures initialization elapsed time, if >= 2s, debugger breakpoints detected
    // @param initStartTime The time_t value captured at init start
    // @return true if timing attack detected (init took >= 2 seconds)
    static bool checkInitTimingAttack(time_t initStartTime);
};

#endif // LAUNCH_DEBUG_DETECTOR_H
