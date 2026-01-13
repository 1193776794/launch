#ifndef LAUNCH_ROOT_DETECTOR_H
#define LAUNCH_ROOT_DETECTOR_H

#include <jni.h>
#include <string>
#include <vector>

/**
 * Root detection result structure
 */
struct RootDetectionResult {
    bool detected;
    std::string method;
    std::string detail;
};

/**
 * Multi-layer detection result
 */
struct MultiLayerResult {
    bool javaResult;
    bool nativeResult;
    bool syscallResult;

    bool isDetected() const {
        return javaResult || nativeResult || syscallResult;
    }

    bool hasInconsistency() const {
        return (javaResult != nativeResult) || (nativeResult != syscallResult);
    }
};

class RootDetector {
public:
    // SU binary paths to check
    static const std::vector<std::string>& getSuPaths();

    // Magisk paths to check
    static const std::vector<std::string>& getMagiskPaths();

    // KernelSU paths to check
    static const std::vector<std::string>& getKernelSUPaths();

    // APatch paths to check
    static const std::vector<std::string>& getAPatchPaths();

    // SukiSU paths to check
    static const std::vector<std::string>& getSukiSUPaths();

    // Root manager package names
    static const std::vector<std::string>& getRootManagerPackages();

    // Root hiding module paths
    static const std::vector<std::string>& getRootHidingPaths();

    // Native layer detection using libc
    static bool checkFileNative(const char* path);
    static bool checkSuFilesNative();
    static bool checkMagiskNative();
    static bool checkKernelSUNative();
    static bool checkAPatchNative();
    static bool checkSukiSUNative();
    static bool checkMountInfoNative();
    static bool checkRootHidingNative();
    static bool checkSuspiciousMountsNative();

    // Syscall layer detection
    static bool checkFileSyscall(const char* path);
    static bool checkSuFilesSyscall();
    static bool checkMagiskSyscall();
    static bool checkKernelSUSyscall();
    static bool checkAPatchSyscall();
    static bool checkSukiSUSyscall();
    static bool checkMountInfoSyscall();
    static bool checkRootHidingSyscall();
    static bool checkSuspiciousMountsSyscall();

    // System property checks
    static bool checkBuildTags();
    static bool checkSelinuxStatus();

    // Combined detection
    static MultiLayerResult detectSu();
    static MultiLayerResult detectMagisk();
    static MultiLayerResult detectKernelSU();
    static MultiLayerResult detectAPatch();
    static MultiLayerResult detectSukiSU();
    static MultiLayerResult detectRootHiding();
};

#endif // LAUNCH_ROOT_DETECTOR_H
