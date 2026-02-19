package com.xff.launch.detector;

/**
 * Native detector interface for multi-layer detection
 * Provides access to Native (libc) and Syscall layer detection methods
 */
public class NativeDetector {

    static {
        System.loadLibrary("launch");
    }

    // ===================== Root Detection =====================

    public native boolean checkSuFilesNative();
    public native boolean checkSuFilesSyscall();

    public native boolean checkMagiskNative();
    public native boolean checkMagiskSyscall();

    public native boolean checkKernelSUNative();
    public native boolean checkKernelSUSyscall();

    public native boolean checkAPatchNative();
    public native boolean checkAPatchSyscall();

    public native boolean checkSukiSUNative();
    public native boolean checkSukiSUSyscall();

    public native boolean checkRootHidingNative();
    public native boolean checkRootHidingSyscall();

    public native boolean checkSuspiciousMountsNative();
    public native boolean checkSuspiciousMountsSyscall();

    public native boolean checkMountInfoNative();
    public native boolean checkMountInfoSyscall();

    // ===================== Hook Detection =====================

    public native boolean checkXposedNative();
    public native boolean checkXposedSyscall();

    public native boolean checkFridaNative();
    public native boolean checkFridaSyscall();

    public native boolean checkLSPosedNative();
    public native boolean checkLSPosedSyscall();
    public native String getLSPosedDetails();

    // Additional LSPosed detection methods
    public native boolean checkLSPosedMemoryNative();
    public native boolean checkLSPosedMemorySyscall();
    public native boolean checkRiruZygiskNative();
    public native boolean checkRiruZygiskSyscall();
    public native boolean checkLSPosedSystemWide();
    public native boolean checkAnonymousExecutableMemory();

    public native boolean checkMemoryHooksNative();
    public native boolean checkMemoryHooksSyscall();

    // SMAPS Integrity Check - 高级内存取证技术
    public native boolean checkSmapsIntegrity();

    // Zygisk detection (通用检测: Magisk Zygisk, ReZygisk, Zygisk Next)
    public native boolean checkZygiskNative();
    public native boolean checkZygiskSyscall();

    // /proc/net/tcp port scanning (IDA & Frida)
    /** Detect IDA port 23946 (0x5D8A) via /proc/net/tcp - native */
    public native boolean checkIdaPortTcpNative();
    /** Detect IDA port 23946 (0x5D8A) via /proc/net/tcp - syscall */
    public native boolean checkIdaPortTcpSyscall();
    /** Detect Frida port 27042 (0x69A2) via /proc/net/tcp - native */
    public native boolean checkFridaPortTcpNative();
    /** Detect Frida port 27042 (0x69A2) via /proc/net/tcp - syscall */
    public native boolean checkFridaPortTcpSyscall();

    // Frida FD linjector detection
    /** Scan /proc/self/fd via syscall(readlinkat) for linjector injector */
    public native boolean checkFridaFdLinjectorSyscall();

    // ===================== Emulator Detection =====================

    public native boolean checkEmulatorNative();
    public native boolean checkEmulatorSyscall();

    public native boolean checkQemuNative();
    public native boolean checkQemuSyscall();

    // ===================== Debug Detection =====================

    public native boolean checkDebuggerNative();
    public native boolean checkDebuggerSyscall();

    public native boolean checkPtraceNative();

    public native int getTracerPid();

    // ===================== File Operations =====================

    public native boolean fileExistsNative(String path);
    public native boolean fileExistsSyscall(String path);
    public native String readFileSyscall(String path);

    // ===================== Readlink Detection (Syscall-based) =====================

    /** Read symbolic link target using libc readlink */
    public native String readlinkNative(String path);

    /** Read symbolic link target using direct syscall */
    public native String readlinkSyscall(String path);

    /** Check if path is a symbolic link using libc lstat */
    public native boolean isSymlinkNative(String path);

    /** Check if path is a symbolic link using direct syscall */
    public native boolean isSymlinkSyscall(String path);

    /** Get real/canonical path using libc realpath */
    public native String realpathNative(String path);

    /** Get real/canonical path using syscalls only */
    public native String realpathSyscall(String path);

    /** Check proc file accessibility via syscall */
    public native String checkProcFileSyscall(String path);

    /** Check for hidden memory mappings via syscall */
    public native boolean checkHiddenMapsSyscall();

    /** Check for suspicious file descriptors via native */
    public native int checkSuspiciousFdsNative();

    /** Check for suspicious file descriptors via syscall */
    public native int checkSuspiciousFdsSyscall();

    /** Check mount namespace manipulation via native */
    public native boolean checkMountNamespaceNative();

    /** Check mount namespace manipulation via syscall */
    public native boolean checkMountNamespaceSyscall();

    // ===================== Zygote Injection Detection =====================
    // (Zygisk detection methods are now defined earlier in the file at lines 66-67)

    /** Check for Riru injection via native */
    public native boolean checkRiruNative();

    /** Check for Riru injection via syscall */
    public native boolean checkRiruSyscall();

    /** Get SELinux context via native */
    public native String getSELinuxContextNative();

    /** Check suspicious memory maps via native */
    public native int checkSuspiciousMapsNative();

    /** Check suspicious memory maps via syscall */
    public native int checkSuspiciousMapsSyscall();

    /** Check app_process integrity via native */
    public native boolean checkAppProcessNative();

    /** Check app_process integrity via syscall */
    public native boolean checkAppProcessSyscall();

    /** Check file integrity via syscall */
    public native boolean checkFileIntegritySyscall(String path);

    /** Count Zygisk modules via syscall */
    public native int countZygiskModulesSyscall();

    /** Check memory integrity (PLT/GOT) via native */
    public native boolean checkMemoryIntegrityNative();

    /** Check memory integrity (PLT/GOT) via syscall */
    public native boolean checkMemoryIntegritySyscall();

    // ===================== System Library Integrity Detection =====================

    /** Check libc.so integrity - detects hooks in critical functions */
    public native boolean checkLibcIntegrity();

    /** Check libart.so integrity - detects ART runtime hooks */
    public native boolean checkLibartIntegrity();

    /** Check libandroid_runtime.so integrity */
    public native boolean checkAndroidRuntimeIntegrity();

    /** Check all system libraries integrity - returns JSON report */
    public native String checkAllSystemLibrariesIntegrity();

    /** Check specific library integrity */
    public native boolean checkLibraryIntegrity(String libName);

    /** Check specific function for inline hooks */
    public native boolean checkFunctionHook(String libName, String funcName);

    /** Check for inline hooks via syscall */
    public native boolean checkInlineHooksSyscall();

    /** Check for suspicious anonymous memory via syscall */
    public native boolean checkSuspiciousAnonMemorySyscall();

    /** Check libc hooks via syscall */
    public native boolean checkLibcHooksSyscall();

    /** Check libart hooks via syscall */
    public native boolean checkArtHooksSyscall();

    /** Check library hooks via native */
    public native boolean checkLibraryHooksNative();

    // ===================== Kernel File Reading =====================

    /** Read kernel/proc file using native libc */
    public native String readKernelFile(String path);

    /** Get CPU serial from /proc/cpuinfo */
    public native String getCpuSerial();
    public native String getCpuSerialSyscall();

    /** Get CPU hardware from /proc/cpuinfo */
    public native String getCpuHardware();
    public native String getCpuHardwareSyscall();

    /** Get boot parameter from /proc/cmdline */
    public native String getBootParam(String paramName);
    public native String getBootParamSyscall(String paramName);

    // ===================== System Properties =====================

    public native String getSystemProperty(String key);
    public native String getBuildPropertyNative(String propName);
    public native String getBuildPropertySyscall(String propName);

    // ===================== Zygote Process Detection =====================

    /**
     * Check if zygote process has abnormal parent
     * Normal: zygote's parent should be init (PID 1)
     * Abnormal: zygote's parent is not init -> possible Zygisk injection
     * @return true if abnormal parent detected
     */
    public native boolean checkZygoteParentNative();

    /**
     * Get zygote process info
     * @return "zygote_pid:parent_pid" or "not_found"
     */
    public native String getZygoteInfo();

    // ===================== Anonymous Executable Memory Detection =====================

    /**
     * Count anonymous rwxp memory regions (no file backing)
     * These are suspicious and could indicate code injection
     * @return Number of anonymous rwxp regions found
     */
    public native int countAnonymousRwxMemory();

    /**
     * Get detailed information about anonymous rwxp regions
     * @return JSON string with address ranges
     */
    public native String getAnonymousRwxDetails();

    // ===================== Timing-based Hook Detection =====================

    /**
     * Benchmark openat() direct syscall timing
     * @param iterations Number of iterations (recommended: 10000+)
     * @return Average time per call in nanoseconds
     */
    public native long benchmarkSyscallOpenat(int iterations);

    /**
     * Benchmark openat() via libc timing (can be hooked)
     * @param iterations Number of iterations
     * @return Average time per call in nanoseconds
     */
    public native long benchmarkLibcOpenat(int iterations);

    /**
     * Benchmark access() direct syscall timing
     * @param iterations Number of iterations
     * @return Average time per call in nanoseconds
     */
    public native long benchmarkSyscallAccess(int iterations);

    /**
     * Benchmark access() via libc timing (can be hooked)
     * @param iterations Number of iterations
     * @return Average time per call in nanoseconds
     */
    public native long benchmarkLibcAccess(int iterations);

    /**
     * Benchmark stat() direct syscall timing
     * @param iterations Number of iterations
     * @return Average time per call in nanoseconds
     */
    public native long benchmarkSyscallStat(int iterations);

    /**
     * Benchmark stat() via libc timing (can be hooked)
     * @param iterations Number of iterations
     * @return Average time per call in nanoseconds
     */
    public native long benchmarkLibcStat(int iterations);

    /**
     * Detect timing anomaly between syscall and libc
     * @param syscallTime Average syscall time in nanoseconds
     * @param libcTime Average libc time in nanoseconds
     * @param threshold Multiplier threshold (e.g., 3.0)
     * @return true if anomaly detected (likely hooked)
     */
    public native boolean detectTimingAnomaly(long syscallTime, long libcTime, float threshold);

    // Singleton instance
    private static NativeDetector instance;

    public static synchronized NativeDetector getInstance() {
        if (instance == null) {
            instance = new NativeDetector();
        }
        return instance;
    }

    private NativeDetector() {
        // Private constructor for singleton
    }
}
