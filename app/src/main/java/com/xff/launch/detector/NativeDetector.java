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

    /**
     * JDWP 多指标聚合检测（native 走 syscall_open + syscall_read，绕 libc/Java 反射 hook）。
     * 返回多行 KEY=VALUE：
     *   ADBCONN=0|1            libadbconnection.so 是否在 /proc/self/maps
     *   JVMTI=0|1              libopenjdkjvmti.so / libjdwp.so 是否加载
     *   JDWP_SOCK=N            /proc/net/unix 中 @jdwp 抽象 socket 数量
     *   JDWP_THREADS=tid:comm|tid:comm   JDWP / ADB-JDWP / AdbConnection 线程列表，无则空串
     */
    public native String getJdwpDetectionReport();

    /**
     * 深层 native 网络检测报告（getifaddrs + netlink RTM_GETROUTE + syscall /proc/net/dev）。
     * 用于 cross-check Java NetworkInterface 是否被 hook 隐藏 VPN。多行 KEY=VALUE。
     *  字段见 cpp/detector/network_detector.h
     */
    public native String getNetworkNativeReport();

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

    // ===================== Extended Fingerprint Collection =====================

    /** Get MAC address via native libc (wlan0/eth0) */
    public native String getMacAddressNative();
    /** Get MAC address via syscall (wlan0/eth0) */
    public native String getMacAddressSyscall();

    /** Get total RAM in MB via native sysconf */
    public native String getTotalRamNative();
    /** Get total RAM in MB via syscall reading /proc/meminfo */
    public native String getTotalRamSyscall();

    /** Get screen virtual size via native libc */
    public native String getScreenInfoNative();
    /** Get screen virtual size via syscall */
    public native String getScreenInfoSyscall();

    /** Get CPU ABI via native __system_property_get */
    public native String getCpuAbiNative();
    /** Get CPU ABI via syscall reading build.prop */
    public native String getCpuAbiSyscall();

    /** Get sensor list from /sys/class/sensors via native opendir */
    public native String getSensorListNative();
    /** Get sensor list from /sys/class/sensors via syscall getdents64 */
    public native String getSensorListSyscall();

    /** Get hash of library names from /proc/self/maps via native */
    public native String getMapsHashNative();
    /** Get hash of library names from /proc/self/maps via syscall */
    public native String getMapsHashSyscall();

    /** Get uname info (sysname release machine) via native uname() */
    public native String getUnameInfoNative();
    /** Get uname info via direct SYS_uname syscall */
    public native String getUnameInfoSyscall();

    /** Get total storage in GB via native statfs on /data */
    public native String getTotalStorageNative();
    /** Get total storage in GB via SYS_statfs syscall on /data */
    public native String getTotalStorageSyscall();

    /** Get device-tree serial from /proc/device-tree/serial-number via native */
    public native String getDeviceTreeSerialNative();
    /** Get device-tree serial from /proc/device-tree/serial-number via syscall */
    public native String getDeviceTreeSerialSyscall();

    // ===================== SVC Fingerprint: Runtime Verification =====================

    /** Get CPU max frequency pattern (e.g. "1800000,1800000,2400000") via native fopen */
    public native String getCpuFreqPatternNative();
    /** Get CPU max frequency pattern via syscall */
    public native String getCpuFreqPatternSyscall();

    /** Get /etc/hosts file hash via native fopen */
    public native String getHostsHashNative();
    /** Get /etc/hosts file hash via syscall */
    public native String getHostsHashSyscall();

    /** Get SELinux state "Enforcing|u:r:untrusted_app" via native */
    public native String getSELinuxFingerprintNative();
    /** Get SELinux state via syscall */
    public native String getSELinuxFingerprintSyscall();

    /** Get process cmdline (package name) via native fopen */
    public native String getCmdlineNative();
    /** Get process cmdline via syscall */
    public native String getCmdlineSyscall();

    // ===================== Runtime Integrity Indicators =====================

    /** Read system property via direct mmap of build.prop files (bypasses __system_property_get) */
    public native String getPropertyMmap(String propName);

    /**
     * Read system property via direct mmap of /dev/__properties__ binary area.
     * Bypasses both Java SystemProperties hooks AND libc __system_property_get inline hooks.
     * Uses syscall_open + mmap to access bionic property area at the kernel boundary.
     */
    public native String readDevPropertyMmap(String propName);

    /**
     * Read property from a specific SELinux context file:
     *   /dev/__properties__/u:object_r:&lt;contextName&gt;:s0
     * 用于精准命中 debug_prop / usb_prop / adbd_prop 这类承载 ADB / 调试开关的 context 文件。
     */
    public native String readPropertyFromContext(String key, String contextName);

    /**
     * Diagnostic probe: try openat() on /dev/__properties__ and every known context file.
     * Returns multi-line text listing each path with either "ok size=N" or "err ERRNAME(N)".
     */
    public native String probeDevPropertyAccess();

    /** Compare mmap vs __system_property_get for 5 key properties, returns mismatch count */
    public native int checkPropertyMmapConsistency();

    /** Read 16 bytes from /dev/urandom via native fopen, returns hex string */
    public native String readUrandomNative();
    /** Read 16 bytes from /dev/urandom via syscall, returns hex string */
    public native String readUrandomSyscall();
    /** Check if urandom returns all zeros or fixed pattern, returns true if anomaly */
    public native boolean checkUrandomIntegrity();

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
