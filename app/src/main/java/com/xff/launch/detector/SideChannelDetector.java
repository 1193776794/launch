package com.xff.launch.detector;

import android.content.Context;
import android.os.Build;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Side-Channel Attack Detection
 * Detects security mitigations and timing-based hook detection:
 * - Cache timing attacks (Prime+Probe, Flush+Reload, etc.)
 * - Kernel memory disclosure
 * - KPTI, KASLR mitigations
 * - Timing-based hook detection for Frida/Xposed
 */
public class SideChannelDetector {

    private final Context context;
    private final NativeDetector nativeDetector;

    // Safe CPUs (in-order execution, less vulnerable to cache attacks)
    private static final String[] SAFE_CPUS = {
            "Cortex-A53", "Cortex-A55", "Cortex-A35"
    };

    public SideChannelDetector(Context context) {
        this.context = context;
        this.nativeDetector = NativeDetector.getInstance();
    }

    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();

        // NOTE: Removed Spectre and Meltdown vulnerability checks
        // These are CPU hardware vulnerabilities, NOT device environment anomalies

        items.add(checkKPTI());
        items.add(checkKASLR());
        items.add(checkPerfEventAccess());
        items.add(checkKallsymsAccess());
        items.add(checkSELinux());
        items.add(checkCacheTimingRisk());
        items.add(checkMemoryDisclosure());

        // Timing-based hook detection
        items.add(checkSyscallTimingOpenat());
        items.add(checkSyscallTimingAccess());
        items.add(checkSyscallTimingStat());

        return items;
    }

    /**
     * Check KPTI (Kernel Page Table Isolation) status
     * KPTI is a kernel security mitigation
     */
    private DetectionItem checkKPTI() {
        DetectionItem item = new DetectionItem("KPTI 内核隔离", "内核页表隔离检测");

        String cmdline = nativeDetector.readFileSyscall("/proc/cmdline");
        boolean kptiDisabled = cmdline.contains("nopti") || cmdline.contains("pti=off");

        // Check meltdown mitigation status
        String meltdown = readVulnerabilityFile("meltdown");
        boolean kptiEnabled = meltdown.toLowerCase().contains("pti") ||
                meltdown.toLowerCase().contains("not affected");

        // Check kernel version (KPTI added in 4.15+)
        String kernelVersion = System.getProperty("os.version", "");
        boolean kernelSupportsKPTI = isKernelVersionAtLeast(kernelVersion, 4, 15);

        // Risk = KPTI disabled
        item.setLayerResult(DetectionLayer.JAVA, kptiDisabled);
        item.setLayerResult(DetectionLayer.NATIVE, !kptiEnabled && !kernelSupportsKPTI);
        item.setLayerResult(DetectionLayer.SYSCALL, kptiDisabled);

        if (kptiDisabled) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("KPTI内核页表隔离已被禁用");
        } else if (kptiEnabled || kernelSupportsKPTI) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("KPTI内核页表隔离已启用");
        } else {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("无法确定KPTI状态");
        }

        return item;
    }

    /**
     * Check KASLR (Kernel Address Space Layout Randomization)
     */
    private DetectionItem checkKASLR() {
        DetectionItem item = new DetectionItem("KASLR 随机化", "内核地址随机化检测");

        // Check /proc/cmdline for nokaslr
        String cmdline = nativeDetector.readFileSyscall("/proc/cmdline");
        boolean kaslrDisabled = cmdline.contains("nokaslr");

        // Check /proc/kallsyms - if addresses are all zeros, KASLR is working
        String kallsyms = nativeDetector.readFileSyscall("/proc/kallsyms");
        boolean kallsymsHidden = kallsyms.isEmpty() ||
                kallsyms.startsWith("0000000000000000") ||
                kallsyms.startsWith("00000000");

        // Check randomize_va_space
        String randomizeVa = nativeDetector.readFileSyscall("/proc/sys/kernel/randomize_va_space");
        boolean aslrEnabled = randomizeVa.trim().equals("2"); // Full ASLR

        // Risk = KASLR disabled
        item.setLayerResult(DetectionLayer.JAVA, kaslrDisabled);
        item.setLayerResult(DetectionLayer.NATIVE, !aslrEnabled);
        item.setLayerResult(DetectionLayer.SYSCALL, !kallsymsHidden);

        if (kaslrDisabled) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("KASLR内核地址随机化已被禁用");
        } else if (kallsymsHidden && aslrEnabled) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("KASLR内核地址随机化已启用");
        } else {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("KASLR可能未完全启用");
        }

        return item;
    }

    /**
     * Check perf_event_paranoid level
     * Controls access to performance counters used in timing attacks
     *
     * Note: This setting is informational for security researchers.
     * Normal Android phones often have default permissive settings,
     * which is acceptable since Android's SELinux and app sandbox
     * already restrict what apps can actually do with perf_event.
     *
     * Paranoid levels:
     * -1: Allow all users to use perf_event (common default)
     *  0: Allow non-root users to use perf_event (user processes only)
     *  1: Allow non-root users to do kernel profiling with tracepoints
     *  2: Disallow kernel profiling for non-root (more secure)
     *  3: Disallow all perf_event for non-root (most secure)
     */
    private DetectionItem checkPerfEventAccess() {
        DetectionItem item = new DetectionItem("性能计数器", "性能计数器访问权限检测");

        String paranoidLevel = nativeDetector.readFileSyscall("/proc/sys/kernel/perf_event_paranoid");
        int level = Integer.MIN_VALUE; // Use MIN_VALUE to indicate "unable to read"
        try {
            level = Integer.parseInt(paranoidLevel.trim());
        } catch (NumberFormatException ignored) {
        }

        // On Android, SELinux and app sandbox already restrict perf_event access
        // So even level=-1 is not a critical risk for normal users
        // We only use WARNING for informational purposes

        // Layer results: true = potential concern (for detailed view)
        item.setLayerResult(DetectionLayer.JAVA, level < 2);
        item.setLayerResult(DetectionLayer.NATIVE, level < 2);
        item.setLayerResult(DetectionLayer.SYSCALL, level < 0);

        if (level >= 3) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("最高限制 (level=" + level + ") - 非root禁止所有性能监控");
        } else if (level >= 2) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("高限制 (level=" + level + ") - 禁止内核性能分析");
        } else if (level >= 1) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("中等限制 (level=" + level + ") - 系统默认配置");
        } else if (level >= 0) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("标准配置 (level=" + level + ") - 允许用户进程性能监控");
        } else if (level == -1) {
            // level=-1 is common default on many Android devices
            // Not a risk because Android's SELinux restricts actual access
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("默认配置 (level=" + level + ") - Android沙箱已限制实际访问");
        } else {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("无法读取配置");
        }

        return item;
    }

    /**
     * Check /proc/kallsyms accessibility
     * Exposed kernel symbols aid in exploiting vulnerabilities
     */
    private DetectionItem checkKallsymsAccess() {
        DetectionItem item = new DetectionItem("内核符号表", "内核符号表暴露检测");

        String kallsyms = nativeDetector.readFileSyscall("/proc/kallsyms");
        String kptrRestrict = nativeDetector.readFileSyscall("/proc/sys/kernel/kptr_restrict");

        boolean symbolsExposed = false;
        if (!kallsyms.isEmpty()) {
            String[] lines = kallsyms.split("\n");
            if (lines.length > 0) {
                String firstLine = lines[0];
                symbolsExposed = !firstLine.startsWith("0000000000000000") &&
                        !firstLine.startsWith("00000000") &&
                        !firstLine.matches("^0+ .*");
            }
        }

        int restrictLevel = -1;
        try {
            restrictLevel = Integer.parseInt(kptrRestrict.trim());
        } catch (NumberFormatException ignored) {
        }

        // Risk = symbols exposed
        item.setLayerResult(DetectionLayer.JAVA, symbolsExposed);
        item.setLayerResult(DetectionLayer.NATIVE, restrictLevel < 1);
        item.setLayerResult(DetectionLayer.SYSCALL, symbolsExposed);

        if (restrictLevel >= 2) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("内核指针对所有用户隐藏");
        } else if (restrictLevel == 1 || !symbolsExposed) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("内核指针对非特权用户隐藏");
        } else if (symbolsExposed) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("内核符号表地址暴露");
        } else {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("无法确定内核符号表状态");
        }

        return item;
    }

    /**
     * Check SELinux status
     * Important for process isolation
     */
    private DetectionItem checkSELinux() {
        DetectionItem item = new DetectionItem("SELinux 状态", "SELinux进程隔离检测");

        String enforce = nativeDetector.readFileSyscall("/sys/fs/selinux/enforce");
        String selinuxStatus = nativeDetector.getBuildPropertyNative("ro.boot.selinux");

        boolean enforcing = enforce.trim().equals("1");
        boolean disabled = selinuxStatus.equalsIgnoreCase("disabled") ||
                selinuxStatus.equalsIgnoreCase("permissive");

        // Risk = SELinux disabled or permissive
        item.setLayerResult(DetectionLayer.JAVA, disabled);
        item.setLayerResult(DetectionLayer.NATIVE, !enforcing);
        item.setLayerResult(DetectionLayer.SYSCALL, disabled);

        if (disabled) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("SELinux已禁用，进程隔离减弱");
        } else if (enforcing) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("SELinux处于强制模式");
        } else {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("SELinux处于宽容模式");
        }

        return item;
    }

    /**
     * Check cache timing attack risk
     * Analyzes CPU features and timing resolution
     */
    private DetectionItem checkCacheTimingRisk() {
        DetectionItem item = new DetectionItem("缓存时序攻击", "缓存时序攻击风险评估");

        // Check CPU cache info
        String cpuInfo = getCpuImplementer();
        boolean outOfOrderCpu = !isCpuInOrder(cpuInfo);

        // Check if device supports ARM pointer authentication
        String cpuFeatures = nativeDetector.readFileSyscall("/proc/cpuinfo");
        boolean hasPAuth = cpuFeatures.toLowerCase().contains("paca") ||
                cpuFeatures.toLowerCase().contains("pacg");

        // Risk = out-of-order CPU without PAC
        boolean highRisk = outOfOrderCpu && !hasPAuth;

        item.setLayerResult(DetectionLayer.JAVA, outOfOrderCpu);
        item.setLayerResult(DetectionLayer.NATIVE, highRisk);
        item.setLayerResult(DetectionLayer.SYSCALL, !hasPAuth);

        if (!outOfOrderCpu) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("CPU为顺序执行，不易受缓存时序攻击");
        } else if (hasPAuth) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("乱序执行CPU，但支持指针认证");
        } else {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("乱序执行CPU可能受缓存攻击影响");
        }

        return item;
    }

    /**
     * Check memory disclosure risk
     */
    private DetectionItem checkMemoryDisclosure() {
        DetectionItem item = new DetectionItem("内存泄露风险", "内存访问权限检测");

        // Check various memory-related files
        boolean memAccessible = new File("/dev/mem").canRead();
        boolean kmemAccessible = new File("/dev/kmem").canRead();

        // Check dmesg access
        String dmesgRestrict = nativeDetector.readFileSyscall("/proc/sys/kernel/dmesg_restrict");
        boolean dmesgRestricted = dmesgRestrict.trim().equals("1");

        int riskCount = 0;
        StringBuilder risks = new StringBuilder();

        if (memAccessible) {
            riskCount++;
            risks.append("/dev/mem可读 ");
        }
        if (kmemAccessible) {
            riskCount++;
            risks.append("/dev/kmem可读 ");
        }
        if (!dmesgRestricted) {
            riskCount++;
            risks.append("dmesg未限制 ");
        }

        // Risk = any memory disclosure issue
        item.setLayerResult(DetectionLayer.JAVA, memAccessible || kmemAccessible);
        item.setLayerResult(DetectionLayer.NATIVE, !dmesgRestricted);
        item.setLayerResult(DetectionLayer.SYSCALL, riskCount > 0);

        if (riskCount == 0) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("内存访问已正确限制");
        } else if (riskCount == 1) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("存在轻微风险: " + risks.toString().trim());
        } else {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("存在内存泄露风险: " + risks.toString().trim());
        }

        return item;
    }

    // Helper methods

    private String readVulnerabilityFile(String name) {
        String path = "/sys/devices/system/cpu/vulnerabilities/" + name;
        String content = nativeDetector.readFileSyscall(path);
        return content != null ? content.trim() : "";
    }

    private String getCpuImplementer() {
        String cpuInfo = nativeDetector.readFileSyscall("/proc/cpuinfo");
        if (cpuInfo == null) return "";

        for (String line : cpuInfo.split("\n")) {
            if (line.startsWith("CPU part") || line.startsWith("CPU implementer") ||
                    line.startsWith("Hardware")) {
                return line;
            }
        }
        return Build.HARDWARE;
    }

    private boolean isCpuInOrder(String cpuInfo) {
        String upper = cpuInfo.toUpperCase();
        for (String cpu : SAFE_CPUS) {
            if (upper.contains(cpu.toUpperCase())) {
                return true;
            }
        }
        return false;
    }

    private boolean isKernelVersionAtLeast(String version, int major, int minor) {
        try {
            String[] parts = version.split("[.-]");
            if (parts.length >= 2) {
                int maj = Integer.parseInt(parts[0]);
                int min = Integer.parseInt(parts[1]);
                return maj > major || (maj == major && min >= minor);
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    // ===================== Timing-based Hook Detection =====================

    /**
     * Check openat() syscall timing to detect hooks
     * Principle: If libc openat() is hooked, it will be much slower than direct syscall
     */
    private DetectionItem checkSyscallTimingOpenat() {
        DetectionItem item = new DetectionItem("系统调用时序-openat", "openat()函数Hook检测");

        final int ITERATIONS = 5000;  // Test 5000 times to amplify timing difference
        final float THRESHOLD = 3.0f;  // If libc is 3x slower, it's suspicious

        try {
            // Benchmark direct syscall (should be very fast, ~100-500ns per call)
            long syscallTime = nativeDetector.benchmarkSyscallOpenat(ITERATIONS);

            // Benchmark libc call (if hooked by Frida/Xposed, will be much slower)
            long libcTime = nativeDetector.benchmarkLibcOpenat(ITERATIONS);

            // Detect anomaly
            boolean isHooked = nativeDetector.detectTimingAnomaly(syscallTime, libcTime, THRESHOLD);

            // Calculate ratio for display
            float ratio = (syscallTime > 0) ? (float)libcTime / (float)syscallTime : 0;

            // Set layer results
            item.setLayerResult(DetectionLayer.JAVA, false);  // Java layer N/A
            item.setLayerResult(DetectionLayer.NATIVE, isHooked);
            item.setLayerResult(DetectionLayer.SYSCALL, !isHooked);

            if (isHooked) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail(String.format("检测到Hook征兆 - Syscall: %dns, Libc: %dns (%.1fx倍)",
                        syscallTime, libcTime, ratio));
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail(String.format("时序正常 - Syscall: %dns, Libc: %dns (%.1fx倍)",
                        syscallTime, libcTime, ratio));
            }
        } catch (Exception e) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("时序检测异常: " + e.getMessage());
        }

        return item;
    }

    /**
     * Check access() syscall timing to detect hooks
     */
    private DetectionItem checkSyscallTimingAccess() {
        DetectionItem item = new DetectionItem("系统调用时序-access", "access()函数Hook检测");

        final int ITERATIONS = 5000;
        final float THRESHOLD = 3.0f;

        try {
            long syscallTime = nativeDetector.benchmarkSyscallAccess(ITERATIONS);
            long libcTime = nativeDetector.benchmarkLibcAccess(ITERATIONS);
            boolean isHooked = nativeDetector.detectTimingAnomaly(syscallTime, libcTime, THRESHOLD);
            float ratio = (syscallTime > 0) ? (float)libcTime / (float)syscallTime : 0;

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, isHooked);
            item.setLayerResult(DetectionLayer.SYSCALL, !isHooked);

            if (isHooked) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail(String.format("检测到Hook征兆 - Syscall: %dns, Libc: %dns (%.1fx倍)",
                        syscallTime, libcTime, ratio));
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail(String.format("时序正常 - Syscall: %dns, Libc: %dns (%.1fx倍)",
                        syscallTime, libcTime, ratio));
            }
        } catch (Exception e) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("时序检测异常: " + e.getMessage());
        }

        return item;
    }

    /**
     * Check stat() syscall timing to detect hooks
     */
    private DetectionItem checkSyscallTimingStat() {
        DetectionItem item = new DetectionItem("系统调用时序-stat", "stat()函数Hook检测");

        final int ITERATIONS = 5000;
        final float THRESHOLD = 3.0f;

        try {
            long syscallTime = nativeDetector.benchmarkSyscallStat(ITERATIONS);
            long libcTime = nativeDetector.benchmarkLibcStat(ITERATIONS);
            boolean isHooked = nativeDetector.detectTimingAnomaly(syscallTime, libcTime, THRESHOLD);
            float ratio = (syscallTime > 0) ? (float)libcTime / (float)syscallTime : 0;

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, isHooked);
            item.setLayerResult(DetectionLayer.SYSCALL, !isHooked);

            if (isHooked) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail(String.format("检测到Hook征兆 - Syscall: %dns, Libc: %dns (%.1fx倍)",
                        syscallTime, libcTime, ratio));
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail(String.format("时序正常 - Syscall: %dns, Libc: %dns (%.1fx倍)",
                        syscallTime, libcTime, ratio));
            }
        } catch (Exception e) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("时序检测异常: " + e.getMessage());
        }

        return item;
    }
}
