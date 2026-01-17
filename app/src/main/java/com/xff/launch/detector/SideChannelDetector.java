package com.xff.launch.detector;

import android.content.Context;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.util.ArrayList;
import java.util.List;

/**
 * Security Environment Detection
 * Detects:
 * - SELinux status (related to Root detection)
 * - Timing-based hook detection for Frida/Xposed
 */
public class SideChannelDetector {

    private final Context context;
    private final NativeDetector nativeDetector;

    public SideChannelDetector(Context context) {
        this.context = context;
        this.nativeDetector = NativeDetector.getInstance();
    }

    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();

        // SELinux status - related to device security environment
        items.add(checkSELinux());

        // Timing-based hook detection (detects Frida/Xposed hooks)
        items.add(checkSyscallTimingOpenat());
        items.add(checkSyscallTimingAccess());
        items.add(checkSyscallTimingStat());

        return items;
    }

    /**
     * Check SELinux status
     * Enforcing = Normal, Otherwise = Abnormal (often indicates Root)
     */
    private DetectionItem checkSELinux() {
        DetectionItem item = new DetectionItem("SELinux 状态", "SELinux安全状态检测");

        // Method 1: Read /sys/fs/selinux/enforce
        String enforce = nativeDetector.readFileSyscall("/sys/fs/selinux/enforce");

        // Method 2: Check getenforce via native property
        String getenforce = nativeDetector.getBuildPropertyNative("ro.boot.selinux");

        // Determine if enforcing
        // enforce file: "1" = Enforcing, "0" = Permissive
        // Handle possible whitespace/newline in the value
        boolean isEnforcing = false;
        if (enforce != null && !enforce.isEmpty()) {
            String trimmed = enforce.trim();
            isEnforcing = trimmed.equals("1") || trimmed.startsWith("1");
        }

        // Fallback: if ro.boot.selinux is "enforcing" or empty (default is enforcing)
        if (!isEnforcing && getenforce != null) {
            isEnforcing = getenforce.isEmpty() ||
                          getenforce.equalsIgnoreCase("enforcing");
        }

        // If we couldn't read the file at all, check if SELinux directory exists
        if (enforce == null || enforce.isEmpty()) {
            // SELinux is enabled if the directory exists
            boolean selinuxExists = nativeDetector.fileExistsSyscall("/sys/fs/selinux");
            if (selinuxExists) {
                // Directory exists but can't read enforce - assume enforcing (permission denied = good)
                isEnforcing = true;
            }
        }

        // Set layer results
        item.setLayerResult(DetectionLayer.JAVA, !isEnforcing);
        item.setLayerResult(DetectionLayer.NATIVE, !isEnforcing);
        item.setLayerResult(DetectionLayer.SYSCALL, !isEnforcing);

        if (isEnforcing) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("SELinux正常");
        } else {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("SELinux异常（非强制模式）");
        }

        return item;
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
