package com.xff.launch.detector;

import android.content.Context;
import android.util.Log;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;
import com.xff.launch.util.ReflectionUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Zygote injection detector
 * Detects Zygisk, Riru, and other Zygote-based injection frameworks
 *
 * Detection techniques based on:
 * - LSPosed/NativeDetector
 * - /proc/self/maps analysis
 * - Native bridge detection
 * - SELinux context analysis
 * - Memory integrity checks
 *
 * References:
 * - https://github.com/LSPosed/NativeDetector
 * - https://github.com/RikkaApps/Riru
 * - https://zygisk.com/
 */
public class ZygoteDetector {

    private static final String TAG = "ZygoteDetector";

    private final Context context;
    private final NativeDetector nativeDetector;

    // Zygisk/Riru related keywords in memory maps
    private static final String[] ZYGOTE_INJECTION_KEYWORDS = {
            "zygisk",
            "libzygisk",
            "riru",
            "libriru",
            "lsposed",
            "liblsposed",
            "edxposed",
            "libedxposed",
            "xposed",
            "dreamland",
            "libwhale",
            "libsandhook",
            "libpine",
            "libdobby",
            "substrate",
            "frida-agent",
            "magisk"
    };

    // Suspicious native bridge values
    private static final String[] SUSPICIOUS_NATIVE_BRIDGES = {
            "libriruloader.so",
            "libriru_",
            "libzygisk_loader",
            "libhoudini",  // Not always suspicious but can be used
            "libnb"
    };

    // Paths to check for Zygisk/Riru modules
    // NOTE: /debug_ramdisk is a normal Android debug ramdisk, NOT a module path
    private static final String[] ZYGISK_MODULE_PATHS = {
            "/data/adb/modules",
            "/data/adb/lspd",
            "/data/adb/riru",
            "/data/adb/zygisk",
            "/dev/zygisk",
            "/dev/riru"
    };

    // System files that should not be modified
    private static final String[] CRITICAL_SYSTEM_FILES = {
            "/system/bin/app_process",
            "/system/bin/app_process32",
            "/system/bin/app_process64",
            "/system/lib/libandroid_runtime.so",
            "/system/lib64/libandroid_runtime.so",
            "/system/lib/libart.so",
            "/system/lib64/libart.so"
    };

    public ZygoteDetector(Context context) {
        this.context = context;
        this.nativeDetector = NativeDetector.getInstance();
    }

    /**
     * Get all Zygote-related detections
     */
    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();

        items.add(checkZygiskInjection());
        items.add(checkZygiskSUDaemon());  // ZygiskSU/Zygisk Next 特有的守护进程检测
        items.add(checkRiruInjection());
        items.add(checkNativeBridge());
        items.add(checkSELinuxContext());
        items.add(checkMemoryMaps());
        items.add(checkAppProcess());
        items.add(checkZygoteModules());
        items.add(checkMemoryIntegrity());
        items.add(checkAnonymousMemory());
        items.add(checkLibraryHooks());

        // 新增检测项
        // Note: Removed checkZygoteParentProcess() - Zygote's parent is always init (PID 1)
        // Zygisk doesn't change Zygote's parent process, so this check is ineffective
        items.add(checkAnonymousRwxMemory());
        items.add(checkInMemoryDexLoader());

        return items;
    }

    /**
     * Check for Zygisk injection in memory maps
     * Supports: Magisk Zygisk, ZygiskSU (Zygisk Next), ReZygisk
     */
    private DetectionItem checkZygiskInjection() {
        DetectionItem item = new DetectionItem("Zygisk 注入", "检测Zygisk框架注入");

        try {
            // Check via native (libc)
            boolean nativeDetected = nativeDetector.checkZygiskNative();

            // Check via syscall
            boolean syscallDetected = nativeDetector.checkZygiskSyscall();

            // Java layer check - read maps
            String maps = nativeDetector.readFileSyscall("/proc/self/maps");
            boolean mapsDetected = maps.toLowerCase().contains("zygisk") ||
                    maps.toLowerCase().contains("libzygisk");

            // Check ro.zygisk.denylists property (ZygiskSU/Zygisk Next feature)
            // If this property exists, Zygisk is installed
            boolean propDetected = false;
            try {
                String denylistProp = System.getProperty("ro.zygisk.denylists");
                if (denylistProp == null) {
                    // Try via reflection for system properties
                    Class<?> spClass = Class.forName("android.os.SystemProperties");
                    java.lang.reflect.Method getMethod = spClass.getMethod("get", String.class, String.class);
                    String value = (String) getMethod.invoke(null, "ro.zygisk.denylists", "");
                    propDetected = !value.isEmpty();
                } else {
                    propDetected = true;
                }
            } catch (Exception ignored) {}

            boolean javaDetected = mapsDetected || propDetected;

            item.setLayerResult(DetectionLayer.JAVA, !javaDetected);
            item.setLayerResult(DetectionLayer.NATIVE, !nativeDetected);
            item.setLayerResult(DetectionLayer.SYSCALL, !syscallDetected);

            if (syscallDetected || nativeDetected) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到Zygisk注入框架");
            } else if (mapsDetected) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("内存映射中检测到Zygisk");
            } else if (propDetected) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到Zygisk (ro.zygisk.denylists)");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未检测到Zygisk");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkZygiskInjection failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check for ZygiskSU (Zygisk Next) daemon processes
     * ZygiskSU uses specific daemon processes: zn-daemon, zn-nsdaemon, zn-zygisk-companion
     */
    private DetectionItem checkZygiskSUDaemon() {
        DetectionItem item = new DetectionItem("ZygiskSU 守护进程", "检测Zygisk Next守护进程");

        try {
            boolean detected = false;
            StringBuilder details = new StringBuilder();

            // ZygiskSU daemon process name patterns
            String[] daemonPatterns = {
                "zn-daemon",           // Main ZygiskSU daemon
                "zn-nsdaemon",         // Namespace daemon
                "zn-zygisk-companion", // Zygisk companion process
                "zygisk_gadget"        // Frida gadget via Zygisk
            };

            // Scan /proc for daemon processes
            java.io.File procDir = new java.io.File("/proc");
            String[] pids = procDir.list((dir, name) -> name.matches("\\d+"));

            if (pids != null) {
                for (String pid : pids) {
                    try {
                        // Try to read cmdline (may fail due to SELinux)
                        java.io.File cmdlineFile = new java.io.File("/proc/" + pid + "/cmdline");
                        if (cmdlineFile.canRead()) {
                            java.io.BufferedReader reader = new java.io.BufferedReader(
                                new java.io.FileReader(cmdlineFile));
                            String cmdline = reader.readLine();
                            reader.close();

                            if (cmdline != null) {
                                cmdline = cmdline.replace('\0', ' ').trim();
                                for (String pattern : daemonPatterns) {
                                    if (cmdline.toLowerCase().contains(pattern.toLowerCase())) {
                                        detected = true;
                                        if (details.length() > 0) details.append(", ");
                                        details.append(pattern);
                                        break;
                                    }
                                }
                            }
                        }
                    } catch (Exception ignored) {
                        // SELinux may block access to other process's info
                    }
                }
            }

            // Also check via native detector
            boolean nativeDetected = nativeDetector.checkZygiskSyscall();

            item.setLayerResult(DetectionLayer.JAVA, !detected);
            item.setLayerResult(DetectionLayer.NATIVE, !nativeDetected);
            item.setLayerResult(DetectionLayer.SYSCALL, !nativeDetected);

            if (detected) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到ZygiskSU守护进程: " + details.toString());
            } else if (nativeDetected) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("Native层检测到Zygisk");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未检测到ZygiskSU守护进程");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkZygiskSUDaemon failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check for Riru injection
     */
    private DetectionItem checkRiruInjection() {
        DetectionItem item = new DetectionItem("Riru 注入", "检测Riru框架注入");

        try {
            // Check via native
            boolean nativeDetected = nativeDetector.checkRiruNative();

            // Check via syscall
            boolean syscallDetected = nativeDetector.checkRiruSyscall();

            // Check Riru paths
            boolean pathExists = false;
            for (String path : new String[]{"/data/adb/riru", "/dev/riru"}) {
                if (nativeDetector.fileExistsSyscall(path)) {
                    pathExists = true;
                    break;
                }
            }

            item.setLayerResult(DetectionLayer.JAVA, !pathExists);
            item.setLayerResult(DetectionLayer.NATIVE, !nativeDetected);
            item.setLayerResult(DetectionLayer.SYSCALL, !syscallDetected);

            if (syscallDetected || nativeDetected) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到Riru注入框架");
            } else if (pathExists) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("检测到Riru相关路径");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未检测到Riru");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkRiruInjection failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check native bridge property (ro.dalvik.vm.native.bridge)
     * Riru and some Zygisk implementations use native bridge for injection
     */
    private DetectionItem checkNativeBridge() {
        DetectionItem item = new DetectionItem("Native Bridge", "检测原生桥接注入");

        try {
            // Get native bridge value via reflection
            String nativeBridge = ReflectionUtils.getSystemProperty("ro.dalvik.vm.native.bridge");

            // Get via native
            String nativeValue = nativeDetector.getBuildPropertyNative("ro.dalvik.vm.native.bridge");

            // Get via syscall
            String syscallValue = nativeDetector.getBuildPropertySyscall("ro.dalvik.vm.native.bridge");

            // Check if native bridge is suspicious
            boolean isSuspicious = false;
            String suspiciousValue = "";

            for (String bridge : SUSPICIOUS_NATIVE_BRIDGES) {
                if (nativeBridge.toLowerCase().contains(bridge.toLowerCase()) ||
                        nativeValue.toLowerCase().contains(bridge.toLowerCase()) ||
                        syscallValue.toLowerCase().contains(bridge.toLowerCase())) {
                    isSuspicious = true;
                    suspiciousValue = nativeBridge.isEmpty() ? nativeValue : nativeBridge;
                    break;
                }
            }

            // Empty or "0" is normal
            boolean javaOk = nativeBridge.isEmpty() || nativeBridge.equals("0");
            boolean nativeOk = nativeValue.isEmpty() || nativeValue.equals("0");
            boolean syscallOk = syscallValue.isEmpty() || syscallValue.equals("0");

            item.setLayerResult(DetectionLayer.JAVA, javaOk && !isSuspicious);
            item.setLayerResult(DetectionLayer.NATIVE, nativeOk && !isSuspicious);
            item.setLayerResult(DetectionLayer.SYSCALL, syscallOk && !isSuspicious);

            if (isSuspicious) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("可疑Native Bridge: " + suspiciousValue);
            } else if (!javaOk || !nativeOk) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("Native Bridge: " + (nativeBridge.isEmpty() ? nativeValue : nativeBridge));
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("Native Bridge正常");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkNativeBridge failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check SELinux context for Zygote manipulation
     * Normal: exec from u:r:init:s0
     * Magisk wrapped: u:r:zygote:s0
     */
    private DetectionItem checkSELinuxContext() {
        DetectionItem item = new DetectionItem("SELinux 上下文", "检测进程安全上下文");

        try {
            // Read /proc/self/attr/prev via syscall
            String prevContext = nativeDetector.readFileSyscall("/proc/self/attr/prev");

            // Read current context
            String currentContext = nativeDetector.readFileSyscall("/proc/self/attr/current");

            // Native check
            String nativePrev = nativeDetector.getSELinuxContextNative();

            // Check for anomalies
            // Normal app should have u:r:untrusted_app context
            // If prev shows zygote manipulation, it's suspicious
            boolean hasZygoteAnomaly = prevContext.contains("u:r:zygote:s0") &&
                    !prevContext.contains("u:r:init:s0");

            boolean hasMagiskContext = currentContext.contains("magisk") ||
                    prevContext.contains("magisk");

            item.setLayerResult(DetectionLayer.JAVA, !hasMagiskContext);
            item.setLayerResult(DetectionLayer.NATIVE, !hasZygoteAnomaly);
            item.setLayerResult(DetectionLayer.SYSCALL, !hasMagiskContext && !hasZygoteAnomaly);

            if (hasMagiskContext) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到Magisk相关上下文");
            } else if (hasZygoteAnomaly) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("Zygote上下文异常: " + truncate(prevContext, 30));
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("SELinux上下文正常");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkSELinuxContext failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check /proc/self/maps for injection signatures
     */
    private DetectionItem checkMemoryMaps() {
        DetectionItem item = new DetectionItem("内存映射", "检测可疑内存映射");

        try {
            // Read maps via syscall
            String maps = nativeDetector.readFileSyscall("/proc/self/maps");
            String mapsLower = maps.toLowerCase();

            // Count suspicious entries
            int suspiciousCount = 0;
            StringBuilder detected = new StringBuilder();

            for (String keyword : ZYGOTE_INJECTION_KEYWORDS) {
                if (mapsLower.contains(keyword.toLowerCase())) {
                    suspiciousCount++;
                    if (detected.length() > 0) detected.append(", ");
                    detected.append(keyword);
                }
            }

            // Native check
            int nativeCount = nativeDetector.checkSuspiciousMapsNative();

            // Syscall check
            int syscallCount = nativeDetector.checkSuspiciousMapsSyscall();

            item.setLayerResult(DetectionLayer.JAVA, suspiciousCount == 0);
            item.setLayerResult(DetectionLayer.NATIVE, nativeCount == 0);
            item.setLayerResult(DetectionLayer.SYSCALL, syscallCount == 0);

            if (syscallCount > 0 || suspiciousCount > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到: " + (detected.length() > 0 ? detected.toString() : "可疑映射"));
            } else if (nativeCount > 0) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("Native层检测到可疑映射");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("内存映射正常");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkMemoryMaps failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check app_process integrity
     */
    private DetectionItem checkAppProcess() {
        DetectionItem item = new DetectionItem("app_process 完整性", "检测应用进程程序");

        try {
            boolean hasAnomaly = false;
            StringBuilder anomalyDetail = new StringBuilder();
            List<String> checkedFiles = new ArrayList<>();
            List<String> legitimateSymlinks = new ArrayList<>();
            List<String> anomalyFiles = new ArrayList<>();

            // Check all app_process related files
            for (String path : CRITICAL_SYSTEM_FILES) {
                if (path.contains("app_process")) {
                    checkedFiles.add(path);

                    // Check if file exists first
                    if (!nativeDetector.fileExistsSyscall(path)) {
                        continue;  // File doesn't exist, skip
                    }

                    // Check if it's a symlink
                    if (nativeDetector.isSymlinkSyscall(path)) {
                        String target = nativeDetector.readlinkSyscall(path);

                        // Legitimate symlinks:
                        // /system/bin/app_process -> app_process32 or app_process64
                        // This is NORMAL in Android!
                        boolean isLegitimateSymlink = false;

                        if (path.equals("/system/bin/app_process")) {
                            // This should point to app_process32 or app_process64
                            if (target != null && (target.equals("app_process32") ||
                                                   target.equals("app_process64") ||
                                                   target.contains("app_process32") ||
                                                   target.contains("app_process64"))) {
                                isLegitimateSymlink = true;
                                legitimateSymlinks.add(path + " → " + target);
                            }
                        }

                        // Only mark as anomaly if it's NOT a legitimate symlink
                        if (!isLegitimateSymlink) {
                            // Suspicious symlink pointing to unusual location
                            if (target != null && (target.contains("/data/") ||
                                                   target.contains("/sdcard/") ||
                                                   target.contains("/tmp/"))) {
                                hasAnomaly = true;
                                anomalyFiles.add(path);
                                if (anomalyDetail.length() > 0) anomalyDetail.append("\n");
                                anomalyDetail.append("• ").append(path).append(" → ").append(target)
                                             .append(" (可疑位置)");
                            }
                        }
                    }

                    // Check file integrity (for actual binaries, not symlinks)
                    else if (!nativeDetector.checkFileIntegritySyscall(path)) {
                        hasAnomaly = true;
                        anomalyFiles.add(path);
                        if (anomalyDetail.length() > 0) anomalyDetail.append("\n");
                        anomalyDetail.append("• ").append(path).append(" 完整性异常");
                    }
                }
            }

            // Native check
            boolean nativeOk = nativeDetector.checkAppProcessNative();

            // Syscall check
            boolean syscallOk = nativeDetector.checkAppProcessSyscall();

            item.setLayerResult(DetectionLayer.JAVA, !hasAnomaly);
            item.setLayerResult(DetectionLayer.NATIVE, nativeOk);
            item.setLayerResult(DetectionLayer.SYSCALL, syscallOk);

            if (!syscallOk || hasAnomaly) {
                item.setStatus(DetectionStatus.RISK);
                if (anomalyDetail.length() > 0) {
                    item.setDetail("检测到异常:\n" + anomalyDetail.toString());
                } else {
                    item.setDetail("app_process 被修改");
                }
            } else if (!nativeOk) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("Native层检测到异常");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                // Show which files were checked and legitimate symlinks
                StringBuilder detail = new StringBuilder();
                detail.append("已检查 ").append(checkedFiles.size()).append(" 个文件，均正常");
                if (!legitimateSymlinks.isEmpty()) {
                    detail.append("\n合法符号链接: ");
                    detail.append(legitimateSymlinks.get(0));
                }
                item.setDetail(detail.toString());
            }

        } catch (Exception e) {
            Log.w(TAG, "checkAppProcess failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("检测异常: " + e.getMessage());
        }

        return item;
    }

    /**
     * Check for Zygote module directories
     */
    private DetectionItem checkZygoteModules() {
        DetectionItem item = new DetectionItem("Zygote 模块", "检测注入模块目录");

        try {
            int foundCount = 0;
            List<String> foundPaths = new ArrayList<>();

            // Check all module paths
            for (String path : ZYGISK_MODULE_PATHS) {
                if (nativeDetector.fileExistsSyscall(path)) {
                    foundCount++;
                    foundPaths.add(path);
                }
            }

            // Also check for modules with zygisk folder
            String modulesPath = "/data/adb/modules";
            if (nativeDetector.fileExistsSyscall(modulesPath)) {
                // This would need directory listing, simplified check
                int zygiskModules = nativeDetector.countZygiskModulesSyscall();
                if (zygiskModules > 0) {
                    foundCount += zygiskModules;
                    if (!foundPaths.contains(modulesPath)) {
                        foundPaths.add(modulesPath);
                    }
                }
            }

            item.setLayerResult(DetectionLayer.JAVA, foundCount == 0);
            item.setLayerResult(DetectionLayer.NATIVE, foundCount == 0);
            item.setLayerResult(DetectionLayer.SYSCALL, foundCount == 0);

            if (foundCount > 0) {
                item.setStatus(DetectionStatus.RISK);

                // Build detailed message with all found paths
                StringBuilder detail = new StringBuilder();
                detail.append("检测到 ").append(foundCount).append(" 个模块路径:\n");

                // Show up to 5 paths to avoid too long text
                int maxDisplay = Math.min(foundPaths.size(), 5);
                for (int i = 0; i < maxDisplay; i++) {
                    detail.append("• ").append(foundPaths.get(i));
                    if (i < maxDisplay - 1) {
                        detail.append("\n");
                    }
                }

                if (foundPaths.size() > 5) {
                    detail.append("\n... 还有 ").append(foundPaths.size() - 5).append(" 个路径");
                }

                item.setDetail(detail.toString());
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未检测到Zygote模块");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkZygoteModules failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check memory integrity for JNI hooks
     * Detects PLT/GOT modifications
     */
    private DetectionItem checkMemoryIntegrity() {
        DetectionItem item = new DetectionItem("内存完整性", "检测JNI钩子");

        try {
            // Check for PLT/GOT hooks via native
            boolean nativeIntact = nativeDetector.checkMemoryIntegrityNative();

            // Check via syscall
            boolean syscallIntact = nativeDetector.checkMemoryIntegritySyscall();

            // Check for inline hooks
            boolean hasInlineHooks = nativeDetector.checkInlineHooksSyscall();

            item.setLayerResult(DetectionLayer.JAVA, true);
            item.setLayerResult(DetectionLayer.NATIVE, nativeIntact);
            item.setLayerResult(DetectionLayer.SYSCALL, syscallIntact && !hasInlineHooks);

            if (hasInlineHooks) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到内联钩子");
            } else if (!syscallIntact || !nativeIntact) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("内存完整性异常");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("内存完整性正常");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkMemoryIntegrity failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check for suspicious anonymous memory
     * Zygisk/Riru hide by using anonymous memory
     */
    private DetectionItem checkAnonymousMemory() {
        DetectionItem item = new DetectionItem("匿名内存", "检测隐藏的注入内存");

        try {
            // Check for r--p pages with private dirty (suspicious)
            // This is a technique to detect hidden Zygisk/Riru
            boolean hasSuspiciousAnon = nativeDetector.checkSuspiciousAnonMemorySyscall();

            // Check smaps for detailed analysis
            String smaps = nativeDetector.readFileSyscall("/proc/self/smaps");
            boolean hasPrivateDirty = checkPrivateDirtyPages(smaps);

            item.setLayerResult(DetectionLayer.JAVA, !hasPrivateDirty);
            item.setLayerResult(DetectionLayer.NATIVE, !hasSuspiciousAnon);
            item.setLayerResult(DetectionLayer.SYSCALL, !hasSuspiciousAnon);

            if (hasSuspiciousAnon) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到可疑匿名内存区域");
            } else if (hasPrivateDirty) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("存在可疑的私有脏页");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("匿名内存正常");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkAnonymousMemory failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check for library hooks in critical libraries
     */
    private DetectionItem checkLibraryHooks() {
        DetectionItem item = new DetectionItem("库函数钩子", "检测系统库钩子");

        try {
            // Check if critical libraries have hooks
            boolean libcHooked = nativeDetector.checkLibcHooksSyscall();
            boolean artHooked = nativeDetector.checkArtHooksSyscall();

            // Native layer check
            boolean nativeOk = nativeDetector.checkLibraryHooksNative();

            item.setLayerResult(DetectionLayer.JAVA, true);
            item.setLayerResult(DetectionLayer.NATIVE, nativeOk);
            item.setLayerResult(DetectionLayer.SYSCALL, !libcHooked && !artHooked);

            if (libcHooked || artHooked) {
                item.setStatus(DetectionStatus.RISK);
                String detail = "";
                if (libcHooked) detail += "libc ";
                if (artHooked) detail += "libart ";
                item.setDetail("检测到库钩子: " + detail.trim());
            } else if (!nativeOk) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("Native层检测到可疑钩子");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未检测到库函数钩子");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkLibraryHooks failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check smaps for suspicious private dirty pages
     */
    private boolean checkPrivateDirtyPages(String smaps) {
        if (smaps == null || smaps.isEmpty()) return false;

        // Look for r--p sections with Private_Dirty > 0
        // This can indicate hidden code injection
        String[] lines = smaps.split("\n");
        boolean inReadOnlySection = false;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];

            // Check for r--p permission (read-only, private)
            if (line.contains("r--p") &&
                    (line.contains("/system/") || line.contains("/apex/"))) {
                inReadOnlySection = true;
            } else if (line.startsWith("Private_Dirty:") && inReadOnlySection) {
                // Check if Private_Dirty is non-zero
                String value = line.replace("Private_Dirty:", "").trim();
                value = value.replace("kB", "").trim();
                try {
                    int dirty = Integer.parseInt(value);
                    if (dirty > 0) {
                        return true;  // Suspicious!
                    }
                } catch (NumberFormatException e) {
                    // Ignore
                }
                inReadOnlySection = false;
            } else if (line.isEmpty() || line.matches("^[0-9a-f]+-[0-9a-f]+.*")) {
                inReadOnlySection = false;
            }
        }

        return false;
    }

    /**
     * Truncate string for display
     */
    private String truncate(String str, int maxLen) {
        if (str == null) return "";
        str = str.trim().replace("\n", " ").replace("\0", "");
        if (str.length() <= maxLen) return str;
        return str.substring(0, maxLen) + "...";
    }

    // ===================== New Detection Methods =====================

    /**
     * Check Zygote parent process
     * Normal: Zygote's parent should be init (PID 1)
     * Abnormal: Zygote's parent is something else -> Zygisk injection
     *
     * Example from user: "find zygisk detected ,zygote root pid 1167"
     */
    private DetectionItem checkZygoteParentProcess() {
        DetectionItem item = new DetectionItem("Zygote 父进程", "检测Zygote父进程异常");

        try {
            // Get zygote info: "zygote_pid:parent_pid"
            String zygoteInfo = nativeDetector.getZygoteInfo();

            if (zygoteInfo.equals("not_found")) {
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("未找到Zygote进程");
                item.setLayerResult(DetectionLayer.JAVA, true);
                item.setLayerResult(DetectionLayer.NATIVE, true);
                item.setLayerResult(DetectionLayer.SYSCALL, true);
                return item;
            }

            // Parse "zygote_pid:parent_pid"
            String[] parts = zygoteInfo.split(":");
            if (parts.length != 2) {
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("解析Zygote信息失败");
                return item;
            }

            int zygotePid = Integer.parseInt(parts[0]);
            int parentPid = Integer.parseInt(parts[1]);

            // Check via native
            boolean hasAbnormalParent = nativeDetector.checkZygoteParentNative();

            item.setLayerResult(DetectionLayer.JAVA, parentPid == 1);
            item.setLayerResult(DetectionLayer.NATIVE, !hasAbnormalParent);
            item.setLayerResult(DetectionLayer.SYSCALL, parentPid == 1);

            // Normal: parent should be init (PID 1)
            if (parentPid != 1 || hasAbnormalParent) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail(String.format("Zygote父进程异常 - PID:%d, PPID:%d (应为1)",
                        zygotePid, parentPid));
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail(String.format("Zygote正常 - PID:%d, PPID:%d", zygotePid, parentPid));
            }

        } catch (Exception e) {
            Log.w(TAG, "checkZygoteParentProcess failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("检测异常: " + e.getMessage());
        }

        return item;
    }

    /**
     * Check for anonymous rwxp memory regions
     * These are suspicious executable memory without file backing
     *
     * Example from user:
     * "7e8b96b000-7e8b96c000 rwxp 00000000 00:00 0"
     * "exec address start-> 0x7e8b96b000, perm -> rwxp, inode -> 0"
     */
    private DetectionItem checkAnonymousRwxMemory() {
        DetectionItem item = new DetectionItem("匿名可执行内存", "检测rwxp匿名内存区域");

        try {
            // Count anonymous rwxp regions
            int count = nativeDetector.countAnonymousRwxMemory();

            // Get details
            String details = nativeDetector.getAnonymousRwxDetails();

            item.setLayerResult(DetectionLayer.JAVA, count == 0);
            item.setLayerResult(DetectionLayer.NATIVE, count < 5);  // Some JIT is normal
            item.setLayerResult(DetectionLayer.SYSCALL, count < 10);

            if (count > 100) {
                // Very high count -> likely hook/injection
                item.setStatus(DetectionStatus.RISK);
                item.setDetail(String.format("检测到 %d 个匿名rwxp区域 (高风险)", count));
            } else if (count > 20) {
                // Moderate count -> suspicious
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail(String.format("检测到 %d 个匿名rwxp区域 (可疑)", count));
            } else if (count > 0) {
                // Low count -> may be normal (JIT, etc.)
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail(String.format("检测到 %d 个匿名rwxp区域 (正常范围)", count));
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未检测到匿名rwxp内存");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkAnonymousRwxMemory failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("检测异常: " + e.getMessage());
        }

        return item;
    }

    /**
     * Check for InMemoryDexClassLoader
     * Detects dynamically loaded DEX from memory (common in LSPosed/Xposed)
     *
     * Example from user:
     * "dex load size -> 2"
     * "dalvik.system.InMemoryDexClassLoader[DexPathList[[dex file...]]]"
     */
    private DetectionItem checkInMemoryDexLoader() {
        DetectionItem item = new DetectionItem("内存DEX加载器", "检测InMemoryDexClassLoader");

        try {
            int inMemoryDexCount = 0;
            List<String> loaderDetails = new ArrayList<>();

            // Get all class loaders in the chain
            ClassLoader currentLoader = context.getClassLoader();
            int depth = 0;
            final int MAX_DEPTH = 20;  // Prevent infinite loop

            while (currentLoader != null && depth < MAX_DEPTH) {
                String loaderName = currentLoader.getClass().getName();

                // Check if it's InMemoryDexClassLoader
                if (loaderName.contains("InMemoryDexClassLoader")) {
                    inMemoryDexCount++;
                    loaderDetails.add(truncate(currentLoader.toString(), 80));
                }

                // Move to parent
                currentLoader = currentLoader.getParent();
                depth++;
            }

            item.setLayerResult(DetectionLayer.JAVA, inMemoryDexCount == 0);
            item.setLayerResult(DetectionLayer.NATIVE, inMemoryDexCount == 0);
            item.setLayerResult(DetectionLayer.SYSCALL, inMemoryDexCount == 0);

            if (inMemoryDexCount > 0) {
                item.setStatus(DetectionStatus.RISK);
                StringBuilder detail = new StringBuilder();
                detail.append(String.format("检测到 %d 个内存DEX加载器:\n", inMemoryDexCount));
                for (int i = 0; i < Math.min(loaderDetails.size(), 3); i++) {
                    detail.append("• ").append(loaderDetails.get(i)).append("\n");
                }
                item.setDetail(detail.toString().trim());
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未检测到InMemoryDexClassLoader");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkInMemoryDexLoader failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("检测异常: " + e.getMessage());
        }

        return item;
    }
}
