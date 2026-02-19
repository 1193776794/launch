package com.xff.launch.detector;

import android.content.Context;
import android.util.Log;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Readlink detector for symlink-based security detection
 * Uses syscall-level detection to bypass hooks
 *
 * Detects:
 * - /proc/self/exe tampering
 * - Suspicious symlinks in system paths
 * - Root/Hook framework symlink hiding
 * - File descriptor anomalies
 * - Mount namespace manipulation
 */
public class ReadlinkDetector {

    private static final String TAG = "ReadlinkDetector";

    private final Context context;
    private final NativeDetector nativeDetector;

    // Suspicious symlink targets that indicate root/hook
    private static final String[] SUSPICIOUS_TARGETS = {
            "magisk", "su", "busybox", "supersu", "superuser",
            "ksu", "kernelsu", "apatch", "lsposed", "edxposed",
            "xposed", "riru", "zygisk", "shamiko", "hide"
    };

    // System paths to check for suspicious symlinks
    private static final String[] SYSTEM_SYMLINK_PATHS = {
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/vendor/bin/su",
            "/system/bin/daemonsu",
            "/system/bin/.ext/.su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su"
    };

    // Paths that should NOT be symlinks to suspicious targets
    // Note: Many system files ARE legitimate symlinks (e.g., sh -> mksh, app_process -> app_process64)
    // We only flag as risk if they point to suspicious targets
    private static final String[] CRITICAL_SYSTEM_FILES = {
            "/system/bin/sh",
            "/system/bin/app_process",
            "/system/bin/app_process32",
            "/system/bin/app_process64",
            "/system/lib/libc.so",
            "/system/lib64/libc.so"
    };

    // Legitimate symlink targets for system files
    private static final String[] LEGITIMATE_TARGETS = {
            "mksh", "toybox", "toolbox", "busybox_orig",
            "app_process32", "app_process64",
            "libc.so", "/apex/com.android.runtime/lib",
            "/apex/com.android.runtime/lib64",
            "/system/", "/vendor/", "/apex/"
    };

    public ReadlinkDetector(Context context) {
        this.context = context;
        this.nativeDetector = NativeDetector.getInstance();
    }

    /**
     * Get all readlink-based detections
     */
    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();

        items.add(checkProcSelfExe());
        items.add(checkProcSelfMaps());
        items.add(checkProcSelfMounts());
        items.add(checkProcSelfRoot());
        items.add(checkProcSelfCwd());
        items.add(checkProcSelfFd());
        items.add(checkSuSymlinks());
        items.add(checkSystemBinaries());
        items.add(checkAppPath());
        items.add(checkMountNamespace());

        return items;
    }

    /**
     * Check /proc/self/exe - should point to app's actual executable
     */
    private DetectionItem checkProcSelfExe() {
        DetectionItem item = new DetectionItem("/proc/self/exe", "检测进程可执行文件路径");

        try {
            // Java layer - use File.getCanonicalPath
            String javaExePath = "";
            try {
                File exeFile = new File("/proc/self/exe");
                if (exeFile.exists()) {
                    javaExePath = exeFile.getCanonicalPath();
                }
            } catch (Exception e) {
                javaExePath = "";
            }

            // Native layer - libc readlink
            String nativeExePath = nativeDetector.readlinkNative("/proc/self/exe");

            // Syscall layer - direct syscall
            String syscallExePath = nativeDetector.readlinkSyscall("/proc/self/exe");

            // Check if paths are consistent and point to expected location
            String packageName = context.getPackageName();
            boolean javaOk = javaExePath.contains(packageName) || javaExePath.contains("app_process");
            boolean nativeOk = nativeExePath.contains(packageName) || nativeExePath.contains("app_process");
            boolean syscallOk = syscallExePath.contains(packageName) || syscallExePath.contains("app_process");

            // Check for suspicious targets
            boolean javaRisk = containsSuspicious(javaExePath);
            boolean nativeRisk = containsSuspicious(nativeExePath);
            boolean syscallRisk = containsSuspicious(syscallExePath);

            // Check consistency between layers
            boolean consistent = nativeExePath.equals(syscallExePath);

            item.setLayerResult(DetectionLayer.JAVA, javaRisk || !javaOk);
            item.setLayerResult(DetectionLayer.NATIVE, nativeRisk || !nativeOk);
            item.setLayerResult(DetectionLayer.SYSCALL, syscallRisk || !syscallOk);

            if (javaRisk || nativeRisk || syscallRisk) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到可疑进程路径: " + syscallExePath);
            } else if (!consistent) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("层级不一致 Native: " + nativeExePath + " Syscall: " + syscallExePath);
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("正常: " + truncate(syscallExePath, 50));
            }

        } catch (Exception e) {
            Log.w(TAG, "checkProcSelfExe failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("检测失败: " + e.getMessage());
        }

        return item;
    }

    /**
     * Check /proc/self/maps symlink consistency
     */
    private DetectionItem checkProcSelfMaps() {
        DetectionItem item = new DetectionItem("/proc/self/maps", "检测内存映射文件");

        try {
            // Check if maps file is accessible and not manipulated
            String nativeResult = nativeDetector.checkProcFileSyscall("/proc/self/maps");
            String syscallResult = nativeDetector.readFileSyscall("/proc/self/maps");

            boolean hasContent = !syscallResult.isEmpty();
            boolean hasSuspicious = containsSuspicious(syscallResult);

            // Check for hidden mappings (indication of hook framework)
            boolean hasHiddenMaps = nativeDetector.checkHiddenMapsSyscall();

            item.setLayerResult(DetectionLayer.JAVA, !hasContent);
            item.setLayerResult(DetectionLayer.NATIVE, hasSuspicious);
            item.setLayerResult(DetectionLayer.SYSCALL, hasHiddenMaps);

            if (hasHiddenMaps) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到隐藏的内存映射");
            } else if (hasSuspicious) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("内存映射中存在可疑内容");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("内存映射正常");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkProcSelfMaps failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check /proc/self/mounts for mount namespace manipulation
     */
    private DetectionItem checkProcSelfMounts() {
        DetectionItem item = new DetectionItem("/proc/self/mounts", "检测挂载命名空间");

        try {
            String nativeMounts = nativeDetector.readlinkNative("/proc/self/mounts");
            String syscallMounts = nativeDetector.readlinkSyscall("/proc/self/mounts");

            // Read actual mount content via syscall
            String mountContent = nativeDetector.readFileSyscall("/proc/self/mounts");

            // Check for overlay/bind mounts that might hide files
            boolean hasOverlay = mountContent.contains("overlay") &&
                    (mountContent.contains("/system") || mountContent.contains("/vendor"));
            boolean hasBindMount = mountContent.contains("magisk") ||
                    mountContent.contains("ksu") || mountContent.contains("apatch");

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, hasOverlay);
            item.setLayerResult(DetectionLayer.SYSCALL, hasBindMount);

            if (hasBindMount) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到Root相关挂载");
            } else if (hasOverlay) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("检测到系统Overlay挂载");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("挂载命名空间正常");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkProcSelfMounts failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check /proc/self/root - should be /
     */
    private DetectionItem checkProcSelfRoot() {
        DetectionItem item = new DetectionItem("/proc/self/root", "检测进程根目录");

        try {
            String nativeRoot = nativeDetector.readlinkNative("/proc/self/root");
            String syscallRoot = nativeDetector.readlinkSyscall("/proc/self/root");

            boolean nativeOk = "/".equals(nativeRoot);
            boolean syscallOk = "/".equals(syscallRoot);
            boolean consistent = nativeRoot.equals(syscallRoot);

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, !nativeOk);
            item.setLayerResult(DetectionLayer.SYSCALL, !syscallOk);

            if (!syscallOk) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("根目录异常: " + syscallRoot);
            } else if (!consistent) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("层级不一致");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("根目录正常: /");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkProcSelfRoot failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check /proc/self/cwd - current working directory
     */
    private DetectionItem checkProcSelfCwd() {
        DetectionItem item = new DetectionItem("/proc/self/cwd", "检测当前工作目录");

        try {
            String nativeCwd = nativeDetector.readlinkNative("/proc/self/cwd");
            String syscallCwd = nativeDetector.readlinkSyscall("/proc/self/cwd");

            boolean hasSuspicious = containsSuspicious(syscallCwd);
            boolean consistent = nativeCwd.equals(syscallCwd);

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, containsSuspicious(nativeCwd));
            item.setLayerResult(DetectionLayer.SYSCALL, hasSuspicious);

            if (hasSuspicious) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("工作目录异常: " + syscallCwd);
            } else if (!consistent) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("层级不一致");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("工作目录: " + truncate(syscallCwd, 40));
            }

        } catch (Exception e) {
            Log.w(TAG, "checkProcSelfCwd failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check /proc/self/fd for suspicious file descriptors
     */
    private DetectionItem checkProcSelfFd() {
        DetectionItem item = new DetectionItem("/proc/self/fd", "检测文件描述符");

        try {
            // Check FDs via syscall for suspicious targets
            int suspiciousFdCount = nativeDetector.checkSuspiciousFdsSyscall();

            // Also check via native
            int nativeFdCount = nativeDetector.checkSuspiciousFdsNative();

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, nativeFdCount != 0);
            item.setLayerResult(DetectionLayer.SYSCALL, suspiciousFdCount != 0);

            if (suspiciousFdCount > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到 " + suspiciousFdCount + " 个可疑文件描述符");
            } else if (nativeFdCount > 0) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("Native层检测到可疑FD");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("文件描述符正常");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkProcSelfFd failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check for SU binary symlinks
     */
    private DetectionItem checkSuSymlinks() {
        DetectionItem item = new DetectionItem("SU 符号链接", "检测SU二进制符号链接");

        try {
            int nativeFound = 0;
            int syscallFound = 0;
            String foundPath = "";

            for (String path : SYSTEM_SYMLINK_PATHS) {
                // Check via native
                if (nativeDetector.isSymlinkNative(path)) {
                    String target = nativeDetector.readlinkNative(path);
                    if (!target.isEmpty()) {
                        nativeFound++;
                        foundPath = path + " -> " + target;
                    }
                }

                // Check via syscall
                if (nativeDetector.isSymlinkSyscall(path)) {
                    String target = nativeDetector.readlinkSyscall(path);
                    if (!target.isEmpty()) {
                        syscallFound++;
                        if (foundPath.isEmpty()) {
                            foundPath = path + " -> " + target;
                        }
                    }
                }
            }

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, nativeFound > 0);
            item.setLayerResult(DetectionLayer.SYSCALL, syscallFound > 0);

            if (syscallFound > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到SU符号链接: " + foundPath);
            } else if (nativeFound > 0) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("Native层检测到SU符号链接");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未检测到SU符号链接");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkSuSymlinks failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check system binaries for suspicious symlink targets
     * Note: Many system binaries ARE legitimate symlinks (sh -> mksh, etc.)
     * We only flag if the target is suspicious (magisk, su, etc.)
     */
    private DetectionItem checkSystemBinaries() {
        DetectionItem item = new DetectionItem("系统二进制文件", "检测系统文件完整性");

        try {
            int nativeSuspicious = 0;
            int syscallSuspicious = 0;
            String suspiciousPath = "";
            int legitimateSymlinks = 0;

            for (String path : CRITICAL_SYSTEM_FILES) {
                // Check if file exists first
                if (!nativeDetector.fileExistsSyscall(path)) {
                    continue;
                }

                // Check via native
                if (nativeDetector.isSymlinkNative(path)) {
                    String target = nativeDetector.readlinkNative(path);
                    if (!target.isEmpty()) {
                        if (isLegitimateTarget(target)) {
                            // This is a normal system symlink (e.g., sh -> mksh)
                            legitimateSymlinks++;
                        } else if (containsSuspicious(target)) {
                            // Target contains suspicious keywords (magisk, su, etc.)
                            nativeSuspicious++;
                            suspiciousPath = path + " -> " + target;
                        }
                    }
                }

                // Check via syscall
                if (nativeDetector.isSymlinkSyscall(path)) {
                    String target = nativeDetector.readlinkSyscall(path);
                    if (!target.isEmpty()) {
                        if (!isLegitimateTarget(target) && containsSuspicious(target)) {
                            syscallSuspicious++;
                            if (suspiciousPath.isEmpty()) {
                                suspiciousPath = path + " -> " + target;
                            }
                        }
                    }
                }
            }

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, nativeSuspicious > 0);
            item.setLayerResult(DetectionLayer.SYSCALL, syscallSuspicious > 0);

            if (syscallSuspicious > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("系统文件指向可疑目标: " + suspiciousPath);
            } else if (nativeSuspicious > 0) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("Native层检测到可疑符号链接");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                if (legitimateSymlinks > 0) {
                    item.setDetail("系统文件正常 (含" + legitimateSymlinks + "个合法符号链接)");
                } else {
                    item.setDetail("系统二进制文件正常");
                }
            }

        } catch (Exception e) {
            Log.w(TAG, "checkSystemBinaries failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check if symlink target is a legitimate system target
     */
    private boolean isLegitimateTarget(String target) {
        if (target == null || target.isEmpty()) return false;
        String lowerTarget = target.toLowerCase();

        for (String legitimate : LEGITIMATE_TARGETS) {
            if (lowerTarget.contains(legitimate.toLowerCase())) {
                return true;
            }
        }

        // Also consider targets within system paths as legitimate
        if (lowerTarget.startsWith("/system/") ||
            lowerTarget.startsWith("/vendor/") ||
            lowerTarget.startsWith("/apex/") ||
            lowerTarget.startsWith("/product/")) {
            return true;
        }

        return false;
    }

    /**
     * Check app's own path for manipulation
     */
    private DetectionItem checkAppPath() {
        DetectionItem item = new DetectionItem("应用路径", "检测应用安装路径");

        try {
            String appPath = context.getApplicationInfo().sourceDir;

            // Check if app path is a symlink
            boolean nativeIsLink = nativeDetector.isSymlinkNative(appPath);
            boolean syscallIsLink = nativeDetector.isSymlinkSyscall(appPath);

            // Get real path
            String nativeReal = nativeDetector.realpathNative(appPath);
            String syscallReal = nativeDetector.realpathSyscall(appPath);

            boolean consistent = nativeReal.equals(syscallReal);
            boolean hasSuspicious = containsSuspicious(nativeReal) || containsSuspicious(syscallReal);

            item.setLayerResult(DetectionLayer.JAVA, hasSuspicious);
            item.setLayerResult(DetectionLayer.NATIVE, nativeIsLink && hasSuspicious);
            item.setLayerResult(DetectionLayer.SYSCALL, syscallIsLink && hasSuspicious);

            if (hasSuspicious) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("应用路径异常: " + syscallReal);
            } else if (!consistent) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("路径解析不一致");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("应用路径正常");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkAppPath failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check mount namespace via /proc/self/ns/mnt
     */
    private DetectionItem checkMountNamespace() {
        DetectionItem item = new DetectionItem("挂载命名空间", "检测命名空间隔离");

        try {
            // Read mount namespace ID
            String selfNs = nativeDetector.readlinkSyscall("/proc/self/ns/mnt");
            String initNs = nativeDetector.readlinkSyscall("/proc/1/ns/mnt");

            // Compare with init process namespace
            boolean sameNamespace = selfNs.equals(initNs);

            // Check if we're in a different namespace (could indicate isolation/sandbox)
            boolean nativeCheck = nativeDetector.checkMountNamespaceNative();
            boolean syscallCheck = nativeDetector.checkMountNamespaceSyscall();

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, !nativeCheck);
            item.setLayerResult(DetectionLayer.SYSCALL, !syscallCheck);

            if (!syscallCheck) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到命名空间隔离，可能存在Root隐藏");
            } else if (!sameNamespace && !selfNs.isEmpty() && !initNs.isEmpty()) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("命名空间与init不同");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("命名空间正常");
            }

        } catch (Exception e) {
            Log.w(TAG, "checkMountNamespace failed", e);
            item.setStatus(DetectionStatus.UNKNOWN);
        }

        return item;
    }

    /**
     * Check if path contains suspicious keywords
     */
    private boolean containsSuspicious(String path) {
        if (path == null || path.isEmpty()) return false;
        String lowerPath = path.toLowerCase();
        for (String suspicious : SUSPICIOUS_TARGETS) {
            if (lowerPath.contains(suspicious)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Truncate string for display
     */
    private String truncate(String str, int maxLen) {
        if (str == null) return "";
        if (str.length() <= maxLen) return str;
        return str.substring(0, maxLen) + "...";
    }
}
