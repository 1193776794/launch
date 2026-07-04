package com.xff.launch.detector;

import android.content.Context;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Tamper/Device-modification tool detection
 * Based on Alibaba sgmain SecGuard heap dump analysis (273 detection strings)
 * Covers: CloudECalc, CPH, DexGuard, ByteOS, hosts tampering, ELF integrity
 */
public class TamperDetector {

    private final Context context;
    private final NativeDetector nativeDetector;

    // CloudECalc (cloud device control)
    private static final String[] CLOUDECALC_PATHS = {
            "/sdcard/Android/data/com.cloudecalc.control",
            "/data/local/tmp/com.cloudecalc.control.version"
    };
    private static final String CLOUDECALC_KEYWORD = "cloudecalc";

    // CPH (Cloud Phone Native)
    private static final String[] CPH_PATHS = {
            "/cphnative"
    };
    private static final String[] CPH_PROPERTIES = {
            "ro.com.cph.cloud_app_engine",
            "cphnative.server.status",
            "ro.com.cph.non_root"
    };

    // DexGuard
    private static final String[] DEXGUARD_PATHS = {
            "/system/framework/com.android.dexguard.jar",
            "/system/lib64/lib_nb_dexguard.so",
            "/system/lib/lib_nb_dexguard.so",
            "/data/local/tmp/dgkernel/log.txt"
    };

    // ByteOS
    private static final String[] BYTEOS_PATHS = {
            "/system/vendor/byteos",
            "/data/system/byteos"
    };

    // System integrity paths
    private static final String[] SYSTEM_INTEGRITY_PATHS = {
            "/system/bin/app_process.orig",
            "/system/bin/app_process_zposed"
    };

    // SELinux deep paths
    private static final String[] SELINUX_PATHS = {
            "/sys/fs/selinux/load",
            "/sys/fs/selinux/policy",
            "/sys/fs/selinux/enforce"
    };

    // 注：这些是 VBMeta 完整性属性，非 SELinux 属性（原命名 SELINUX_PROPERTIES 有误，已更名）
    private static final String[] VBMETA_PROPERTIES = {
            "ro.boot.vbmeta.digest"
    };

    public TamperDetector(Context context) {
        this.context = context;
        this.nativeDetector = NativeDetector.getInstance();
    }

    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(detectTamperTools());
        items.add(detectHostsTampering());
        // detectRwxpMemory 已去重:RWX/匿名可执行内存由 SideChannel.checkAnonymousRwxMemory(超集)覆盖。
        items.add(detectMountsChange());
        items.add(detectSystemIntegrity());
        return items;
    }

    /**
     * Detect device tampering tools: CloudECalc, CPH, DexGuard, ByteOS
     */
    public DetectionItem detectTamperTools() {
        DetectionItem item = new DetectionItem("改机/云控工具", "检测 CloudECalc/CPH/DexGuard/ByteOS");

        boolean detected = false;

        // CloudECalc
        for (String path : CLOUDECALC_PATHS) {
            if (new File(path).exists()) {
                detected = true;
                item.addDetectionDetail("☁️ CloudECalc", path, "文件存在", DetectionLayer.JAVA, "📂");
            }
        }

        // CPH
        for (String path : CPH_PATHS) {
            if (new File(path).exists()) {
                detected = true;
                item.addDetectionDetail("📱 CPH", path, "文件存在", DetectionLayer.JAVA, "📂");
            }
        }
        for (String prop : CPH_PROPERTIES) {
            try {
                String val = nativeDetector.getSystemProperty(prop);
                if (val != null && !val.isEmpty()) {
                    detected = true;
                    item.addDetectionDetail("⚙️ CPH 属性", prop, "值: " + val, DetectionLayer.JAVA, "🔧");
                }
            } catch (Exception ignored) {}
        }

        // DexGuard
        for (String path : DEXGUARD_PATHS) {
            if (new File(path).exists()) {
                detected = true;
                item.addDetectionDetail("🛡️ DexGuard", path, "文件存在", DetectionLayer.JAVA, "📂");
            }
        }

        // ByteOS
        for (String path : BYTEOS_PATHS) {
            if (new File(path).exists()) {
                detected = true;
                item.addDetectionDetail("🔧 ByteOS", path, "文件存在", DetectionLayer.JAVA, "📂");
            }
        }

        item.setLayerResult(DetectionLayer.JAVA, detected);

        // Native layer check
        boolean nativeDetected = false;
        String[][] allPaths = {CLOUDECALC_PATHS, CPH_PATHS, DEXGUARD_PATHS, BYTEOS_PATHS};
        for (String[] paths : allPaths) {
            for (String path : paths) {
                if (nativeDetector.fileExistsNative(path)) {
                    nativeDetected = true;
                }
            }
        }
        item.setLayerResult(DetectionLayer.NATIVE, nativeDetected);

        // Syscall layer
        boolean syscallDetected = false;
        for (String[] paths : allPaths) {
            for (String path : paths) {
                if (nativeDetector.fileExistsSyscall(path)) {
                    syscallDetected = true;
                }
            }
        }
        item.setLayerResult(DetectionLayer.SYSCALL, syscallDetected);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到改机/云控工具");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        return item;
    }

    /**
     * Detect /etc/hosts tampering (sgmain stage 9)
     * Check for non-standard entries in hosts file
     */
    public DetectionItem detectHostsTampering() {
        DetectionItem item = new DetectionItem("/etc/hosts 篡改", "检测 hosts 文件是否被修改");

        boolean detected = false;
        int customEntries = 0;

        try {
            BufferedReader reader = new BufferedReader(new FileReader("/etc/hosts"));
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                // Standard entries: localhost
                if (line.contains("localhost") || line.contains("ip6-localhost")) continue;

                // Non-standard entry found
                customEntries++;
                detected = true;
                if (customEntries <= 5) {
                    item.addDetectionDetail("📝 自定义条目", line, "非标准 hosts 条目", DetectionLayer.JAVA, "⚠️");
                }
            }
            reader.close();
        } catch (Exception e) {
            // Can't read hosts - might be restricted
            item.addDetectionDetail("⚠️ 访问受限", "/etc/hosts", "无法读取", DetectionLayer.JAVA, "🔒");
        }

        if (customEntries > 5) {
            item.addDetectionDetail("📊 统计", "自定义条目数", customEntries + " 条", DetectionLayer.JAVA, "📈");
        }

        item.setLayerResult(DetectionLayer.JAVA, detected);
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        item.setLayerResult(DetectionLayer.SYSCALL, detected);

        if (detected) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("hosts 文件包含 " + customEntries + " 条自定义条目");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("hosts 文件正常");
        }

        return item;
    }

    /**
     * Detect rwxp (read-write-execute) memory regions (sgmain mprotect detection)
     * rwxp memory regions indicate code injection or runtime code generation
     */
    public DetectionItem detectRwxpMemory() {
        DetectionItem item = new DetectionItem("RWX 内存检测", "检测可读写可执行内存区域 (代码注入标志)");

        boolean detected = false;
        int rwxCount = 0;

        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = reader.readLine()) != null) {
                // Look for rwxp permissions
                if (line.contains("rwxp")) {
                    rwxCount++;
                    if (rwxCount <= 3) {
                        String[] parts = line.split("\\s+");
                        String addr = parts.length > 0 ? parts[0] : "";
                        String path = parts.length > 5 ? parts[parts.length - 1] : "[anonymous]";
                        item.addDetectionDetail("💾 RWX 区域", addr, "路径: " + path, DetectionLayer.NATIVE, "⚠️");
                    }
                }
            }
            reader.close();
        } catch (Exception ignored) {}

        // Some rwxp is normal (JIT compiler), but many is suspicious
        if (rwxCount > 10) {
            detected = true;
        }

        if (rwxCount > 3) {
            item.addDetectionDetail("📊 统计", "RWX 区域数", rwxCount + " 个", DetectionLayer.NATIVE, "📈");
        }

        item.setLayerResult(DetectionLayer.JAVA, false);
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        item.setLayerResult(DetectionLayer.SYSCALL, detected);

        if (detected) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("发现 " + rwxCount + " 个 RWX 内存区域 (可能存在代码注入)");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("RWX 内存区域数量正常 (" + rwxCount + " 个)");
        }

        return item;
    }

    /**
     * Detect mount changes between two scans (sgmain triple-scan technique)
     * sgmain scans /proc/mounts at stages 6, 19 to detect runtime changes
     */
    public DetectionItem detectMountsChange() {
        DetectionItem item = new DetectionItem("挂载点变化", "双时间点扫描 /proc/mounts 检测运行时变化");

        boolean detected = false;

        try {
            // First scan
            List<String> mounts1 = readMounts();

            // Brief delay
            Thread.sleep(100);

            // Second scan
            List<String> mounts2 = readMounts();

            // Compare
            int addedCount = 0;
            int removedCount = 0;

            for (String m : mounts2) {
                if (!mounts1.contains(m)) {
                    addedCount++;
                    if (addedCount <= 3) {
                        item.addDetectionDetail("➕ 新增挂载", m, "运行时新增", DetectionLayer.NATIVE, "📌");
                    }
                }
            }
            for (String m : mounts1) {
                if (!mounts2.contains(m)) {
                    removedCount++;
                    if (removedCount <= 3) {
                        item.addDetectionDetail("➖ 移除挂载", m, "运行时移除", DetectionLayer.NATIVE, "📌");
                    }
                }
            }

            if (addedCount > 0 || removedCount > 0) {
                detected = true;
                item.addDetectionDetail("📊 变化统计",
                    "新增: " + addedCount + " / 移除: " + removedCount,
                    "挂载点在检测期间发生变化", DetectionLayer.NATIVE, "📈");
            }

        } catch (Exception ignored) {}

        item.setLayerResult(DetectionLayer.JAVA, detected);
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        item.setLayerResult(DetectionLayer.SYSCALL, detected);

        if (detected) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("检测到运行时挂载点变化");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("挂载点稳定");
        }

        return item;
    }

    /**
     * Detect system integrity issues
     */
    public DetectionItem detectSystemIntegrity() {
        DetectionItem item = new DetectionItem("系统完整性", "检测系统文件篡改和 SELinux 深度");

        boolean detected = false;

        // Check suspicious system file replacements
        for (String path : SYSTEM_INTEGRITY_PATHS) {
            if (new File(path).exists()) {
                detected = true;
                item.addDetectionDetail("📁 系统文件", path, "备份/替换文件存在", DetectionLayer.JAVA, "⚠️");
            }
        }

        // SELinux deep check
        for (String path : SELINUX_PATHS) {
            File f = new File(path);
            if (f.exists() && f.canRead()) {
                try {
                    BufferedReader reader = new BufferedReader(new FileReader(f));
                    String content = reader.readLine();
                    reader.close();

                    if (path.contains("enforce") && content != null) {
                        if ("0".equals(content.trim())) {
                            detected = true;
                            item.addDetectionDetail("🔓 SELinux", path, "Permissive 模式", DetectionLayer.JAVA, "⚠️");
                        } else {
                            item.addDetectionDetail("🔒 SELinux", path, "Enforcing 模式", DetectionLayer.JAVA, "✅");
                        }
                    }
                } catch (Exception ignored) {}
            }
        }

        // Check vbmeta digest property
        for (String prop : VBMETA_PROPERTIES) {
            try {
                String val = nativeDetector.getSystemProperty(prop);
                if (val != null && !val.isEmpty()) {
                    item.addDetectionDetail("🔐 VBMeta", prop, "值: " + val, DetectionLayer.JAVA, "🔑");
                }
            } catch (Exception ignored) {}
        }

        item.setLayerResult(DetectionLayer.JAVA, detected);
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        item.setLayerResult(DetectionLayer.SYSCALL, detected);

        if (detected) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("检测到系统完整性异常");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("系统完整性正常");
        }

        return item;
    }

    // Helper: read /proc/mounts
    private List<String> readMounts() {
        List<String> mounts = new ArrayList<>();
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/mounts"));
            String line;
            while ((line = reader.readLine()) != null) {
                mounts.add(line.trim());
            }
            reader.close();
        } catch (Exception ignored) {}
        return mounts;
    }

    private boolean isPackageInstalled(String packageName) {
        try {
            context.getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
