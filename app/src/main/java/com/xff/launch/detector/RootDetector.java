package com.xff.launch.detector;

import android.content.Context;
import android.content.pm.PackageManager;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Root detection implementation with multi-layer support
 */
public class RootDetector {

    private final Context context;
    private final NativeDetector nativeDetector;

    // SU binary paths
    private static final String[] SU_PATHS = {
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/vendor/bin/su",
            "/su/bin/su"
    };

    // Root manager package names
    private static final String[] ROOT_PACKAGES = {
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu",
            "me.bmax.apatch",
            "org.sukisu.manager",
            "com.noshufou.android.su",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "me.phh.superuser"
    };

    public RootDetector(Context context) {
        this.context = context;
        this.nativeDetector = NativeDetector.getInstance();
    }

    /**
     * Detect SU files with multi-layer approach
     */
    public DetectionItem detectSuFiles() {
        DetectionItem item = new DetectionItem("SU 文件检测", "检测 SU 二进制文件");

        List<String> detectedPaths = new ArrayList<>();

        // Java layer
        boolean javaResult = checkSuFilesJavaDetailed(detectedPaths);
        item.setLayerResult(DetectionLayer.JAVA, javaResult);

        // Native layer
        boolean nativeResult = nativeDetector.checkSuFilesNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer
        boolean syscallResult = nativeDetector.checkSuFilesSyscall();
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        // Determine status based on most trustworthy result
        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 SU 文件");

            // 添加详细检测信息
            collectSuFilesDetails(item, detectedPaths);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        // Check for hook indication
        if (item.hasInconsistentResults()) {
            item.setDetail(item.getDetail() + " (检测层不一致)");
            item.addDetectionDetail("⚠️ 异常情况", "检测层不一致",
                "可能存在 Hook 绕过", DetectionLayer.JAVA, "🚨");
        }

        return item;
    }

    /**
     * Detect Magisk with multi-layer approach
     */
    public DetectionItem detectMagisk() {
        DetectionItem item = new DetectionItem("Magisk 检测", "检测 Magisk Root 方案");

        // Java layer
        boolean javaResult = checkMagiskJava();
        item.setLayerResult(DetectionLayer.JAVA, javaResult);

        // Native layer
        boolean nativeResult = nativeDetector.checkMagiskNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer
        boolean syscallResult = nativeDetector.checkMagiskSyscall();
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 Magisk");

            // 添加详细检测信息
            collectMagiskDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        if (item.hasInconsistentResults()) {
            item.setDetail(item.getDetail() + " (检测层不一致)");
        }

        return item;
    }

    /**
     * Detect KernelSU with multi-layer approach
     */
    public DetectionItem detectKernelSU() {
        DetectionItem item = new DetectionItem("KernelSU 检测", "检测 KernelSU Root 方案");

        // Java layer
        boolean javaResult = checkKernelSUJava();
        item.setLayerResult(DetectionLayer.JAVA, javaResult);

        // Native layer
        boolean nativeResult = nativeDetector.checkKernelSUNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer
        boolean syscallResult = nativeDetector.checkKernelSUSyscall();
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 KernelSU");

            // 添加详细检测信息
            collectKernelSUDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        if (item.hasInconsistentResults()) {
            item.setDetail(item.getDetail() + " (检测层不一致)");
        }

        return item;
    }

    /**
     * Detect APatch with multi-layer approach
     */
    public DetectionItem detectAPatch() {
        DetectionItem item = new DetectionItem("APatch 检测", "检测 APatch Root 方案");

        // Java layer
        boolean javaResult = checkAPatchJava();
        item.setLayerResult(DetectionLayer.JAVA, javaResult);

        // Native layer
        boolean nativeResult = nativeDetector.checkAPatchNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer
        boolean syscallResult = nativeDetector.checkAPatchSyscall();
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 APatch");

            // 添加详细检测信息
            collectAPatchDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        if (item.hasInconsistentResults()) {
            item.setDetail(item.getDetail() + " (检测层不一致)");
        }

        return item;
    }

    /**
     * Detect SukiSU/SukiSU Ultra with multi-layer approach
     */
    public DetectionItem detectSukiSU() {
        DetectionItem item = new DetectionItem("SukiSU 检测", "检测 SukiSU / SUSFS");

        // Java layer
        boolean javaResult = checkSukiSUJava();
        item.setLayerResult(DetectionLayer.JAVA, javaResult);

        // Native layer
        boolean nativeResult = nativeDetector.checkSukiSUNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer
        boolean syscallResult = nativeDetector.checkSukiSUSyscall();
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 SukiSU/SUSFS");

            // 添加详细检测信息
            collectSukiSUDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        if (item.hasInconsistentResults()) {
            item.setDetail(item.getDetail() + " (检测层不一致)");
        }

        return item;
    }

    /**
     * Detect Root managers
     */
    public DetectionItem detectRootManagers() {
        DetectionItem item = new DetectionItem("Root 管理器", "检测已安装的 Root 管理应用");

        String detectedManager = null;
        for (String pkg : ROOT_PACKAGES) {
            if (isPackageInstalled(pkg)) {
                detectedManager = pkg;
                break;
            }
        }

        if (detectedManager != null) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 " + getAppName(detectedManager));
            item.setLayerResult(DetectionLayer.JAVA, true);

            // 添加详细检测信息
            collectRootManagerDetails(item, detectedManager);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
            item.setLayerResult(DetectionLayer.JAVA, false);
        }

        return item;
    }

    /**
     * Detect Root hiding modules
     */
    public DetectionItem detectRootHiding() {
        DetectionItem item = new DetectionItem("Root 隐藏模块", "检测 Shamiko/ZygiskAssistant 等");

        // Native layer
        boolean nativeResult = nativeDetector.checkRootHidingNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer
        boolean syscallResult = nativeDetector.checkRootHidingSyscall();
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("检测到隐藏模块");

            // 添加详细检测信息
            collectRootHidingDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        if (item.hasInconsistentResults()) {
            item.setDetail(item.getDetail() + " (检测层不一致)");
        }

        return item;
    }

    /**
     * Detect suspicious mounts
     */
    public DetectionItem detectSuspiciousMounts() {
        DetectionItem item = new DetectionItem("可疑挂载检测", "检测异常的文件系统挂载");

        // Native layer
        boolean nativeResult = nativeDetector.checkSuspiciousMountsNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer
        boolean syscallResult = nativeDetector.checkSuspiciousMountsSyscall();
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("检测到可疑挂载");

            // 添加详细检测信息
            collectSuspiciousMountsDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        if (item.hasInconsistentResults()) {
            item.setDetail(item.getDetail() + " (检测层不一致)");
        }

        return item;
    }

    /**
     * Get all root detection items
     */
    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(detectMagisk());
        items.add(detectSuFiles());
        items.add(detectKernelSU());
        items.add(detectAPatch());
        items.add(detectSukiSU());
        items.add(detectRootManagers());
        items.add(detectRootHiding());
        items.add(detectSuspiciousMounts());
        return items;
    }

    // ===================== Java Layer Methods =====================

    private boolean checkSuFilesJava() {
        for (String path : SU_PATHS) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkSuFilesJavaDetailed(List<String> detectedPaths) {
        boolean detected = false;
        for (String path : SU_PATHS) {
            try {
                File suFile = new File(path);
                if (suFile.exists()) {
                    detected = true;
                    detectedPaths.add(path);
                }
            } catch (Exception ignored) {
            }
        }
        return detected;
    }

    private boolean checkMagiskJava() {
        return isPackageInstalled("com.topjohnwu.magisk") ||
                new File("/sbin/.magisk").exists() ||
                new File("/data/adb/magisk").exists();
    }

    private boolean checkKernelSUJava() {
        return isPackageInstalled("me.weishu.kernelsu") ||
                new File("/data/adb/ksu").exists();
    }

    private boolean checkAPatchJava() {
        return isPackageInstalled("me.bmax.apatch") ||
                new File("/data/adb/ap").exists();
    }

    private boolean checkSukiSUJava() {
        return isPackageInstalled("org.sukisu.manager") ||
                new File("/data/adb/sukisu").exists();
    }

    private boolean isPackageInstalled(String packageName) {
        try {
            context.getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private String getAppName(String packageName) {
        switch (packageName) {
            case "com.topjohnwu.magisk":
                return "Magisk Manager";
            case "me.weishu.kernelsu":
                return "KernelSU Manager";
            case "me.bmax.apatch":
                return "APatch Manager";
            case "org.sukisu.manager":
                return "SukiSU Manager";
            case "eu.chainfire.supersu":
                return "SuperSU";
            default:
                return packageName;
        }
    }

    // ===================== Detail Collection Methods =====================

    /**
     * Collect detailed SU files detection information
     */
    private void collectSuFilesDetails(DetectionItem item, List<String> detectedPaths) {
        if (detectedPaths.isEmpty()) return;

        // 添加检测到的文件路径
        for (String path : detectedPaths) {
            try {
                File suFile = new File(path);
                String details = "路径: " + path;

                // 尝试获取文件权限
                if (suFile.canRead()) {
                    details += "\n可读: ✓";
                }
                if (suFile.canExecute()) {
                    details += "\n可执行: ✓";
                }

                // 获取文件大小
                long size = suFile.length();
                details += "\n大小: " + (size / 1024) + " KB";

                item.addDetectionDetail("📁 SU 文件", path,
                    details, DetectionLayer.JAVA, "🔓");
            } catch (Exception ignored) {
            }
        }

        // 添加总数统计
        if (detectedPaths.size() > 1) {
            item.addDetectionDetail("📊 检测统计", "检测到的 SU 文件数量",
                detectedPaths.size() + " 个", DetectionLayer.JAVA, "📈");
        }
    }

    /**
     * Collect detailed Magisk detection information
     */
    private void collectMagiskDetails(DetectionItem item) {
        // 检测 Magisk 相关文件
        String[] magiskPaths = {
            "/sbin/.magisk",
            "/data/adb/magisk",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
            "/data/adb/modules"
        };

        for (String path : magiskPaths) {
            File file = new File(path);
            if (file.exists()) {
                String detail = "路径: " + path + "\n类型: " + (file.isDirectory() ? "目录" : "文件");
                if (file.isDirectory()) {
                    File[] children = file.listFiles();
                    if (children != null) {
                        detail += "\n包含: " + children.length + " 项";
                    }
                }
                item.addDetectionDetail("📁 Magisk 特征", path,
                    detail, DetectionLayer.NATIVE, "🧲");
            }
        }

        // 检测 Magisk Manager 包
        if (isPackageInstalled("com.topjohnwu.magisk")) {
            try {
                android.content.pm.PackageInfo pkgInfo =
                    context.getPackageManager().getPackageInfo("com.topjohnwu.magisk", 0);
                String detail = "包名: com.topjohnwu.magisk\n版本: " + pkgInfo.versionName +
                    " (" + pkgInfo.versionCode + ")";
                item.addDetectionDetail("📱 Magisk Manager", "已安装",
                    detail, DetectionLayer.JAVA, "📦");
            } catch (Exception ignored) {
            }
        }

        // 检测 Zygisk
        File zygiskMarker = new File("/data/adb/modules/.zygisk");
        if (zygiskMarker.exists()) {
            item.addDetectionDetail("🔄 Zygisk", "Magisk Zygisk 模式",
                "检测到 Zygisk 标记文件", DetectionLayer.NATIVE, "⚙️");
        }

        // 检测挂载点
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line;
            int magiskMounts = 0;
            while ((line = reader.readLine()) != null) {
                if (line.contains("magisk") || line.contains("/sbin/.magisk")) {
                    magiskMounts++;
                }
            }
            reader.close();
            if (magiskMounts > 0) {
                item.addDetectionDetail("💾 挂载点", "Magisk 挂载",
                    "检测到 " + magiskMounts + " 个 Magisk 挂载点",
                    DetectionLayer.SYSCALL, "🔍");
            }
        } catch (Exception ignored) {
        }
    }

    /**
     * Collect detailed KernelSU detection information
     */
    private void collectKernelSUDetails(DetectionItem item) {
        // 检测 KernelSU 文件
        String[] ksuPaths = {
            "/data/adb/ksu",
            "/data/adb/ksud",
            "/data/adb/ksu/bin/busybox",
            "/data/adb/ksu/bin/resetprop"
        };

        for (String path : ksuPaths) {
            File file = new File(path);
            if (file.exists()) {
                item.addDetectionDetail("📁 KernelSU 特征", path,
                    "类型: " + (file.isDirectory() ? "目录" : "文件"),
                    DetectionLayer.NATIVE, "🔧");
            }
        }

        // 检测 KernelSU Manager
        if (isPackageInstalled("me.weishu.kernelsu")) {
            try {
                android.content.pm.PackageInfo pkgInfo =
                    context.getPackageManager().getPackageInfo("me.weishu.kernelsu", 0);
                item.addDetectionDetail("📱 KernelSU Manager", "已安装",
                    "版本: " + pkgInfo.versionName, DetectionLayer.JAVA, "📦");
            } catch (Exception ignored) {
            }
        }

        // 检测内核模块
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/modules"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.toLowerCase().contains("kernelsu") || line.toLowerCase().contains("ksu")) {
                    item.addDetectionDetail("⚙️ 内核模块", "KernelSU 模块",
                        line, DetectionLayer.SYSCALL, "🔩");
                }
            }
            reader.close();
        } catch (Exception ignored) {
        }
    }

    /**
     * Collect detailed APatch detection information
     */
    private void collectAPatchDetails(DetectionItem item) {
        // 检测 APatch 文件
        String[] apatchPaths = {
            "/data/adb/ap",
            "/data/adb/apd",
            "/data/adb/ap/bin"
        };

        for (String path : apatchPaths) {
            File file = new File(path);
            if (file.exists()) {
                item.addDetectionDetail("📁 APatch 特征", path,
                    "类型: " + (file.isDirectory() ? "目录" : "文件"),
                    DetectionLayer.NATIVE, "🩹");
            }
        }

        // 检测 APatch Manager
        if (isPackageInstalled("me.bmax.apatch")) {
            try {
                android.content.pm.PackageInfo pkgInfo =
                    context.getPackageManager().getPackageInfo("me.bmax.apatch", 0);
                item.addDetectionDetail("📱 APatch Manager", "已安装",
                    "版本: " + pkgInfo.versionName, DetectionLayer.JAVA, "📦");
            } catch (Exception ignored) {
            }
        }

        // 检测 SuperKey 机制
        File superKeyMarker = new File("/data/adb/ap/.superkey");
        if (superKeyMarker.exists()) {
            item.addDetectionDetail("🔑 SuperKey", "APatch SuperKey",
                "检测到 SuperKey 标记", DetectionLayer.NATIVE, "🗝️");
        }
    }

    /**
     * Collect detailed SukiSU detection information
     */
    private void collectSukiSUDetails(DetectionItem item) {
        // 检测 SukiSU 文件
        String[] sukisuPaths = {
            "/data/adb/sukisu",
            "/data/adb/ksu"  // SukiSU 继承自 KernelSU
        };

        for (String path : sukisuPaths) {
            File file = new File(path);
            if (file.exists()) {
                item.addDetectionDetail("📁 SukiSU 特征", path,
                    "类型: " + (file.isDirectory() ? "目录" : "文件"),
                    DetectionLayer.NATIVE, "🌸");
            }
        }

        // 检测 SUSFS 特征
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/filesystems"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("susfs")) {
                    item.addDetectionDetail("⚠️ SUSFS 检测", "SUSFS 文件系统",
                        "检测到 SUSFS: " + line.trim(),
                        DetectionLayer.SYSCALL, "🛡️");
                }
            }
            reader.close();
        } catch (Exception ignored) {
        }

        // 检测 SukiSU Manager
        if (isPackageInstalled("org.sukisu.manager")) {
            try {
                android.content.pm.PackageInfo pkgInfo =
                    context.getPackageManager().getPackageInfo("org.sukisu.manager", 0);
                item.addDetectionDetail("📱 SukiSU Manager", "已安装",
                    "版本: " + pkgInfo.versionName, DetectionLayer.JAVA, "📦");
            } catch (Exception ignored) {
            }
        }

        // 检测隐藏挂载点
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line;
            int suspiciousMounts = 0;
            while ((line = reader.readLine()) != null) {
                if (line.contains("sus_") || line.contains("susfs")) {
                    suspiciousMounts++;
                }
            }
            reader.close();
            if (suspiciousMounts > 0) {
                item.addDetectionDetail("💾 隐藏挂载", "SUSFS 挂载点",
                    "检测到 " + suspiciousMounts + " 个可疑挂载点",
                    DetectionLayer.SYSCALL, "🔍");
            }
        } catch (Exception ignored) {
        }
    }

    /**
     * Collect detailed Root manager detection information
     */
    private void collectRootManagerDetails(DetectionItem item, String detectedPackage) {
        try {
            android.content.pm.PackageInfo pkgInfo =
                context.getPackageManager().getPackageInfo(detectedPackage, 0);

            String detail = "包名: " + detectedPackage +
                "\n版本: " + pkgInfo.versionName + " (" + pkgInfo.versionCode + ")" +
                "\n应用名: " + getAppName(detectedPackage);

            // 获取安装时间
            long installTime = pkgInfo.firstInstallTime;
            detail += "\n安装时间: " + new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                .format(new java.util.Date(installTime));

            // 获取数据目录
            String dataDir = context.getPackageManager()
                .getApplicationInfo(detectedPackage, 0).dataDir;
            detail += "\n数据目录: " + dataDir;

            item.addDetectionDetail("📱 Root 管理器", getAppName(detectedPackage),
                detail, DetectionLayer.JAVA, "⚙️");

        } catch (Exception ignored) {
        }
    }

    /**
     * Collect detailed Root hiding modules information
     */
    private void collectRootHidingDetails(DetectionItem item) {
        // 检测隐藏模块目录
        String[] hidingModules = {
            "shamiko",
            "zygisk-assistant",
            "zygiskNext",
            "HideMyApplist",
            "playintegrityfix",
            "trickystore"
        };

        File modulesDir = new File("/data/adb/modules");
        if (modulesDir.exists() && modulesDir.isDirectory()) {
            File[] modules = modulesDir.listFiles();
            if (modules != null) {
                for (File module : modules) {
                    String moduleName = module.getName().toLowerCase();
                    for (String hidingName : hidingModules) {
                        if (moduleName.contains(hidingName.toLowerCase())) {
                            // 读取模块信息
                            File propFile = new File(module, "module.prop");
                            String moduleInfo = "模块目录: " + module.getAbsolutePath();
                            if (propFile.exists()) {
                                try {
                                    BufferedReader reader = new BufferedReader(new FileReader(propFile));
                                    String line;
                                    StringBuilder propContent = new StringBuilder();
                                    while ((line = reader.readLine()) != null) {
                                        if (line.startsWith("name=") ||
                                            line.startsWith("version=") ||
                                            line.startsWith("author=")) {
                                            propContent.append("\n").append(line);
                                        }
                                    }
                                    reader.close();
                                    moduleInfo += propContent.toString();
                                } catch (Exception ignored) {
                                }
                            }
                            item.addDetectionDetail("🎭 隐藏模块", module.getName(),
                                moduleInfo, DetectionLayer.NATIVE, "🔒");
                        }
                    }
                }
            }
        }

        // 检测 Shamiko 白名单
        File shamikoConfig = new File("/data/adb/shamiko");
        if (shamikoConfig.exists()) {
            item.addDetectionDetail("🎭 Shamiko 配置", "Shamiko 白名单",
                "检测到 Shamiko 配置目录", DetectionLayer.NATIVE, "📋");
        }
    }

    /**
     * Collect detailed suspicious mounts information
     */
    private void collectSuspiciousMountsDetails(DetectionItem item) {
        try {
            // 读取 /proc/self/mountinfo
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line;
            int suspiciousCount = 0;

            // 可疑挂载模式
            String[] suspiciousPatterns = {
                "magisk",
                "zygisk",
                "zygisksu",
                "overlay",
                "tmpfs",
                "debug_ramdisk",
                "module.prop",
                "/data/adb/modules",
                "cacerts"
            };

            while ((line = reader.readLine()) != null) {
                boolean isSuspicious = false;
                String matchedPattern = "";

                // 检查是否匹配可疑模式
                for (String pattern : suspiciousPatterns) {
                    if (line.toLowerCase().contains(pattern.toLowerCase())) {
                        isSuspicious = true;
                        matchedPattern = pattern;
                        break;
                    }
                }

                // 检测异常的 cacerts 重复挂载
                if (line.contains("/system/etc/security/cacerts")) {
                    // 统计同一行中 cacerts 出现的次数
                    int count = 0;
                    int index = 0;
                    while ((index = line.indexOf("cacerts", index)) != -1) {
                        count++;
                        index += "cacerts".length();
                    }
                    if (count > 2) {
                        isSuspicious = true;
                        matchedPattern = "cacerts (重复挂载 x" + count + ")";
                    }
                }

                if (isSuspicious) {
                    suspiciousCount++;

                    // 只显示前 10 个挂载点的详情
                    if (suspiciousCount <= 10) {
                        // 解析挂载信息
                        String[] parts = line.split(" ");
                        String mountPoint = parts.length > 4 ? parts[4] : "未知";
                        String fsType = parts.length > 8 ? parts[8] : "未知";
                        String mountSource = parts.length > 9 ? parts[9] : "未知";

                        String detail = "挂载点: " + mountPoint +
                            "\n类型: " + fsType +
                            "\n来源: " + mountSource +
                            "\n匹配: " + matchedPattern;

                        item.addDetectionDetail("📁 可疑挂载", matchedPattern,
                            detail, DetectionLayer.SYSCALL, "⚠️");
                    }
                }
            }
            reader.close();

            // 添加总数统计
            if (suspiciousCount > 10) {
                item.addDetectionDetail("📊 挂载统计", "总数",
                    "检测到 " + suspiciousCount + " 个可疑挂载（仅显示前10个）",
                    DetectionLayer.SYSCALL, "📈");
            } else if (suspiciousCount > 0) {
                item.addDetectionDetail("📊 挂载统计", "总数",
                    "检测到 " + suspiciousCount + " 个可疑挂载",
                    DetectionLayer.SYSCALL, "📈");
            }

            // 检测 ZygiskSU 特征
            boolean hasZygiskSU = false;
            BufferedReader reader2 = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            while ((line = reader2.readLine()) != null) {
                if (line.contains("zygisksu") || line.contains("zygisk_su")) {
                    hasZygiskSU = true;
                    item.addDetectionDetail("🔍 ZygiskSU", "ZygiskSU 挂载",
                        "检测到 ZygiskSU 文件系统挂载",
                        DetectionLayer.SYSCALL, "🚨");
                    break;
                }
            }
            reader2.close();

            // 检测证书挂载异常
            BufferedReader reader3 = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            int cacertsMounts = 0;
            while ((line = reader3.readLine()) != null) {
                if (line.contains("/system/etc/security/cacerts")) {
                    cacertsMounts++;
                }
            }
            reader3.close();

            if (cacertsMounts > 1) {
                item.addDetectionDetail("🔒 证书挂载", "异常挂载",
                    "检测到 " + cacertsMounts + " 个 cacerts 挂载（正常应为1个）",
                    DetectionLayer.SYSCALL, "⚠️");
            }

        } catch (Exception e) {
            android.util.Log.e("RootDetector", "Error reading mountinfo", e);
        }
    }
}
