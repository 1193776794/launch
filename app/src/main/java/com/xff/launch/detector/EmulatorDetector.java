package com.xff.launch.detector;

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.BatteryManager;
import android.os.Build;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Emulator and virtual machine detection with multi-layer support
 */
public class EmulatorDetector {

    private final Context context;
    private final NativeDetector nativeDetector;

    // Known emulator Build properties
    private static final String[] EMULATOR_PROPERTIES = {
            "goldfish",
            "ranchu",
            "generic",
            "vbox86",
            "nox",
            "genymotion",
            "sdk",
            "google_sdk",
            "Emulator",
            "Android SDK built for x86"
    };

    // Known emulator packages
    private static final String[] EMULATOR_PACKAGES = {
            "com.bignox.app.store.hd",
            "com.microvirt.guide",
            "com.bluestacks.settings"
    };

    public EmulatorDetector(Context context) {
        this.context = context;
        this.nativeDetector = NativeDetector.getInstance();
    }

    /**
     * Detect emulator environment
     */
    public DetectionItem detectEmulator() {
        DetectionItem item = new DetectionItem("模拟器环境", "检测是否运行在模拟器中");

        // Java layer
        boolean javaResult = checkEmulatorJava();
        item.setLayerResult(DetectionLayer.JAVA, javaResult);

        // Native layer
        boolean nativeResult = nativeDetector.checkEmulatorNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer
        boolean syscallResult = nativeDetector.checkEmulatorSyscall();
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到模拟器环境");

            // 添加详细检测信息
            collectEmulatorDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("真实设备");
        }

        if (item.hasInconsistentResults()) {
            item.setDetail(item.getDetail() + " (检测层不一致)");
        }

        return item;
    }

    /**
     * Detect virtual machine features
     */
    public DetectionItem detectVirtualMachine() {
        DetectionItem item = new DetectionItem("虚拟机特征", "检测虚拟机相关特征");

        // Java layer - Build properties
        boolean javaResult = checkBuildProperties();
        item.setLayerResult(DetectionLayer.JAVA, javaResult);

        // Native layer - QEMU detection
        boolean nativeResult = nativeDetector.checkQemuNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer
        boolean syscallResult = nativeDetector.checkQemuSyscall();
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到虚拟机特征");

            // 添加详细检测信息
            collectVirtualMachineDetails(item);
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
     * Detect multi-instance/dual-space apps
     */
    public DetectionItem detectMultiInstance() {
        DetectionItem item = new DetectionItem("多开检测", "检测应用多开/分身环境");

        boolean detected = checkMultiInstance();
        item.setLayerResult(DetectionLayer.JAVA, detected);

        if (detected) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("检测到多开环境");

            // 添加详细检测信息
            collectMultiInstanceDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        return item;
    }

    /**
     * Detect cloud phone
     */
    public DetectionItem detectCloudPhone() {
        DetectionItem item = new DetectionItem("云手机检测", "检测云手机环境");

        boolean detected = checkCloudPhone();
        item.setLayerResult(DetectionLayer.JAVA, detected);

        if (detected) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("可能是云手机");

            // 添加详细检测信息
            collectCloudPhoneDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        return item;
    }

    /**
     * Get all emulator detection items
     */
    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(detectEmulator());
        items.add(detectVirtualMachine());
        items.add(detectMultiInstance());
        items.add(detectCloudPhone());
        return items;
    }

    // ===================== Java Layer Methods =====================

    private boolean checkEmulatorJava() {
        return checkBuildProperties() ||
                checkEmulatorPackages() ||
                checkSensorCount() ||
                checkBatteryStatus();
    }

    private boolean checkBuildProperties() {
        String fingerprint = Build.FINGERPRINT.toLowerCase();
        String model = Build.MODEL.toLowerCase();
        String manufacturer = Build.MANUFACTURER.toLowerCase();
        String brand = Build.BRAND.toLowerCase();
        String device = Build.DEVICE.toLowerCase();
        String product = Build.PRODUCT.toLowerCase();
        String hardware = Build.HARDWARE.toLowerCase();

        for (String prop : EMULATOR_PROPERTIES) {
            String lowerProp = prop.toLowerCase();
            if (fingerprint.contains(lowerProp) ||
                    model.contains(lowerProp) ||
                    manufacturer.contains(lowerProp) ||
                    brand.contains(lowerProp) ||
                    device.contains(lowerProp) ||
                    product.contains(lowerProp) ||
                    hardware.contains(lowerProp)) {
                return true;
            }
        }
        return false;
    }

    private boolean checkEmulatorPackages() {
        PackageManager pm = context.getPackageManager();
        for (String pkg : EMULATOR_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }
        return false;
    }

    private boolean checkSensorCount() {
        SensorManager sensorManager = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
        if (sensorManager != null) {
            List<Sensor> sensors = sensorManager.getSensorList(Sensor.TYPE_ALL);
            // Real devices typically have 10+ sensors
            return sensors.size() < 5;
        }
        return false;
    }

    private boolean checkBatteryStatus() {
        BatteryManager bm = (BatteryManager) context.getSystemService(Context.BATTERY_SERVICE);
        if (bm != null) {
            int batteryLevel = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY);
            // Always 50% or no battery info might indicate emulator
            return batteryLevel == 50 || batteryLevel == -1;
        }
        return false;
    }

    private boolean checkMultiInstance() {
        // Check if running in a multi-instance environment
        // Look for unusual data paths
        String dataDir = context.getApplicationInfo().dataDir;
        if (dataDir != null) {
            // Check for unusual path patterns indicating multi-instance
            if (dataDir.contains("/parallel_intl/") ||
                    dataDir.contains("/dual/") ||
                    dataDir.contains("/clone/") ||
                    dataDir.contains("/multiuser/")) {
                return true;
            }
        }

        // Check for multi-instance apps
        PackageManager pm = context.getPackageManager();
        String[] multiInstanceApps = {
                "com.parallel.space",
                "com.lbe.parallel.intl",
                "com.excelliance.dualaid",
                "com.ludashi.dualspace"
        };
        for (String pkg : multiInstanceApps) {
            try {
                pm.getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }

        return false;
    }

    private boolean checkCloudPhone() {
        // Check for cloud phone services
        String[] cloudPhonePackages = {
                "com.huawei.cloudphone",
                "com.tencent.gamehelper.cloud",
                "com.alibaba.mnntech.cloudgame"
        };

        PackageManager pm = context.getPackageManager();
        for (String pkg : cloudPhonePackages) {
            try {
                pm.getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }

        // Check for typical cloud phone indicators in Build
        if (Build.BRAND.equalsIgnoreCase("generic") &&
                Build.MODEL.contains("cloud")) {
            return true;
        }

        return false;
    }

    // ===================== Detail Collection Methods =====================

    /**
     * Collect detailed emulator detection information
     */
    private void collectEmulatorDetails(DetectionItem item) {
        // Build 属性检测
        collectBuildPropertiesDetails(item);

        // 传感器检测
        collectSensorDetails(item);

        // 电池检测
        collectBatteryDetails(item);

        // 模拟器特征文件
        collectEmulatorFilesDetails(item);

        // 模拟器应用包
        collectEmulatorPackagesDetails(item);
    }

    /**
     * Collect Build properties details
     */
    private void collectBuildPropertiesDetails(DetectionItem item) {
        String fingerprint = Build.FINGERPRINT.toLowerCase();
        String model = Build.MODEL;
        String manufacturer = Build.MANUFACTURER;
        String brand = Build.BRAND;
        String device = Build.DEVICE;
        String product = Build.PRODUCT;
        String hardware = Build.HARDWARE;

        StringBuilder suspiciousProps = new StringBuilder();
        int suspiciousCount = 0;

        for (String prop : EMULATOR_PROPERTIES) {
            String lowerProp = prop.toLowerCase();
            if (fingerprint.contains(lowerProp)) {
                suspiciousProps.append("• FINGERPRINT 包含 '").append(prop).append("'\n");
                suspiciousCount++;
            }
            if (model.toLowerCase().contains(lowerProp)) {
                suspiciousProps.append("• MODEL 包含 '").append(prop).append("'\n");
                suspiciousCount++;
            }
            if (hardware.toLowerCase().contains(lowerProp)) {
                suspiciousProps.append("• HARDWARE 包含 '").append(prop).append("'\n");
                suspiciousCount++;
            }
        }

        if (suspiciousCount > 0) {
            item.addDetectionDetail("📋 Build 属性", "可疑属性",
                suspiciousProps.toString().trim(), DetectionLayer.JAVA, "⚠️");
        }

        // 添加完整 Build 信息
        String buildInfo = "BRAND: " + brand +
            "\nMANUFACTURER: " + manufacturer +
            "\nMODEL: " + model +
            "\nDEVICE: " + device +
            "\nPRODUCT: " + product +
            "\nHARDWARE: " + hardware;
        item.addDetectionDetail("📱 设备信息", "Build 信息",
            buildInfo, DetectionLayer.JAVA, "📊");
    }

    /**
     * Collect sensor details
     */
    private void collectSensorDetails(DetectionItem item) {
        SensorManager sensorManager = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
        if (sensorManager != null) {
            List<Sensor> sensors = sensorManager.getSensorList(Sensor.TYPE_ALL);
            int sensorCount = sensors.size();

            String detail = "传感器数量: " + sensorCount;
            if (sensorCount < 5) {
                detail += "\n⚠️ 数量异常（真机通常 > 10）";
            }

            // 列出所有传感器
            StringBuilder sensorList = new StringBuilder("\n\n传感器列表:");
            for (Sensor sensor : sensors) {
                sensorList.append("\n• ").append(sensor.getName());
            }
            detail += sensorList.toString();

            item.addDetectionDetail("📡 传感器检测", "传感器信息",
                detail, DetectionLayer.JAVA, "🎯");
        }
    }

    /**
     * Collect battery details
     */
    private void collectBatteryDetails(DetectionItem item) {
        BatteryManager bm = (BatteryManager) context.getSystemService(Context.BATTERY_SERVICE);
        if (bm != null) {
            int batteryLevel = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY);
            int temperature = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW);

            String detail = "电量: " + batteryLevel + "%";
            if (batteryLevel == 50 || batteryLevel == -1) {
                detail += "\n⚠️ 固定值（模拟器特征）";
            }

            detail += "\n温度: " + (temperature / 10.0) + "°C";

            item.addDetectionDetail("🔋 电池检测", "电池状态",
                detail, DetectionLayer.JAVA, "⚡");
        }
    }

    /**
     * Collect emulator files details
     */
    private void collectEmulatorFilesDetails(DetectionItem item) {
        String[] emulatorFiles = {
            // QEMU
            "/dev/qemu_pipe",
            "/dev/qemu_trace",
            "/dev/goldfish_pipe",
            "/sys/devices/virtual/misc/qemu_pipe",
            "/sys/class/misc/qemu_pipe",
            "/sys/qemu_trace",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/system/lib/libc_malloc_debug_qemu.so-arm",
            "/system/bin/qemu-props",
            "/system/framework/libqemu_wl.txt",
            "/data/downloads/qemu_list.txt",
            "/system/etc/init.goldfish.rc",
            "/system/etc/init.ranchu.rc",
            // Android Emulator
            "/system/lib/egl/libEGL_emulation.so",
            // VirtualBox
            "/sys/module/vboxsf",
            "/ueventd.vbox86.rc",
            // Nox (夜神模拟器)
            "/system/bin/nox-vbox-sf",
            "/system/lib/libnox.so",
            "/system/lib/libnb.so",
            // Droid4X (海马玩模拟器)
            "/system/droid4x",
            "/system/bin/droid4x-vbox-sf",
            // TiantianVM (天天模拟器)
            "/system/lib/egl/libEGL_tiantianVM.so",
            "/system/bin/ttVM-vbox-sf",
            // BlueStacks
            "/dev/com.bluestacks.superuser.daemon",
            "/boot/bstmods/vboxsf.ko",
            // AndroVM
            "/system/bin/androVM-vbox-sf",
            // Yiwan (逸玩模拟器)
            "/system/bin/yiwan-prop",
            "/system/bin/yiwan-sf"
        };

        for (String path : emulatorFiles) {
            File file = new File(path);
            if (file.exists()) {
                String detail = "路径: " + path +
                    "\n类型: " + (file.isDirectory() ? "目录" : "文件");
                item.addDetectionDetail("📁 模拟器文件", path,
                    detail, DetectionLayer.NATIVE, "📄");
            }
        }
    }

    /**
     * Collect emulator packages details
     */
    private void collectEmulatorPackagesDetails(DetectionItem item) {
        for (String pkg : EMULATOR_PACKAGES) {
            if (isPackageInstalled(pkg)) {
                try {
                    android.content.pm.PackageInfo pkgInfo =
                        context.getPackageManager().getPackageInfo(pkg, 0);
                    String detail = "包名: " + pkg +
                        "\n版本: " + pkgInfo.versionName;
                    item.addDetectionDetail("📱 模拟器应用", getEmulatorName(pkg),
                        detail, DetectionLayer.JAVA, "📦");
                } catch (Exception ignored) {
                }
            }
        }
    }

    private boolean isPackageInstalled(String packageName) {
        try {
            context.getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private String getEmulatorName(String packageName) {
        if (packageName.contains("nox")) return "夜神模拟器";
        if (packageName.contains("microvirt")) return "逍遥模拟器";
        if (packageName.contains("bluestacks")) return "BlueStacks";
        return packageName;
    }

    /**
     * Collect virtual machine details
     */
    private void collectVirtualMachineDetails(DetectionItem item) {
        // QEMU 文件检测
        String[] qemuFiles = {
            "/dev/qemu_pipe",
            "/dev/qemu_trace",
            "/sys/qemu_trace"
        };

        for (String path : qemuFiles) {
            File file = new File(path);
            if (file.exists()) {
                item.addDetectionDetail("📁 QEMU 特征", path,
                    "检测到 QEMU 文件", DetectionLayer.NATIVE, "🖥️");
            }
        }

        // VirtualBox 检测
        if (Build.HARDWARE.toLowerCase().contains("vbox")) {
            item.addDetectionDetail("🖥️ VirtualBox", "硬件标识",
                "HARDWARE: " + Build.HARDWARE, DetectionLayer.JAVA, "📦");
        }

        // CPU 架构检测
        String abi = Build.CPU_ABI;
        String abi2 = Build.CPU_ABI2;
        if (abi.contains("x86") || abi2.contains("x86")) {
            item.addDetectionDetail("💻 CPU 架构", "x86 架构",
                "ABI: " + abi + "\nABI2: " + abi2 +
                "\n⚠️ 真机通常为 ARM", DetectionLayer.JAVA, "⚙️");
        }
    }

    /**
     * Collect multi-instance details
     */
    private void collectMultiInstanceDetails(DetectionItem item) {
        // 数据目录检测
        String dataDir = context.getApplicationInfo().dataDir;
        if (dataDir != null) {
            item.addDetectionDetail("📁 数据目录", "应用路径",
                dataDir, DetectionLayer.JAVA, "📂");

            if (dataDir.contains("/parallel_intl/") ||
                dataDir.contains("/dual/") ||
                dataDir.contains("/clone/")) {
                item.addDetectionDetail("⚠️ 异常路径", "多开特征",
                    "路径包含多开标识", DetectionLayer.JAVA, "🚨");
            }
        }

        // 检测多开应用
        String[] multiInstanceApps = {
            "com.parallel.space",
            "com.lbe.parallel.intl",
            "com.excelliance.dualaid",
            "com.ludashi.dualspace"
        };

        PackageManager pm = context.getPackageManager();
        for (String pkg : multiInstanceApps) {
            try {
                android.content.pm.PackageInfo pkgInfo = pm.getPackageInfo(pkg, 0);
                String detail = "包名: " + pkg +
                    "\n版本: " + pkgInfo.versionName;
                item.addDetectionDetail("📱 多开应用", getMultiAppName(pkg),
                    detail, DetectionLayer.JAVA, "📦");
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }

        // UID 检测
        int uid = android.os.Process.myUid();
        item.addDetectionDetail("🔢 UID", "进程 UID",
            "UID: " + uid, DetectionLayer.JAVA, "🆔");
    }

    private String getMultiAppName(String packageName) {
        if (packageName.contains("parallel.space")) return "平行空间";
        if (packageName.contains("lbe.parallel")) return "平行空间国际版";
        if (packageName.contains("dualaid")) return "双开助手";
        if (packageName.contains("ludashi")) return "鲁大师双开";
        return packageName;
    }

    /**
     * Collect cloud phone details
     */
    private void collectCloudPhoneDetails(DetectionItem item) {
        // 检测云手机应用
        String[] cloudPhonePackages = {
            "com.huawei.cloudphone",
            "com.tencent.gamehelper.cloud",
            "com.alibaba.mnntech.cloudgame"
        };

        PackageManager pm = context.getPackageManager();
        for (String pkg : cloudPhonePackages) {
            try {
                android.content.pm.PackageInfo pkgInfo = pm.getPackageInfo(pkg, 0);
                String detail = "包名: " + pkg +
                    "\n版本: " + pkgInfo.versionName;
                item.addDetectionDetail("📱 云手机应用", getCloudPhoneName(pkg),
                    detail, DetectionLayer.JAVA, "☁️");
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }

        // Build 信息
        if (Build.BRAND.equalsIgnoreCase("generic") &&
            Build.MODEL.contains("cloud")) {
            item.addDetectionDetail("📋 Build 特征", "云手机标识",
                "BRAND: " + Build.BRAND + "\nMODEL: " + Build.MODEL,
                DetectionLayer.JAVA, "☁️");
        }
    }

    private String getCloudPhoneName(String packageName) {
        if (packageName.contains("huawei")) return "华为云手机";
        if (packageName.contains("tencent")) return "腾讯云游戏";
        if (packageName.contains("alibaba")) return "阿里云手机";
        return packageName;
    }
}
