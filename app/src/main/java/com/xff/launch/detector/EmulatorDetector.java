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

    // Known emulator packages (expanded from sgmain heap dump)
    private static final String[] EMULATOR_PACKAGES = {
            "com.bignox.app.store.hd",
            "com.microvirt.guide",
            "com.bluestacks.settings",
            "com.microvirt.market",
            "com.microvirt.launcher",
            "com.microvirt.installe",
            "com.bluestacks.appmart",
            "com.bluestacks.home",
            "com.bignox.google.installer"
    };

    // Redroid (Docker cloud phone) properties - 2024 new (from sgmain heap dump)
    private static final String[] REDROID_PROPERTIES = {
            "ro.boot.redroid_height",
            "ro.boot.redroid_width",
            "ro.boot.redroid_wifi",
            "ro.boot.redroid_wifi_gateway",
            "ro.boot.redroid_net_dns1",
            "ro.boot.redroid_net_ndns",
            "ro.kernel.redroid.width",
            "ro.kernel.redroid.height",
            "ro.kernel.redroid.fps",
            "init.svc.redroid_net"
    };

    // VirtualBox deep detection paths (from sgmain heap dump - 20+ paths)
    private static final String[] VBOX_PATHS = {
            "/sys/module/vboxguest",
            "/sys/module/vboxvideo",
            "/sys/module/vboxsf",
            "/sys/class/misc/vboxuser",
            "/sys/class/misc/vboxguest",
            "/sys/class/bdi/vboxsf-c",
            "/sys/devices/virtual/misc/vboxuser",
            "/sys/devices/virtual/misc/vboxguest",
            "/sys/devices/virtual/bdi/vboxsf-c",
            "/sys/bus/pci/drivers/vboxguest",
            "/dev/vboxuser",
            "/dev/vboxguest",
            "/init.vbox86.rc",
            "/system/lib/hw/gralloc.vbox86.so",
            "/system/lib/hw/sensors.vbox86.so",
            "/system/lib/hw/audio.primary.vbox86.so",
            "/system/lib/hw/gps.vbox86.so",
            "/system/lib/vboxguest.ko",
            "/system/lib/vboxvideo.ko",
            "/system/lib/vboxsf.ko",
            "/system/bin/mount.vboxsf",
            "/system/xbin/mount.vboxsf",
            "/system/bin/androVM-vbox-sf"
    };

    // Nox deep detection paths (from sgmain heap dump)
    private static final String[] NOX_PATHS = {
            "/system/lib/libnoxd.so",
            "/system/lib/libnoxspeedup.so",
            "/system/bin/nox-prop",
            "/system/bin/noxd",
            "/system/bin/shellnox",
            "/system/bin/noxscreen",
            "/system/bin/noxspeedup",
            "/system/bin/enable_nox",
            "/data/property/persist.nox.simulator_version",
            "/data/misc/profiles/ref/com.bignox.app.store.hd",
            "/data/misc/profiles/ref/com.bignox.google.installer"
    };

    // Rockchip-based device paths (cloud phone/emulator indicator from sgmain)
    private static final String[] ROCKCHIP_PATHS = {
            "/sys/bus/platform/driver/rockchip-system-monitor",
            "/sys/bus/platform/driver/rockchip-nocp",
            "/sys/bus/platform/driver/rockchip-pm",
            "/sys/bus/platform/driver/rockchip-pcie",
            "/sys/bus/platform/driver/rockchip-pinctrl",
            "/sys/bus/platform/driver/dwmmc_rockchip",
            "/sys/bus/nvmem/deivces/rockchip-otp0",
            "/sys/devices/platform/rockchip-system-monitor",
            "/sys/module/nvmem_rockchip_otp",
            "/sys/module/nvmem_rockchip_otp/parameters/rockchip_otp_wr_magic",
            "/sys/module/rockchip_pwm_remotectl",
            "/sys/kernel/debug/pinctrl/pinctrl-rockchip-pinctrl",
            "/proc/irq/69/rockchip_thermal",
            "/proc/irq/19/rockchip_usb2phy",
            "/vendor/etc/init/hw/init.rockchip.rc",
            "/vendor/etc/init/init.rockchip.drmservice.rc",
            "/vendor/bin/rockchip.drmservice"
    };

    // Other emulator-specific paths (Droid4X, MEmu, BlueStacks deep, ttVM)
    private static final String[] OTHER_EMULATOR_PATHS = {
            "/system/bin/droid4x",
            "/system/bin/droid4x-prop",
            "/system/lib/libdroid4x.so",
            "/system/lib/libmicrovirt.so",
            "/system/bin/microvirt-prop",
            "/data/data/com.microvirt.market",
            "/data/data/com.microvirt.launcher",
            "/data/data/com.microvirt.installe",
            "/data/data/com.bluestacks.appmart",
            "/data/data/com.bluestacks.home",
            "/data/bluestacks.prop",
            "/data/.bluestacks.prop",
            "/system/bin/ttVM-vbox-sf"
    };

    // CPU frequency paths for emulator detection
    private static final String CPU_FREQ_PATH = "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq";

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
        items.add(detectRedroid());
        items.add(detectVirtualBoxDeep());
        items.add(detectNoxDeep());
        items.add(detectRockchip());
        items.add(detectCpuFrequency());
        return items;
    }

    /**
     * Detect Redroid (Docker-based Android cloud phone) - 2024 new
     * Based on sgmain SecGuard heap dump
     */
    public DetectionItem detectRedroid() {
        DetectionItem item = new DetectionItem("Redroid 云手机", "检测 Docker 安卓云手机 (Redroid)");

        boolean detected = false;

        // Check Redroid system properties
        for (String prop : REDROID_PROPERTIES) {
            try {
                String val = null;
                if (prop.startsWith("init.svc.")) {
                    val = System.getProperty(prop);
                } else {
                    // Use native property read
                    val = nativeDetector.getSystemProperty(prop);
                }
                if (val != null && !val.isEmpty()) {
                    detected = true;
                    item.addDetectionDetail("🐳 Redroid 属性", prop, "值: " + val, DetectionLayer.JAVA, "☁️");
                }
            } catch (Exception ignored) {}
        }

        item.setLayerResult(DetectionLayer.JAVA, detected);
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        item.setLayerResult(DetectionLayer.SYSCALL, detected);

        if (detected) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 Redroid Docker 云手机环境");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }
        return item;
    }

    /**
     * Detect VirtualBox deep features (23 paths from sgmain)
     */
    public DetectionItem detectVirtualBoxDeep() {
        DetectionItem item = new DetectionItem("VirtualBox 深度", "深度检测 VirtualBox 虚拟机特征");

        boolean javaDetected = false;
        boolean nativeDetected = false;
        int hitCount = 0;

        for (String path : VBOX_PATHS) {
            if (new java.io.File(path).exists()) {
                javaDetected = true;
                hitCount++;
                if (hitCount <= 5) {
                    item.addDetectionDetail("📁 VBox 路径", path, "文件存在", DetectionLayer.JAVA, "📂");
                }
            }
            if (nativeDetector.fileExistsNative(path)) {
                nativeDetected = true;
            }
        }

        if (hitCount > 5) {
            item.addDetectionDetail("📊 统计", "VBox 命中", hitCount + " 个路径命中", DetectionLayer.JAVA, "📈");
        }

        item.setLayerResult(DetectionLayer.JAVA, javaDetected);
        item.setLayerResult(DetectionLayer.NATIVE, nativeDetected);
        item.setLayerResult(DetectionLayer.SYSCALL, nativeDetected);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 VirtualBox 虚拟机 (" + hitCount + " 处特征)");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }
        return item;
    }

    /**
     * Detect Nox emulator deep features (11 paths from sgmain)
     */
    public DetectionItem detectNoxDeep() {
        DetectionItem item = new DetectionItem("夜神深度检测", "深度检测夜神模拟器特征");

        boolean javaDetected = false;
        boolean nativeDetected = false;
        int hitCount = 0;

        for (String path : NOX_PATHS) {
            if (new java.io.File(path).exists()) {
                javaDetected = true;
                hitCount++;
                item.addDetectionDetail("📁 Nox 路径", path, "文件存在", DetectionLayer.JAVA, "📂");
            }
            if (nativeDetector.fileExistsNative(path)) {
                nativeDetected = true;
            }
        }

        // Also check other emulator paths
        for (String path : OTHER_EMULATOR_PATHS) {
            if (new java.io.File(path).exists()) {
                javaDetected = true;
                hitCount++;
                item.addDetectionDetail("📁 模拟器路径", path, "文件存在", DetectionLayer.JAVA, "📂");
            }
        }

        // Check nox service property
        try {
            String noxSvc = System.getProperty("init.svc.noxd");
            if (noxSvc != null && !noxSvc.isEmpty()) {
                javaDetected = true;
                item.addDetectionDetail("⚙️ Nox 服务", "init.svc.noxd", "值: " + noxSvc, DetectionLayer.JAVA, "🔧");
            }
        } catch (Exception ignored) {}

        item.setLayerResult(DetectionLayer.JAVA, javaDetected);
        item.setLayerResult(DetectionLayer.NATIVE, nativeDetected);
        item.setLayerResult(DetectionLayer.SYSCALL, nativeDetected);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到夜神/模拟器特征 (" + hitCount + " 处)");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }
        return item;
    }

    /**
     * Detect Rockchip-based cloud phone/emulator (17 paths from sgmain)
     */
    public DetectionItem detectRockchip() {
        DetectionItem item = new DetectionItem("Rockchip 云手机", "检测 Rockchip 芯片云手机特征");

        boolean detected = false;
        int hitCount = 0;

        for (String path : ROCKCHIP_PATHS) {
            if (new java.io.File(path).exists()) {
                detected = true;
                hitCount++;
                if (hitCount <= 5) {
                    item.addDetectionDetail("📁 Rockchip", path, "文件存在", DetectionLayer.JAVA, "📂");
                }
            }
        }

        if (hitCount > 5) {
            item.addDetectionDetail("📊 统计", "Rockchip 命中", hitCount + " 个路径命中", DetectionLayer.JAVA, "📈");
        }

        item.setLayerResult(DetectionLayer.JAVA, detected);
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        item.setLayerResult(DetectionLayer.SYSCALL, detected);

        if (detected) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 Rockchip 云手机特征 (" + hitCount + " 处)");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }
        return item;
    }

    /**
     * Detect emulator via CPU frequency analysis (sgmain stage 10)
     * Real devices have varying frequencies; emulators often have fixed/zero values
     */
    public DetectionItem detectCpuFrequency() {
        DetectionItem item = new DetectionItem("CPU 频率分析", "通过 CPU 频率检测模拟器");

        boolean detected = false;
        int cpuCount = Runtime.getRuntime().availableProcessors();
        int zeroCount = 0;
        int readableCount = 0;
        long lastFreq = -1;
        boolean allSame = true;

        for (int i = 0; i < Math.min(cpuCount, 8); i++) {
            String path = String.format(CPU_FREQ_PATH, i);
            try {
                java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(path));
                String line = reader.readLine();
                reader.close();

                if (line != null) {
                    readableCount++;
                    long freq = Long.parseLong(line.trim());
                    if (freq == 0) {
                        zeroCount++;
                    }
                    if (lastFreq >= 0 && freq != lastFreq) {
                        allSame = false;
                    }
                    lastFreq = freq;
                    item.addDetectionDetail("📊 CPU" + i + " 频率",
                        String.format("%d KHz", freq),
                        path, DetectionLayer.JAVA, "⚡");
                }
            } catch (Exception ignored) {
                // Can't read = might be emulator or permission issue
            }
        }

        // Heuristic: all zero or all identical = suspicious
        if (readableCount > 0 && (zeroCount == readableCount || (allSame && readableCount > 1))) {
            detected = true;
        }

        // Can't read any CPU freq = very suspicious
        if (readableCount == 0 && cpuCount > 0) {
            detected = true;
            item.addDetectionDetail("⚠️ CPU 频率", "无法读取", "所有 CPU 频率不可读", DetectionLayer.JAVA, "❌");
        }

        item.setLayerResult(DetectionLayer.JAVA, detected);
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        item.setLayerResult(DetectionLayer.SYSCALL, detected);

        if (detected) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("CPU 频率异常 (可能是模拟器)");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail(String.format("已检测 %d 个 CPU 核心频率正常", readableCount));
        }
        return item;
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
            "/dev/qemu_pipe",
            "/dev/qemu_trace",
            "/dev/goldfish_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
            "/system/etc/init.goldfish.rc",
            "/system/etc/init.ranchu.rc"
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
