package com.xff.launch.ui.fingerprint;

import android.app.ActivityManager;
import android.content.Context;
import android.database.Cursor;
import android.media.MediaDrm;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.provider.Settings;
import android.util.Base64;
import android.util.DisplayMetrics;

import com.xff.launch.detector.NativeDetector;
import com.xff.launch.model.FingerprintSpec;
import com.xff.launch.util.HwProbe;
import com.xff.launch.util.ReflectionUtils;
import com.xff.launch.util.WebProbe;

import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;

import static com.xff.launch.model.FingerprintSpec.Group;
import static com.xff.launch.model.FingerprintSpec.HashTag;
import static com.xff.launch.model.FingerprintSpec.define;
import static com.xff.launch.model.ProbeMethod.JAVA_API;
import static com.xff.launch.model.ProbeMethod.JAVA_FILE;
import static com.xff.launch.model.ProbeMethod.JAVA_REFLECT;
import static com.xff.launch.model.ProbeMethod.MMAP;
import static com.xff.launch.model.ProbeMethod.NATIVE_FILE;
import static com.xff.launch.model.ProbeMethod.NATIVE_PROP;
import static com.xff.launch.model.ProbeMethod.SYSCALL;

/**
 * 所有指纹项的<b>声明聚集地</b>。
 *
 * <p>这是本模块唯一需要改动的"业务文件"：
 * <ul>
 *   <li>加一个新指纹 → 复制一个 {@code define(...).probe(...)} 块。</li>
 *   <li>给已有指纹加一种采集方式 → 在它的链上加一行 {@code .probe(...)}。</li>
 * </ul>
 * 引擎、UI、投票、Hash 全自动接住，无需改动其它文件。
 *
 * <p>约定：同一指纹项内的所有 probe 应指向<b>同一逻辑值</b>，这样多路投票才有意义
 * （不要把"短内核版本"和"长 /proc/version"混进一项）。
 */
public final class FingerprintDefinitions {

    private FingerprintDefinitions() {}

    public static List<FingerprintSpec> build(final Context ctx, final NativeDetector nd) {
        List<FingerprintSpec> specs = new ArrayList<>();

        // ==================== 基础标识 ====================

        specs.add(define("android_id", "ANDROID_ID", Group.IDENTITY, HashTag.NONE)
                .probe(JAVA_REFLECT, "Secure.getString 反射", () -> ReflectionUtils.getAndroidId(ctx.getContentResolver()))
                .probe(JAVA_API, "Settings.Secure.ANDROID_ID",
                        () -> Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID)));

        specs.add(propItem("serial", "设备序列号", HashTag.HARDWARE, "ro.serialno", ReflectionUtils::getSerial, () -> Build.SERIAL, nd)
                .probe(SYSCALL, "iSerial (syscall)", "/sys/class/android_usb/android0/iSerial",
                        () -> nd.readFileSyscall("/sys/class/android_usb/android0/iSerial")));

        specs.add(propItem("model", "设备型号", HashTag.HARDWARE, "ro.product.model", ReflectionUtils::getModel, () -> Build.MODEL, nd));
        specs.add(propItem("brand", "品牌", HashTag.HARDWARE, "ro.product.brand", ReflectionUtils::getBrand, () -> Build.BRAND, nd));
        specs.add(propItem("fingerprint", "Build 指纹", HashTag.SOFTWARE, "ro.build.fingerprint", ReflectionUtils::getFingerprint, () -> Build.FINGERPRINT, nd));

        // ==================== 内核标识 ====================

        // boot_id 每次开机都变，weight(0) 不纳入 composite，避免设备指纹随重启漂移
        specs.add(fileItem("boot_id", "Boot ID", HashTag.SOFTWARE, "/proc/sys/kernel/random/boot_id", nd).weight(0));
        // kernel_version：osrelease 文件高版本可能被封，Java API os.version 兜底
        specs.add(fileItem("kernel_version", "内核版本", HashTag.NONE, "/proc/sys/kernel/osrelease", nd)
                .probe(JAVA_API, "System.getProperty(os.version)", () -> System.getProperty("os.version")));
        specs.add(fileItem("hostname", "主机名", HashTag.NONE, "/proc/sys/kernel/hostname", nd)
                .probe(JAVA_REFLECT, "SystemProperties net.hostname", () -> ReflectionUtils.getSystemProperty("net.hostname")));

        // ==================== 硬件标识 ====================

        specs.add(define("cpu_serial", "CPU 序列号", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_REFLECT, "/proc/cpuinfo Serial", () -> ReflectionUtils.getCpuSerial())
                .probe(NATIVE_FILE, "getCpuSerial (native)", () -> nd.getCpuSerial())
                .probe(SYSCALL, "getCpuSerial (syscall)", () -> nd.getCpuSerialSyscall()));

        // cpu_hardware：新内核 /proc/cpuinfo 删了 Hardware 行，ro.hardware 属性兜底
        specs.add(define("cpu_hardware", "CPU 硬件", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_REFLECT, "/proc/cpuinfo Hardware", () -> ReflectionUtils.getCpuHardware())
                .probe(NATIVE_FILE, "getCpuHardware (native)", () -> nd.getCpuHardware())
                .probe(SYSCALL, "getCpuHardware (syscall)", () -> nd.getCpuHardwareSyscall())
                .probe(JAVA_API, "Build.HARDWARE", () -> Build.HARDWARE)
                .probe(NATIVE_PROP, "__system_property_get(ro.hardware)", () -> nd.getBuildPropertyNative("ro.hardware")));

        specs.add(fileItem("soc_serial", "SoC 序列号", HashTag.HARDWARE, "/sys/devices/soc0/serial_number", nd));
        specs.add(fileItem("soc_id", "SoC ID", HashTag.HARDWARE, "/sys/devices/soc0/soc_id", nd));

        // ==================== Boot 参数 ====================

        specs.add(bootParamItem("boot_serial", "Boot 序列号", HashTag.HARDWARE, "androidboot.serialno", "ro.boot.serialno", nd));
        specs.add(bootParamItem("boot_hardware", "Boot 硬件", HashTag.NONE, "androidboot.hardware", "ro.boot.hardware", nd));
        specs.add(bootParamItem("boot_device", "Boot Device", HashTag.NONE, "androidboot.bootdevice", "ro.boot.bootdevice", nd));

        // ==================== 其它系统 ID ====================

        specs.add(define("drm_id", "DRM ID (Widevine)", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "MediaDrm 设备唯一ID", () -> getWidevineDeviceId()));

        specs.add(propItem("vbmeta_digest", "VBMeta 摘要", HashTag.SOFTWARE, "ro.boot.vbmeta.digest", nd));
        specs.add(propItem("build_id", "Build ID", HashTag.SOFTWARE, "ro.build.id", ReflectionUtils::getId, null, nd));
        specs.add(propItem("display_id", "Display ID", HashTag.SOFTWARE, "ro.build.display.id", ReflectionUtils::getDisplay, null, nd));
        specs.add(propItem("bootloader", "Bootloader", HashTag.SOFTWARE, "ro.bootloader", ReflectionUtils::getBootloader, null, nd));
        specs.add(propItem("radio", "基带版本", HashTag.NONE, "gsm.version.baseband", ReflectionUtils::getRadioVersion, null, nd));

        specs.add(propItem("device", "设备代号", HashTag.HARDWARE, "ro.product.device", ReflectionUtils::getDevice, () -> Build.DEVICE, nd));
        specs.add(propItem("board", "主板", HashTag.HARDWARE, "ro.product.board", ReflectionUtils::getBoard, () -> Build.BOARD, nd));
        specs.add(propItem("manufacturer", "制造商", HashTag.HARDWARE, "ro.product.manufacturer", ReflectionUtils::getManufacturer, () -> Build.MANUFACTURER, nd));
        specs.add(propItem("product", "产品名", HashTag.HARDWARE, "ro.product.name", ReflectionUtils::getProduct, () -> Build.PRODUCT, nd));

        specs.add(propItem("build_type", "构建类型", HashTag.SOFTWARE, "ro.build.type", () -> ReflectionUtils.getBuildField("TYPE"), null, nd));
        specs.add(propItem("build_tags", "构建标签", HashTag.SOFTWARE, "ro.build.tags", () -> ReflectionUtils.getBuildField("TAGS"), null, nd));
        specs.add(propItem("android_version", "Android 版本", HashTag.SOFTWARE, "ro.build.version.release", () -> ReflectionUtils.getBuildVersionField("RELEASE"), null, nd));
        specs.add(propItem("sdk_level", "API 级别", HashTag.SOFTWARE, "ro.build.version.sdk", () -> ReflectionUtils.getBuildVersionField("SDK_INT"), null, nd));
        specs.add(propItem("security_patch", "安全补丁", HashTag.SOFTWARE, "ro.build.version.security_patch", () -> ReflectionUtils.getBuildVersionField("SECURITY_PATCH"), null, nd));

        // ==================== 硬件运行时 ====================

        // MAC 各路来源大小写不一，统一归一化为大写避免误判不一致
        specs.add(define("mac_address", "MAC 地址", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "NetworkInterface wlan0", () -> getWlanMac())
                .probe(JAVA_FILE, "address 文件", "/sys/class/net/wlan0/address", () -> upper(ReflectionUtils.readFileFirstLine("/sys/class/net/wlan0/address")))
                .probe(NATIVE_FILE, "getMacAddress (native)", () -> upper(nd.getMacAddressNative()))
                .probe(SYSCALL, "getMacAddress (syscall)", () -> upper(nd.getMacAddressSyscall())));

        specs.add(define("total_ram", "总内存", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "ActivityManager.MemoryInfo", () -> getTotalRamJava(ctx))
                .probe(NATIVE_FILE, "getTotalRam (native)", () -> roundRam(nd.getTotalRamNative()))
                .probe(SYSCALL, "getTotalRam (syscall)", () -> roundRam(nd.getTotalRamSyscall())));

        specs.add(define("screen_info", "屏幕分辨率", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "DisplayMetrics", () -> getScreenJava(ctx))
                .probe(NATIVE_FILE, "getScreenInfo (native)", () -> nd.getScreenInfoNative())
                .probe(SYSCALL, "getScreenInfo (syscall)", () -> nd.getScreenInfoSyscall()));

        specs.add(define("cpu_abi", "处理器架构", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "Build.SUPPORTED_ABIS[0]", () -> Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "")
                .probe(NATIVE_FILE, "getCpuAbi (native)", () -> nd.getCpuAbiNative())
                .probe(SYSCALL, "getCpuAbi (syscall)", () -> nd.getCpuAbiSyscall()));

        specs.add(define("total_storage", "存储容量", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "StatFs(data)", () -> getStorageJava())
                .probe(NATIVE_FILE, "getTotalStorage (native)", () -> nd.getTotalStorageNative())
                .probe(SYSCALL, "getTotalStorage (syscall)", () -> nd.getTotalStorageSyscall()));

        specs.add(define("uname_info", "内核架构信息", Group.KERNEL, HashTag.NONE)
                .probe(NATIVE_FILE, "uname (native)", () -> nd.getUnameInfoNative())
                .probe(SYSCALL, "uname (syscall)", () -> nd.getUnameInfoSyscall()));

        specs.add(propItem("timezone", "时区", HashTag.SOFTWARE, "persist.sys.timezone", () -> TimeZone.getDefault().getID(), null, nd));
        specs.add(propItem("language", "系统语言", HashTag.SOFTWARE, "persist.sys.language", () -> Locale.getDefault().toString(), null, nd));

        // ==================== GSF ====================

        specs.add(define("gsf_id", "GSF ID", Group.SYSTEM, HashTag.NONE)
                .probe(JAVA_API, "gservices content://", () -> getGsfId(ctx)));

        // ==================== SVC 运行时校验 ====================

        specs.add(define("cpu_freq", "CPU 频率指纹", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_FILE, "cpufreq 逐核", "/sys/devices/system/cpu/cpuN/cpufreq/cpuinfo_max_freq", () -> collectCpuFreqJava())
                .probe(NATIVE_FILE, "getCpuFreqPattern (native)", () -> nd.getCpuFreqPatternNative())
                .probe(SYSCALL, "getCpuFreqPattern (syscall)", () -> nd.getCpuFreqPatternSyscall()));

        specs.add(define("hosts_hash", "Hosts Hash", Group.SYSTEM, HashTag.SOFTWARE)
                .probe(JAVA_FILE, "djb2(/etc/hosts)", "/etc/hosts", () -> computeHostsHashJava())
                .probe(NATIVE_FILE, "getHostsHash (native)", () -> nd.getHostsHashNative())
                .probe(SYSCALL, "getHostsHash (syscall)", () -> nd.getHostsHashSyscall()));

        specs.add(define("selinux", "SELinux 状态", Group.SYSTEM, HashTag.SOFTWARE)
                .probe(JAVA_FILE, "enforce + attr/current", "/sys/fs/selinux/enforce", () -> collectSELinuxJava())
                .probe(NATIVE_FILE, "getSELinuxFingerprint (native)", () -> nd.getSELinuxFingerprintNative())
                .probe(SYSCALL, "getSELinuxFingerprint (syscall)", () -> nd.getSELinuxFingerprintSyscall()));

        // ==================== 扩展硬件指纹（传感器/GPU/相机/存储等）====================

        // ⭐ 存储芯片序列 eMMC/UFS CID —— 每台唯一，多路读 sysfs
        specs.add(define("storage_cid", "存储芯片 CID", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_FILE, "mmc/ufs cid 多路径", "/sys/block/mmcblk0/device/cid", () -> HwProbe.storageCid())
                .probe(NATIVE_FILE, "cid (native)", "/sys/block/mmcblk0/device/cid", () -> firstLine(nd.readKernelFile("/sys/block/mmcblk0/device/cid")))
                .probe(SYSCALL, "cid (syscall)", "/sys/block/mmcblk0/device/cid", () -> firstLine(nd.readFileSyscall("/sys/block/mmcblk0/device/cid"))));

        // ⭐ 传感器列表指纹 —— 机型级铁稳、高熵、无权限（SensorID 的稳定替身）
        specs.add(define("sensor_list", "传感器列表指纹", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "SensorManager.getSensorList", () -> HwProbe.sensorListFingerprint(ctx)));

        // GPU 渲染指纹 —— 离屏 EGL 取 GL 字符串
        specs.add(define("gpu_render", "GPU 渲染指纹", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "EGL GL_VENDOR/RENDERER/VERSION", () -> HwProbe.gpuFingerprint()));

        // 相机特性指纹
        specs.add(define("camera_fp", "相机特性指纹", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "CameraCharacteristics", () -> HwProbe.cameraFingerprint(ctx)));

        // 编解码器指纹
        specs.add(define("media_codec", "编解码器指纹", Group.SYSTEM, HashTag.SOFTWARE)
                .probe(JAVA_API, "MediaCodecList", () -> HwProbe.mediaCodecFingerprint()));

        // /proc/cpuinfo 全量 hash
        specs.add(define("cpuinfo_hash", "CPUInfo 全量 Hash", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_FILE, "djb2(/proc/cpuinfo)", "/proc/cpuinfo", () -> HwProbe.fileHash("/proc/cpuinfo")));

        // 输入设备指纹
        specs.add(define("input_devices", "输入设备指纹", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_FILE, "djb2(input/devices)", "/proc/bus/input/devices", () -> HwProbe.fileHash("/proc/bus/input/devices")));

        // Device-Tree compatible（机型/板型）
        specs.add(define("device_tree", "Device-Tree 标识", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_FILE, "device-tree/compatible", "/proc/device-tree/compatible", () -> HwProbe.deviceTreeCompat()));

        // 内存布局 hash —— 注：Android 10+ 物理地址被抹零，实际熵偏低，仅机型级参考
        specs.add(define("mem_layout", "内存布局 Hash", Group.HARDWARE, HashTag.NONE)
                .probe(JAVA_FILE, "djb2(iomem/zoneinfo)", "/proc/iomem", () -> HwProbe.fileHashAny("/proc/iomem", "/proc/zoneinfo")));

        // ==================== 隐蔽采集维度（调研新增）====================

        // ⭐ Vulkan 硬件指纹 —— deviceUUID 跨重启/进程/驱动版本稳定，难伪造
        specs.add(define("vulkan_fp", "Vulkan 硬件指纹", Group.HARDWARE, HashTag.HARDWARE)
                .probe(NATIVE_PROP, "vkGetPhysicalDeviceProperties2", () -> nd.getVulkanFingerprintNative()));

        // 电池特征 —— 设计容量(机型级稳定) + 技术
        specs.add(define("battery_fp", "电池特征", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "PowerProfile + sysfs", () -> HwProbe.batteryFingerprint(ctx)));

        // 热区列表 —— 传感器类型清单
        specs.add(define("thermal_zones", "热区列表指纹", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_FILE, "thermal_zone*/type", "/sys/class/thermal", () -> HwProbe.thermalZonesFingerprint()));

        // CPU 拓扑 —— 大小核分簇布局
        specs.add(define("cpu_topology", "CPU 拓扑指纹", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_FILE, "cpu*/topology", "/sys/devices/system/cpu", () -> HwProbe.cpuTopologyFingerprint()));

        // GPU 能力/扩展全集 —— 比 renderer 串熵更高
        specs.add(define("gpu_caps", "GPU 扩展/能力指纹", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "GL_EXTENSIONS+limits+EGL", () -> HwProbe.gpuCapsFingerprint()));

        // GPU 像素渲染指纹 —— WebGL canvas 安卓移植，离屏渲染+glReadPixels（GPU+驱动级·难伪造）
        // weight(3): 稳定且难伪造，在 composite 中加权强调
        specs.add(define("gl_pixel_fp", "GPU 像素渲染指纹", Group.HARDWARE, HashTag.HARDWARE)
                .weight(3)
                .probe(JAVA_API, "离屏GLES+glReadPixels+SHA256", () -> HwProbe.glPixelFingerprint()));

        // 音频 HAL 参数
        specs.add(define("audio_fp", "音频 HAL 指纹", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "OUTPUT_SAMPLE_RATE/FRAMES", () -> HwProbe.audioFingerprint(ctx)));

        // 系统属性全量 hash —— 构建级软件指纹
        specs.add(define("prop_set_hash", "系统属性全量 Hash", Group.SYSTEM, HashTag.SOFTWARE)
                .probe(JAVA_REFLECT, "djb2(ro.* 属性集)", () -> HwProbe.propSetHash()));

        // 内核配置 hash
        specs.add(define("kernel_config", "内核配置 Hash", Group.SYSTEM, HashTag.SOFTWARE)
                .probe(JAVA_FILE, "gunzip(/proc/config.gz)", "/proc/config.gz", () -> HwProbe.kernelConfigHash()));

        // ==================== WebView 侧指纹（独立取证链·机型相关）====================

        // WebView User-Agent —— 含机型/安卓版本/Chrome 版本/Build（含 Chrome 版本会随更新变，不进 composite）
        specs.add(define("webview_ua", "WebView UA", Group.SYSTEM, HashTag.NONE).weight(0)
                .probe(JAVA_API, "WebSettings.getDefaultUserAgent", () -> WebProbe.userAgent(ctx)));

        // WebView JS 指纹 —— navigator/screen/WebGL 渲染器，与 native 侧交叉验证
        specs.add(define("webview_fp", "WebView JS 指纹", Group.HARDWARE, HashTag.HARDWARE)
                .probe(JAVA_API, "navigator+screen+WebGL", () -> {
                    String j = WebProbe.bundle(ctx);
                    return j.isEmpty() ? "" : ReflectionUtils.djb2Hash(j);
                }));

        // GPU 渲染器一致性 —— native EGL vs WebView WebGL，归一化后比对；不一致即 GPU 信息被篡改
        // 复用多路投票：两路相同→一致，不同→红色不一致，一方空→忽略不误报。不进 composite。
        specs.add(define("gpu_renderer_xcheck", "GPU 渲染器一致性", Group.HARDWARE, HashTag.NONE).weight(0)
                .probe(JAVA_API, "native EGL GL_RENDERER", () -> {
                    String[] p = HwProbe.gpuFingerprint().split("\\|");
                    return p.length > 1 ? HwProbe.normalizeGpuRenderer(p[1]) : "";
                })
                .probe(JAVA_API, "WebView WebGL renderer", () -> HwProbe.normalizeGpuRenderer(WebProbe.webglRenderer(ctx))));

        return specs;
    }

    // ==================== 模板：减少样板 ====================

    /**
     * 系统属性型指纹模板：反射 Build 字段 + 直读 Build 字段 + native/syscall/mmap 读属性。
     *
     * @param reflect 反射取 Build.X 的 collector（如 ReflectionUtils::getModel），可空
     * @param direct  直读 Build.X 的 collector（如 () -> Build.MODEL），可空
     */
    private static FingerprintSpec propItem(String id, String name, HashTag hash, String prop,
                                            com.xff.launch.model.Collector reflect,
                                            com.xff.launch.model.Collector direct,
                                            NativeDetector nd) {
        FingerprintSpec spec = define(id, name, Group.IDENTITY, hash);
        if (reflect != null) spec.probe(JAVA_REFLECT, "Build 反射", reflect);
        if (direct != null) spec.probe(JAVA_API, "Build 直读", direct);
        spec.probe(NATIVE_PROP, "__system_property_get(" + prop + ")", () -> nd.getBuildPropertyNative(prop));
        spec.probe(SYSCALL, prop + " (syscall)", () -> nd.getBuildPropertySyscall(prop));
        spec.probe(MMAP, prop + " (mmap)", "/dev/__properties__", () -> nd.readDevPropertyMmap(prop));
        return spec;
    }

    /** 仅靠系统属性（无对应 Build 字段）的模板：反射 SystemProperties + native/syscall/mmap。 */
    private static FingerprintSpec propItem(String id, String name, HashTag hash, String prop, NativeDetector nd) {
        FingerprintSpec spec = define(id, name, Group.IDENTITY, hash);
        spec.probe(JAVA_REFLECT, "SystemProperties.get(" + prop + ")", () -> ReflectionUtils.getSystemProperty(prop));
        spec.probe(NATIVE_PROP, "__system_property_get(" + prop + ")", () -> nd.getBuildPropertyNative(prop));
        spec.probe(SYSCALL, prop + " (syscall)", () -> nd.getBuildPropertySyscall(prop));
        spec.probe(MMAP, prop + " (mmap)", "/dev/__properties__", () -> nd.readDevPropertyMmap(prop));
        return spec;
    }

    /** 文件型指纹模板：Java 读 + native fopen + syscall openat，同一路径。 */
    private static FingerprintSpec fileItem(String id, String name, HashTag hash, String path, NativeDetector nd) {
        return define(id, name, Group.KERNEL, hash)
                .probe(JAVA_FILE, "readFileFirstLine", path, () -> ReflectionUtils.readFileFirstLine(path))
                .probe(NATIVE_FILE, "fopen/fgets (native)", path, () -> firstLine(nd.readKernelFile(path)))
                .probe(SYSCALL, "openat/read (syscall)", path, () -> firstLine(nd.readFileSyscall(path)));
    }

    /**
     * Boot 参数型指纹模板：解析 /proc/cmdline 的 androidboot.X。
     * 高版本 /proc/cmdline 对 App 被 SELinux 封禁，用对应 ro.boot.X 属性兜底。
     */
    private static FingerprintSpec bootParamItem(String id, String name, HashTag hash, String param, String prop, NativeDetector nd) {
        FingerprintSpec spec = define(id, name, Group.BOOT, hash)
                .probe(JAVA_FILE, "cmdline 解析 " + param, "/proc/cmdline", () -> ReflectionUtils.getBootParam(param))
                .probe(NATIVE_FILE, "getBootParam (native)", () -> nd.getBootParam(param))
                .probe(SYSCALL, "getBootParam (syscall)", () -> nd.getBootParamSyscall(param));
        if (prop != null) {
            spec.probe(JAVA_REFLECT, "SystemProperties " + prop, () -> ReflectionUtils.getSystemProperty(prop))
                .probe(NATIVE_PROP, "__system_property_get(" + prop + ")", () -> nd.getBuildPropertyNative(prop));
        }
        return spec;
    }

    // ==================== Java 侧采集 helper ====================

    private static String firstLine(String s) {
        if (s == null) return "";
        int nl = s.indexOf('\n');
        return (nl >= 0 ? s.substring(0, nl) : s).trim();
    }

    private static String upper(String s) {
        return s == null ? "" : s.toUpperCase(Locale.ROOT);
    }

    private static String getWlanMac() {
        try {
            NetworkInterface wlan0 = NetworkInterface.getByName("wlan0");
            if (wlan0 != null) {
                byte[] mac = wlan0.getHardwareAddress();
                if (mac != null && mac.length > 0) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < mac.length; i++) {
                        sb.append(String.format("%02X", mac[i]));
                        if (i < mac.length - 1) sb.append(":");
                    }
                    return sb.toString();
                }
            }
        } catch (Exception ignored) {}
        return "";
    }

    private static String getTotalRamJava(Context ctx) {
        try {
            ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) {
                ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
                am.getMemoryInfo(mi);
                long mb = mi.totalMem / (1024L * 1024L);
                mb = ((mb + 64) / 128) * 128;
                return mb + " MB";
            }
        } catch (Exception ignored) {}
        return "";
    }

    /** 把 "7890 MB" 归一化到最近的 128MB，消除各层微小差异。 */
    private static String roundRam(String raw) {
        if (raw == null || raw.isEmpty()) return "";
        try {
            String num = raw.replaceAll("[^0-9]", "");
            if (num.isEmpty()) return raw;
            long mb = Long.parseLong(num);
            mb = ((mb + 64) / 128) * 128;
            return mb + " MB";
        } catch (NumberFormatException e) {
            return raw;
        }
    }

    private static String getScreenJava(Context ctx) {
        try {
            DisplayMetrics dm = ctx.getResources().getDisplayMetrics();
            return dm.widthPixels + "x" + dm.heightPixels + "@" + dm.densityDpi;
        } catch (Exception e) {
            return "";
        }
    }

    private static String getStorageJava() {
        try {
            StatFs statFs = new StatFs(Environment.getDataDirectory().getPath());
            long totalBytes = statFs.getTotalBytes();
            return (totalBytes / (1024L * 1024L * 1024L)) + " GB";
        } catch (Exception e) {
            return "";
        }
    }

    private static String getGsfId(Context ctx) {
        try {
            Uri gsfUri = Uri.parse("content://com.google.android.gsf.gservices");
            Cursor cursor = ctx.getContentResolver().query(gsfUri, null, null, new String[]{"android_id"}, null);
            if (cursor != null) {
                String id = "";
                if (cursor.moveToFirst() && cursor.getColumnCount() >= 2) {
                    id = cursor.getString(1);
                }
                cursor.close();
                return id;
            }
        } catch (Exception ignored) {}
        return "";
    }

    private static String getWidevineDeviceId() {
        final UUID WIDEVINE_UUID = new UUID(0xEDEF8BA979D64ACEL, 0xA3C827DCD51D21EDL);
        MediaDrm mediaDrm = null;
        try {
            mediaDrm = new MediaDrm(WIDEVINE_UUID);
            byte[] deviceId = mediaDrm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID);
            if (deviceId != null && deviceId.length > 0) {
                return Base64.encodeToString(deviceId, Base64.NO_WRAP);
            }
        } catch (Exception ignored) {
        } finally {
            if (mediaDrm != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) mediaDrm.close();
                else mediaDrm.release();
            }
        }
        return "";
    }

    private static String collectCpuFreqJava() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            String freq = ReflectionUtils.readFileFirstLine(
                    "/sys/devices/system/cpu/cpu" + i + "/cpufreq/cpuinfo_max_freq");
            if (freq == null || freq.isEmpty()) break;
            if (sb.length() > 0) sb.append(",");
            sb.append(freq.trim());
        }
        return sb.toString();
    }

    private static String computeHostsHashJava() {
        String content = ReflectionUtils.readFile("/etc/hosts");
        if (content.isEmpty()) content = ReflectionUtils.readFile("/system/etc/hosts");
        if (content.isEmpty()) return "";
        return ReflectionUtils.djb2Hash(content);
    }

    private static String collectSELinuxJava() {
        String enforce = ReflectionUtils.readFileFirstLine("/sys/fs/selinux/enforce");
        String state = "1".equals(enforce) ? "Enforcing" : "Permissive";
        String context = ReflectionUtils.readFileFirstLine("/proc/self/attr/current");
        if (context != null && !context.isEmpty()) {
            int colonCount = 0;
            for (int i = 0; i < context.length(); i++) {
                if (context.charAt(i) == ':') {
                    colonCount++;
                    if (colonCount == 3) {
                        context = context.substring(0, i);
                        break;
                    }
                }
            }
        } else {
            context = "unknown";
        }
        return state + "|" + context;
    }
}
