package com.xff.launch.detector;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.IBinder;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;
import com.xff.launch.util.ReflectionUtils;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * 系统服务 / OEM 框架 / HAL / 特征文件 一致性检测。
 *
 * <p>沙箱在 app 维度伪造 Build/property 容易，但一台真实 OxygenOS(OnePlus 11) 还在这些"更深、更难
 * 逐 app 复刻"的面上留有确定痕迹：
 * <ul>
 *   <li>servicemanager 里注册的 OEM 系统服务（oplus/oneplus 系）与其 binder 接口描述符；</li>
 *   <li>boot classpath 里的 OEM framework 类(com.oplus.os.OplusBuild / OplusFeatureConfigManager)
 *       及其 ClassLoader 来源（真机=BootClassLoader，注入的假类=app/其它 loader）；</li>
 *   <li>vendor HAL(vintf manifest / init.svc.oplus.*.hal) 与 /dev/hwbinder；</li>
 *   <li>OxygenOS 独有的分区/文件(/my_product、oplus-framework.jar、ro.build.oplus_ext_partitions)；</li>
 *   <li>——反过来——当前系统(LineageOS)残留的 ro.lineage.* / org.lineageos.* 痕迹（伪装反证）。</li>
 * </ul>
 * 声称 OnePlus 但这些 OEM 痕迹缺失，或反而出现 LineageOS 痕迹 → 机型伪造被戳穿。
 */
public class SystemServiceDetector {

    private final Context context;
    private final NativeDetector nativeDetector;

    // OEM 系统服务/HAL 名称关键字（在 servicemanager listServices 及 init.svc 中出现）
    private static final String[] OEM_SERVICE_KEYWORDS = {
            "oplus", "oppo", "oneplus", "coloros", "heytap", "op_"
    };

    // OEM framework 类：真机 OxygenOS/ColorOS 一定在 boot classpath 里
    private static final String[][] OEM_FRAMEWORK_CLASSES = {
            {"com.oplus.os.OplusBuild", "getOplusOSVERSION"},
            {"com.oplus.content.OplusFeatureConfigManager", "hasFeature"},
            {"com.oplus.os.OplusUsbEnvironment", null},
            {"com.color.os.ColorOSInfo", null},
            {"com.oplus.util.OplusTypeCastingHelper", null},
            {"android.os.OplusUsbEnvironment", null},
            {"com.oplus.app.OplusAppInfo", null},
    };

    // OxygenOS/ColorOS 独有文件与目录（存在=真 OEM ROM）
    private static final String[] OEM_FEATURE_PATHS = {
            "/my_product", "/my_company", "/my_bigball", "/my_heytap", "/my_manifest",
            "/my_region", "/my_carrier", "/my_stock", "/my_preload", "/my_engineering",
            "/system/framework/oplus-framework.jar",
            "/system_ext/framework/oplus-framework.jar",
            "/vendor/etc/extension/",
            "/odm/etc/oplus_",
            "/sys/class/oplus_chg",
            "/proc/oplusVersion",
    };

    // LineageOS / 自定义 ROM 痕迹属性（出现=伪装反证）
    private static final String[] CUSTOM_ROM_PROPS = {
            "ro.lineage.build.version", "ro.lineage.version", "ro.lineage.device",
            "ro.lineage.build.version.plat.rev", "ro.modversion", "ro.cm.version",
            "org.lineageos.build.date", "ro.lineagelegal.url",
            "persist.sys.lineage.trust",
    };

    // LineageOS / 自定义 ROM 痕迹文件
    private static final String[] CUSTOM_ROM_PATHS = {
            "/system/framework/org.lineageos.platform-res.apk",
            "/system/framework/org.lineageos.platform.jar",
            "/system_ext/framework/org.lineageos.platform.jar",
            "/system/addon.d",
            "/system/priv-app/LineageSettingsProvider",
            "/system/priv-app/LineageParts",
            "/system/etc/init/lineage-recovery.rc",
    };

    // LineageOS / 自定义 ROM 痕迹包名
    private static final String[] CUSTOM_ROM_PACKAGES = {
            "org.lineageos.lineageparts", "org.lineageos.settings.device",
            "org.lineageos.updater", "lineageos.platform",
            "com.android.settings.intelligence",
    };

    public SystemServiceDetector(Context context) {
        this.context = context.getApplicationContext();
        this.nativeDetector = NativeDetector.getInstance();
    }

    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(detectServiceManagerList());
        items.add(detectOemFrameworkClasses());
        items.add(detectHalManifest());
        items.add(detectOemFeatureFiles());
        items.add(detectCustomRomLeak());
        items.add(detectSystemLibIntegrity());
        return items;
    }

    // ============================================================
    // 1. servicemanager 服务清单 + OEM 服务 + binder 描述符
    // ============================================================

    private DetectionItem detectServiceManagerList() {
        DetectionItem item = new DetectionItem("系统服务清单 (servicemanager)",
                "ServiceManager.listServices + OEM 服务存在性 + binder 接口描述符");
        try {
            String[] services = listServices();
            if (services == null) {
                item.addDetectionDetail("⚪ listServices", "不可用",
                        "隐藏 API 受限且 bypass 失败，无法枚举系统服务", DetectionLayer.JAVA, "⚪");
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("无法枚举系统服务（隐藏 API 受限）");
                markLayers(item, false);
                return item;
            }

            int total = services.length;
            item.addDetectionDetail("📋 服务总数", String.valueOf(total),
                    "listServices() 返回的已注册服务数", DetectionLayer.JAVA, "📊");

            // 统计 OEM 服务
            List<String> oemHits = new ArrayList<>();
            for (String s : services) {
                if (s == null) continue;
                String ls = s.toLowerCase();
                for (String kw : OEM_SERVICE_KEYWORDS) {
                    if (ls.contains(kw)) { oemHits.add(s); break; }
                }
            }
            for (int i = 0; i < Math.min(oemHits.size(), 12); i++) {
                item.addDetectionDetail("🟢 OEM 服务", oemHits.get(i),
                        "OnePlus/OPPO 专有系统服务", DetectionLayer.JAVA, "🟢");
            }

            // binder 接口描述符抽样（验证 getService 真能拿到 binder，且描述符可读）
            String[] probeNames = {"package", "activity", "power", "phone"};
            int descOk = 0;
            for (String name : probeNames) {
                String desc = getInterfaceDescriptor(name);
                if (desc != null && !desc.isEmpty()) {
                    descOk++;
                    item.addDetectionDetail("🔗 " + name, desc,
                            "getService(\"" + name + "\").getInterfaceDescriptor()", DetectionLayer.JAVA, "🔗");
                }
            }

            // 判定：声称 OEM 机型
            String brand = firstNonEmpty(ReflectionUtils.getBrand(), readProp("ro.product.brand"));
            boolean claimsOem = brand != null &&
                    (brand.toLowerCase().contains("oneplus") || brand.toLowerCase().contains("oppo")
                            || brand.toLowerCase().contains("oplus"));

            boolean risk = false, warn = false;
            if (claimsOem && oemHits.isEmpty()) {
                risk = true;
                item.addDetectionDetail("🔴 OEM 服务缺失", "0 个",
                        "Build 声称 " + brand + " 但 servicemanager 里没有任何 oplus/oneplus 服务 —— 真机不可能",
                        DetectionLayer.JAVA, "🔴");
            } else if (oemHits.isEmpty()) {
                warn = true;
                item.addDetectionDetail("🟡 无 OEM 服务", "0 个",
                        "未发现 OEM 专有服务（AOSP/原生系统特征）", DetectionLayer.JAVA, "🟡");
            }
            // 服务总数异常少 → servicemanager 被裁剪/伪造
            if (total > 0 && total < 40) {
                warn = true;
                item.addDetectionDetail("🟡 服务数偏少", String.valueOf(total),
                        "真机通常 >100 个服务，过少疑似伪造/裁剪的服务列表", DetectionLayer.JAVA, "🟡");
            }
            if (descOk == 0) {
                warn = true;
                item.addDetectionDetail("🟡 描述符不可读", "0/" + probeNames.length,
                        "核心服务 binder 描述符全部拿不到，疑似 hook 拦截", DetectionLayer.JAVA, "🟡");
            }

            markLayers(item, risk);
            if (risk) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("服务清单与声称机型矛盾（缺 OEM 服务）");
            } else if (warn) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("服务清单存在可疑点（总数/OEM/描述符）");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("服务清单正常，OEM 服务 " + oemHits.size() + " 个 / 共 " + total + " 个");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 2. OEM framework 类存在性 + ClassLoader 来源
    // ============================================================

    private DetectionItem detectOemFrameworkClasses() {
        DetectionItem item = new DetectionItem("OEM framework 类/特性",
                "反射 com.oplus.* 框架类 + ClassLoader 来源(真机=Boot vs 注入=app)");
        try {
            String brand = firstNonEmpty(ReflectionUtils.getBrand(), readProp("ro.product.brand"));
            boolean claimsOem = brand != null &&
                    (brand.toLowerCase().contains("oneplus") || brand.toLowerCase().contains("oppo")
                            || brand.toLowerCase().contains("oplus"));

            int found = 0, injected = 0;
            ClassLoader boot = String.class.getClassLoader(); // BootClassLoader
            for (String[] entry : OEM_FRAMEWORK_CLASSES) {
                String cls = entry[0];
                String method = entry[1];
                try {
                    Class<?> c = Class.forName(cls);
                    found++;
                    ClassLoader cl = c.getClassLoader();
                    boolean fromBoot = (cl == null || cl == boot
                            || "BootClassLoader".equals(cl.getClass().getSimpleName()));
                    if (!fromBoot) injected++;

                    String loaderName = cl == null ? "boot(null)" : cl.getClass().getSimpleName();
                    // 尝试调用特性方法取值（如 OplusBuild.getOplusOSVERSION）
                    String call = "";
                    if (method != null) {
                        try {
                            Method m = c.getDeclaredMethod(method);
                            m.setAccessible(true);
                            Object r = m.invoke(null);
                            call = r != null ? String.valueOf(r) : "null";
                        } catch (Throwable ignore) {
                            try {
                                // hasFeature(String) 形态
                                Method m = c.getDeclaredMethod(method, String.class);
                                m.setAccessible(true);
                                Object inst = c.getMethod("getInstance", Context.class) != null
                                        ? c.getMethod("getInstance", Context.class).invoke(null, context) : null;
                                Object r = m.invoke(inst, "oplus.software.oplus_exp");
                                call = "hasFeature=" + r;
                            } catch (Throwable ignore2) {
                                call = "(方法不可调用)";
                            }
                        }
                    }
                    item.addDetectionDetail(fromBoot ? "🟢 " + cls : "🔴 " + cls,
                            "loader=" + loaderName + (call.isEmpty() ? "" : "  " + method + "→" + call),
                            fromBoot ? "来自 BootClassLoader = 真框架类"
                                    : "非 Boot 加载 = 疑似注入的假 OEM 类", DetectionLayer.JAVA,
                            fromBoot ? "🟢" : "🔴");
                } catch (ClassNotFoundException e) {
                    item.addDetectionDetail("⚪ " + cls, "未找到", "该 OEM 框架类不存在",
                            DetectionLayer.JAVA, "⚪");
                }
            }

            boolean risk = false;
            if (injected > 0) {
                risk = true;
                item.addDetectionDetail("🔴 注入的假类", injected + " 个",
                        "OEM 框架类由非 BootClassLoader 加载 —— 沙箱把假类塞进了 app 进程",
                        DetectionLayer.JAVA, "🔴");
            }
            if (claimsOem && found == 0) {
                risk = true;
                item.addDetectionDetail("🔴 框架类全缺失", "声称 " + brand,
                        "Build 声称 OnePlus/OPPO 但一个 com.oplus.* 框架类都没有 —— 非真 OxygenOS",
                        DetectionLayer.JAVA, "🔴");
            }

            markLayers(item, risk);
            if (risk) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("OEM 框架类与声称机型矛盾（缺失或被注入)");
            } else if (found > 0) {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("OEM 框架类存在且均来自 BootClassLoader (" + found + " 个)");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("非 OEM 机型，无 OEM 框架类（自洽)");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 3. HAL 清单 / vintf / vendor HAL
    // ============================================================

    private DetectionItem detectHalManifest() {
        DetectionItem item = new DetectionItem("HAL 清单 / vintf",
                "vintf manifest / vendor HAL / init.svc HAL 与 /dev/hwbinder");
        try {
            int problems = 0, warns = 0;

            // /dev/hwbinder 存在性（HIDL 传输）
            boolean hwbinder = fileExists("/dev/hwbinder");
            item.addDetectionDetail(hwbinder ? "🟢 /dev/hwbinder" : "🟡 /dev/hwbinder",
                    hwbinder ? "存在" : "缺失",
                    "HIDL HAL 传输节点", DetectionLayer.SYSCALL, hwbinder ? "🟢" : "🟡");

            // vintf manifest 可读性 + 是否含 oplus HAL 接口
            String vintf = firstNonEmpty(
                    nativeDetector.readFileSyscall("/vendor/etc/vintf/manifest.xml"),
                    ReflectionUtils.readFile("/vendor/etc/vintf/manifest.xml"));
            if (!isEmpty(vintf)) {
                boolean hasOplusHal = vintf.toLowerCase().contains("oplus")
                        || vintf.toLowerCase().contains("oppo");
                int len = vintf.length();
                item.addDetectionDetail("📄 vintf manifest", "可读 " + len + "B"
                                + (hasOplusHal ? " · 含 oplus HAL" : " · 无 oplus"),
                        "/vendor/etc/vintf/manifest.xml", DetectionLayer.SYSCALL,
                        hasOplusHal ? "🟢" : "🟡");
            } else {
                warns++;
                item.addDetectionDetail("🟡 vintf manifest", "不可读",
                        "/vendor/etc/vintf/manifest.xml 读不到（可能权限，或被裁剪）",
                        DetectionLayer.SYSCALL, "🟡");
            }

            // init.svc.oplus.*.hal.service 运行状态（真机 OxygenOS 有多个 oplus HAL 常驻）
            String[] oplusHalSvc = {
                    "init.svc.oplus.performance.hal.service-1-0",
                    "init.svc.oplus.powermonitor.hal.service-1-0",
                    "init.svc.oplus.rpmh.hal.service-1-0",
                    "init.svc.vendor.oplus.hardware.performance",
            };
            int halRunning = 0;
            for (String key : oplusHalSvc) {
                String st = readProp(key);
                if (!isEmpty(st)) {
                    halRunning++;
                    item.addDetectionDetail("🟢 oplus HAL", key.replace("init.svc.", "") + "=" + st,
                            "OEM HAL init 服务状态", DetectionLayer.SYSCALL, "🟢");
                }
            }

            String brand = firstNonEmpty(ReflectionUtils.getBrand(), readProp("ro.product.brand"));
            boolean claimsOem = brand != null && (brand.toLowerCase().contains("oneplus")
                    || brand.toLowerCase().contains("oppo") || brand.toLowerCase().contains("oplus"));

            if (claimsOem && halRunning == 0) {
                problems++;
                item.addDetectionDetail("🔴 OEM HAL 缺失", "0 个 oplus HAL 运行",
                        "声称 OnePlus 但无任何 oplus HAL init 服务 —— 真机不可能", DetectionLayer.SYSCALL, "🔴");
            }

            markLayers(item, problems > 0);
            if (problems > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("HAL 层与声称机型矛盾（缺 OEM HAL）");
            } else if (warns > 0) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("HAL 清单部分不可读（部分需 root/权限）");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("HAL 清单自洽，oplus HAL " + halRunning + " 个运行");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 4. OEM 特征文件/目录（跨层 fileExists 交叉）
    // ============================================================

    private DetectionItem detectOemFeatureFiles() {
        DetectionItem item = new DetectionItem("OEM 特征文件/目录",
                "OxygenOS 独有分区/文件存在性 + 跨层(libc vs syscall)一致");
        try {
            String brand = firstNonEmpty(ReflectionUtils.getBrand(), readProp("ro.product.brand"));
            boolean claimsOem = brand != null && (brand.toLowerCase().contains("oneplus")
                    || brand.toLowerCase().contains("oppo") || brand.toLowerCase().contains("oplus"));

            int present = 0, hookMismatch = 0;
            for (String path : OEM_FEATURE_PATHS) {
                boolean libc = nativeDetector.fileExistsNative(path);
                boolean sys = nativeDetector.fileExistsSyscall(path);
                if (libc || sys) present++;
                if (libc != sys) {
                    hookMismatch++;
                    item.addDetectionDetail("🔴 跨层不一致", path + " libc=" + libc + " syscall=" + sys,
                            "libc 与 syscall 对同一路径存在性判断不同 —— 文件存在性被 hook",
                            DetectionLayer.SYSCALL, "🔴");
                } else if (libc) {
                    item.addDetectionDetail("🟢 存在", path, "OxygenOS 特征路径", DetectionLayer.SYSCALL, "🟢");
                }
            }

            // ro.build.oplus_ext_partitions 应列出 my_* 分区
            String extParts = readProp("ro.build.oplus_ext_partitions");
            if (!isEmpty(extParts)) {
                item.addDetectionDetail("🟢 ext_partitions", extParts,
                        "ro.build.oplus_ext_partitions", DetectionLayer.SYSCALL, "🟢");
            }

            boolean risk = false, warn = false;
            if (hookMismatch > 0) risk = true;
            if (claimsOem && present == 0 && isEmpty(extParts)) {
                risk = true;
                item.addDetectionDetail("🔴 OEM 特征全缺失", "声称 " + brand,
                        "声称 OnePlus 但 my_* 分区 / oplus-framework.jar / ext_partitions 全不存在 —— 非真 OxygenOS",
                        DetectionLayer.SYSCALL, "🔴");
            } else if (present == 0 && !claimsOem) {
                item.addDetectionDetail("⚪ 无 OEM 特征", "0 个", "非 OEM 机型，自洽", DetectionLayer.SYSCALL, "⚪");
            }

            markLayers(item, risk);
            if (risk) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("OEM 特征文件与声称机型矛盾 (present=" + present + ", hook=" + hookMismatch + ")");
            } else if (warn) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("OEM 特征文件部分异常");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("OEM 特征文件自洽 (present=" + present + ")");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 5. 自定义 ROM 残留（伪装反证）—— 本沙箱最可能被抓点
    // ============================================================

    private DetectionItem detectCustomRomLeak() {
        DetectionItem item = new DetectionItem("自定义 ROM 残留 [伪装反证]",
                "声称 OEM 时是否残留 LineageOS/AOSP 的 属性/文件/包 痕迹");
        try {
            String brand = firstNonEmpty(ReflectionUtils.getBrand(), readProp("ro.product.brand"));
            boolean claimsOem = brand != null && (brand.toLowerCase().contains("oneplus")
                    || brand.toLowerCase().contains("oppo") || brand.toLowerCase().contains("oplus"));

            int leaks = 0;

            // 属性残留（多源读，绕单点 hook）
            for (String key : CUSTOM_ROM_PROPS) {
                String v = readProp(key);
                if (!isEmpty(v)) {
                    leaks++;
                    item.addDetectionDetail("🔴 ROM 属性残留", key + "=" + v,
                            "自定义 ROM 专有属性泄漏 —— 与声称的 OEM 机型矛盾", DetectionLayer.SYSCALL, "🔴");
                }
            }

            // 文件残留（跨层 fileExists）
            for (String path : CUSTOM_ROM_PATHS) {
                if (nativeDetector.fileExistsNative(path) || nativeDetector.fileExistsSyscall(path)) {
                    leaks++;
                    item.addDetectionDetail("🔴 ROM 文件残留", path,
                            "LineageOS/自定义 ROM 文件存在", DetectionLayer.SYSCALL, "🔴");
                }
            }

            // 包名残留
            PackageManager pm = context.getPackageManager();
            for (String pkg : CUSTOM_ROM_PACKAGES) {
                if (isPackageInstalled(pm, pkg)) {
                    leaks++;
                    item.addDetectionDetail("🔴 ROM 包残留", pkg,
                            "自定义 ROM 系统应用存在", DetectionLayer.JAVA, "🔴");
                }
            }

            if (leaks == 0) {
                item.addDetectionDetail("🟢 无残留", "clean",
                        "未发现自定义 ROM 属性/文件/包痕迹", DetectionLayer.SYSCALL, "🟢");
            }

            // 声称 OEM 却有自定义 ROM 残留 = 铁证；不声称 OEM 但有残留 = 信息(如实为 LineageOS)
            boolean risk = leaks > 0 && claimsOem;
            markLayers(item, risk);
            if (risk) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("声称 " + brand + " 却残留 " + leaks + " 处自定义 ROM 痕迹 —— 机型伪造实锤");
            } else if (leaks > 0) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("检测到 " + leaks + " 处自定义 ROM 痕迹（与声称品牌不冲突）");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("无自定义 ROM 残留痕迹");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 6. 系统库完整性（磁盘 vs 内存 / maps 多映射）
    // ============================================================

    private DetectionItem detectSystemLibIntegrity() {
        DetectionItem item = new DetectionItem("系统库完整性 (磁盘 vs 内存)",
                "libc/libart inline-hook + /proc/self/maps 多映射交叉(部分需 root)");
        try {
            int problems = 0;

            // native 侧：关键系统库完整性（磁盘 ELF vs 内存段字节）
            // [修正·反转 bug] native check*Integrity 返回 true = 完整(干净)、false = 检测到 hook
            // (见 integrity_detector.cpp checkLibraryIntegrity "Return true if clean")。原代码把 true 当
            // "检测到 hook" → 干净库反被标红。改为 hooked = !clean;异常/未加载时 native 返 true → 不误报。
            boolean libcHooked = safeBool(() -> !nativeDetector.checkLibcIntegrity());
            boolean libartHooked = safeBool(() -> !nativeDetector.checkLibartIntegrity());
            boolean androidRtHooked = safeBool(() -> !nativeDetector.checkAndroidRuntimeIntegrity());
            item.addDetectionDetail(libcHooked ? "🔴 libc.so" : "🟢 libc.so",
                    libcHooked ? "检测到 hook" : "完整",
                    "关键 libc 函数内存字节 vs 磁盘 ELF 比对", DetectionLayer.NATIVE, libcHooked ? "🔴" : "🟢");
            item.addDetectionDetail(libartHooked ? "🔴 libart.so" : "🟢 libart.so",
                    libartHooked ? "检测到 hook" : "完整",
                    "ART 运行时 inline-hook 检测", DetectionLayer.NATIVE, libartHooked ? "🔴" : "🟢");
            item.addDetectionDetail(androidRtHooked ? "🔴 libandroid_runtime.so" : "🟢 libandroid_runtime.so",
                    androidRtHooked ? "检测到 hook" : "完整",
                    "JNI 运行时完整性", DetectionLayer.NATIVE, androidRtHooked ? "🔴" : "🟢");
            if (libcHooked) problems++;
            if (libartHooked) problems++;
            if (androidRtHooked) problems++;

            // 函数级 inline-hook 报告
            String fnReport = safeStr(() -> nativeDetector.getFunctionHookReport());
            // [修正·bug] native 干净时返回 "CLEAN\n"(带换行),原 !equals("CLEAN") 因换行为 true →
            // 误进循环、把字面行 "CLEAN" 当成一条函数 hook 计入。先 trim 再判,循环里也跳过 "CLEAN"。
            if (fnReport != null && !fnReport.trim().isEmpty() && !fnReport.trim().equals("CLEAN")) {
                for (String line : fnReport.split("\n")) {
                    String ln = line.trim();
                    if (ln.isEmpty() || ln.equals("CLEAN")) continue;
                    problems++;
                    item.addDetectionDetail("🔴 函数 hook", ln,
                            "内存字节 ≠ 磁盘 ELF 首段", DetectionLayer.NATIVE, "🔴");
                }
            }

            // /proc/self/maps 多映射交叉：native vs syscall 名单 hash 应一致
            String mapsN = safeStr(() -> nativeDetector.getMapsHashNative());
            String mapsS = safeStr(() -> nativeDetector.getMapsHashSyscall());
            if (!isEmpty(mapsN) && !isEmpty(mapsS)) {
                boolean same = mapsN.equals(mapsS);
                item.addDetectionDetail(same ? "🟢 maps 一致" : "🔴 maps 不一致",
                        "N=" + mapsN + " S=" + mapsS,
                        "libc opendir vs syscall getdents 读 /proc/self/maps 名单 hash",
                        DetectionLayer.SYSCALL, same ? "🟢" : "🔴");
                if (!same) problems++;
            }

            item.addDetectionDetail("ℹ️ 说明", "完整逐页磁盘vs内存 hash 需 root",
                    "app 层只能比对可读段；系统分区完整逐页校验需 root/dm-verity",
                    DetectionLayer.NATIVE, "ℹ️");

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, problems > 0);
            item.setLayerResult(DetectionLayer.SYSCALL, problems > 0);
            if (problems > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("系统库完整性异常 (" + problems + " 项 hook/不一致)");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("关键系统库磁盘 vs 内存一致，maps 跨层一致");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // ServiceManager 隐藏 API 访问（含 HiddenApiBypass 尝试）
    // ============================================================

    private static boolean hiddenApiExempted = false;

    private static synchronized void ensureHiddenApiExempt() {
        if (hiddenApiExempted) return;
        try {
            // 元反射绕过隐藏 API 黑名单：通过 Class.class 的 getDeclaredMethod 取 VMRuntime，
            // 再调用 setHiddenApiExemptions("L") 放行所有非 SDK 接口。
            Method forName = Class.class.getDeclaredMethod("forName", String.class);
            Method getDeclaredMethod = Class.class.getDeclaredMethod(
                    "getDeclaredMethod", String.class, Class[].class);
            Class<?> vmRuntimeClass = (Class<?>) forName.invoke(null, "dalvik.system.VMRuntime");
            Method getRuntime = (Method) getDeclaredMethod.invoke(
                    vmRuntimeClass, "getRuntime", new Class[0]);
            Method setExemptions = (Method) getDeclaredMethod.invoke(
                    vmRuntimeClass, "setHiddenApiExemptions", new Class[]{String[].class});
            Object vmRuntime = getRuntime.invoke(null);
            setExemptions.invoke(vmRuntime, new Object[]{new String[]{"L"}});
        } catch (Throwable ignored) {
            // 失败也无妨，下面的反射会各自 try
        }
        hiddenApiExempted = true;
    }

    private String[] listServices() {
        ensureHiddenApiExempt();
        try {
            Class<?> sm = Class.forName("android.os.ServiceManager");
            Method m = sm.getDeclaredMethod("listServices");
            m.setAccessible(true);
            Object r = m.invoke(null);
            if (r instanceof String[]) return (String[]) r;
        } catch (Throwable ignored) {
        }
        return null;
    }

    private String getInterfaceDescriptor(String serviceName) {
        ensureHiddenApiExempt();
        try {
            Class<?> sm = Class.forName("android.os.ServiceManager");
            Method get = sm.getDeclaredMethod("getService", String.class);
            get.setAccessible(true);
            Object binder = get.invoke(null, serviceName);
            if (binder instanceof IBinder) {
                String d = ((IBinder) binder).getInterfaceDescriptor();
                return d != null ? d : "";
            }
        } catch (Throwable ignored) {
        }
        return "";
    }

    // ============================================================
    // Helpers
    // ============================================================

    private String readProp(String key) {
        String v = safe(nativeDetector.getBuildPropertyNative(key));
        if (!isEmpty(v)) return v;
        v = safe(nativeDetector.getBuildPropertySyscall(key));
        if (!isEmpty(v)) return v;
        v = safe(ReflectionUtils.getSystemProperty(key));
        if (!isEmpty(v)) return v;
        v = safe(nativeDetector.readDevPropertyMmap(key));
        return isEmpty(v) ? "" : v;
    }

    private boolean fileExists(String path) {
        try {
            return nativeDetector.fileExistsNative(path) || nativeDetector.fileExistsSyscall(path);
        } catch (Throwable t) {
            return false;
        }
    }

    private boolean isPackageInstalled(PackageManager pm, String pkg) {
        try {
            pm.getPackageInfo(pkg, 0);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private interface BoolSupplier { boolean get() throws Throwable; }
    private interface StrSupplier { String get() throws Throwable; }

    private static boolean safeBool(BoolSupplier s) {
        try { return s.get(); } catch (Throwable t) { return false; }
    }

    private static String safeStr(StrSupplier s) {
        try { return s.get(); } catch (Throwable t) { return ""; }
    }

    private void markLayers(DetectionItem item, boolean detected) {
        item.setLayerResult(DetectionLayer.JAVA, detected);
        item.setLayerResult(DetectionLayer.NATIVE, false);
        item.setLayerResult(DetectionLayer.SYSCALL, false);
    }

    private static String firstNonEmpty(String... vals) {
        for (String v : vals) if (!isEmpty(v)) return v;
        return "";
    }

    private static boolean isEmpty(String s) {
        return s == null || s.isEmpty() || s.equals("unknown");
    }

    private static String safe(String s) {
        return s == null ? "" : s.trim();
    }

    private void unknown(DetectionItem item, Throwable t) {
        markLayers(item, false);
        item.setStatus(DetectionStatus.UNKNOWN);
        item.setDetail("检测异常: " + (t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName()));
    }
}
