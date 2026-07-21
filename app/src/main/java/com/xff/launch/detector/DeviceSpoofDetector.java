package com.xff.launch.detector;

import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;
import com.xff.launch.util.ReflectionUtils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 改机 / 一键新机 检测。
 *
 * <p>从"系统目录 / 文件 / 安装目录 / 内存映射 / 属性源"判断本机是否被一键新机类工具或 per-app
 * 指纹沙箱改成了"新机"。与已有 TamperDetector(云控工具)、HookDetector(LSPosed 框架)、
 * DeviceConsistencyDetector(机型 6 源自洽)、SystemServiceDetector(OEM 框架/ROM 残留) 互补，本组
 * 专注"改机工具落地痕迹 + 磁盘 vs 运行期脱节 + boot dex/伪装库注入 + 标识符漂移"这几条正交面：
 * <ul>
 *   <li>已知改机/多开/Xposed 管理器/一键新机工具**包**存在性(含伪装包名)；</li>
 *   <li>改机工具**留痕文件/目录**(/data/adb/lspd、/data/adb/modules、比特指纹 device_sensors.json…)
 *       + 跨层(libc vs syscall)存在性一致性；</li>
 *   <li>**磁盘 build.prop/vendor build.prop vs 运行期属性**逐键比对(resetprop/hook 改运行期而磁盘脱节)；</li>
 *   <li>**boot class path 异常 / 匿名·memfd·非标准 location 的 dex**(kFrameworkInBoot 重点覆盖)；</li>
 *   <li>proc/self/maps 里伪装成系统库但路径与 inode 异常的 .so；</li>
 *   <li>**属性内核边界 vs libc 交叉**(改机 hook 判定)；</li>
 *   <li>**设备标识符(serial/android_id/device-tree) 多源漂移**。</li>
 * </ul>
 * 纯 app 层可跑(无需 root)；需 root 才能读内容的项按"存在即命中"或明确标注。
 */
public class DeviceSpoofDetector {

    private final Context context;
    private final NativeDetector nativeDetector;

    // ---- 1. 已知改机/多开/Xposed 管理器/一键新机 工具包(含伪装/别名) ----
    // 说明: LSPosed 管理器包(org.lsposed.manager)已由 HookDetector 覆盖, 本组补齐改机/多开/一键新机族。
    private static final String[][] SPOOF_TOOL_PACKAGES = {
            // {包名, 分类说明}
            {"de.robv.android.xposed.installer", "Xposed 安装器"},
            {"org.meowcat.edxposed.manager", "EdXposed 管理器"},
            {"me.weishu.exp", "太极 TaiChi (免 root Xposed)"},
            {"io.va.exposed", "VirtualXposed"},
            {"io.virtualapp", "VirtualApp 宿主"},
            {"com.lody.virtual", "VirtualApp 引擎"},
            {"com.lbe.parallel", "平行空间 (多开)"},
            {"com.lbe.parallel.intl", "平行空间 国际版"},
            {"com.excelliance.dualaid", "双开助手"},
            {"com.by.chaos", "Chaos 多开框架"},
            {"com.qihoo.magic", "360 分身大师"},
            {"com.jiubang.commerce.gomultiple", "GO 多开"},
            {"com.ludashi.superboost", "鲁大师多开"},
            {"com.cloudecalc.control", "CloudECalc 云控改机"},
            {"com.cloudphone.cph", "CPH 云机"},
            {"catch_.me_.if_.you_.can_", "GameGuardian"},
            {"org.lsposed.lspatch", "LSPatch (免 root 注入)"},
            {"cn.myflymind.a008", "008 一键新机(常见别名)"},
    };

    // ---- 2. 改机工具留痕文件/目录 ----
    private static final String[][] SPOOF_ARTIFACT_PATHS = {
            // {路径, 说明, 是否需要 root 读内容(存在性本身多数可探)}
            {"/data/adb/lspd", "LSPosed 框架数据目录", "root"},
            {"/data/adb/lspd/config/modules_config.db", "LSPosed 模块作用域库", "root"},
            {"/data/adb/modules", "Magisk/Zygisk 模块总目录", "root"},
            {"/data/adb/modules/zygisk_lsposed", "Zygisk LSPosed 模块", "root"},
            {"/data/misc/lspd", "LSPosed misc 数据", "root"},
            {"/data/adb/magisk", "Magisk 目录", "root"},
            {"/data/adb/ksu", "KernelSU 目录", "root"},
            {"/data/adb/ap", "APatch 目录", "root"},
            {"/data/misc/riru", "Riru 注入框架", "root"},
            // 比特指纹手机 / 硬改盒子配置(澎湃披露)
            {"/data/system/device_sensors.json", "比特指纹 传感器伪造配置", "root"},
            {"/data/system/d1", "比特指纹 系统属性伪造配置", "root"},
            {"/sys/devcfg/wifimac", "WiFi MAC 伪造配置", ""},
            // 云控 / CPH
            {"/cphnative", "CPH 云机 native", ""},
            {"/data/local/tmp/com.cloudecalc.control.version", "CloudECalc 版本标记", ""},
            {"/sdcard/Android/data/com.cloudecalc.control", "CloudECalc 数据目录", ""},
            // 传统 Xposed
            {"/system/framework/XposedBridge.jar", "Xposed 框架 jar", ""},
            {"/system/lib64/libxposed_art.so", "Xposed ART 注入库", ""},
    };

    // ---- 3. 磁盘 build.prop 逐键比对的身份键 ----
    private static final String[] IDENTITY_PROP_KEYS = {
            "ro.product.model", "ro.product.brand", "ro.product.device", "ro.product.name",
            "ro.product.manufacturer", "ro.build.fingerprint", "ro.build.version.release",
            "ro.build.version.incremental", "ro.build.display.id", "ro.build.id",
            "ro.product.vendor.model", "ro.product.vendor.brand", "ro.soc.model",
            "ro.board.platform", "ro.serialno",
    };

    // boot classpath 合法条目前缀
    private static final String[] LEGIT_BCP_PREFIXES = {
            "/apex/", "/system/framework/", "/system_ext/framework/",
    };

    // maps 里 .so 合法后端前缀
    private static final String[] LEGIT_SO_PREFIXES = {
            "/apex/", "/system/lib", "/system/lib64", "/system_ext/lib", "/product/lib",
            "/vendor/lib", "/odm/lib", "/data/app/", "/data/dalvik-cache/",
    };

    // maps 里 dex/jar/oat/vdex/art 合法后端前缀
    private static final String[] LEGIT_DEX_PREFIXES = {
            "/apex/", "/system/framework/", "/system_ext/framework/", "/system/app/",
            "/system/priv-app/", "/product/", "/vendor/", "/data/dalvik-cache/",
            "/data/misc/apexdata/", "/data/app/",
    };

    public DeviceSpoofDetector(Context context) {
        this.context = context.getApplicationContext();
        this.nativeDetector = NativeDetector.getInstance();
    }

    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(detectSpoofToolPackages());
        items.add(detectSpoofArtifactPaths());
        items.add(detectBuildPropDiskVsRuntime());
        items.add(detectBootClasspathDex());
        items.add(detectSystemLibInjection());
        items.add(detectPropHookCrossSource());
        items.add(detectIdentifierSpoofDrift());
        return items;
    }

    // ============================================================
    // 1. 已知改机/多开/Xposed/一键新机 工具包
    // ============================================================

    private DetectionItem detectSpoofToolPackages() {
        DetectionItem item = new DetectionItem("改机/多开/一键新机 工具包",
                "已知 Xposed 管理器/多开分身/云控/一键新机 App 包存在性(含伪装名)");
        try {
            PackageManager pm = context.getPackageManager();
            int hits = 0;
            for (String[] entry : SPOOF_TOOL_PACKAGES) {
                String pkg = entry[0], desc = entry[1];
                if (isPackageInstalled(pm, pkg)) {
                    hits++;
                    item.addDetectionDetail("🔴 " + desc, pkg,
                            "已安装该改机/多开/注入工具包", DetectionLayer.JAVA, "🔴");
                }
            }

            // 关键词扫描已安装包(可能受 QUERY_ALL_PACKAGES 限制, 命中为强证据)
            int kwHits = scanInstalledByKeyword(pm, item);

            if (hits == 0 && kwHits == 0) {
                item.addDetectionDetail("🟢 无已知工具包", "clean",
                        "未发现已知改机/多开/一键新机工具包(注: 包可见性可能受限)",
                        DetectionLayer.JAVA, "🟢");
            }
            item.addDetectionDetail("ℹ️ 说明", "Android 11+ 列全部包需 QUERY_ALL_PACKAGES",
                    "逐包 getPackageInfo 不受限, 但工具可改名/隐藏 → 与文件/框架痕迹合判",
                    DetectionLayer.JAVA, "ℹ️");

            int total = hits + kwHits;
            markJava(item, total > 0);
            if (total > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到 " + total + " 个改机/多开/一键新机工具包");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未发现已知工具包");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    private int scanInstalledByKeyword(PackageManager pm, DetectionItem item) {
        int kwHits = 0;
        String[] kws = {"xposed", "virtualapp", "dualspace", "parallel", "multidroid",
                "changer", "faker", "spoof", "godmode", "clone", "gamekiller"};
        try {
            List<android.content.pm.PackageInfo> pkgs = pm.getInstalledPackages(0);
            if (pkgs != null) {
                for (android.content.pm.PackageInfo pi : pkgs) {
                    if (pi == null || pi.packageName == null) continue;
                    String pn = pi.packageName.toLowerCase();
                    for (String kw : kws) {
                        if (pn.contains(kw)) {
                            kwHits++;
                            if (kwHits <= 8) {
                                item.addDetectionDetail("🔴 关键词命中", pi.packageName,
                                        "包名含改机/多开关键词 '" + kw + "'", DetectionLayer.JAVA, "🔴");
                            }
                            break;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return kwHits;
    }

    // ============================================================
    // 2. 改机工具留痕文件/目录 (跨层存在性)
    // ============================================================

    private DetectionItem detectSpoofArtifactPaths() {
        DetectionItem item = new DetectionItem("改机工具留痕文件/目录",
                "LSPosed/Zygisk/比特指纹/云控 落地路径存在性 + 跨层(libc vs syscall)一致");
        try {
            int present = 0, hookMismatch = 0;
            for (String[] entry : SPOOF_ARTIFACT_PATHS) {
                String path = entry[0], desc = entry[1];
                boolean rootOnly = entry.length > 2 && "root".equals(entry[2]);
                boolean libc = safeFileNative(path);
                boolean sys = safeFileSyscall(path);
                if (libc != sys) {
                    hookMismatch++;
                    item.addDetectionDetail("🔴 跨层不一致", path + "  libc=" + libc + " syscall=" + sys,
                            "同一路径 libc 与 syscall 存在性判断不同 —— 文件被 hook 隐藏(改机工具藏自己)",
                            DetectionLayer.SYSCALL, "🔴");
                } else if (libc) {
                    present++;
                    item.addDetectionDetail("🔴 " + desc, path + (rootOnly ? "  [存在]" : ""),
                            rootOnly ? "改机/注入框架目录存在(读内容需 root, 存在性即信号)"
                                    : "改机工具留痕文件存在", DetectionLayer.SYSCALL, "🔴");
                }
            }

            if (present == 0 && hookMismatch == 0) {
                item.addDetectionDetail("🟢 无留痕", "clean",
                        "未发现改机工具/注入框架落地路径", DetectionLayer.SYSCALL, "🟢");
            }

            boolean risk = present > 0 || hookMismatch > 0;
            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, risk);
            item.setLayerResult(DetectionLayer.SYSCALL, risk);
            if (hookMismatch > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("留痕路径存在性被 hook 隐藏 (" + hookMismatch + " 处跨层不一致)");
            } else if (present > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到 " + present + " 处改机工具/注入框架留痕");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未发现改机工具留痕路径");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 3. 磁盘 build.prop vs 运行期属性
    // ============================================================

    /**
     * resetprop/Xposed 改的是运行期属性(内存 prop_area / SystemProperties 返回值), 磁盘
     * /system/build.prop、/vendor/build.prop 不会同步。逐身份键比对"磁盘文件值" vs "运行期多源值":
     *   磁盘有值 && 运行期空/unknown         → 属性被删(resetprop --delete)
     *   磁盘值 != 运行期值                    → 属性被改(resetprop -n / Xposed hook)
     * 这是最易抓到"运行期伪造但磁盘漏同步"的一条。
     */
    private DetectionItem detectBuildPropDiskVsRuntime() {
        DetectionItem item = new DetectionItem("磁盘 build.prop vs 运行期属性",
                "逐键比对 /system/build.prop、/vendor/build.prop 磁盘值与运行期属性(resetprop/hook 破绽)");
        try {
            Map<String, String> disk = new LinkedHashMap<>();
            int filesRead = 0;
            for (String f : new String[]{"/system/build.prop", "/vendor/build.prop",
                    "/odm/etc/build.prop", "/product/build.prop", "/system_ext/etc/build.prop"}) {
                String content = readFileMultiSource(f);
                if (!isEmpty(content)) {
                    filesRead++;
                    parseProps(content, disk);
                }
            }

            if (filesRead == 0) {
                item.addDetectionDetail("⚪ 磁盘不可读", "0 个 build.prop",
                        "无法读取任一磁盘 build.prop(权限受限), 本项无法比对", DetectionLayer.SYSCALL, "⚪");
                markJava(item, false);
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("磁盘 build.prop 不可读, 无法比对");
                return item;
            }

            int changed = 0, deleted = 0, matched = 0;
            for (String key : IDENTITY_PROP_KEYS) {
                String dv = disk.get(key);
                if (isEmpty(dv)) continue; // 磁盘无此键, 跳过
                String rv = readProp(key);  // 运行期多源
                if (isEmpty(rv)) {
                    deleted++;
                    item.addDetectionDetail("🔴 属性被删", key + "  磁盘=" + dv + " 运行期=∅",
                            "磁盘 build.prop 有值但运行期读不到 —— resetprop --delete / hook 隐藏",
                            DetectionLayer.SYSCALL, "🔴");
                } else if (!dv.equals(rv)) {
                    changed++;
                    item.addDetectionDetail("🔴 属性被改", key + "  磁盘=" + dv + " ⇋ 运行期=" + rv,
                            "磁盘 build.prop 与运行期属性不一致 —— 运行期值被改机 hook 篡改",
                            DetectionLayer.SYSCALL, "🔴");
                } else {
                    matched++;
                }
            }

            if (changed == 0 && deleted == 0) {
                item.addDetectionDetail("🟢 磁盘=运行期", matched + " 键一致",
                        "所有磁盘身份键与运行期属性一致(" + filesRead + " 个 build.prop 已读)",
                        DetectionLayer.SYSCALL, "🟢");
            }

            boolean risk = (changed + deleted) > 0;
            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, risk);
            item.setLayerResult(DetectionLayer.SYSCALL, risk);
            if (risk) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("磁盘 vs 运行期脱节: 改 " + changed + " / 删 " + deleted + " —— 运行期属性被改机篡改");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("磁盘 build.prop 与运行期属性一致 (" + matched + " 键)");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 4. Boot class path 异常 / 匿名·memfd·非标准 location 的 dex (kFrameworkInBoot)
    // ============================================================

    private DetectionItem detectBootClasspathDex() {
        DetectionItem item = new DetectionItem("Boot dex 异常 (kFrameworkInBoot)",
                "$BOOTCLASSPATH 条目 + /proc/self/maps 里 boot/framework dex 的 location 是否规整");
        try {
            int problems = 0;

            // 4a. $BOOTCLASSPATH 逐条前缀校验
            String bcp = System.getenv("BOOTCLASSPATH");
            if (!isEmpty(bcp)) {
                int entries = 0, bad = 0;
                for (String jar : bcp.split(":")) {
                    jar = jar.trim();
                    if (jar.isEmpty()) continue;
                    entries++;
                    if (!hasPrefix(jar, LEGIT_BCP_PREFIXES)) {
                        bad++;
                        problems++;
                        item.addDetectionDetail("🔴 BCP 非标准条目", jar,
                                "boot classpath 出现非 /apex、非 /system framework 的条目 —— 疑似注入 framework",
                                DetectionLayer.JAVA, "🔴");
                    }
                }
                item.addDetectionDetail(bad == 0 ? "🟢 $BOOTCLASSPATH" : "🟡 $BOOTCLASSPATH",
                        entries + " 条目, " + bad + " 非标准",
                        "全部应指向 /apex 或 /system(_ext)/framework", DetectionLayer.JAVA,
                        bad == 0 ? "🟢" : "🟡");
            } else {
                item.addDetectionDetail("⚪ $BOOTCLASSPATH", "空",
                        "环境变量读不到(异常环境)", DetectionLayer.JAVA, "⚪");
            }

            // 4b. /proc/self/maps 里 dex/jar/oat/vdex/art 映射后端分类
            int anonDex = 0, memfdDex = 0, deletedDex = 0, oddPathDex = 0, legitDex = 0;
            try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"))) {
                String line;
                String ownApk = safeStr(() -> context.getApplicationInfo().sourceDir);
                String ownData = safeStr(() -> context.getApplicationInfo().dataDir);
                while ((line = br.readLine()) != null) {
                    String path = mapsPath(line);
                    if (path == null) continue;
                    String low = path.toLowerCase();
                    boolean isDexLike = low.endsWith(".dex") || low.endsWith(".jar")
                            || low.endsWith(".oat") || low.endsWith(".vdex") || low.endsWith(".art")
                            || low.endsWith(".odex")
                            || (low.startsWith("[anon:dalvik-") && (low.contains(".jar") || low.contains(".dex")
                                    || low.contains("classes") || low.contains("/framework/")));
                    if (!isDexLike) continue;
                    // [修正·FP] ART 启动/应用 image(.art)本就匿名映射,命名为
                    // [anon:dalvik-/system/framework/boot-*.art] 等 —— 每个 app(含完全干净的)都有 ~18 个,
                    // 是 zygote 预载的 boot image,不是注入。真注入是内存 .dex/.jar,不是 .art image。
                    // 不排除会把所有 app 误判为红(boot.art 普遍存在)。
                    if (low.contains(".art")) { legitDex++; continue; }
                    // 自身 apk / data 目录的 dex 合法
                    if (!isEmpty(ownApk) && path.startsWith(stripApkSuffix(ownApk))) { legitDex++; continue; }
                    if (!isEmpty(ownData) && path.startsWith(ownData)) { legitDex++; continue; }

                    if (path.contains("(deleted)")) {
                        deletedDex++; problems++;
                        addOnce(item, "🔴 deleted dex", trimPath(path),
                                "已删除文件的 dex/jar 仍映射在内存 —— 典型注入/替换痕迹", "🔴");
                    } else if (low.startsWith("memfd:") || low.contains("/memfd:")) {
                        memfdDex++; problems++;
                        addOnce(item, "🔴 memfd dex", trimPath(path),
                                "从匿名内存文件(memfd) 加载的 dex —— framework 注入常用手法", "🔴");
                    } else if (low.startsWith("[anon:")) {
                        anonDex++; problems++;
                        addOnce(item, "🔴 匿名 boot dex", trimPath(path),
                                "承载 framework/boot 的匿名 dex 映射 —— 疑似 kFrameworkInBoot 注入", "🔴");
                    } else if (path.startsWith("/") && !hasPrefix(path, LEGIT_DEX_PREFIXES)) {
                        oddPathDex++; problems++;
                        addOnce(item, "🔴 非标准 dex 路径", trimPath(path),
                                "dex/jar 从非系统/非 dalvik-cache 路径加载(如 /data/local/tmp)", "🔴");
                    } else {
                        legitDex++;
                    }
                }
            }
            item.addDetectionDetail(problems == 0 ? "🟢 dex 映射规整" : "🔴 dex 映射异常",
                    "合法=" + legitDex + " 匿名=" + anonDex + " memfd=" + memfdDex
                            + " deleted=" + deletedDex + " 异常路径=" + oddPathDex,
                    "/proc/self/maps dex/jar/oat 后端分类", DetectionLayer.SYSCALL,
                    problems == 0 ? "🟢" : "🔴");

            item.setLayerResult(DetectionLayer.JAVA, problems > 0);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, problems > 0);
            if (problems > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("boot/framework dex 出现匿名/memfd/deleted/非标准 location (" + problems + " 处) —— 疑似 framework 注入");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("boot classpath 与 dex 映射后端均规整");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 5. /proc/self/maps 伪装系统库 .so (路径/inode 异常)
    // ============================================================

    private DetectionItem detectSystemLibInjection() {
        DetectionItem item = new DetectionItem("伪装系统库 .so 注入",
                "/proc/self/maps 可执行 .so 后端路径/inode 异常 + 系统库名却非系统路径");
        try {
            int oddPath = 0, zeroInode = 0, masquerade = 0, injectLib = 0, legit = 0;
            // 已知注入库名(伪装/框架)
            String[] injectNames = {"liblspd", "liblsposed", "libriru", "libzygisk", "libmemtrack_real",
                    "libxposed", "libsandhook", "libwhale", "libfrida", "libsubstrate", "libepic"};
            // 常被冒名的系统库
            String[] systemLibNames = {"libc.so", "libart.so", "libandroid_runtime.so",
                    "libbinder.so", "libcutils.so", "libutils.so"};

            String ownApk = safeStr(() -> context.getApplicationInfo().sourceDir);
            String ownData = safeStr(() -> context.getApplicationInfo().dataDir);

            try (BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"))) {
                String line;
                while ((line = br.readLine()) != null) {
                    // 只看可执行段
                    if (!line.contains(" r-xp ") && !line.contains(" rwxp ")) continue;
                    String path = mapsPath(line);
                    if (path == null) continue;
                    String low = path.toLowerCase();
                    if (!low.endsWith(".so") && !low.contains(".so ") && !low.matches(".*\\.so.*")) {
                        // 只关心 .so 或伪装成 .so 的具名段
                        if (!low.startsWith("[anon:") ) continue;
                    }
                    String base = baseName(path);

                    // 注入框架库名
                    boolean isInject = false;
                    for (String n : injectNames) {
                        if (base.toLowerCase().contains(n)) { isInject = true; break; }
                    }
                    if (isInject) {
                        injectLib++;
                        addOnce(item, "🔴 注入库", trimPath(path),
                                "已知 Hook/注入框架 .so 加载在进程内", "🔴");
                        continue;
                    }

                    // 自身 native 库合法
                    if ((!isEmpty(ownApk) && path.startsWith(stripApkSuffix(ownApk)))
                            || (!isEmpty(ownData) && path.startsWith(ownData))) { legit++; continue; }

                    // 系统库名却非系统路径 = 伪装
                    boolean isSysName = false;
                    for (String n : systemLibNames) { if (base.equals(n)) { isSysName = true; break; } }
                    if (isSysName && path.startsWith("/") && !hasPrefix(path, LEGIT_SO_PREFIXES)) {
                        masquerade++;
                        addOnce(item, "🔴 伪装系统库", base + " @ " + trimPath(path),
                                "系统库名却从非系统路径加载 —— 冒充系统库的注入 .so", "🔴");
                        continue;
                    }

                    // (deleted) / memfd / inode=0 具名 .so
                    long inode = mapsInode(line);
                    if (path.contains("(deleted)") || low.startsWith("memfd:") || low.contains("/memfd:")) {
                        oddPath++;
                        addOnce(item, "🔴 异常后端库", trimPath(path),
                                "可执行 .so 从 deleted/memfd 后端加载 —— 注入痕迹", "🔴");
                    } else if (path.startsWith("/") && low.endsWith(".so")
                            && !hasPrefix(path, LEGIT_SO_PREFIXES)) {
                        oddPath++;
                        addOnce(item, "🔴 非标准库路径", trimPath(path),
                                "可执行 .so 从非系统/非自身路径加载(如 /data/local/tmp)", "🔴");
                    } else if (inode == 0 && low.endsWith(".so") && path.startsWith("/")) {
                        zeroInode++;
                        addOnce(item, "🔴 inode=0 库", trimPath(path),
                                "具名 .so 映射 inode 为 0 —— 文件已删/匿名后端伪装", "🔴");
                    } else {
                        legit++;
                    }
                }
            }

            // maps 跨层 hash 一致性(过滤 maps 隐藏注入库的反证)
            String mapsN = safeStr(() -> nativeDetector.getMapsHashNative());
            String mapsS = safeStr(() -> nativeDetector.getMapsHashSyscall());
            boolean mapsDivergent = false;
            if (!isEmpty(mapsN) && !isEmpty(mapsS) && !mapsN.equals(mapsS)) {
                mapsDivergent = true;
                item.addDetectionDetail("🔴 maps 跨层不一致", "N=" + mapsN + " S=" + mapsS,
                        "libc opendir vs syscall getdents 读 maps 名单不同 —— maps 被过滤(藏注入库)",
                        DetectionLayer.SYSCALL, "🔴");
            }

            int problems = oddPath + zeroInode + masquerade + injectLib + (mapsDivergent ? 1 : 0);
            if (problems == 0) {
                item.addDetectionDetail("🟢 库映射干净", "合法 " + legit + " 段",
                        "无伪装/注入/异常后端 .so, maps 跨层一致", DetectionLayer.SYSCALL, "🟢");
            }

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, problems > 0);
            item.setLayerResult(DetectionLayer.SYSCALL, problems > 0);
            if (problems > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("发现伪装/注入 .so (" + problems + " 处): 注入" + injectLib
                        + " 伪装" + masquerade + " 异常后端" + oddPath + " inode0=" + zeroInode);
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("可执行库映射均来自系统/自身路径, 无伪装注入");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 6. 属性内核边界 vs libc 交叉 (改机 hook 判定)
    // ============================================================

    /**
     * __system_property_get(libc) 可被 inline-hook, 但直接 mmap /dev/__properties__ 内核属性区读到
     * 未经 libc 的原始值。两路对身份键不一致 = libc 属性读被改机 hook。与 DeviceConsistencyDetector 的
     * 6 源机型自洽去重: 本项只挑 "libc vs 内核边界 vs foreach" 的 delta, 以改机 hook 口径定级。
     */
    private DetectionItem detectPropHookCrossSource() {
        DetectionItem item = new DetectionItem("属性 hook 交叉 (libc vs 内核区)",
                "__system_property_get vs mmap /dev/__properties__ vs foreach 对身份键取值差异");
        try {
            int mismatch = 0;

            // native 侧聚合: mmap vs __system_property_get 对 5 关键属性的 mismatch 计数
            int nativeMm = -1;
            try { nativeMm = nativeDetector.checkPropertyMmapConsistency(); } catch (Throwable ignore) {}
            if (nativeMm > 0) {
                mismatch += nativeMm;
                item.addDetectionDetail("🔴 mmap vs libc", nativeMm + " 键不一致",
                        "checkPropertyMmapConsistency: 内核属性区与 __system_property_get 取值不同 —— libc 属性 hook",
                        DetectionLayer.NATIVE, "🔴");
            } else if (nativeMm == 0) {
                item.addDetectionDetail("🟢 mmap vs libc", "0 键不一致",
                        "内核属性区与 libc 一致", DetectionLayer.NATIVE, "🟢");
            }

            // 逐身份键三路: DP(内核 mmap) vs N(libc) vs FE(foreach)
            String[] keys = {"ro.product.model", "ro.product.brand", "ro.build.fingerprint",
                    "ro.serialno", "ro.product.device"};
            for (String key : keys) {
                String dp = safe(nativeDetector.readDevPropertyMmap(key)); // 内核边界
                String n = safe(nativeDetector.getBuildPropertyNative(key)); // libc
                String fe = safe(nativeDetector.getPropForeachNative(key));   // foreach 不同入口
                // 取第一非空基准
                String base = firstNonEmpty(dp, n, fe);
                if (isEmpty(base)) continue;
                StringBuilder diff = new StringBuilder();
                if (!isEmpty(dp) && !dp.equals(base)) diff.append("DP=").append(dp).append(" ");
                if (!isEmpty(n) && !n.equals(base)) diff.append("N=").append(n).append(" ");
                if (!isEmpty(fe) && !fe.equals(base)) diff.append("FE=").append(fe).append(" ");
                boolean bad = diff.length() > 0;
                if (bad) {
                    mismatch++;
                    item.addDetectionDetail("🔴 " + key, "base=" + base + "  分歧: " + diff,
                            "DP=内核 /dev/__properties__  N=libc  FE=foreach; 分歧= 部分读路被改机 hook 漏改",
                            DetectionLayer.SYSCALL, "🔴");
                }
            }

            if (mismatch == 0) {
                item.addDetectionDetail("🟢 属性读路一致", "clean",
                        "内核区/libc/foreach 对身份键取值一致(未见 libc 属性 hook, 或沙箱已做内核级统一)",
                        DetectionLayer.SYSCALL, "🟢");
            }
            item.addDetectionDetail("ℹ️ 说明", "本条对纯 libc/Java hook 强, 对内核级统一伪造弱",
                    "若沙箱在内核属性区就统一改值, 三路一致 → 本条漏报(反证沙箱做到了内核级)",
                    DetectionLayer.SYSCALL, "ℹ️");

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, mismatch > 0);
            item.setLayerResult(DetectionLayer.SYSCALL, mismatch > 0);
            if (mismatch > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("属性读路交叉不一致 (" + mismatch + " 处) —— libc 属性被改机 hook");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("内核区/libc/foreach 属性读路一致");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 7. 设备标识符多源漂移 (serial / android_id / device-tree)
    // ============================================================

    private DetectionItem detectIdentifierSpoofDrift() {
        DetectionItem item = new DetectionItem("设备标识符多源漂移",
                "serial(Build/ro.serialno/ro.boot.serialno/device-tree) 与 android_id 多源一致性");
        try {
            int problems = 0;

            // serial 多源
            String buildSerial = "";
            try { buildSerial = safe(Build.getSerial()); }
            catch (SecurityException se) { buildSerial = "受限"; }
            catch (Throwable ignore) {}
            String roSerial = readProp("ro.serialno");
            String bootSerial = readProp("ro.boot.serialno");
            String dtSerial = firstNonEmpty(safe(nativeDetector.getDeviceTreeSerialNative()),
                    safe(nativeDetector.getDeviceTreeSerialSyscall()));

            item.addDetectionDetail("🔑 Build.getSerial", nz(buildSerial),
                    "需 READ_PHONE_STATE, 普通 app 常返 unknown", DetectionLayer.JAVA, "📊");
            item.addDetectionDetail("🔑 ro.serialno", nz(roSerial), "属性 serial", DetectionLayer.SYSCALL, "📊");
            item.addDetectionDetail("🔑 ro.boot.serialno", nz(bootSerial), "bootloader serial", DetectionLayer.SYSCALL, "📊");
            item.addDetectionDetail("🔑 device-tree serial", nz(dtSerial),
                    "/proc/device-tree/serial-number(硬件锚点, 难伪造)", DetectionLayer.SYSCALL, "📊");

            // 收集非空 serial 的不同值
            List<String> serials = new ArrayList<>();
            for (String s : new String[]{buildSerial, roSerial, bootSerial, dtSerial}) {
                if (!isEmpty(s) && !s.equals("受限") && !s.equalsIgnoreCase("unknown")
                        && !serials.contains(s.toLowerCase())) {
                    serials.add(s.toLowerCase());
                }
            }
            if (serials.size() >= 2) {
                problems++;
                item.addDetectionDetail("🔴 serial 漂移", serials.size() + " 个不同值",
                        "不同读取路径给出不同 serial —— 改机工具只改了部分 serial 源", DetectionLayer.SYSCALL, "🔴");
            }
            // device-tree 有真 serial 但 ro.serialno 被抹/改
            if (!isEmpty(dtSerial) && !dtSerial.equalsIgnoreCase("unknown")) {
                if (!isEmpty(roSerial) && !roSerial.equalsIgnoreCase(dtSerial)) {
                    problems++;
                    item.addDetectionDetail("🔴 serial 与硬件锚点冲突",
                            "device-tree=" + dtSerial + " ro.serialno=" + roSerial,
                            "属性 serial 与 device-tree 硬件 serial 不符 —— serial 被伪造", DetectionLayer.SYSCALL, "🔴");
                }
            }

            // android_id 格式
            try {
                ContentResolver cr = context.getContentResolver();
                String aid = Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID);
                if (!isEmpty(aid)) {
                    boolean fmtOk = aid.matches("[0-9a-fA-F]{16}");
                    item.addDetectionDetail(fmtOk ? "🟢 android_id" : "🟡 android_id",
                            aid.length() == 16 ? aid : aid + " (len=" + aid.length() + ")",
                            "Settings.Secure.ANDROID_ID 应为 16 位 hex", DetectionLayer.JAVA,
                            fmtOk ? "🟢" : "🟡");
                }
            } catch (Throwable ignore) {}

            item.addDetectionDetail("ℹ️ 每-app 漂移", "单 app 检测器无法直接观测跨 app 不同值",
                    "一键新机的'每 app 不同标识符'需服务端跨 app 关联或双进程构造, app 层此处为盲区",
                    DetectionLayer.JAVA, "ℹ️");

            item.setLayerResult(DetectionLayer.JAVA, problems > 0);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, problems > 0);
            if (problems > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("设备标识符多源漂移 (" + problems + " 处) —— serial 被部分伪造");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("设备标识符多源一致(或不可读, 无冲突)");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // Helpers
    // ============================================================

    /** 运行期属性多源读: libc → build.prop(syscall) → SystemProperties 反射 → dev/__properties__ mmap。 */
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

    /** 读文件多源: syscall → libc kernel read → Java。 */
    private String readFileMultiSource(String path) {
        String v = safeStr(() -> nativeDetector.readFileSyscall(path));
        if (!isEmpty(v)) return v;
        v = safeStr(() -> nativeDetector.readKernelFile(path));
        if (!isEmpty(v)) return v;
        v = safeStr(() -> ReflectionUtils.readFile(path));
        return isEmpty(v) ? "" : v;
    }

    /** 解析 build.prop 的 key=value(忽略注释), 只在 key 未存在时写入(首见优先)。 */
    private static void parseProps(String content, Map<String, String> out) {
        for (String line : content.split("\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            int eq = line.indexOf('=');
            if (eq <= 0) continue;
            String k = line.substring(0, eq).trim();
            String val = line.substring(eq + 1).trim();
            if (!k.isEmpty() && !out.containsKey(k)) out.put(k, val);
        }
    }

    /** 从 /proc/self/maps 行取路径(第 6 列起), 无路径返回 null。 */
    private static String mapsPath(String line) {
        // 格式: addr perms offset dev inode  pathname
        int idx = -1, spaces = 0;
        // 找到第 5 个空白后的内容(pathname 可能含空格如 (deleted))
        int col = 0;
        for (int i = 0; i < line.length(); i++) {
            if (line.charAt(i) == ' ') {
                // skip consecutive
                while (i + 1 < line.length() && line.charAt(i + 1) == ' ') i++;
                col++;
                if (col == 5) { idx = i + 1; break; }
            }
        }
        if (idx < 0 || idx >= line.length()) return null;
        String p = line.substring(idx).trim();
        if (p.isEmpty()) return null;
        return p;
    }

    /** 从 maps 行取 inode(第 5 列)。 */
    private static long mapsInode(String line) {
        try {
            String[] parts = line.trim().split("\\s+");
            if (parts.length >= 5) return Long.parseLong(parts[4]);
        } catch (Throwable ignore) {}
        return -1;
    }

    private static boolean hasPrefix(String s, String[] prefixes) {
        for (String p : prefixes) if (s.startsWith(p)) return true;
        return false;
    }

    /** 去掉 apk 的 base.apk 尾部, 得安装目录前缀(用于匹配自身 dex/so)。 */
    private static String stripApkSuffix(String apk) {
        int idx = apk.lastIndexOf('/');
        return idx > 0 ? apk.substring(0, idx) : apk;
    }

    private static String baseName(String path) {
        String p = path;
        int sp = p.indexOf(" (deleted)");
        if (sp > 0) p = p.substring(0, sp);
        int idx = p.lastIndexOf('/');
        return idx >= 0 ? p.substring(idx + 1) : p;
    }

    private static String trimPath(String p) {
        return p.length() > 90 ? "..." + p.substring(p.length() - 87) : p;
    }

    // 同类 detail 去重(避免同一异常刷屏), 最多每类 6 条
    private final Map<String, Integer> addOnceCounter = new LinkedHashMap<>();
    private void addOnce(DetectionItem item, String category, String value, String note, String icon) {
        int c = addOnceCounter.getOrDefault(category, 0);
        if (c < 6) {
            item.addDetectionDetail(category, value, note, DetectionLayer.SYSCALL, icon);
            addOnceCounter.put(category, c + 1);
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

    private boolean safeFileNative(String path) {
        try { return nativeDetector.fileExistsNative(path); } catch (Throwable t) { return false; }
    }

    private boolean safeFileSyscall(String path) {
        try { return nativeDetector.fileExistsSyscall(path); } catch (Throwable t) { return false; }
    }

    private interface StrSupplier { String get() throws Throwable; }

    private static String safeStr(StrSupplier s) {
        try { String v = s.get(); return v == null ? "" : v; } catch (Throwable t) { return ""; }
    }

    private void markJava(DetectionItem item, boolean detected) {
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

    private static String nz(String s) {
        return isEmpty(s) ? "(空)" : s;
    }

    private void unknown(DetectionItem item, Throwable t) {
        item.setLayerResult(DetectionLayer.JAVA, false);
        item.setLayerResult(DetectionLayer.NATIVE, false);
        item.setLayerResult(DetectionLayer.SYSCALL, false);
        item.setStatus(DetectionStatus.UNKNOWN);
        item.setDetail("检测异常: " + (t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName()));
    }
}
