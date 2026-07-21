package com.xff.launch.detector;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.display.DisplayManager;
import android.os.Build;
import android.util.DisplayMetrics;
import android.view.Display;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;
import com.xff.launch.util.ReflectionUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 机型一致性检测。
 *
 * <p>针对"每-app 维度伪造 Build/system property/机型元数据"的沙箱：真实机型在系统的每个
 * 数据源(Java Build 字段 / SystemProperties 反射 / libc __system_property_get / 直读 build.prop /
 * mmap /dev/__properties__ / __system_property_foreach)以及每个分区(system/vendor/odm/product/
 * system_ext/bootimage)上都是"自洽"的。沙箱只在部分 hook 点改值时，会在这些交叉源之间露出裂缝。
 *
 * <p>参照真机(OnePlus 11 CPH2451/OP594DL1, salami, SoC SM8550/kalama, OxygenOS 13)的真实 getprop
 * 结构：
 * <ul>
 *   <li>ro.product.model=CPH2451, brand=OnePlus, device=OP594DL1（main / vendor / odm / bootimage 一致）</li>
 *   <li>ro.product.system.* / product.* / system_ext.* = oplus / ossi（通用分区身份）</li>
 *   <li>ro.system.build.fingerprint = oplus/ossi/ossi:13/...；ro.vendor/odm.build.fingerprint = OnePlus/CPH2451/...</li>
 *   <li>ro.soc.model=SM8550, ro.soc.manufacturer=QTI, ro.board.platform=kalama, ro.hardware=qcom</li>
 * </ul>
 * 沙箱要完美伪造 OxygenOS，必须在所有源 + 所有分区复刻这套结构，任一遗漏即被本组抓到。
 */
public class DeviceConsistencyDetector {

    private final Context context;
    private final NativeDetector nativeDetector;

    // 已知机型 → 期望 SoC / 平台。用于"Build.MODEL 声称的机型" vs "真实硬件平台"交叉校验。
    // 值来自真机 build.prop（OnePlus 11 = SM8550 / kalama）。
    private static final Map<String, String[]> MODEL_SOC = new LinkedHashMap<>();
    static {
        // model 前缀 → {expectSoc, expectPlatform, 屏幕WxH, 期望dpi(近似), 家族}
        MODEL_SOC.put("CPH2447", new String[]{"SM8550", "kalama"}); // OnePlus 11 国际
        MODEL_SOC.put("CPH2449", new String[]{"SM8550", "kalama"}); // OnePlus 11 印度
        MODEL_SOC.put("CPH2451", new String[]{"SM8550", "kalama"}); // OnePlus 11 美版
        MODEL_SOC.put("PHB110",  new String[]{"SM8550", "kalama"}); // OnePlus 11 国行
    }

    public DeviceConsistencyDetector(Context context) {
        this.context = context.getApplicationContext();
        this.nativeDetector = NativeDetector.getInstance();
    }

    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(detectPropCrossLayer());
        items.add(detectPartitionProps());
        items.add(detectFingerprintPartitions());
        items.add(detectSocConsistency());
        items.add(detectVersionConsistency());
        items.add(detectDisplayConsistency());
        items.add(detectHwProfileConsistency());
        return items;
    }

    // ============================================================
    // 1. Build 字段多源交叉校验（每-app hook 漏路检测）
    // ============================================================

    /**
     * 对每个关键属性，从 6 条独立读取路径取值并比对：
     *   J  = android.os.Build 字段（Java）
     *   SP = android.os.SystemProperties.get 反射
     *   N  = libc __system_property_get（native）
     *   BP = 直读 build.prop（syscall）
     *   DP = mmap /dev/__properties__ 内核属性区（syscall，绕 libc/Java hook）
     *   FE = __system_property_foreach 全量遍历（native，不同 libc 入口）
     * 真机所有非空路径必一致；任一路径的值 ≠ 其它非空路径 → 沙箱漏了这条读路 = RISK。
     */
    private DetectionItem detectPropCrossLayer() {
        DetectionItem item = new DetectionItem("Build 字段多源交叉校验",
                "同一属性经 Java/SystemProperties/libc/build.prop/dev-properties/foreach 6 路读取比对");
        try {
            // {属性名, 对应 Build 字段(可空)}
            String[][] props = {
                    {"ro.product.model", "MODEL"},
                    {"ro.product.brand", "BRAND"},
                    {"ro.product.device", "DEVICE"},
                    {"ro.product.name", "PRODUCT"},
                    {"ro.product.manufacturer", "MANUFACTURER"},
                    {"ro.build.fingerprint", "FINGERPRINT"},
                    {"ro.hardware", "HARDWARE"},
                    {"ro.build.version.release", null},
            };

            int mismatches = 0;
            for (String[] p : props) {
                String key = p[0];
                String buildField = p[1];

                Map<String, String> sources = new LinkedHashMap<>();
                if (buildField != null) sources.put("J", ReflectionUtils.getBuildField(buildField));
                sources.put("SP", safe(ReflectionUtils.getSystemProperty(key)));
                sources.put("N", safe(nativeDetector.getBuildPropertyNative(key)));
                sources.put("BP", safe(nativeDetector.getBuildPropertySyscall(key)));
                sources.put("DP", safe(nativeDetector.readDevPropertyMmap(key)));
                sources.put("FE", safe(nativeDetector.getPropForeachNative(key)));

                // 取第一条非空值做基准
                String base = null;
                for (String v : sources.values()) {
                    if (!isEmpty(v)) { base = v; break; }
                }
                if (base == null) continue; // 全空，跳过

                StringBuilder divergent = new StringBuilder();
                for (Map.Entry<String, String> e : sources.entrySet()) {
                    String v = e.getValue();
                    if (isEmpty(v)) continue;
                    if (!v.equals(base)) {
                        divergent.append(e.getKey()).append("=").append(v).append("  ");
                    }
                }

                boolean bad = divergent.length() > 0;
                if (bad) mismatches++;
                String icon = bad ? "🔴" : "🟢";
                String valueLine = "base(" + firstNonEmptyKey(sources) + ")=" + base
                        + (bad ? "  ⇋ 分歧: " + divergent : "  [6源一致]");
                item.addDetectionDetail(bad ? "❌ " + key : "✅ " + key,
                        valueLine,
                        "J=Build SP=SystemProperties N=libc BP=build.prop DP=dev/__properties__ FE=foreach",
                        DetectionLayer.SYSCALL, icon);
            }

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, mismatches > 0);
            item.setLayerResult(DetectionLayer.SYSCALL, mismatches > 0);
            if (mismatches > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到 " + mismatches + " 个属性在不同读取路径间取值不一致 —— 每-app 属性 hook 漏了部分读路");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("所有关键属性 6 路读取完全一致");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 2. 分区 ro.product.* 自洽
    // ============================================================

    /**
     * 读 ro.product.{,system.,vendor.,odm.,product.,system_ext.,bootimage.}{brand,device,model}
     * 并比对分区间关系。真机 OxygenOS 有确定结构：
     *   vendor / odm / bootimage / main = OnePlus / OP594DL1 / CPH24xx（"厂商身份"组）
     *   system / product / system_ext   = oplus / ossi / ossi（"通用身份"组）
     * 沙箱若只改了 main（Build.* 走的那个）而漏了 vendor/odm 分区，或全部改成同一个值破坏了
     * 真机的双组结构，即暴露。同时任一分区若仍残留 lineage/aosp/calyx 身份 = 伪装反证。
     */
    private DetectionItem detectPartitionProps() {
        DetectionItem item = new DetectionItem("分区 ro.product.* 自洽",
                "system/vendor/odm/product/system_ext/bootimage 各分区机型身份是否自洽");
        try {
            String[] partitions = {"", "system.", "vendor.", "odm.", "product.", "system_ext.", "bootimage."};
            String[] fields = {"brand", "device", "model"};

            String vendorBrand = readProp("ro.product.vendor.brand");
            String odmBrand = readProp("ro.product.odm.brand");
            String mainBrand = readProp("ro.product.brand");

            int problems = 0;
            for (String field : fields) {
                StringBuilder row = new StringBuilder();
                List<String> distinct = new ArrayList<>();
                for (String part : partitions) {
                    String key = "ro.product." + part + field;
                    String val = readProp(key);
                    row.append(part.isEmpty() ? "main" : part.replace(".", "")).append("=")
                            .append(isEmpty(val) ? "∅" : val).append("  ");
                    if (!isEmpty(val) && !distinct.contains(val.toLowerCase())) {
                        distinct.add(val.toLowerCase());
                    }
                    // 伪装反证：任何分区残留非 OEM 身份
                    if (!isEmpty(val)) {
                        String lv = val.toLowerCase();
                        if (lv.contains("lineage") || lv.contains("aosp") || lv.contains("calyx")
                                || lv.contains("crdroid") || lv.contains("evolution")) {
                            problems++;
                            item.addDetectionDetail("🔴 伪装反证", key + "=" + val,
                                    "分区仍残留自定义 ROM 身份，与声称的 OEM 机型矛盾",
                                    DetectionLayer.SYSCALL, "🔴");
                        }
                    }
                }
                item.addDetectionDetail("📊 " + field, row.toString().trim(),
                        "真机 OxygenOS: vendor/odm/main=OEM 身份, system/product/system_ext=通用(oplus/ossi)",
                        DetectionLayer.SYSCALL, "📊");
            }

            // 关键关系校验：厂商身份组的 vendor/odm 分区不能为空且应与 main 同族
            boolean vendorMissing = isEmpty(vendorBrand) || isEmpty(odmBrand);
            if (vendorMissing && !isEmpty(mainBrand)) {
                problems++;
                item.addDetectionDetail("🔴 分区缺失",
                        "vendor.brand=" + nz(vendorBrand) + " odm.brand=" + nz(odmBrand),
                        "main 声称 " + mainBrand + " 但 vendor/odm 分区品牌缺失 —— 真机绝不会缺",
                        DetectionLayer.SYSCALL, "🔴");
            } else if (!isEmpty(mainBrand) && !isEmpty(vendorBrand)
                    && !mainBrand.equalsIgnoreCase(vendorBrand)) {
                problems++;
                item.addDetectionDetail("🔴 品牌冲突",
                        "main=" + mainBrand + " vendor=" + vendorBrand,
                        "main 与 vendor 分区品牌不一致 —— 每-app 只改了部分分区",
                        DetectionLayer.SYSCALL, "🔴");
            }

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, problems > 0);
            item.setLayerResult(DetectionLayer.SYSCALL, problems > 0);
            if (problems > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("分区机型身份不自洽 (" + problems + " 项) —— 伪装未覆盖全部分区");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("各分区机型身份自洽");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 3. 分区 build.fingerprint 结构
    // ============================================================

    /**
     * 真机每个分区各有自己的 build.fingerprint：
     *   ro.build.fingerprint / ro.bootimage / ro.vendor / ro.odm = OnePlus/CPH2451/OP594DL1:13/...
     *   ro.system.build.fingerprint                              = oplus/ossi/ossi:13/...
     * 沙箱若只 hook 了 Build.FINGERPRINT（= ro.build.fingerprint）而漏了 ro.system/vendor/odm
     * 各分区指纹，或把它们全设成同一串，即与真机双结构矛盾。
     */
    private DetectionItem detectFingerprintPartitions() {
        DetectionItem item = new DetectionItem("分区 build.fingerprint 结构",
                "system/vendor/odm/bootimage 各分区指纹格式与自洽性");
        try {
            String[] keys = {
                    "ro.build.fingerprint",
                    "ro.system.build.fingerprint",
                    "ro.vendor.build.fingerprint",
                    "ro.odm.build.fingerprint",
                    "ro.bootimage.build.fingerprint",
                    "ro.product.build.fingerprint",
            };
            int problems = 0;
            String mainFp = readProp("ro.build.fingerprint");
            for (String key : keys) {
                String fp = readProp(key);
                if (isEmpty(fp)) {
                    // 主指纹存在但分区指纹缺失（system/vendor 尤其不该缺）
                    if (!isEmpty(mainFp) && (key.contains("system") || key.contains("vendor"))) {
                        problems++;
                        item.addDetectionDetail("🟡 " + key, "(缺失)",
                                "真机该分区应有独立指纹，缺失说明伪装未覆盖", DetectionLayer.SYSCALL, "🟡");
                    }
                    continue;
                }
                boolean formatOk = fp.split("/").length >= 3 && fp.contains(":");
                if (!formatOk) problems++;
                item.addDetectionDetail(formatOk ? "🟢 " + key : "🔴 " + key, fp,
                        "格式: brand/product/device:release/id/incremental:type/tags",
                        DetectionLayer.SYSCALL, formatOk ? "🟢" : "🔴");
            }

            // 结构校验：system 指纹的 SDK/release 段应与主指纹一致（版本必须同步）
            String sysFp = readProp("ro.system.build.fingerprint");
            if (!isEmpty(mainFp) && !isEmpty(sysFp)) {
                String mainRel = fpReleaseSegment(mainFp);
                String sysRel = fpReleaseSegment(sysFp);
                if (!isEmpty(mainRel) && !isEmpty(sysRel) && !mainRel.equals(sysRel)) {
                    problems++;
                    item.addDetectionDetail("🔴 版本段冲突",
                            "main:" + mainRel + " vs system:" + sysRel,
                            "主指纹与 system 分区指纹的 Android 版本段不一致", DetectionLayer.SYSCALL, "🔴");
                }
            }

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, problems > 0);
            item.setLayerResult(DetectionLayer.SYSCALL, problems > 0);
            if (problems > 0) {
                item.setStatus(problems >= 2 ? DetectionStatus.RISK : DetectionStatus.WARNING);
                item.setDetail("分区指纹结构异常 (" + problems + " 项)");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("各分区指纹格式与版本自洽");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 4. SoC / Board vs 声称机型
    // ============================================================

    /**
     * 交叉 ro.board.platform / ro.soc.model / ro.soc.manufacturer / ro.hardware /
     * /proc/cpuinfo(Hardware) 与 Build.MODEL 声称的机型应有 SoC。
     * 声称 OnePlus 11(CPH24xx) → 必须 SoC=SM8550 & platform=kalama。
     * 注：若沙箱跑在真机 8Gen2 上，此项会通过（硬件真实）；跑在异构硬件/模拟器上则暴露。
     */
    private DetectionItem detectSocConsistency() {
        DetectionItem item = new DetectionItem("SoC/Board vs 机型",
                "ro.board.platform / ro.soc.model / cpuinfo 与声称机型应有芯片是否匹配");
        try {
            String model = firstNonEmpty(ReflectionUtils.getBuildField("MODEL"), readProp("ro.product.model"));
            String board = readProp("ro.board.platform");
            String socModel = readProp("ro.soc.model");
            String socMfr = readProp("ro.soc.manufacturer");
            String hardware = readProp("ro.hardware");
            String cpuinfoHw = firstNonEmpty(safe(nativeDetector.getCpuHardware()),
                    safe(nativeDetector.getCpuHardwareSyscall()));

            item.addDetectionDetail("📱 声称机型", nz(model), "Build.MODEL / ro.product.model", DetectionLayer.JAVA, "📊");
            item.addDetectionDetail("🔧 ro.board.platform", nz(board), "SoC 平台代号", DetectionLayer.SYSCALL, "📊");
            item.addDetectionDetail("🔧 ro.soc.model", nz(socModel), "SoC 型号", DetectionLayer.SYSCALL, "📊");
            item.addDetectionDetail("🔧 ro.soc.manufacturer", nz(socMfr), "SoC 厂商", DetectionLayer.SYSCALL, "📊");
            item.addDetectionDetail("🔧 ro.hardware", nz(hardware), "硬件平台", DetectionLayer.SYSCALL, "📊");
            item.addDetectionDetail("🔧 cpuinfo Hardware", nz(cpuinfoHw), "/proc/cpuinfo", DetectionLayer.SYSCALL, "📊");

            int problems = 0;
            String[] expect = matchModelSoc(model);
            if (expect != null) {
                if (!isEmpty(socModel) && !socModel.equalsIgnoreCase(expect[0])) {
                    problems++;
                    item.addDetectionDetail("🔴 SoC 不符", "期望 " + expect[0] + " 实为 " + socModel,
                            "声称机型的 SoC 与真实 ro.soc.model 不符", DetectionLayer.SYSCALL, "🔴");
                }
                if (!isEmpty(board) && !board.equalsIgnoreCase(expect[1])) {
                    problems++;
                    item.addDetectionDetail("🔴 平台不符", "期望 " + expect[1] + " 实为 " + board,
                            "声称机型的平台代号与 ro.board.platform 不符", DetectionLayer.SYSCALL, "🔴");
                }
                if (problems == 0) {
                    item.addDetectionDetail("🟢 SoC 匹配", expect[0] + " / " + expect[1],
                            "声称机型与真实 SoC/平台一致", DetectionLayer.SYSCALL, "🟢");
                }
            } else {
                item.addDetectionDetail("⚪ 机型未在库", nz(model),
                        "机型不在内置 SoC 映射表，仅做内部自洽校验", DetectionLayer.JAVA, "⚪");
            }

            // 内部自洽：ro.soc.manufacturer=QTI/Qualcomm 时 ro.hardware 应为 qcom，board 非空
            if (!isEmpty(socMfr) && (socMfr.equalsIgnoreCase("QTI") || socMfr.toLowerCase().contains("qual"))) {
                if (!isEmpty(hardware) && !hardware.toLowerCase().contains("qcom")) {
                    problems++;
                    item.addDetectionDetail("🔴 平台内部冲突", "soc=Qualcomm 但 ro.hardware=" + hardware,
                            "高通芯片 ro.hardware 应含 qcom", DetectionLayer.SYSCALL, "🔴");
                }
            }

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, problems > 0);
            item.setLayerResult(DetectionLayer.SYSCALL, problems > 0);
            if (problems > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("SoC/平台与声称机型不匹配 (" + problems + " 项) —— 机型伪造");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("SoC/平台与声称机型自洽");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 5. 系统版本一致性
    // ============================================================

    /**
     * SDK_INT / RELEASE / SECURITY_PATCH 多源比对，并交叉指纹里内嵌的版本段。
     * 沙箱把 Android 16 伪装成 OxygenOS 13 时，若 SDK_INT(=36) 与指纹里的 Android 版本段(13)
     * 矛盾、或 ro.build.version.oplusrom 与真实 SDK 不匹配，即暴露。
     */
    private DetectionItem detectVersionConsistency() {
        DetectionItem item = new DetectionItem("系统版本一致性",
                "SDK_INT / RELEASE / SECURITY_PATCH / 指纹版本段 交叉校验");
        try {
            int sdkInt = Build.VERSION.SDK_INT;
            String sdkProp = firstNonEmpty(readProp("ro.build.version.sdk"),
                    ReflectionUtils.getBuildVersionField("SDK_INT"));
            String release = firstNonEmpty(Build.VERSION.RELEASE, "");
            String releaseProp = readProp("ro.build.version.release");
            String patch = safeVer("SECURITY_PATCH");
            String patchProp = readProp("ro.build.version.security_patch");
            String fp = readProp("ro.build.fingerprint");
            String oplusRom = readProp("ro.build.version.oplusrom");

            item.addDetectionDetail("🔢 SDK_INT", sdkInt + " (prop:" + nz(sdkProp) + ")",
                    "Build.VERSION.SDK_INT vs ro.build.version.sdk", DetectionLayer.JAVA, "📊");
            item.addDetectionDetail("🔢 RELEASE", nz(release) + " (prop:" + nz(releaseProp) + ")",
                    "Android 版本号", DetectionLayer.JAVA, "📊");
            item.addDetectionDetail("🔢 SECURITY_PATCH", nz(patch) + " (prop:" + nz(patchProp) + ")",
                    "安全补丁级别", DetectionLayer.JAVA, "📊");
            if (!isEmpty(oplusRom)) {
                item.addDetectionDetail("🔢 oplusrom", oplusRom,
                        "OxygenOS/ColorOS ROM 版本", DetectionLayer.SYSCALL, "📊");
            }

            int problems = 0;
            // SDK vs prop
            if (!isEmpty(sdkProp) && !String.valueOf(sdkInt).equals(sdkProp)) {
                problems++;
                item.addDetectionDetail("🔴 SDK 冲突", "Build=" + sdkInt + " prop=" + sdkProp,
                        "SDK_INT 与 ro.build.version.sdk 不一致", DetectionLayer.SYSCALL, "🔴");
            }
            // RELEASE vs prop
            if (!isEmpty(release) && !isEmpty(releaseProp) && !release.equals(releaseProp)) {
                problems++;
                item.addDetectionDetail("🔴 RELEASE 冲突", "Build=" + release + " prop=" + releaseProp,
                        "Android 版本号在 Build 与 property 间不一致", DetectionLayer.SYSCALL, "🔴");
            }
            // SDK vs 指纹版本段: fp = brand/product/device:RELEASE/id/... ；RELEASE 应与 SDK 对应
            if (!isEmpty(fp)) {
                String fpRel = fpReleaseSegment(fp);
                if (!isEmpty(fpRel)) {
                    int expectSdkForRel = releaseToSdk(fpRel);
                    if (expectSdkForRel > 0 && expectSdkForRel != sdkInt) {
                        problems++;
                        item.addDetectionDetail("🔴 SDK↔指纹冲突",
                                "SDK_INT=" + sdkInt + " 但指纹 Android " + fpRel + "(应 SDK " + expectSdkForRel + ")",
                                "指纹里的 Android 版本与 SDK_INT 对不上 —— 高版本系统套低版本指纹",
                                DetectionLayer.SYSCALL, "🔴");
                    }
                }
            }
            // 安全补丁多源
            if (!isEmpty(patch) && !isEmpty(patchProp) && !patch.equals(patchProp)) {
                problems++;
                item.addDetectionDetail("🔴 补丁冲突", "Build=" + patch + " prop=" + patchProp,
                        "SECURITY_PATCH 多源不一致", DetectionLayer.SYSCALL, "🔴");
            }

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, problems > 0);
            item.setLayerResult(DetectionLayer.SYSCALL, problems > 0);
            if (problems > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("系统版本信息不自洽 (" + problems + " 项) —— 版本伪装破绽");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("系统版本信息多源一致");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 6. 屏幕参数 vs 机型
    // ============================================================

    /**
     * 真机 OnePlus 11: 1440x3216, ~525dpi, 支持 120Hz。屏幕分辨率/密度/刷新率由物理面板决定，
     * 沙箱若只改 Build 字段而未同步伪造 Display，声称旗舰机却报出异常分辨率/低刷即暴露。
     */
    private DetectionItem detectDisplayConsistency() {
        DetectionItem item = new DetectionItem("屏幕参数 vs 机型",
                "分辨率 / DPI / 刷新率 与声称机型应有面板是否匹配");
        try {
            DisplayMetrics dm = context.getResources().getDisplayMetrics();
            int w = dm.widthPixels, h = dm.heightPixels;
            int longEdge = Math.max(w, h), shortEdge = Math.min(w, h);
            int densityDpi = dm.densityDpi;
            float refresh = 60f;
            try {
                DisplayManager dmgr = (DisplayManager) context.getSystemService(Context.DISPLAY_SERVICE);
                Display d = dmgr != null ? dmgr.getDisplay(Display.DEFAULT_DISPLAY) : null;
                if (d != null) refresh = d.getRefreshRate();
            } catch (Throwable ignored) {}

            item.addDetectionDetail("📐 分辨率", w + "x" + h, "DisplayMetrics 像素", DetectionLayer.JAVA, "📊");
            item.addDetectionDetail("📐 densityDpi", String.valueOf(densityDpi), "屏幕密度", DetectionLayer.JAVA, "📊");
            item.addDetectionDetail("📐 刷新率", String.format("%.0fHz", refresh),
                    "Display.getRefreshRate", DetectionLayer.JAVA, "📊");

            String model = firstNonEmpty(ReflectionUtils.getBuildField("MODEL"), readProp("ro.product.model"));
            boolean isOp11 = matchModelSoc(model) != null;
            int problems = 0;
            if (isOp11) {
                // OnePlus 11 面板: 1440x3216(可能降采样 1080x2412), 主流旗舰 densityDpi 通常 480~560, 120Hz
                boolean resOk = (longEdge >= 2280) && (shortEdge >= 1020);
                boolean dpiOk = densityDpi >= 380 && densityDpi <= 600;
                boolean hzOk = refresh >= 90f; // 旗舰应支持高刷
                if (!resOk) {
                    problems++;
                    item.addDetectionDetail("🔴 分辨率异常", shortEdge + "x" + longEdge,
                            "声称 OnePlus 11 但分辨率低于旗舰面板应有值", DetectionLayer.JAVA, "🔴");
                }
                if (!dpiOk) {
                    problems++;
                    item.addDetectionDetail("🔴 DPI 异常", String.valueOf(densityDpi),
                            "densityDpi 超出旗舰机合理范围", DetectionLayer.JAVA, "🔴");
                }
                if (!hzOk) {
                    item.addDetectionDetail("🟡 刷新率偏低", String.format("%.0fHz", refresh),
                            "声称旗舰但当前刷新率 <90Hz（可能省电模式，仅告警）", DetectionLayer.JAVA, "🟡");
                }
                if (problems == 0 && hzOk) {
                    item.addDetectionDetail("🟢 面板匹配", shortEdge + "x" + longEdge + " @" + String.format("%.0fHz", refresh),
                            "屏幕参数符合声称机型", DetectionLayer.JAVA, "🟢");
                }
            } else {
                item.addDetectionDetail("⚪ 机型未在库", nz(model),
                        "机型不在面板库，仅记录参数", DetectionLayer.JAVA, "⚪");
            }

            item.setLayerResult(DetectionLayer.JAVA, problems > 0);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, false);
            if (problems > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("屏幕参数与声称机型不符 (" + problems + " 项)");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("屏幕参数与声称机型自洽");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // 7. 传感器/内存/存储 合理性 vs 机型
    // ============================================================

    private DetectionItem detectHwProfileConsistency() {
        DetectionItem item = new DetectionItem("硬件规格合理性 vs 机型",
                "传感器数量 / RAM / CPU 核数 与声称旗舰机是否吻合");
        try {
            int sensorCount = countSensors();
            long ramMb = parseLongSafe(nativeDetector.getTotalRamNative());
            if (ramMb <= 0) ramMb = parseLongSafe(nativeDetector.getTotalRamSyscall());
            int cores = Runtime.getRuntime().availableProcessors();
            String model = firstNonEmpty(ReflectionUtils.getBuildField("MODEL"), readProp("ro.product.model"));
            boolean isFlagship = matchModelSoc(model) != null;

            item.addDetectionDetail("🧭 传感器数量", String.valueOf(sensorCount),
                    "SensorManager TYPE_ALL", DetectionLayer.JAVA, "📊");
            item.addDetectionDetail("💾 RAM", ramMb + " MB",
                    "native/syscall /proc/meminfo", DetectionLayer.SYSCALL, "📊");
            item.addDetectionDetail("🖥️ CPU 核数", String.valueOf(cores),
                    "availableProcessors", DetectionLayer.JAVA, "📊");

            int problems = 0, warns = 0;
            if (isFlagship) {
                if (sensorCount < 8) { warns++;
                    item.addDetectionDetail("🟡 传感器偏少", String.valueOf(sensorCount),
                            "旗舰机通常 >10 个传感器，过少疑似伪造/精简", DetectionLayer.JAVA, "🟡"); }
                if (ramMb > 0 && ramMb < 6000) { warns++;
                    item.addDetectionDetail("🟡 RAM 偏低", ramMb + "MB",
                            "OnePlus 11 应为 8~16GB", DetectionLayer.SYSCALL, "🟡"); }
                if (cores < 6) { problems++;
                    item.addDetectionDetail("🔴 核数异常", String.valueOf(cores),
                            "8Gen2 为 8 核，核数过少 = 非该 SoC", DetectionLayer.JAVA, "🔴"); }
                if (problems == 0 && warns == 0) {
                    item.addDetectionDetail("🟢 规格吻合", sensorCount + "感/" + ramMb + "MB/" + cores + "核",
                            "硬件规格符合声称旗舰机", DetectionLayer.JAVA, "🟢");
                }
            } else {
                item.addDetectionDetail("⚪ 机型未在库", nz(model), "仅记录规格", DetectionLayer.JAVA, "⚪");
            }

            item.setLayerResult(DetectionLayer.JAVA, problems > 0);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, false);
            if (problems > 0) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("硬件规格与声称机型严重不符 (" + problems + " 项)");
            } else if (warns > 0) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("硬件规格部分偏离声称机型 (" + warns + " 项)");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("硬件规格与声称机型合理吻合");
            }
        } catch (Throwable t) {
            unknown(item, t);
        }
        return item;
    }

    // ============================================================
    // Helpers
    // ============================================================

    /** 多源读属性：libc → build.prop → SystemProperties 反射 → dev/__properties__ mmap。取第一条非空。 */
    private int countSensors() {
        try {
            SensorManager sm = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
            if (sm == null) return -1;
            List<Sensor> list = sm.getSensorList(Sensor.TYPE_ALL);
            return list != null ? list.size() : -1;
        } catch (Throwable t) {
            return -1;
        }
    }

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

    private static String[] matchModelSoc(String model) {
        if (isEmpty(model)) return null;
        String up = model.toUpperCase();
        for (Map.Entry<String, String[]> e : MODEL_SOC.entrySet()) {
            if (up.contains(e.getKey())) return e.getValue();
        }
        return null;
    }

    /** 从指纹中取 release 段： brand/product/device:RELEASE/id/incr:type/tags */
    private static String fpReleaseSegment(String fp) {
        try {
            int colon = fp.indexOf(':');
            if (colon < 0) return "";
            String after = fp.substring(colon + 1);
            int slash = after.indexOf('/');
            return slash > 0 ? after.substring(0, slash) : after;
        } catch (Exception e) {
            return "";
        }
    }

    /** Android release 版本号 → 期望 SDK_INT（主流映射）。未知返回 0。 */
    private static int releaseToSdk(String rel) {
        if (isEmpty(rel)) return 0;
        String major = rel.split("\\.")[0].trim();
        switch (major) {
            case "16": return 36;
            case "15": return 35;
            case "14": return 34;
            case "13": return 33;
            case "12": return 31; // 12/12L=31/32
            case "11": return 30;
            case "10": return 29;
            case "9":  return 28;
            default:   return 0;
        }
    }

    private static String safeVer(String field) {
        try {
            Class<?> c = Class.forName("android.os.Build$VERSION");
            Object v = c.getField(field).get(null);
            return v != null ? v.toString() : "";
        } catch (Throwable t) {
            return "";
        }
    }

    private static long parseLongSafe(String s) {
        if (isEmpty(s)) return -1;
        try {
            // 值可能是 "7823" 或 "7823 MB"
            StringBuilder num = new StringBuilder();
            for (char ch : s.toCharArray()) {
                if (Character.isDigit(ch)) num.append(ch); else if (num.length() > 0) break;
            }
            return num.length() > 0 ? Long.parseLong(num.toString()) : -1;
        } catch (Exception e) {
            return -1;
        }
    }

    private static String firstNonEmptyKey(Map<String, String> m) {
        for (Map.Entry<String, String> e : m.entrySet()) {
            if (!isEmpty(e.getValue())) return e.getKey();
        }
        return "?";
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
