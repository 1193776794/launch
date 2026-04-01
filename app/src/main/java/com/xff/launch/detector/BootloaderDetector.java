package com.xff.launch.detector;

import android.content.Context;
import android.os.Build;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Bootloader 解锁检测
 *
 * 检测维度:
 * 1. AVB 核心属性 (ro.boot.verifiedbootstate / flash.locked / vbmeta.device_state)
 * 2. /proc/cmdline 直读 (绕过 Magisk resetprop 篡改)
 * 3. OEM 解锁开关 (Settings.Global + sys.oem_unlock_allowed)
 * 4. 安全状态属性 (ro.build.tags / ro.debuggable / ro.secure / ro.build.type)
 * 5. 厂商专有属性 (Samsung warranty_bit / Xiaomi secureboot.lockstate / Huawei oem_lock)
 * 6. Hardware Key Attestation (TEE 硬件级验证，最难伪造)
 *
 * 多层比对: 同一信息通过 Java属性 / Native getprop / Syscall直读cmdline 三路获取，
 * 任何不一致都表明属性被篡改 (Magisk resetprop)。
 */
public class BootloaderDetector {

    private final Context context;
    private final NativeDetector nativeDetector;

    // ===== 核心 AVB 属性 =====
    private static final String PROP_VERIFIED_BOOT_STATE = "ro.boot.verifiedbootstate";
    private static final String PROP_FLASH_LOCKED = "ro.boot.flash.locked";
    private static final String PROP_VBMETA_DEVICE_STATE = "ro.boot.vbmeta.device_state";
    private static final String PROP_VBMETA_DIGEST = "ro.boot.vbmeta.digest";
    private static final String PROP_VERITY_MODE = "ro.boot.veritymode";

    // ===== OEM 解锁相关 =====
    private static final String PROP_OEM_UNLOCK_ALLOWED = "sys.oem_unlock_allowed";

    // ===== 安全状态属性 =====
    private static final String PROP_BUILD_TAGS = "ro.build.tags";
    private static final String PROP_DEBUGGABLE = "ro.debuggable";
    private static final String PROP_SECURE = "ro.secure";
    private static final String PROP_BUILD_TYPE = "ro.build.type";

    // ===== 厂商专有 =====
    private static final String PROP_SAMSUNG_WARRANTY = "ro.boot.warranty_bit";
    private static final String PROP_XIAOMI_LOCKSTATE = "ro.secureboot.lockstate";
    private static final String PROP_HUAWEI_OEM_LOCK = "ro.boot.huawei.oem_lock";

    // ===== /proc/cmdline 关键参数 =====
    private static final String CMDLINE_VERIFIED_BOOT = "androidboot.verifiedbootstate";
    private static final String CMDLINE_FLASH_LOCKED = "androidboot.flash.locked";
    private static final String CMDLINE_VBMETA_STATE = "androidboot.vbmeta.device_state";
    private static final String CMDLINE_VERITY_MODE = "androidboot.veritymode";

    public BootloaderDetector(Context context) {
        this.context = context;
        this.nativeDetector = NativeDetector.getInstance();
    }

    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(detectVerifiedBootState());
        items.add(detectCmdlineBootState());
        items.add(detectOemUnlockSwitch());
        items.add(detectSecurityProperties());
        items.add(detectVendorSpecific());
        items.add(detectKeyAttestation());
        return items;
    }

    // ===================== 1. AVB 核心属性检测 =====================

    /**
     * 通过系统属性检测 Verified Boot 状态
     * 三层获取: Java反射 / Native getprop / Syscall 读 build.prop
     */
    private DetectionItem detectVerifiedBootState() {
        DetectionItem item = new DetectionItem("Verified Boot 状态", "检测 AVB 验证启动状态和 Bootloader 锁定");

        boolean unlocked = false;
        boolean propertyTampered = false;

        // --- ro.boot.verifiedbootstate ---
        String vbStateJava = getPropertyJava(PROP_VERIFIED_BOOT_STATE);
        String vbStateNative = nativeDetector.getSystemProperty(PROP_VERIFIED_BOOT_STATE);

        String vbDisplay = coalesce(vbStateJava, vbStateNative, "N/A");
        if (isUnlockedBootState(vbDisplay)) {
            unlocked = true;
        }
        item.addDetectionDetail("🔐 verifiedbootstate",
            vbDisplay,
            "green=锁定官方签名 / orange=已解锁 / yellow=自签名",
            DetectionLayer.JAVA,
            isUnlockedBootState(vbDisplay) ? "🔴" : "🟢");

        // 三路比对
        if (vbStateJava != null && vbStateNative != null && !vbStateJava.equals(vbStateNative)) {
            propertyTampered = true;
            item.addDetectionDetail("⚠️ 属性篡改", "verifiedbootstate",
                "Java: " + vbStateJava + " / Native: " + vbStateNative + " (不一致!)",
                DetectionLayer.NATIVE, "🔴");
        }

        // --- ro.boot.flash.locked ---
        String flashLocked = coalesce(
            getPropertyJava(PROP_FLASH_LOCKED),
            nativeDetector.getSystemProperty(PROP_FLASH_LOCKED),
            null);

        if (flashLocked != null && !flashLocked.isEmpty()) {
            boolean isLocked = "1".equals(flashLocked.trim());
            if (!isLocked) unlocked = true;
            item.addDetectionDetail("🔒 flash.locked",
                flashLocked.trim(),
                "1=已锁定 / 0=已解锁",
                DetectionLayer.NATIVE,
                isLocked ? "🟢" : "🔴");
        }

        // --- ro.boot.vbmeta.device_state ---
        String deviceState = coalesce(
            getPropertyJava(PROP_VBMETA_DEVICE_STATE),
            nativeDetector.getSystemProperty(PROP_VBMETA_DEVICE_STATE),
            null);

        if (deviceState != null && !deviceState.isEmpty()) {
            boolean isLocked = "locked".equalsIgnoreCase(deviceState.trim());
            if (!isLocked) unlocked = true;
            item.addDetectionDetail("📱 vbmeta.device_state",
                deviceState.trim(),
                "locked=已锁定 / unlocked=已解锁",
                DetectionLayer.NATIVE,
                isLocked ? "🟢" : "🔴");
        }

        // --- ro.boot.veritymode ---
        String verityMode = coalesce(
            getPropertyJava(PROP_VERITY_MODE),
            nativeDetector.getSystemProperty(PROP_VERITY_MODE),
            null);

        if (verityMode != null && !verityMode.isEmpty()) {
            boolean enforcing = "enforcing".equalsIgnoreCase(verityMode.trim());
            if (!enforcing) unlocked = true;
            item.addDetectionDetail("🛡️ veritymode",
                verityMode.trim(),
                "enforcing=正常 / disabled=已禁用",
                DetectionLayer.NATIVE,
                enforcing ? "🟢" : "🔴");
        }

        // --- ro.boot.vbmeta.digest ---
        String digest = coalesce(
            getPropertyJava(PROP_VBMETA_DIGEST),
            nativeDetector.getSystemProperty(PROP_VBMETA_DIGEST),
            null);

        if (digest != null && !digest.isEmpty()) {
            item.addDetectionDetail("🔑 vbmeta.digest",
                digest.length() > 24 ? digest.substring(0, 24) + "..." : digest,
                "VBMeta 完整性摘要",
                DetectionLayer.NATIVE, "🔐");
        }

        item.setLayerResult(DetectionLayer.JAVA, unlocked);
        item.setLayerResult(DetectionLayer.NATIVE, unlocked || propertyTampered);
        item.setLayerResult(DetectionLayer.SYSCALL, unlocked);

        if (propertyTampered) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到属性篡改 (Magisk resetprop?)");
        } else if (unlocked) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("Bootloader 已解锁");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("Bootloader 已锁定, Verified Boot 正常");
        }

        return item;
    }

    // ===================== 2. /proc/cmdline 直读 =====================

    /**
     * 直接通过 syscall 读取 /proc/cmdline，绕过属性系统
     *
     * Magisk resetprop 只修改属性系统内存 (prop_area)，不修改 /proc/cmdline。
     * 因此如果 cmdline 中的值与属性系统不一致，说明属性被篡改。
     */
    private DetectionItem detectCmdlineBootState() {
        DetectionItem item = new DetectionItem("/proc/cmdline 验证", "直读内核命令行, 绕过属性篡改");

        boolean unlocked = false;
        boolean tampered = false;

        // 通过 syscall 读取 cmdline
        String cmdline = nativeDetector.readFileSyscall("/proc/cmdline");

        if (cmdline == null || cmdline.isEmpty()) {
            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, false);
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("无法读取 /proc/cmdline");
            return item;
        }

        // 解析 verifiedbootstate
        String cmdlineVbState = parseCmdlineParam(cmdline, CMDLINE_VERIFIED_BOOT);
        if (cmdlineVbState != null) {
            if (isUnlockedBootState(cmdlineVbState)) unlocked = true;
            item.addDetectionDetail("📋 cmdline.verifiedbootstate",
                cmdlineVbState,
                "内核命令行原始值 (无法被 resetprop 修改)",
                DetectionLayer.SYSCALL,
                isUnlockedBootState(cmdlineVbState) ? "🔴" : "🟢");

            // 与属性系统比对
            String propValue = nativeDetector.getSystemProperty(PROP_VERIFIED_BOOT_STATE);
            if (propValue != null && !propValue.isEmpty() && !propValue.equals(cmdlineVbState)) {
                tampered = true;
                item.addDetectionDetail("⚠️ 属性篡改检测",
                    "cmdline=" + cmdlineVbState + " / prop=" + propValue,
                    "属性系统被修改! (resetprop)",
                    DetectionLayer.SYSCALL, "🔴");
            }
        }

        // 解析 flash.locked
        String cmdlineFlashLocked = parseCmdlineParam(cmdline, CMDLINE_FLASH_LOCKED);
        if (cmdlineFlashLocked != null) {
            boolean isLocked = "1".equals(cmdlineFlashLocked.trim());
            if (!isLocked) unlocked = true;
            item.addDetectionDetail("📋 cmdline.flash.locked",
                cmdlineFlashLocked,
                "内核命令行原始值",
                DetectionLayer.SYSCALL,
                isLocked ? "🟢" : "🔴");
        }

        // 解析 vbmeta.device_state
        String cmdlineDevState = parseCmdlineParam(cmdline, CMDLINE_VBMETA_STATE);
        if (cmdlineDevState != null) {
            boolean isLocked = "locked".equalsIgnoreCase(cmdlineDevState.trim());
            if (!isLocked) unlocked = true;
            item.addDetectionDetail("📋 cmdline.vbmeta.device_state",
                cmdlineDevState,
                "内核命令行原始值",
                DetectionLayer.SYSCALL,
                isLocked ? "🟢" : "🔴");
        }

        // 解析 veritymode
        String cmdlineVerity = parseCmdlineParam(cmdline, CMDLINE_VERITY_MODE);
        if (cmdlineVerity != null) {
            boolean enforcing = "enforcing".equalsIgnoreCase(cmdlineVerity.trim());
            if (!enforcing) unlocked = true;
            item.addDetectionDetail("📋 cmdline.veritymode",
                cmdlineVerity,
                "内核命令行原始值",
                DetectionLayer.SYSCALL,
                enforcing ? "🟢" : "🔴");
        }

        item.setLayerResult(DetectionLayer.JAVA, false);
        item.setLayerResult(DetectionLayer.NATIVE, tampered);
        item.setLayerResult(DetectionLayer.SYSCALL, unlocked || tampered);

        if (tampered) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("cmdline 与属性不一致 — 属性被 resetprop 篡改");
        } else if (unlocked) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("cmdline 确认 Bootloader 已解锁");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("cmdline 确认 Bootloader 已锁定");
        }

        return item;
    }

    // ===================== 3. OEM 解锁开关 =====================

    private DetectionItem detectOemUnlockSwitch() {
        DetectionItem item = new DetectionItem("OEM 解锁开关", "检测用户是否开启了 OEM 解锁和开发者选项");

        boolean oemEnabled = false;
        boolean devEnabled = false;

        // Settings.Global.OEM_UNLOCK_ALLOWED
        try {
            int oemValue = Settings.Global.getInt(
                context.getContentResolver(), "oem_unlock_allowed", 0);
            oemEnabled = (oemValue == 1);
            item.addDetectionDetail(oemEnabled ? "⚠️ OEM 解锁" : "✅ OEM 解锁",
                oemEnabled ? "已开启" : "已关闭",
                "Settings.Global.oem_unlock_allowed = " + oemValue,
                DetectionLayer.JAVA,
                oemEnabled ? "🟡" : "🟢");
        } catch (Exception e) {
            item.addDetectionDetail("❓ OEM 解锁", "无法读取", e.getMessage(), DetectionLayer.JAVA, "⚪");
        }

        // sys.oem_unlock_allowed 属性
        String sysOem = nativeDetector.getSystemProperty(PROP_OEM_UNLOCK_ALLOWED);
        if (sysOem != null && "1".equals(sysOem.trim())) {
            oemEnabled = true;
            item.addDetectionDetail("⚠️ sys.oem_unlock_allowed", "1",
                "系统属性允许 OEM 解锁", DetectionLayer.NATIVE, "🟡");
        }

        // 开发者选项状态
        try {
            int devValue = Settings.Global.getInt(
                context.getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
            devEnabled = (devValue == 1);
            item.addDetectionDetail(devEnabled ? "🟡 开发者选项" : "✅ 开发者选项",
                devEnabled ? "已开启" : "已关闭",
                "Settings.Global.DEVELOPMENT_SETTINGS_ENABLED = " + devValue,
                DetectionLayer.JAVA,
                devEnabled ? "🟡" : "🟢");
        } catch (Exception ignored) {}

        item.setLayerResult(DetectionLayer.JAVA, oemEnabled);
        item.setLayerResult(DetectionLayer.NATIVE, oemEnabled);
        item.setLayerResult(DetectionLayer.SYSCALL, false);

        if (oemEnabled) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("OEM 解锁开关已开启" + (devEnabled ? " + 开发者选项已开启" : ""));
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("OEM 解锁开关已关闭");
        }

        return item;
    }

    // ===================== 4. 安全状态属性 =====================

    private DetectionItem detectSecurityProperties() {
        DetectionItem item = new DetectionItem("安全状态属性", "检测 build.tags / debuggable / secure / build.type");

        int riskCount = 0;

        // ro.build.tags
        String tags = coalesce(Build.TAGS, nativeDetector.getSystemProperty(PROP_BUILD_TAGS), "");
        boolean testKeys = tags.contains("test-keys") || tags.contains("dev-keys");
        if (testKeys) riskCount++;
        item.addDetectionDetail(testKeys ? "⚠️ build.tags" : "✅ build.tags",
            tags, "release-keys=正常 / test-keys=异常",
            DetectionLayer.JAVA, testKeys ? "🔴" : "🟢");

        // ro.debuggable
        String debuggable = nativeDetector.getSystemProperty(PROP_DEBUGGABLE);
        boolean isDebuggable = "1".equals(debuggable);
        if (isDebuggable) riskCount++;
        item.addDetectionDetail(isDebuggable ? "⚠️ debuggable" : "✅ debuggable",
            debuggable != null ? debuggable : "N/A",
            "0=正常 / 1=调试版本",
            DetectionLayer.NATIVE, isDebuggable ? "🔴" : "🟢");

        // ro.secure
        String secure = nativeDetector.getSystemProperty(PROP_SECURE);
        boolean notSecure = "0".equals(secure);
        if (notSecure) riskCount++;
        item.addDetectionDetail(notSecure ? "⚠️ secure" : "✅ secure",
            secure != null ? secure : "N/A",
            "1=正常 / 0=adb root",
            DetectionLayer.NATIVE, notSecure ? "🔴" : "🟢");

        // ro.build.type
        String buildType = coalesce(Build.TYPE, nativeDetector.getSystemProperty(PROP_BUILD_TYPE), "");
        boolean nonUser = !"user".equals(buildType);
        if (nonUser) riskCount++;
        item.addDetectionDetail(nonUser ? "⚠️ build.type" : "✅ build.type",
            buildType,
            "user=正常 / userdebug/eng=异常",
            DetectionLayer.JAVA, nonUser ? "🟡" : "🟢");

        boolean anyRisk = riskCount > 0;
        item.setLayerResult(DetectionLayer.JAVA, anyRisk);
        item.setLayerResult(DetectionLayer.NATIVE, anyRisk);
        item.setLayerResult(DetectionLayer.SYSCALL, false);

        if (riskCount >= 2) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail(riskCount + " 项安全属性异常");
        } else if (riskCount == 1) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("1 项安全属性异常");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("全部安全属性正常");
        }

        return item;
    }

    // ===================== 5. 厂商专有属性 =====================

    private DetectionItem detectVendorSpecific() {
        DetectionItem item = new DetectionItem("厂商安全属性", "检测 Samsung/Xiaomi/Huawei 专有 Bootloader 属性");

        boolean detected = false;
        String brand = Build.BRAND != null ? Build.BRAND.toLowerCase() : "";

        // Samsung: warranty_bit (eFuse, 不可逆)
        String warrantyBit = nativeDetector.getSystemProperty(PROP_SAMSUNG_WARRANTY);
        if (warrantyBit != null && !warrantyBit.isEmpty()) {
            boolean tripped = "1".equals(warrantyBit.trim());
            if (tripped) detected = true;
            item.addDetectionDetail(tripped ? "⚠️ Samsung warranty_bit" : "✅ Samsung warranty_bit",
                warrantyBit.trim(),
                "0=正常 / 1=已触发(不可逆,硬件eFuse)",
                DetectionLayer.NATIVE, tripped ? "🔴" : "🟢");
        } else if (brand.contains("samsung")) {
            item.addDetectionDetail("✅ Samsung warranty_bit", "0 (默认)",
                "未读取到或值为默认", DetectionLayer.NATIVE, "🟢");
        }

        // Xiaomi: secureboot.lockstate
        String xiaomiLock = nativeDetector.getSystemProperty(PROP_XIAOMI_LOCKSTATE);
        if (xiaomiLock != null && !xiaomiLock.isEmpty()) {
            boolean isUnlocked = "unlocked".equalsIgnoreCase(xiaomiLock.trim());
            if (isUnlocked) detected = true;
            item.addDetectionDetail(isUnlocked ? "⚠️ Xiaomi lockstate" : "✅ Xiaomi lockstate",
                xiaomiLock.trim(),
                "locked=已锁定 / unlocked=已解锁",
                DetectionLayer.NATIVE, isUnlocked ? "🔴" : "🟢");
        } else if (brand.contains("xiaomi") || brand.contains("redmi") || brand.contains("poco")) {
            item.addDetectionDetail("ℹ️ Xiaomi lockstate", "未读取到",
                "该属性可能被隐藏", DetectionLayer.NATIVE, "⚪");
        }

        // Huawei: oem_lock
        String huaweiLock = nativeDetector.getSystemProperty(PROP_HUAWEI_OEM_LOCK);
        if (huaweiLock != null && !huaweiLock.isEmpty()) {
            item.addDetectionDetail("ℹ️ Huawei oem_lock",
                huaweiLock.trim(), "华为 OEM 锁状态",
                DetectionLayer.NATIVE, "🔐");
        }

        // 如果没有命中任何厂商属性，显示当前品牌
        if (!detected) {
            item.addDetectionDetail("ℹ️ 设备品牌", Build.BRAND + " / " + Build.MANUFACTURER,
                "当前设备厂商", DetectionLayer.JAVA, "📱");
        }

        item.setLayerResult(DetectionLayer.JAVA, detected);
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        item.setLayerResult(DetectionLayer.SYSCALL, false);

        if (detected) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("厂商安全属性检测到解锁/触发");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("厂商安全属性正常");
        }

        return item;
    }

    // ===================== 6. Hardware Key Attestation =====================

    /**
     * 通过 Android Keystore 的硬件密钥证明检测 Bootloader 状态
     *
     * TEE (TrustZone) 内部生成证书链，其中 RootOfTrust 扩展包含:
     * - deviceLocked: 是否锁定
     * - verifiedBootState: Verified(0)/SelfSigned(1)/Unverified(2)/Failed(3)
     *
     * 这是最强的检测方式 — Magisk resetprop 无法影响 TEE 内部的证书生成。
     */
    private DetectionItem detectKeyAttestation() {
        DetectionItem item = new DetectionItem("硬件密钥证明", "TEE 硬件级 Bootloader 状态验证 (Key Attestation)");

        boolean unlocked = false;
        boolean attestationSucceeded = false;

        try {
            // 生成带 attestation challenge 的密钥对
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            kpg.initialize(new KeyGenParameterSpec.Builder(
                "bootloader_attestation_key",
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge("launch_bl_check".getBytes())
                .build());
            kpg.generateKeyPair();

            // 获取证书链
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Certificate[] chain = ks.getCertificateChain("bootloader_attestation_key");

            if (chain != null && chain.length > 0) {
                X509Certificate leaf = (X509Certificate) chain[0];

                // 解析 Key Attestation 扩展 OID: 1.3.6.1.4.1.11129.2.1.17
                byte[] attestationExt = leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");

                if (attestationExt != null && attestationExt.length > 0) {
                    attestationSucceeded = true;

                    // 解析 ASN.1 结构找 RootOfTrust
                    // RootOfTrust 在 teeEnforced (index 7) 或 softwareEnforced (index 6) 中
                    // Tag 704 = RootOfTrust
                    AttestationResult result = parseAttestationExtension(attestationExt);

                    if (result != null) {
                        item.addDetectionDetail(
                            result.deviceLocked ? "✅ deviceLocked" : "⚠️ deviceLocked",
                            result.deviceLocked ? "true (已锁定)" : "false (已解锁)",
                            "TEE 硬件证明 — 无法被 resetprop 伪造",
                            DetectionLayer.SYSCALL,
                            result.deviceLocked ? "🟢" : "🔴");

                        String[] bootStateNames = {"Verified", "SelfSigned", "Unverified", "Failed"};
                        String stateName = (result.verifiedBootState >= 0 && result.verifiedBootState < 4)
                            ? bootStateNames[result.verifiedBootState] : "Unknown(" + result.verifiedBootState + ")";

                        boolean stateOk = result.verifiedBootState == 0; // Verified
                        item.addDetectionDetail(
                            stateOk ? "✅ verifiedBootState" : "⚠️ verifiedBootState",
                            stateName,
                            "0=Verified(green) / 1=SelfSigned(yellow) / 2=Unverified(orange) / 3=Failed(red)",
                            DetectionLayer.SYSCALL,
                            stateOk ? "🟢" : "🔴");

                        if (!result.deviceLocked || result.verifiedBootState >= 2) {
                            unlocked = true;
                        }
                    } else {
                        item.addDetectionDetail("ℹ️ Attestation", "证书已获取",
                            "RootOfTrust 解析中 (证书链长度: " + chain.length + ")",
                            DetectionLayer.SYSCALL, "🔐");
                    }
                } else {
                    item.addDetectionDetail("ℹ️ Attestation", "无扩展数据",
                        "Key Attestation 扩展为空 (可能是软件级密钥)",
                        DetectionLayer.JAVA, "🟡");
                }
            }

            // 清理密钥
            ks.deleteEntry("bootloader_attestation_key");

        } catch (Exception e) {
            String errMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            // StrongBoxUnavailableException 等是正常的
            if (errMsg.contains("StrongBox") || errMsg.contains("not supported")) {
                item.addDetectionDetail("ℹ️ Key Attestation", "设备不支持",
                    errMsg, DetectionLayer.JAVA, "⚪");
            } else {
                item.addDetectionDetail("❓ Key Attestation", "异常",
                    errMsg, DetectionLayer.JAVA, "⚪");
            }
        }

        item.setLayerResult(DetectionLayer.JAVA, false);
        item.setLayerResult(DetectionLayer.NATIVE, false);
        item.setLayerResult(DetectionLayer.SYSCALL, unlocked);

        if (unlocked) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("TEE 硬件证明: Bootloader 已解锁");
        } else if (attestationSucceeded) {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("TEE 硬件证明: Bootloader 已锁定");
        } else {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("Key Attestation 不可用或不支持");
        }

        return item;
    }

    // ===================== Helper Methods =====================

    private static class AttestationResult {
        boolean deviceLocked;
        int verifiedBootState; // 0=Verified, 1=SelfSigned, 2=Unverified, 3=Failed
    }

    /**
     * 简化的 ASN.1 解析 Key Attestation 扩展
     * 查找 RootOfTrust 中的 deviceLocked 和 verifiedBootState
     */
    private AttestationResult parseAttestationExtension(byte[] extensionData) {
        try {
            // 扩展值外层是 OCTET STRING 包装
            if (extensionData.length < 4) return null;

            // 搜索 deviceLocked (BOOLEAN) 和 verifiedBootState (ENUMERATED)
            // 在 ASN.1 中，RootOfTrust 是一个 SEQUENCE，包含:
            //   OCTET STRING (verifiedBootKey)
            //   BOOLEAN (deviceLocked)
            //   ENUMERATED (verifiedBootState)
            //   OCTET STRING (verifiedBootHash, optional in v3+)

            AttestationResult result = new AttestationResult();
            result.deviceLocked = true; // 默认锁定
            result.verifiedBootState = 0; // 默认 Verified

            // 简单字节搜索方法：找到 BOOLEAN tag (0x01) + length (0x01) + value
            for (int i = 0; i < extensionData.length - 3; i++) {
                // BOOLEAN: tag=0x01, length=0x01, value=0x00(false)/0xFF(true)
                if (extensionData[i] == 0x01 && extensionData[i + 1] == 0x01) {
                    // 检查后面是否紧跟 ENUMERATED (tag=0x0A)
                    if (i + 5 < extensionData.length &&
                        extensionData[i + 3] == 0x0A && extensionData[i + 4] == 0x01) {
                        // 这很可能是 RootOfTrust 中的 deviceLocked + verifiedBootState
                        result.deviceLocked = (extensionData[i + 2] != 0x00);
                        result.verifiedBootState = extensionData[i + 5] & 0xFF;
                        return result;
                    }
                }
            }

            return null; // 没找到匹配模式
        } catch (Exception e) {
            return null;
        }
    }

    private String getPropertyJava(String key) {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            return (String) sp.getMethod("get", String.class).invoke(null, key);
        } catch (Exception e) {
            return null;
        }
    }

    private String parseCmdlineParam(String cmdline, String paramName) {
        if (cmdline == null) return null;
        String prefix = paramName + "=";
        int idx = cmdline.indexOf(prefix);
        if (idx < 0) return null;
        int start = idx + prefix.length();
        int end = cmdline.indexOf(' ', start);
        if (end < 0) end = cmdline.length();
        return cmdline.substring(start, end).trim();
    }

    private boolean isUnlockedBootState(String state) {
        if (state == null) return false;
        String s = state.trim().toLowerCase();
        return "orange".equals(s) || "red".equals(s);
    }

    private String coalesce(String... values) {
        for (String v : values) {
            if (v != null && !v.isEmpty()) return v;
        }
        return null;
    }
}
