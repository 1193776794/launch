package com.xff.launch.detector;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.telephony.TelephonyManager;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.pm.ApplicationInfo;
import android.view.accessibility.AccessibilityManager;
import android.view.inputmethod.InputMethodInfo;
import android.view.inputmethod.InputMethodManager;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

/**
 * 设备真实度 / 风控信号检测。
 *
 * <p>对照京东 JDGuard 的设备真实度信号链（field 2 锁屏 / field 5+14-1 电池 /
 * field 15 反刷单无障碍 / field 14-8~10 Keystore Attestation），把这些"风控旁证"
 * 维度移植进环境检测板块。它们单独不构成硬风险，但组合起来揭示设备是否为
 * 真实长期使用的私人设备，还是模拟器 / 农场机 / 自动化刷单机。
 *
 * <ul>
 *   <li>锁屏安全凭据：真机用户多数设了 PIN/指纹；裸机/模拟器多数未设。</li>
 *   <li>电池真实度：模拟器 technology 空 / 温度电压恒 0；真机有真实读数。</li>
 *   <li>无障碍服务：抢券/秒杀/连点脚本几乎都依赖 AccessibilityService。</li>
 *   <li>TEE 信任根：硬件密钥能否进可信执行环境；软件级=无 TEE，疑似模拟器。</li>
 * </ul>
 */
public class DeviceAuthenticityDetector {

    private final Context context;

    public DeviceAuthenticityDetector(Context context) {
        this.context = context.getApplicationContext();
    }

    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(detectLockscreen());
        items.add(detectBattery());
        items.add(detectAccessibility());
        items.add(detectTeeTrustRoot());
        items.add(detectSimInfo());
        items.add(detectInputMethods());
        return items;
    }

    // ===================== 1. 锁屏安全凭据 (JD field 2) =====================

    private DetectionItem detectLockscreen() {
        DetectionItem item = new DetectionItem("锁屏安全凭据", "是否设置 PIN/图案/密码/指纹/面部 (真机使用真实度信号)");
        try {
            KeyguardManager km = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
            boolean secure = km != null && km.isKeyguardSecure();
            item.addDetectionDetail(secure ? "🔒 锁屏凭据" : "🔓 锁屏凭据",
                    secure ? "已设置" : "未设置",
                    "isKeyguardSecure() — 未设置常见于裸机/模拟器/刚重置的临时机",
                    DetectionLayer.JAVA, secure ? "🟢" : "🟡");

            item.setLayerResult(DetectionLayer.JAVA, !secure);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, false);
            if (secure) {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("已设置锁屏安全凭据");
            } else {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("未设置任何锁屏安全凭据 (低真实度信号)");
            }
        } catch (Exception e) {
            unknown(item, e);
        }
        return item;
    }

    // ===================== 2. 电池真实度 (JD field 5 / 14-1) =====================

    private DetectionItem detectBattery() {
        DetectionItem item = new DetectionItem("电池真实度", "BATTERY_CHANGED extras — 模拟器电池特征恒定/缺失");
        try {
            IntentFilter f = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent i = context.registerReceiver(null, f);
            if (i == null) {
                unknown(item, null);
                return item;
            }

            int plugged = i.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
            int status = i.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
            int health = i.getIntExtra(BatteryManager.EXTRA_HEALTH, -1);
            int level = i.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
            int scale = i.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
            int temperature = i.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0); // 0.1°C
            int voltage = i.getIntExtra(BatteryManager.EXTRA_VOLTAGE, 0);          // mV
            String technology = i.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY);
            boolean present = i.getBooleanExtra(BatteryManager.EXTRA_PRESENT, true);

            int pct = (scale > 0 && level >= 0) ? (level * 100 / scale) : level;

            item.addDetectionDetail("🔌 plugged", pluggedName(plugged),
                    "0=未插 1=AC 2=USB 4=无线 8=Dock", DetectionLayer.JAVA, "📊");
            item.addDetectionDetail("⚡ status", statusName(status),
                    "充电状态", DetectionLayer.JAVA, "📊");
            item.addDetectionDetail("🔋 level", pct + "%",
                    "电量百分比", DetectionLayer.JAVA, "📊");
            item.addDetectionDetail("🌡️ temperature",
                    (temperature / 10.0) + "°C",
                    "真机 ~25~40°C；恒 0 多为模拟器", DetectionLayer.JAVA,
                    temperature == 0 ? "🟡" : "🟢");
            item.addDetectionDetail("🔧 voltage", voltage + " mV",
                    "真机 ~3700~4400mV；恒 0 多为模拟器", DetectionLayer.JAVA,
                    voltage == 0 ? "🟡" : "🟢");
            item.addDetectionDetail("🧪 technology",
                    technology == null || technology.isEmpty() ? "(空)" : technology,
                    "真机如 Li-ion/Li-poly；空多为模拟器", DetectionLayer.JAVA,
                    (technology == null || technology.isEmpty()) ? "🟡" : "🟢");
            item.addDetectionDetail("❤️ health", healthName(health),
                    "电池健康状态", DetectionLayer.JAVA, "📊");

            // 模拟器特征打分：温度/电压/技术/存在性 异常累加
            int emuScore = 0;
            if (temperature == 0) emuScore++;
            if (voltage == 0) emuScore++;
            if (technology == null || technology.isEmpty()) emuScore++;
            if (!present) emuScore++;
            // 模拟器常见：未插但满电固定 / 温度电压恒 0
            boolean suspicious = emuScore >= 2;

            item.setLayerResult(DetectionLayer.JAVA, suspicious);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, false);
            if (emuScore >= 3) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("电池特征高度疑似模拟器 (" + emuScore + " 项异常)");
            } else if (emuScore == 2) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("电池特征部分异常 (" + emuScore + " 项)");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("电池读数正常 (真机特征)");
            }
        } catch (Exception e) {
            unknown(item, e);
        }
        return item;
    }

    // ===================== 3. 无障碍服务 / 反刷单 (JD field 15) =====================

    private DetectionItem detectAccessibility() {
        DetectionItem item = new DetectionItem("无障碍服务", "已启用的 AccessibilityService — 抢券/秒杀/连点脚本入口");
        try {
            boolean globalEnabled = false;
            try {
                globalEnabled = Settings.Secure.getInt(context.getContentResolver(),
                        Settings.Secure.ACCESSIBILITY_ENABLED, 0) == 1;
            } catch (Exception ignored) {}

            AccessibilityManager am = (AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
            List<AccessibilityServiceInfo> enabled = am != null
                    ? am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                    : null;

            int count = enabled != null ? enabled.size() : 0;
            item.addDetectionDetail(globalEnabled ? "⚠️ 无障碍总开关" : "✅ 无障碍总开关",
                    globalEnabled ? "已开启" : "已关闭",
                    "Settings.Secure.accessibility_enabled", DetectionLayer.JAVA,
                    globalEnabled ? "🟡" : "🟢");

            if (count == 0) {
                item.addDetectionDetail("✅ 已启用服务", "无", "无任何 AccessibilityService 激活",
                        DetectionLayer.JAVA, "🟢");
            } else {
                for (AccessibilityServiceInfo info : enabled) {
                    String id = info.getId();
                    item.addDetectionDetail("⚠️ 已启用服务", id != null ? id : "(未知)",
                            "激活的无障碍服务 — 自动化工具常驻此处", DetectionLayer.JAVA, "🟡");
                }
            }

            boolean active = count > 0;
            item.setLayerResult(DetectionLayer.JAVA, active);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, false);
            if (active) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("检测到 " + count + " 个已启用的无障碍服务");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("无已启用的无障碍服务");
            }
        } catch (Exception e) {
            unknown(item, e);
        }
        return item;
    }

    // ===================== 4. TEE 硬件信任根 (JD field 14-8~10) =====================

    private DetectionItem detectTeeTrustRoot() {
        DetectionItem item = new DetectionItem("TEE 硬件信任根", "AndroidKeyStore 密钥能否进入可信执行环境 (模拟器无 TEE)");
        final String alias = "launch_tee_probe_key";
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            kpg.initialize(new KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build());
            kpg.generateKeyPair();

            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            PrivateKey pk = (PrivateKey) ks.getKey(alias, null);
            KeyFactory factory = KeyFactory.getInstance(pk.getAlgorithm(), "AndroidKeyStore");
            KeyInfo info = factory.getKeySpec(pk, KeyInfo.class);

            boolean secureHardware;
            String levelDesc;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                int lvl = info.getSecurityLevel();
                // KeyProperties.SECURITY_LEVEL_*: -1 UNKNOWN_SECURE, 0 SOFTWARE, 1 TRUSTED_ENVIRONMENT, 2 STRONGBOX
                secureHardware = lvl == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                        || lvl == KeyProperties.SECURITY_LEVEL_STRONGBOX
                        || lvl == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE;
                levelDesc = securityLevelName(lvl);
            } else {
                secureHardware = info.isInsideSecureHardware();
                levelDesc = secureHardware ? "TEE (isInsideSecureHardware)" : "SOFTWARE";
            }

            item.addDetectionDetail(secureHardware ? "🟢 安全级别" : "🟡 安全级别",
                    levelDesc,
                    "TRUSTED_ENVIRONMENT/STRONGBOX=有硬件 TEE；SOFTWARE=无 TEE(疑似模拟器)",
                    DetectionLayer.SYSCALL, secureHardware ? "🟢" : "🟡");

            ks.deleteEntry(alias);

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, !secureHardware);
            if (secureHardware) {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("密钥位于硬件 TEE — 真机特征");
            } else {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("密钥仅软件级 — 无硬件 TEE (疑似模拟器/异常 ROM)");
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            item.addDetectionDetail("❓ TEE 探测", "异常", msg, DetectionLayer.JAVA, "⚪");
            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, false);
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("TEE 信任根探测不可用: " + msg);
            tryDelete(alias);
        }
        return item;
    }

    // ===================== 5. SIM 卡信息 (JD field 13-7) =====================

    private DetectionItem detectSimInfo() {
        DetectionItem item = new DetectionItem("SIM 卡信息", "SIM 状态/运营商/国家 — 无 SIM 多为模拟器/农场机");
        try {
            TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm == null) { unknown(item, null); return item; }

            int state = tm.getSimState();
            String op = tm.getSimOperator();
            String opName = tm.getSimOperatorName();
            String iso = tm.getSimCountryIso();

            boolean ready = state == TelephonyManager.SIM_STATE_READY;
            boolean absent = state == TelephonyManager.SIM_STATE_ABSENT;

            item.addDetectionDetail(ready ? "📶 SIM 状态" : "🟡 SIM 状态", simStateName(state),
                    "READY=已就绪 / ABSENT=无卡(模拟器/农场机常见)", DetectionLayer.JAVA,
                    ready ? "🟢" : "🟡");
            if (op != null && !op.isEmpty()) {
                item.addDetectionDetail("🏢 运营商", op + (opName != null && !opName.isEmpty() ? " (" + opName + ")" : ""),
                        "MCC+MNC 运营商代码", DetectionLayer.JAVA, "📊");
            }
            if (iso != null && !iso.isEmpty()) {
                item.addDetectionDetail("🌐 SIM 国家", iso, "getSimCountryIso", DetectionLayer.JAVA, "📊");
            }

            item.setLayerResult(DetectionLayer.JAVA, absent);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, false);
            if (ready) {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("SIM 就绪 (真实用户特征)");
            } else if (absent) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("无 SIM 卡 (模拟器/农场机/纯 WiFi 设备)");
            } else {
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("SIM 状态: " + simStateName(state));
            }
        } catch (Exception e) {
            unknown(item, e);
        }
        return item;
    }

    // ===================== 6. 输入法清单 (JD field 3-2) =====================

    private DetectionItem detectInputMethods() {
        DetectionItem item = new DetectionItem("输入法清单", "已启用输入法 — 第三方/自动化键盘信号");
        try {
            InputMethodManager imm = (InputMethodManager) context.getSystemService(Context.INPUT_METHOD_SERVICE);
            if (imm == null) { unknown(item, null); return item; }
            List<InputMethodInfo> enabled = imm.getEnabledInputMethodList();
            int thirdParty = 0;
            int count = enabled != null ? enabled.size() : 0;
            if (enabled != null) {
                for (InputMethodInfo imi : enabled) {
                    boolean system = false;
                    try {
                        ApplicationInfo ai = imi.getServiceInfo().applicationInfo;
                        system = ai != null && (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                    } catch (Exception ignored) {}
                    if (!system) thirdParty++;
                    item.addDetectionDetail(system ? "⌨️ 系统输入法" : "⚠️ 第三方输入法",
                            imi.getId(),
                            system ? "预装输入法" : "第三方输入法 — 可记录/自动输入",
                            DetectionLayer.JAVA, system ? "🟢" : "🟡");
                }
            }
            item.setLayerResult(DetectionLayer.JAVA, thirdParty > 0);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, false);
            if (count == 0) {
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("无法获取输入法清单");
            } else if (thirdParty > 0) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail("检测到 " + thirdParty + " 个第三方输入法 (共 " + count + " 个启用)");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("仅系统输入法 (共 " + count + " 个)");
            }
        } catch (Exception e) {
            unknown(item, e);
        }
        return item;
    }

    // ===================== Helpers =====================

    private void tryDelete(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            ks.deleteEntry(alias);
        } catch (Exception ignored) {}
    }

    private void unknown(DetectionItem item, Exception e) {
        item.setLayerResult(DetectionLayer.JAVA, false);
        item.setLayerResult(DetectionLayer.NATIVE, false);
        item.setLayerResult(DetectionLayer.SYSCALL, false);
        item.setStatus(DetectionStatus.UNKNOWN);
        item.setDetail("无法采集" + (e != null && e.getMessage() != null ? ": " + e.getMessage() : ""));
    }

    private static String pluggedName(int p) {
        switch (p) {
            case 0: return "0 (未插)";
            case BatteryManager.BATTERY_PLUGGED_AC: return "1 (AC)";
            case BatteryManager.BATTERY_PLUGGED_USB: return "2 (USB)";
            case BatteryManager.BATTERY_PLUGGED_WIRELESS: return "4 (无线)";
            default: return String.valueOf(p);
        }
    }

    private static String statusName(int s) {
        switch (s) {
            case BatteryManager.BATTERY_STATUS_CHARGING: return "2 (充电中)";
            case BatteryManager.BATTERY_STATUS_DISCHARGING: return "3 (放电中)";
            case BatteryManager.BATTERY_STATUS_NOT_CHARGING: return "4 (未充电)";
            case BatteryManager.BATTERY_STATUS_FULL: return "5 (已充满)";
            default: return s + " (未知)";
        }
    }

    private static String healthName(int h) {
        switch (h) {
            case BatteryManager.BATTERY_HEALTH_GOOD: return "2 (良好)";
            case BatteryManager.BATTERY_HEALTH_OVERHEAT: return "3 (过热)";
            case BatteryManager.BATTERY_HEALTH_DEAD: return "4 (损坏)";
            case BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE: return "5 (过压)";
            case BatteryManager.BATTERY_HEALTH_COLD: return "7 (过冷)";
            default: return h + " (未知)";
        }
    }

    private static String simStateName(int s) {
        switch (s) {
            case TelephonyManager.SIM_STATE_ABSENT: return "1 (ABSENT 无卡)";
            case TelephonyManager.SIM_STATE_PIN_REQUIRED: return "2 (PIN_REQUIRED)";
            case TelephonyManager.SIM_STATE_PUK_REQUIRED: return "3 (PUK_REQUIRED)";
            case TelephonyManager.SIM_STATE_NETWORK_LOCKED: return "4 (NETWORK_LOCKED)";
            case TelephonyManager.SIM_STATE_READY: return "5 (READY 就绪)";
            default: return s + " (UNKNOWN)";
        }
    }

    private static String securityLevelName(int lvl) {
        switch (lvl) {
            case KeyProperties.SECURITY_LEVEL_SOFTWARE: return "SOFTWARE (软件级)";
            case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT: return "TRUSTED_ENVIRONMENT (TEE)";
            case KeyProperties.SECURITY_LEVEL_STRONGBOX: return "STRONGBOX (安全芯片)";
            case KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE: return "UNKNOWN_SECURE (安全但未知)";
            default: return "UNKNOWN(" + lvl + ")";
        }
    }
}
