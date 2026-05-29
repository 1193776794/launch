package com.xff.launch.detector;

import android.content.Context;
import android.os.Debug;
import android.provider.Settings;
import android.util.Log;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Debug detection with multi-layer support
 */
public class DebugDetector {

    private static final String TAG = "AdbDbgProp";

    private final Context context;
    private final NativeDetector nativeDetector;

    public DebugDetector(Context context) {
        this.context = context;
        this.nativeDetector = NativeDetector.getInstance();
    }

    /**
     * Detect USB debugging status.
     *
     * 单读 Settings.Global.ADB_ENABLED 不可靠 —— MIUI / Xposed / hook 框架经常拦截
     * 这个 ContentProvider 调用或返回旧值（实测 MIUI 上 settings get 显示 1、但
     * Settings.Global.getInt 读出 0）。
     *
     * 改成多源融合：
     *  · JAVA    层 — Settings.Global.ADB_ENABLED
     *  · NATIVE  层 — Native syscall mmap 读 sys.usb.config / sys.usb.state /
     *                 init.svc.adbd / persist.sys.usb.config，任一含 "adb" 或 adbd=running 即开
     *  · SYSCALL 层 — Java FileChannel.map 旁路同样的几条属性
     * 任一源说"开"即判 WARNING（USB 调试开），并把跨源不一致单独列为 hook 嫌疑。
     */
    public DetectionItem detectUsbDebugging() {
        DetectionItem item = new DetectionItem("USB 调试",
                "Settings + sys.usb.config / init.svc.adbd 多源融合");

        // ===== JAVA 层 Settings =====
        int adbEnabledSetting = -1;
        try {
            adbEnabledSetting = Settings.Global.getInt(context.getContentResolver(),
                    Settings.Global.ADB_ENABLED, -1);
        } catch (Throwable ignored) {
        }
        boolean settingsSaysOn = adbEnabledSetting == 1;

        // ===== NATIVE / SYSCALL 层：通过三路属性源旁证 =====
        String[][] defs = {
                {"sys.usb.config",         "usb_control_prop",          "usb_prop"},
                {"sys.usb.state",          "usb_control_prop",          "usb_prop"},
                {"init.svc.adbd",          "init_service_status_prop",  "default_prop"},
                {"persist.sys.usb.config", "system_prop",               "usb_prop"},
        };
        String[] keys = propKeys(defs);

        Map<String, String> apiVals = readPropertiesViaApi(keys);
        Map<String, String> javaMmapVals = readPropertiesViaMmap(keys);
        if (javaMmapVals == null) javaMmapVals = java.util.Collections.emptyMap();
        Map<String, String> nativeMmapVals = readPropertiesByContext(defs);

        // sys.usb.config / sys.usb.state / persist.sys.usb.config 是「USB function 列表」，
        // 含 "adb" 即说明 USB function 已切到 ADB 通道（调试开）。
        // init.svc.adbd == "running" 是 adbd 守护进程在跑（也是开关明确为开的标志）。
        boolean nativeSaysOn = anySourceHit(apiVals, javaMmapVals, nativeMmapVals, "sys.usb.config", VAL_CONTAINS_ADB)
                || anySourceHit(apiVals, javaMmapVals, nativeMmapVals, "sys.usb.state", VAL_CONTAINS_ADB)
                || anySourceHit(apiVals, javaMmapVals, nativeMmapVals, "init.svc.adbd", VAL_EQ_RUNNING);

        // SYSCALL 层（Java FileChannel.map 旁路）单独算一遍，便于跨层不一致诊断
        boolean syscallSaysOn = valueHits(javaMmapVals.get("sys.usb.config"), VAL_CONTAINS_ADB)
                || valueHits(javaMmapVals.get("sys.usb.state"), VAL_CONTAINS_ADB)
                || valueHits(javaMmapVals.get("init.svc.adbd"), VAL_EQ_RUNNING);

        item.setLayerResult(DetectionLayer.JAVA, settingsSaysOn);
        item.setLayerResult(DetectionLayer.NATIVE, nativeSaysOn);
        item.setLayerResult(DetectionLayer.SYSCALL, syscallSaysOn);

        boolean isOn = settingsSaysOn || nativeSaysOn || syscallSaysOn;

        if (isOn) {
            item.setStatus(DetectionStatus.WARNING);
            StringBuilder d = new StringBuilder("已开启");
            if (settingsSaysOn) d.append("; Settings=1");
            String anyUsbCfg = firstNonEmpty(apiVals.get("sys.usb.config"),
                    javaMmapVals.get("sys.usb.config"), nativeMmapVals.get("sys.usb.config"));
            if (anyUsbCfg != null && anyUsbCfg.contains("adb")) {
                d.append("; sys.usb.config=").append(anyUsbCfg);
            }
            String anyAdbd = firstNonEmpty(apiVals.get("init.svc.adbd"),
                    javaMmapVals.get("init.svc.adbd"), nativeMmapVals.get("init.svc.adbd"));
            if ("running".equals(anyAdbd)) d.append("; adbd=running");
            item.setDetail(d.toString());

            collectUsbDebuggingDetails(item, adbEnabledSetting,
                    apiVals, javaMmapVals, nativeMmapVals);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("已关闭");
        }

        // 跨源不一致 = 强 hook 嫌疑（典型：Settings 报 0、但 sys.usb.config=adb）
        if (settingsSaysOn != (nativeSaysOn || syscallSaysOn)) {
            item.addDetectionDetail("⚠️ 异常情况",
                    "Settings 与属性源结论不一致 (疑似 ContentProvider/属性被 hook)",
                    "Settings.ADB_ENABLED=" + adbEnabledSetting
                            + "\nsys.usb.config: API=" + formatValue(apiVals.get("sys.usb.config"))
                            + " / NativeMmap=" + formatValue(nativeMmapVals.get("sys.usb.config"))
                            + " / JavaMmap=" + formatValue(javaMmapVals.get("sys.usb.config"))
                            + "\ninit.svc.adbd: API=" + formatValue(apiVals.get("init.svc.adbd"))
                            + " / NativeMmap=" + formatValue(nativeMmapVals.get("init.svc.adbd"))
                            + " / JavaMmap=" + formatValue(javaMmapVals.get("init.svc.adbd")),
                    DetectionLayer.NATIVE, "🚨");
            if (item.getStatus() != DetectionStatus.WARNING) {
                item.setStatus(DetectionStatus.RISK);
            }
        }

        return item;
    }

    // 谓词：用于 anySourceHit / valueHits
    private static final int VAL_CONTAINS_ADB = 1;
    private static final int VAL_EQ_RUNNING = 2;
    private static final int VAL_TRUTHY = 3;          // "1"/"true"/"on"/"yes"/"enabled"
    private static final int VAL_TRUTHY_ADB_ROOT = 4; // 还接受 "root"/"running"

    private static boolean valueHits(String v, int predicate) {
        if (v == null || v.isEmpty()) return false;
        switch (predicate) {
            case VAL_CONTAINS_ADB: return v.contains("adb");
            case VAL_EQ_RUNNING:   return "running".equals(v);
            case VAL_TRUTHY: {
                String t = v.trim().toLowerCase(java.util.Locale.US);
                return "1".equals(t) || "true".equals(t) || "on".equals(t)
                        || "yes".equals(t) || "enabled".equals(t);
            }
            case VAL_TRUTHY_ADB_ROOT: {
                String t = v.trim().toLowerCase(java.util.Locale.US);
                return "1".equals(t) || "true".equals(t) || "on".equals(t)
                        || "yes".equals(t) || "enabled".equals(t)
                        || "root".equals(t) || "running".equals(t);
            }
            default: return false;
        }
    }

    private static boolean anySourceHit(Map<String, String> a, Map<String, String> b,
                                        Map<String, String> c, String key, int predicate) {
        return valueHits(a.get(key), predicate)
                || valueHits(b.get(key), predicate)
                || valueHits(c.get(key), predicate);
    }

    private static String firstNonEmpty(String... candidates) {
        for (String s : candidates) {
            if (s != null && !s.isEmpty()) return s;
        }
        return null;
    }

    /** 把 String[][]{key, ctx1, ctx2} 的第 0 列提成 String[] keys 用于属性读取。 */
    private static String[] propKeys(String[][] defs) {
        String[] keys = new String[defs.length];
        for (int i = 0; i < defs.length; i++) keys[i] = defs[i][0];
        return keys;
    }

    /**
     * Detect debugger connection
     */
    public DetectionItem detectDebugger() {
        DetectionItem item = new DetectionItem("调试器连接", "检测是否有调试器连接");

        // Java layer
        boolean javaResult = Debug.isDebuggerConnected();
        item.setLayerResult(DetectionLayer.JAVA, javaResult);

        // Native layer
        boolean nativeResult = nativeDetector.checkDebuggerNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer
        boolean syscallResult = nativeDetector.checkDebuggerSyscall();
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到调试器");

            // 添加详细检测信息
            collectDebuggerDetails(item, javaResult, nativeResult, syscallResult);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未连接");
        }

        if (item.hasInconsistentResults()) {
            item.setDetail(item.getDetail() + " (检测层不一致)");
        }

        return item;
    }

    /**
     * Detect JDWP (Java Debug Wire Protocol).
     *
     * JDWP 在 Android 上的真实运行路径（AOSP 9+）：
     *   adbd ──@jdwp-control unix abstract socket──> ART runtime
     *                                                 │
     *                                                 ├─ libadbconnection.so (启用 JDWP 即加载)
     *                                                 ├─ "ADB-JDWP Connection Control Thread"
     *                                                 └─ attach 时 dlopen libopenjdkjvmti.so
     *
     * 因此 TracerPid > 0 跟 JDWP 完全无关（那是 ptrace）。本检测按真正的 JDWP 指标分三层：
     *
     *   JAVA 层（易被 hook）:
     *     · Debug.isDebuggerConnected() / Debug.waitingForDebugger() — VMDebug 直读 JDWP 状态
     *     · ApplicationInfo FLAG_DEBUGGABLE — App 是否允许 JDWP attach
     *     · Java 线程枚举 — 找 JDWP/ADB-JDWP/AdbConnection 命名
     *     · /proc/net/unix 文件读 — 找 @jdwp 抽象 socket
     *
     *   NATIVE 层（syscall_open + syscall_read 绕 libc 内联 hook）:
     *     · /proc/self/maps 命中 libadbconnection.so / libopenjdkjvmti.so / libjdwp.so
     *     · /proc/net/unix @jdwp 数量
     *     · /proc/self/task/*\/comm JDWP 线程列表
     *
     *   SYSCALL 层（已有 mmap 直读 /dev/__properties__）:
     *     · dalvik.vm.jdwp-provider 值 — adbconnection (默认开启) / internal (旧版开启) / none (禁用)
     *
     *   一致性校验：Java 与 Native 检测结果出现分歧 → 强 hook 嫌疑（Java 反射被静默化或
     *   /proc 被 hook 屏蔽），单独标记为异常情况。
     */
    public DetectionItem detectJdwp() {
        DetectionItem item = new DetectionItem("JDWP 检测",
                "JDWP / @jdwp-control / libadbconnection 多层检测");

        // ===== JAVA 层 =====
        boolean debuggerConnected = false;
        boolean waitingForDebugger = false;
        try {
            debuggerConnected = Debug.isDebuggerConnected();
            waitingForDebugger = Debug.waitingForDebugger();
        } catch (Throwable ignored) {
        }
        boolean appDebuggable = isAppDebuggable();
        String[] javaThreadCats = scanJavaThreadsForJdwpByKind();
        String javaThreadHitsCtl = javaThreadCats[0];
        String javaThreadHitsXport = javaThreadCats[1];
        int javaUnixSocketsTotal = countJdwpUnixSocketsJava();
        int javaUnixSocketsSelf = countJdwpUnixSocketsForSelfJava();

        // 真 attach 信号：
        //   · Debug API 明确报告
        //   · 当前 PID 自己的 @jdwp socket 存在
        //   · post-attach transport 线程命中（"JDWP Transport/Event/Command/Helper", "JVMTI Agent"）
        // 弱信号（仅"JDWP 通道可用"，不代表已 attach）：control 线程命名、全局 @jdwp 计数
        //   ↳ 在任何 FLAG_DEBUGGABLE app 上都常驻，不能当 RISK
        boolean javaHit = debuggerConnected || waitingForDebugger
                || javaUnixSocketsSelf > 0 || !javaThreadHitsXport.isEmpty();
        // layer 维度 "Java 层能否观察到 JDWP 相关信号"，含 attach + capability。
        // 这是 dialog "✓检测到 / ✗未检测到" 用的，反映这层对 JDWP 的可见性，
        // 是否上 RISK 由整体 status 判定（attach vs capability）。
        boolean javaLayerObserved = javaHit
                || !javaThreadHitsCtl.isEmpty()
                || javaUnixSocketsTotal > 0;
        item.setLayerResult(DetectionLayer.JAVA, javaLayerObserved);

        // ===== NATIVE 层 =====
        Map<String, String> nativeReport;
        try {
            nativeReport = parseKeyValueReport(nativeDetector.getJdwpDetectionReport());
            Log.i(TAG, "jdwp-report: " + nativeReport);
        } catch (Throwable t) {
            nativeReport = java.util.Collections.emptyMap();
        }
        boolean adbConnLoaded = "1".equals(nativeReport.get("ADBCONN"));
        boolean jvmtiLoaded = "1".equals(nativeReport.get("JVMTI"));
        int nativeUnixSocketsTotal = parseIntSafe(nativeReport.get("JDWP_SOCK"), 0);
        int nativeUnixSocketsSelf = parseIntSafe(nativeReport.get("JDWP_SOCK_SELF"), 0);
        String nativeThreadHitsCtl = nativeReport.getOrDefault("JDWP_THREADS_CTL", "");
        String nativeThreadHitsXport = nativeReport.getOrDefault("JDWP_THREADS_XPORT", "");

        // 主动 connect 探测结果（魔改版思路：不扫 /proc，syscall connect 探活）
        // - adbdSockHit=1 (EACCES) → adbd 活着，只是 SELinux 不让我连（正常）
        // - jdwpCtlHit=1 (connect 成功) → 系统侧 JDWP 通道已就位、accept 了我们 → capability
        //   注：仍非 attach 凭证；attach 凭证看 libopenjdkjvmti.so / transport thread
        boolean adbdSockHit = "1".equals(nativeReport.get("ADBD_SOCK_HIT"));
        int adbdSockErrno = parseIntSafe(nativeReport.get("ADBD_SOCK_ERRNO"), -1);
        String adbdSockName = nativeReport.getOrDefault("ADBD_SOCK_NAME", "");
        boolean jdwpCtlHit = "1".equals(nativeReport.get("JDWP_CTL_HIT"));
        int jdwpCtlErrno = parseIntSafe(nativeReport.get("JDWP_CTL_ERRNO"), -1);
        String jdwpCtlName = nativeReport.getOrDefault("JDWP_CTL_NAME", "");

        // 真 attach 信号：
        //   · libopenjdkjvmti.so / libjdwp.so dlopen（attach 时才加载）
        //   · 当前 PID 的 @jdwp socket 存在
        //   · transport 线程命中（同 Java 层）
        // 弱信号：libadbconnection.so（ART 对任何 debuggable app 都加载）、控制线程命名、
        //   /proc/net/unix 里别的进程的 @jdwp 项 — 这些都不算 RISK
        boolean nativeHit = jvmtiLoaded || nativeUnixSocketsSelf > 0
                || !nativeThreadHitsXport.isEmpty();
        // Native 层可观察信号 (含 capability)
        boolean nativeLayerObserved = nativeHit
                || adbConnLoaded
                || !nativeThreadHitsCtl.isEmpty()
                || nativeUnixSocketsTotal > 0;
        item.setLayerResult(DetectionLayer.NATIVE, nativeLayerObserved);

        // 仅作展示用的"JDWP 通道可用"指标
        boolean jdwpCapability = adbConnLoaded
                || !javaThreadHitsCtl.isEmpty() || !nativeThreadHitsCtl.isEmpty()
                || javaUnixSocketsTotal > 0 || nativeUnixSocketsTotal > 0
                || jdwpCtlHit || adbdSockHit;

        // ===== SYSCALL 层: dalvik.vm.jdwp-provider via mmap =====
        String provider = "";
        try {
            provider = nativeDetector.readDevPropertyMmap("dalvik.vm.jdwp-provider");
            if (provider == null) provider = "";
        } catch (Throwable ignored) {
        }
        // adbconnection (默认) / internal (旧版) → JDWP 路径可用；none → 禁用
        boolean providerEnables = !provider.isEmpty() && !"none".equalsIgnoreCase(provider);
        // Syscall 层可观察信号：provider 属性 + 主动 connect 探测 (用 syscall socket+connect)
        boolean syscallLayerObserved = providerEnables || jdwpCtlHit || adbdSockHit;
        item.setLayerResult(DetectionLayer.SYSCALL, syscallLayerObserved);

        // ===== 聚合判定 =====
        // jdwpReady = 系统侧 JDWP 通道是否准备好。多源择一即可：
        //   · provider 属性可读且非 none （旧路，但 MIUI/HarmonyOS 等 ROM 上经常读不到）
        //   · jdwpCtlHit (主动 connect @jdwp-control 成功) — 最直接的"门开着"证据
        //   · adbConnLoaded + 控制线程存在 (jdwpCapability) — ART 已加载 JDWP 通道
        // 任一即视为系统 JDWP capability 就位。
        boolean jdwpReady = providerEnables || jdwpCtlHit || jdwpCapability;

        // 统计有多少层观察到 JDWP 信号（attach 或 capability 都算），用于 verdict 升级
        int layerObservedCount = (javaLayerObserved ? 1 : 0)
                + (nativeLayerObserved ? 1 : 0)
                + (syscallLayerObserved ? 1 : 0);

        if (javaHit || nativeHit) {
            // 真 attach 凭证命中：debugger 连了 / libopenjdkjvmti 加载 / transport 线程 / @jdwp-self
            item.setStatus(DetectionStatus.RISK);
            StringBuilder d = new StringBuilder("JDWP 活跃: ");
            if (debuggerConnected) d.append("Debugger已连; ");
            if (waitingForDebugger) d.append("等待调试器; ");
            if (jvmtiLoaded) d.append("libopenjdkjvmti(attach时dlopen); ");
            int selfSock = Math.max(javaUnixSocketsSelf, nativeUnixSocketsSelf);
            if (selfSock > 0) d.append("@jdwp-self x").append(selfSock).append("; ");
            if (!nativeThreadHitsXport.isEmpty() || !javaThreadHitsXport.isEmpty()) {
                d.append("JDWP transport线程; ");
            }
            item.setDetail(d.toString().trim());
        } else if (jdwpReady && appDebuggable && layerObservedCount >= 2) {
            // ≥2 层观察到 capability 信号 + app 可被 attach：JDWP 攻击面充分暴露，
            // 即便此刻无 attach 也是高风险窗口（任何时候 jdb/Studio Profiler/Frida JVMTI
            // 都能直接接管），判 RISK。
            item.setStatus(DetectionStatus.RISK);
            StringBuilder hint = new StringBuilder();
            if (!provider.isEmpty()) hint.append("provider=").append(provider).append("; ");
            if (jdwpCtlHit)          hint.append("@jdwp-control accept; ");
            if (adbConnLoaded)       hint.append("libadbconnection 加载; ");
            if (adbdSockHit)         hint.append("adbd 活(EACCES); ");
            String h = hint.length() == 0 ? "" : " (" + hint.toString().trim() + ")";
            item.setDetail("JDWP 攻击面就位 / " + layerObservedCount
                    + " 层 capability 命中，可被随时 attach" + h);
        } else if (jdwpReady && appDebuggable) {
            // 仅 1 层 capability 信号 (弱) + app debuggable → WARNING
            item.setStatus(DetectionStatus.WARNING);
            StringBuilder hint = new StringBuilder();
            if (!provider.isEmpty()) hint.append("provider=").append(provider).append("; ");
            if (jdwpCtlHit)          hint.append("@jdwp-control accept; ");
            if (adbConnLoaded)       hint.append("libadbconnection 加载; ");
            if (adbdSockHit)         hint.append("adbd 活(EACCES); ");
            String h = hint.length() == 0 ? "" : " (" + hint.toString().trim() + ")";
            item.setDetail("JDWP 通道就位（弱信号） / 当前无调试器 attach" + h);
        } else if (jdwpReady) {
            // 系统侧就位，但 app 不 debuggable，外部无法 attach 上来
            item.setStatus(DetectionStatus.SAFE);
            StringBuilder hint = new StringBuilder();
            if (!provider.isEmpty()) hint.append("provider=").append(provider).append("; ");
            if (jdwpCtlHit)          hint.append("@jdwp-control accept; ");
            String h = hint.length() == 0 ? "" : " (" + hint.toString().trim() + ")";
            item.setDetail("JDWP 系统侧就位 / App 非 debuggable 无法 attach" + h);
        } else {
            // provider 不可读 + 无任何 capability 信号 + 无 attach → 真"没开 JDWP"
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail(provider.isEmpty()
                    ? "JDWP 未启用"
                    : "JDWP 未启用 (provider=" + provider + ")");
        }

        // 跨层不一致 = 强 hook 嫌疑（只比 attach 信号，不比 capability 噪声）
        if (javaHit != nativeHit) {
            item.addDetectionDetail("⚠️ 异常情况",
                    "Java 与 Native 层 JDWP attach 信号不一致",
                    "Java=" + javaHit + " / Native=" + nativeHit
                            + "\n（Java 反射可能被屏蔽 或 /proc 路径被 hook 过滤）",
                    DetectionLayer.NATIVE, "🚨");
        }

        collectJdwpDetails(item,
                debuggerConnected, waitingForDebugger, appDebuggable,
                javaThreadHitsCtl, javaThreadHitsXport,
                javaUnixSocketsTotal, javaUnixSocketsSelf,
                adbConnLoaded, jvmtiLoaded,
                nativeUnixSocketsTotal, nativeUnixSocketsSelf,
                nativeThreadHitsCtl, nativeThreadHitsXport,
                provider,
                adbdSockHit, adbdSockErrno, adbdSockName,
                jdwpCtlHit, jdwpCtlErrno, jdwpCtlName);

        Log.i(TAG, "jdwp-verdict: status=" + item.getStatus()
                + " detail=" + item.getDetail()
                + " javaHit=" + javaHit + " nativeHit=" + nativeHit
                + " jvmti=" + jvmtiLoaded
                + " xport[java=" + (!javaThreadHitsXport.isEmpty())
                + ",native=" + (!nativeThreadHitsXport.isEmpty()) + "]"
                + " selfSock[java=" + javaUnixSocketsSelf
                + ",native=" + nativeUnixSocketsSelf + "]"
                + " debugAPI[connected=" + debuggerConnected
                + ",waiting=" + waitingForDebugger + "]");

        return item;
    }

    /**
     * Detect ptrace
     * Normal: TracerPid:0 (no debugger attached)
     * Abnormal: TracerPid:>0 (debugger attached)
     */
    public DetectionItem detectPtrace() {
        DetectionItem item = new DetectionItem("Ptrace 检测", "检测 ptrace 跟踪");

        // Syscall layer - most trustworthy, read TracerPid value
        int syscallTracerPid = readTracerPidSyscall();

        // Java layer - read /proc/self/status
        int javaTracerPid = readTracerPidJava();

        // Native layer - read TracerPid via native
        int nativeTracerPid = nativeDetector.getTracerPid();

        // Set layer results (INVERTED: true = safe, false = detected)
        item.setLayerResult(DetectionLayer.JAVA, javaTracerPid == 0);
        item.setLayerResult(DetectionLayer.NATIVE, nativeTracerPid == 0);
        item.setLayerResult(DetectionLayer.SYSCALL, syscallTracerPid == 0);

        // Check all threads
        String allThreadsStatus = checkAllThreadsTracerPid();

        // Build detailed status message
        StringBuilder detail = new StringBuilder();
        detail.append("TracerPid:").append(syscallTracerPid);

        // FIXED: Check if TracerPid > 0 (being traced)
        if (syscallTracerPid > 0) {
            item.setStatus(DetectionStatus.RISK);
            detail.append(" (被跟踪!)");
            if (!allThreadsStatus.isEmpty()) {
                detail.append("\n").append(allThreadsStatus);
            }

            // 添加详细检测信息
            collectPtraceDetails(item, javaTracerPid, nativeTracerPid, syscallTracerPid);
        } else {
            // TracerPid = 0, normal case
            item.setStatus(DetectionStatus.SAFE);
            detail.append(" (正常)");
        }

        // Add layer comparison warning
        if (javaTracerPid != syscallTracerPid || nativeTracerPid != syscallTracerPid) {
            detail.append("\n⚠️ 多层检测结果不一致");
            detail.append(String.format(" (Java:%d, Native:%d, Syscall:%d)",
                    javaTracerPid, nativeTracerPid, syscallTracerPid));
            item.addDetectionDetail("⚠️ 异常情况", "检测层不一致",
                String.format("Java:%d, Native:%d, Syscall:%d",
                    javaTracerPid, nativeTracerPid, syscallTracerPid),
                DetectionLayer.JAVA, "🚨");
        }

        item.setDetail(detail.toString());

        return item;
    }

    /**
     * Detect ptrace self-protection
     * Apps can use ptrace(PTRACE_TRACEME) to protect themselves from debuggers
     */
    public DetectionItem detectPtraceSelfProtection() {
        DetectionItem item = new DetectionItem("Ptrace 自我保护", "检测反调试保护机制");

        // If app uses ptrace to protect itself, TracerPid will be non-zero
        // but it will be our own PID or parent PID
        int currentPid = android.os.Process.myPid();
        int tracerPid = readTracerPidSyscall();

        boolean isProtected = false;
        DetectionStatus status = DetectionStatus.SAFE;
        String detail = "";

        if (tracerPid > 0) {
            // Check if tracer is ourselves or parent
            if (tracerPid == currentPid) {
                isProtected = true;
                status = DetectionStatus.SAFE;
                detail = String.format("已启用自我保护 (TracerPid:%d = 自身)", tracerPid);
            } else {
                // Check if it's parent process
                try {
                    String statContent = nativeDetector.readFileSyscall("/proc/self/stat");
                    if (statContent != null && !statContent.isEmpty()) {
                        // Parse parent PID from stat
                        int parenClose = statContent.lastIndexOf(')');
                        if (parenClose > 0) {
                            String[] parts = statContent.substring(parenClose + 1).trim().split("\\s+");
                            if (parts.length > 1) {
                                int parentPid = Integer.parseInt(parts[1]);
                                if (tracerPid == parentPid) {
                                    isProtected = true;
                                    status = DetectionStatus.SAFE;
                                    detail = String.format("已启用自我保护 (TracerPid:%d = 父进程)", tracerPid);
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    // Ignore
                }

                if (!isProtected) {
                    // It's an external debugger - RISK!
                    status = DetectionStatus.RISK;
                    detail = String.format("⚠️ 外部调试器 (TracerPid:%d)", tracerPid);
                }
            }
        } else {
            // TracerPid = 0, no protection, but this is NORMAL for most apps
            status = DetectionStatus.SAFE;
            detail = "TracerPid:0 (正常 - 无反调试保护)";
        }

        // Set layer results (true = safe/normal, false = risk)
        item.setLayerResult(DetectionLayer.JAVA, tracerPid == 0 || isProtected);
        item.setLayerResult(DetectionLayer.NATIVE, tracerPid == 0 || isProtected);
        item.setLayerResult(DetectionLayer.SYSCALL, tracerPid == 0 || isProtected);

        item.setStatus(status);
        item.setDetail(detail);

        return item;
    }

    /**
     * Get all debug detection items
     */
    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(detectUsbDebugging());
        items.add(detectDebugger());
        items.add(detectJdwp());
        items.add(detectPtrace());
        items.add(detectPtraceSelfProtection());
        items.add(detectAdbAndDebugSwitch());
        items.add(detectAdbConnection());
        items.add(detectAdbdRuntime());
        items.add(detectUsbFunctionsRuntime());
        items.add(detectPropertyAreaTampering());
        return items;
    }

    /**
     * 敏感属性「篡改痕迹」检测。
     *
     * 思路（参考京东 com.jd.stat.common.kit.devproperties.b）：Bionic 用 trie 组织 prop_info，
     * 同一 prop key 在 prop_area 文件里**只应该有一份记录**。如果用 c.a(key) 返回
     * `List<String>` 扫到多份，就是属性被双写/注入的特征（典型 hook 框架痕迹）。
     *
     * 本检测对每个敏感 key 在每个 known context 文件里调 findAllValues：
     *  · 同一文件出现 >= 2 次 → 强篡改痕迹 (RISK)
     *  · 跨 >=2 个 context 文件出现 → 弱痕迹 (某些通用 key 在 exported_* 系列里可能有副本，
     *    所以只展示不直接判 RISK)
     *
     * 检测范围覆盖：ADB / 调试开关 + bootloader 解锁 + Riru 注入（最后两类来自京东 b.java）。
     */
    public DetectionItem detectPropertyAreaTampering() {
        DetectionItem item = new DetectionItem("属性区篡改痕迹",
                "扫描 prop_info 二进制区，同 key 多份 = hook 双写");

        // 敏感 key 列表。命中即扫，未命中不当篡改（缺失是正常的）。
        String[] sensitiveKeys = {
                // ADB / 调试
                "ro.debuggable", "ro.secure", "ro.adb.secure",
                "persist.sys.usb.config", "sys.usb.config", "sys.usb.state",
                "service.adb.tcp.port", "init.svc.adbd",
                // bootloader (京东 b.a 检测点)
                "ro.boot.verifiedbootstate", "ro.boot.vbmeta.device_state",
                // Riru / hook (京东 b.b 检测点)
                "ro.dalvik.vm.native.bridge",
        };

        // key → context → [value, value, ...]
        Map<String, Map<String, List<String>>> matrix = new LinkedHashMap<>();
        int totalFilesOpened = 0;

        for (String ctxName : KNOWN_PROP_CONTEXTS) {
            ByteBuffer buf = openPropertyMap(new File(DEV_PROPERTIES_ROOT, ctxName));
            if (buf == null) continue;
            totalFilesOpened++;
            for (String key : sensitiveKeys) {
                List<String> all = findAllValues(buf, key);
                if (all.isEmpty()) continue;
                matrix.computeIfAbsent(key, k -> new LinkedHashMap<>()).put(ctxName, all);
            }
        }
        // 兜底：旧版 Android 整目录是单文件
        ByteBuffer rootBuf = openPropertyMap(DEV_PROPERTIES_ROOT);
        if (rootBuf != null) {
            totalFilesOpened++;
            for (String key : sensitiveKeys) {
                List<String> all = findAllValues(rootBuf, key);
                if (all.isEmpty()) continue;
                matrix.computeIfAbsent(key, k -> new LinkedHashMap<>())
                        .put("<root>", all);
            }
        }

        if (totalFilesOpened == 0) {
            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("无法访问 /dev/__properties__");
            return item;
        }

        int strongTamperKeys = 0;   // 同一文件内出现 >= 2 次
        int crossContextKeys = 0;   // 跨 >=2 个文件出现
        StringBuilder summary = new StringBuilder();
        StringBuilder diffDetail = new StringBuilder();

        for (Map.Entry<String, Map<String, List<String>>> e : matrix.entrySet()) {
            String key = e.getKey();
            Map<String, List<String>> perCtx = e.getValue();

            boolean dupInSingleFile = false;
            for (Map.Entry<String, List<String>> c : perCtx.entrySet()) {
                if (c.getValue().size() >= 2) {
                    dupInSingleFile = true;
                    item.addDetectionDetail("🚨 同文件多份",
                            key + " @ " + c.getKey(),
                            "命中 " + c.getValue().size() + " 次: " + c.getValue(),
                            DetectionLayer.NATIVE, "🚨");
                    diffDetail.append(key).append(" @ ").append(c.getKey())
                            .append(" x").append(c.getValue().size()).append("\n");
                }
            }
            if (dupInSingleFile) {
                strongTamperKeys++;
                summary.append(key).append("@dup; ");
                continue;
            }

            if (perCtx.size() >= 2) {
                crossContextKeys++;
                StringBuilder ctxList = new StringBuilder();
                for (Map.Entry<String, List<String>> c : perCtx.entrySet()) {
                    if (ctxList.length() > 0) ctxList.append("\n");
                    ctxList.append(c.getKey()).append(" → ").append(c.getValue());
                }
                item.addDetectionDetail("⚠️ 跨 context 多份",
                        key + " 出现于 " + perCtx.size() + " 个文件",
                        ctxList.toString(),
                        DetectionLayer.NATIVE, "⚠️");
            }
        }

        item.setLayerResult(DetectionLayer.JAVA, strongTamperKeys > 0);
        item.setLayerResult(DetectionLayer.NATIVE, strongTamperKeys > 0);

        if (strongTamperKeys > 0) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("发现 " + strongTamperKeys + " 个 key 在同文件内多份 (hook 双写)"
                    + (summary.length() > 0 ? ": " + summary.toString().trim() : ""));
        } else if (crossContextKeys > 0) {
            // 跨 context 出现部分场景是合理的（exported_* 转发），不直接判 RISK
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("发现 " + crossContextKeys + " 个 key 在多个 context 文件中出现 (可能正常 exported)");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未发现 prop_info 篡改痕迹 (扫描 " + totalFilesOpened + " 个 context 文件)");
        }

        Log.i(TAG, "tamper-scan: opened=" + totalFilesOpened
                + " strong=" + strongTamperKeys
                + " cross=" + crossContextKeys);

        return item;
    }

    /**
     * ADB 网络监听检测。
     *
     * 局限：Android 10+ 起 untrusted_app 读不到 /proc/net/tcp（EACCES），无法从应用域
     * 列出全局 socket 表，所以「host 是否真实建立 TCP 连接」做不到（实测确认）。
     * 退而求其次：
     *  · 用 SystemProperties 读 service.adb.tcp.port 拿到「期望监听端口」
     *  · 用主动 TCP connect 探测端口是否真的在监听（多一层旁证，能抓到 hook 把 port
     *    改 -1 但 socket 没关的伪装）
     *  · 默认端口 5555 也兜底探一次（adb tcpip 模式）
     *
     * USB ADB 走 USB function driver 不走 TCP，从 app 域无法观察 host 是否已 attach。
     * USB 调试的实际启用状态由 detectAdbAndDebugSwitch() 已覆盖。
     */
    public DetectionItem detectAdbConnection() {
        DetectionItem item = new DetectionItem("ADB 网络监听",
                "主动 TCP 探测 wireless adbd 监听端口");

        int configuredPort = -1;
        try {
            Map<String, String> apiVals = readPropertiesViaApi(new String[]{"service.adb.tcp.port"});
            String p = apiVals.get("service.adb.tcp.port");
            if (p != null && !p.isEmpty() && !"-1".equals(p) && !"0".equals(p)) {
                configuredPort = Integer.parseInt(p.trim());
            }
        } catch (Throwable ignored) {
        }

        List<Integer> probePorts = new ArrayList<>();
        if (configuredPort > 0) probePorts.add(configuredPort);
        if (!probePorts.contains(5555)) probePorts.add(5555);

        List<Integer> openPorts = new ArrayList<>();
        for (int port : probePorts) {
            if (probeLocalTcpPort(port)) {
                openPorts.add(port);
            }
        }

        Log.i(TAG, "adb-listen: configured=" + configuredPort
                + " probed=" + probePorts
                + " open=" + openPorts);

        item.setLayerResult(DetectionLayer.JAVA, !openPorts.isEmpty());

        if (!openPorts.isEmpty()) {
            item.setStatus(DetectionStatus.RISK);
            StringBuilder detail = new StringBuilder("wireless adbd 监听中: ");
            for (int i = 0; i < openPorts.size(); i++) {
                if (i > 0) detail.append(", ");
                detail.append("127.0.0.1:").append(openPorts.get(i));
            }
            item.setDetail(detail.toString());
            for (int port : openPorts) {
                String label = port == configuredPort
                        ? "service.adb.tcp.port = " + port
                        : "默认 wireless adb 端口";
                item.addDetectionDetail("🌐 监听端口", "TCP " + port,
                        "127.0.0.1:" + port + " 可连接\n" + label,
                        DetectionLayer.JAVA, "📡");
            }
            if (configuredPort > 0 && !openPorts.contains(configuredPort)) {
                item.addDetectionDetail("⚠️ 异常情况", "属性指向的端口未在监听",
                        "service.adb.tcp.port=" + configuredPort + " 但 connect 失败",
                        DetectionLayer.JAVA, "🚨");
            }
        } else if (configuredPort > 0) {
            // 属性显示开了端口，但 connect 失败 — 异常状态（hook 嫌疑）
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("属性指向 wireless 端口 " + configuredPort
                    + " 但 connect 失败 (可能被 hook 写入假值)");
            item.addDetectionDetail("⚠️ 异常情况",
                    "service.adb.tcp.port=" + configuredPort + " 但端口未监听",
                    "SystemProperties 与实际 socket 状态不一致",
                    DetectionLayer.JAVA, "🚨");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("wireless ADB 未启用");
        }

        item.addDetectionDetail("ℹ️ 检测限制", "USB ADB host attached 不可观测",
                "Android 10+ untrusted_app 无法读 /proc/net/tcp；USB ADB 走 USB function 不走 TCP。\n"
                        + "本检测仅覆盖 wireless ADB 监听 (\"adb tcpip\" / Android 11+ Wireless Debugging)",
                DetectionLayer.JAVA, "ℹ️");

        return item;
    }

    /**
     * adbd daemon 运行态独立检测项。四轴融合判定，跟 detectAdbAndDebugSwitch /
     * detectAdbConnection 的信源完全独立 —— hook 框架想全屏蔽需打四套。
     *
     * 学魔改版 detectAdbdRuntime 的设计 + 我们已有的三路属性基建：
     *   · 属性轴   — 5 个 key (init.svc.adbd / service.adb.{tcp,tls}.port /
     *                 service.adb.root / persist.adb.tls_server.enable) 走
     *                 API + Native mmap + Java mmap 三路融合
     *   · 进程轴   — 遍历 /proc 找 cmdline / comm == "adbd"
     *                  ↳ 读 cmdline/comm 走 readSmallTextLayered (Java + syscall fallback)
     *   · 端口轴   — 主动 TCP connect 探测 tcp.port / tls.port / 5555
     *   · socket 轴 — /dev/socket/adbd connect EACCES (复用 ADBD_SOCK_HIT 字段)
     */
    public DetectionItem detectAdbdRuntime() {
        DetectionItem item = new DetectionItem("adbd 运行态",
                "属性 + /proc 进程 + TCP/TLS 端口 + /dev/socket/adbd 四轴融合");

        // ===== 轴 1: 5 ADB 属性多路读 =====
        String[][] defs = {
                {"init.svc.adbd",                 "init_service_status_prop", "default_prop"},
                {"service.adb.tcp.port",          "adbd_config_prop",         "usb_prop"},
                {"service.adb.tls.port",          "adbd_config_prop",         "default_prop"},
                {"service.adb.root",              "adbd_prop",                "default_prop"},
                {"persist.adb.tls_server.enable", "adbd_config_prop",         "default_prop"},
        };
        String[] keys = propKeys(defs);

        Map<String, String> apiVals = readPropertiesViaApi(keys);
        Map<String, String> javaMmapVals = readPropertiesViaMmap(keys);
        if (javaMmapVals == null) javaMmapVals = java.util.Collections.emptyMap();
        Map<String, String> nativeMmapVals = readPropertiesByContext(defs);

        boolean adbdRunning = anySourceHit(apiVals, javaMmapVals, nativeMmapVals,
                "init.svc.adbd", VAL_EQ_RUNNING);
        int tcpPort = bestAdbPort(apiVals, javaMmapVals, nativeMmapVals, "service.adb.tcp.port");
        int tlsPort = bestAdbPort(apiVals, javaMmapVals, nativeMmapVals, "service.adb.tls.port");
        boolean adbRoot = anySourceHit(apiVals, javaMmapVals, nativeMmapVals,
                "service.adb.root", VAL_TRUTHY_ADB_ROOT);
        boolean tlsEnabled = anySourceHit(apiVals, javaMmapVals, nativeMmapVals,
                "persist.adb.tls_server.enable", VAL_TRUTHY);

        boolean propAxisHit = adbdRunning || tcpPort > 0 || tlsPort > 0 || adbRoot || tlsEnabled;

        // 每个 key 三路对比展示
        for (String[] def : defs) {
            String k = def[0];
            String apiV = apiVals.get(k);
            String natV = nativeMmapVals.get(k);
            String javV = javaMmapVals.get(k);
            if (apiV == null && natV == null && javV == null) continue;
            int predicate;
            if (k.equals("init.svc.adbd"))                          predicate = VAL_EQ_RUNNING;
            else if (k.equals("service.adb.root"))                  predicate = VAL_TRUTHY_ADB_ROOT;
            else if (k.equals("persist.adb.tls_server.enable"))     predicate = VAL_TRUTHY;
            else                                                    predicate = -1; // 端口走数值判定
            boolean hit;
            if (predicate < 0) {
                hit = parseAdbPort(apiV) > 0 || parseAdbPort(natV) > 0 || parseAdbPort(javV) > 0;
            } else {
                hit = valueHits(apiV, predicate) || valueHits(natV, predicate) || valueHits(javV, predicate);
            }
            String display = "API     = " + formatValue(apiV)
                    + "\nNative  = " + formatValue(natV)
                    + "\nJava    = " + formatValue(javV);
            item.addDetectionDetail(hit ? "⚠️ adbd 属性命中" : "📄 adbd 属性",
                    k, display, DetectionLayer.JAVA, hit ? "⚠️" : "📄");
        }

        // ===== 轴 2: /proc 扫 adbd 进程 =====
        AdbdProcessScan scan = scanAdbdProcesses();
        for (String hitDetail : scan.matches) {
            item.addDetectionDetail("🔄 adbd 进程", "adbd", hitDetail,
                    DetectionLayer.SYSCALL, "🚨");
        }
        if (scan.matches.isEmpty()) {
            if (scan.procReadable) {
                item.addDetectionDetail("🔍 /proc 扫描", "未发现 adbd",
                        "已扫描 " + scan.checkedPids + " 个 pid，无命中",
                        DetectionLayer.SYSCALL, "✅");
            } else {
                item.addDetectionDetail("🔍 /proc 扫描", "目录不可枚举",
                        "/proc 不可读，无法扫描 adbd 进程（不影响其他检测）",
                        DetectionLayer.SYSCALL, "ℹ️");
            }
        }

        // ===== 轴 3: TCP/TLS 端口主动 connect =====
        List<Integer> probePorts = new ArrayList<>();
        if (tcpPort > 0) probePorts.add(tcpPort);
        if (tlsPort > 0 && !probePorts.contains(tlsPort)) probePorts.add(tlsPort);
        if (!probePorts.contains(5555)) probePorts.add(5555);

        List<Integer> openPorts = new ArrayList<>();
        for (int port : probePorts) {
            if (probeLocalTcpPort(port)) openPorts.add(port);
        }
        for (int port : openPorts) {
            String label;
            if (port == tcpPort)      label = "service.adb.tcp.port = " + port;
            else if (port == tlsPort) label = "service.adb.tls.port = " + port + " (Wireless Debugging TLS)";
            else                       label = "默认 wireless adb 端口";
            item.addDetectionDetail("🌐 ADB 端口", "TCP " + port,
                    "127.0.0.1:" + port + " 可连接\n" + label,
                    DetectionLayer.JAVA, "🚨");
        }
        if (openPorts.isEmpty()) {
            item.addDetectionDetail("🌐 ADB 端口", "本机端口探测",
                    "probed=" + probePorts + ", open=[]",
                    DetectionLayer.JAVA, "✅");
        }

        // ===== 轴 4: /dev/socket/adbd connect EACCES (复用 native getJdwpDetectionReport) =====
        Map<String, String> nativeReport;
        try {
            nativeReport = parseKeyValueReport(nativeDetector.getJdwpDetectionReport());
        } catch (Throwable t) {
            nativeReport = java.util.Collections.emptyMap();
        }
        boolean adbdSockHit = "1".equals(nativeReport.get("ADBD_SOCK_HIT"));
        int adbdSockErrno = parseIntSafe(nativeReport.get("ADBD_SOCK_ERRNO"), -1);
        String adbdSockName = nativeReport.getOrDefault("ADBD_SOCK_NAME", "");

        {
            String hint;
            String icon;
            if (adbdSockHit) {
                hint = "SELinux 拒，adbd 在监听 → adbd 活";
                icon = "⚠️";
            } else if (adbdSockErrno == 111) {
                hint = "ECONNREFUSED — adbd 不在监听";
                icon = "✅";
            } else if (adbdSockErrno == 2) {
                hint = "ENOENT — /dev/socket/adbd 不存在";
                icon = "✅";
            } else if (adbdSockErrno == 0) {
                hint = "connect 成功（异常 — 普通 untrusted_app 不应能连）";
                icon = "🚨";
            } else {
                hint = "errno=" + adbdSockErrno;
                icon = "ℹ️";
            }
            item.addDetectionDetail("🔌 主动 connect", "/dev/socket/adbd",
                    "errno=" + adbdSockErrno + " (" + adbdSockName + ")\n" + hint,
                    DetectionLayer.NATIVE, icon);
        }

        // ===== 聚合 =====
        item.setLayerResult(DetectionLayer.JAVA, propAxisHit || !openPorts.isEmpty());
        item.setLayerResult(DetectionLayer.NATIVE, adbdSockHit);
        item.setLayerResult(DetectionLayer.SYSCALL, !scan.matches.isEmpty());

        boolean anyHit = propAxisHit || !scan.matches.isEmpty() || !openPorts.isEmpty() || adbdSockHit;
        if (anyHit) {
            item.setStatus(DetectionStatus.RISK);
            StringBuilder d = new StringBuilder();
            if (adbdRunning) d.append("init.svc.adbd=running; ");
            if (tcpPort > 0) d.append("tcp.port=").append(tcpPort).append("; ");
            if (tlsPort > 0) d.append("tls.port=").append(tlsPort).append("; ");
            if (adbRoot)     d.append("adb-root; ");
            if (tlsEnabled)  d.append("tls_server 开; ");
            if (!scan.matches.isEmpty()) d.append("adbd 进程 x").append(scan.matches.size()).append("; ");
            if (!openPorts.isEmpty())    d.append("端口").append(openPorts).append("可连; ");
            if (adbdSockHit)             d.append("/dev/socket/adbd EACCES; ");
            item.setDetail(d.toString().trim());
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未发现 adbd 运行态证据");
        }

        Log.i(TAG, "adbd-runtime: api=" + apiVals
                + " native=" + nativeMmapVals
                + " java=" + javaMmapVals
                + " procScan=" + scan.matches.size() + "/" + scan.checkedPids
                + " openPorts=" + openPorts
                + " adbdSock=" + adbdSockHit + "/" + adbdSockName);

        return item;
    }

    /**
     * USB Functions 运行态独立检测 —— 直接看"当前 USB 功能列表是否含 adb"，
     * 而不是只看 ADB toggle 或 adbd 进程。命中维度：
     *   · 属性轴   — 4 个 USB key 走三路融合 (API + Native mmap + Java mmap)
     *                  - sys.usb.config / sys.usb.state 含 "adb" / "ffs.adb"
     *                  - sys.usb.ffs.ready truthy
     *                  - persist.sys.usb.config 含 "adb"
     *   · framework — UsbManager.getCurrentFunctions() bitmask & USB_FUNCTION_ADB
     *                  (反射调 system-hidden API，untrusted_app 通常被拒)
     *   · sysfs    — /sys/class/android_usb/android0/{functions,state,enable} 文本扫
     *   · configfs — /config/usb_gadget/g1/configs/b.1/ 目录列举找 "adb"/"ffs.adb"
     *   · FFS      — /dev/usb-ffs/adb/ep0 等 FunctionFS 端点是否存在
     *
     * 抗 hook 设计：
     *   - 三路属性源对比：API 被 hook 但属性区原始数据存在时三路不一致触发 RISK
     *   - 文件读 走 readSmallTextLayered (Java FileReader + native readFileSyscall 兜底)
     *   - 文件存在性 走 fileExistsLayered (java File.exists + native fileExistsSyscall 兜底)
     */
    public DetectionItem detectUsbFunctionsRuntime() {
        DetectionItem item = new DetectionItem("USB Functions 运行态",
                "USB functions/state/FunctionFS 与属性三路融合");

        // ===== 三路属性读取 =====
        String[] keys = propKeys(USB_RUNTIME_PROPS);

        Map<String, String> apiVals = readPropertiesViaApi(keys);
        Map<String, String> nativeVals = readPropertiesByContext(USB_RUNTIME_PROPS);
        Map<String, String> javaMmapVals = readPropertiesViaMmap(keys);
        if (javaMmapVals == null) javaMmapVals = java.util.Collections.emptyMap();

        boolean apiAdb = hasCurrentUsbAdb(apiVals);
        boolean nativeAdb = hasCurrentUsbAdb(nativeVals);
        boolean javaAdb = hasCurrentUsbAdb(javaMmapVals);

        boolean ffsReady = hasFfsReady(apiVals) || hasFfsReady(nativeVals) || hasFfsReady(javaMmapVals);
        boolean persistAdb = hasPersistUsbAdb(apiVals) || hasPersistUsbAdb(nativeVals)
                || hasPersistUsbAdb(javaMmapVals);

        StringBuilder diff = new StringBuilder();
        boolean inconsistent = false;

        for (String[] def : USB_RUNTIME_PROPS) {
            String k = def[0];
            String apiV = apiVals.get(k);
            String natV = nativeVals.get(k);
            String javV = javaMmapVals.get(k);
            if (apiV == null && natV == null && javV == null) continue;

            boolean keyHit;
            String defaultIcon;
            if (isCurrentUsbFunctionKey(k)) {
                keyHit = containsAdbFunctionLoose(apiV) || containsAdbFunctionLoose(natV)
                        || containsAdbFunctionLoose(javV);
                defaultIcon = keyHit ? "🚨" : "📄";
            } else if ("sys.usb.ffs.ready".equals(k)) {
                keyHit = valueHits(apiV, VAL_TRUTHY) || valueHits(natV, VAL_TRUTHY)
                        || valueHits(javV, VAL_TRUTHY);
                defaultIcon = keyHit ? "⚠️" : "📄";
            } else { // persist.sys.usb.config
                keyHit = containsAdbFunctionLoose(apiV) || containsAdbFunctionLoose(natV)
                        || containsAdbFunctionLoose(javV);
                defaultIcon = keyHit ? "⚠️" : "📄";
            }
            boolean consistent = consistentValues(apiV, natV, javV);
            String display = "API     = " + formatValue(apiV)
                    + "\nNative  = " + formatValue(natV)
                    + "\nJava    = " + formatValue(javV);
            item.addDetectionDetail(keyHit ? "USB 属性命中" : "USB 属性",
                    k, display, DetectionLayer.NATIVE, !consistent ? "🚨" : defaultIcon);
            if (!consistent) {
                inconsistent = true;
                diff.append(k).append(": API=").append(formatValue(apiV))
                        .append(" / Native=").append(formatValue(natV))
                        .append(" / Java=").append(formatValue(javV)).append("\n");
            }
        }
        if (inconsistent) {
            item.addDetectionDetail("⚠️ 异常情况", "USB 属性三路不一致",
                    diff.toString().trim(), DetectionLayer.NATIVE, "🚨");
        }

        // ===== framework 反射：UsbManager.getCurrentFunctions() =====
        UsbFrameworkScan fwScan = scanUsbFrameworkRuntime();
        String fwIcon = fwScan.adbRuntime ? "🚨" : (fwScan.available ? "📋" : "ℹ️");
        item.addDetectionDetail("🔧 USB framework", "UsbManager runtime", fwScan.detail,
                DetectionLayer.JAVA, fwIcon);

        // ===== sysfs / configfs / FFS 存在性扫描 =====
        UsbRuntimeScan rtScan = scanUsbRuntimeFiles(item);

        // ===== 聚合判定 =====
        boolean anyAdb = apiAdb || nativeAdb || javaAdb;
        // API 路被 hook 报"无 adb"，但 Native/Java mmap/framework/runtime 任一命中 → 强 hook 嫌疑
        boolean apiSilentNativeHit = !apiAdb
                && (nativeAdb || javaAdb || fwScan.adbRuntime || rtScan.adbRuntime);
        boolean anyAdbRuntime = anyAdb || fwScan.adbRuntime || rtScan.adbRuntime;
        boolean ffsEvidenceAny = ffsReady || persistAdb || rtScan.ffsEvidence;

        item.setLayerResult(DetectionLayer.JAVA, apiAdb || fwScan.adbRuntime);
        item.setLayerResult(DetectionLayer.NATIVE, nativeAdb);
        item.setLayerResult(DetectionLayer.SYSCALL, javaAdb || rtScan.adbRuntime);

        if (apiSilentNativeHit) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("API 路报无 adb，但 Native/mmap/runtime 命中 (强 hook 嫌疑)");
            item.addDetectionDetail("⚠️ USB runtime 异常",
                    "API 与 runtime 不一致",
                    "API sys.usb.config/state 未含 adb，但 Native mmap / Java mmap / framework / "
                            + "sysfs / configfs 任一命中 → API 路被 hook 高度嫌疑",
                    DetectionLayer.SYSCALL, "🚨");
        } else if (inconsistent) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("USB 属性 API/Native/Java 不一致 (hook 嫌疑)");
        } else if (anyAdbRuntime) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("当前 USB runtime 包含 adb function");
        } else if (ffsEvidenceAny) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("FunctionFS / persist 辅助证据，但当前 USB function 未确认 adb");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("当前 USB runtime 未发现 adb function");
        }

        Log.i(TAG, "usb-functions: apiAdb=" + apiAdb + " natAdb=" + nativeAdb
                + " javAdb=" + javaAdb + " ffsReady=" + ffsReady + " persistAdb=" + persistAdb
                + " fw=" + fwScan.adbRuntime + " rt=" + rtScan.adbRuntime
                + " ffsEvidence=" + rtScan.ffsEvidence
                + " readable=" + rtScan.readableCount + "/" + (rtScan.readableCount + rtScan.unreadableCount));

        return item;
    }

    // ===================== USB functions helpers =====================

    /** "adb" 或 "ffs.adb" 子串匹配 (大小写不敏感)。 */
    private static boolean containsAdbFunctionLoose(String v) {
        if (v == null) return false;
        String low = v.toLowerCase(java.util.Locale.US);
        return low.contains("adb") || low.contains("ffs.adb");
    }

    private static boolean hasCurrentUsbAdb(Map<String, String> m) {
        if (m == null) return false;
        return containsAdbFunctionLoose(m.get("sys.usb.config"))
                || containsAdbFunctionLoose(m.get("sys.usb.state"));
    }

    private static boolean hasFfsReady(Map<String, String> m) {
        if (m == null) return false;
        return valueHits(m.get("sys.usb.ffs.ready"), VAL_TRUTHY);
    }

    private static boolean hasPersistUsbAdb(Map<String, String> m) {
        if (m == null) return false;
        return containsAdbFunctionLoose(m.get("persist.sys.usb.config"));
    }

    private static boolean isCurrentUsbFunctionKey(String k) {
        return "sys.usb.config".equals(k) || "sys.usb.state".equals(k);
    }

    /** UsbManager.getCurrentFunctions() 返回 long bitmask → 人类可读串。 */
    private static String decodeUsbFunctions(long bits) {
        if (bits == 0) return "none";
        List<String> parts = new ArrayList<>();
        if ((USB_FUNCTION_ADB & bits) != 0) parts.add("adb");
        if ((2  & bits) != 0) parts.add("accessory");
        if ((4  & bits) != 0) parts.add("mtp");
        if ((8  & bits) != 0) parts.add("midi");
        if ((16 & bits) != 0) parts.add("ptp");
        if ((32 & bits) != 0) parts.add("rndis");
        if ((64 & bits) != 0) parts.add("audio_source");
        if (parts.isEmpty()) parts.add("unknown_bits=0x" + Long.toHexString(bits));
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < parts.size(); i++) {
            if (i > 0) s.append(",");
            s.append(parts.get(i));
        }
        return s.toString();
    }

    /**
     * 反射调 UsbManager.getCurrentFunctions() / getCurrentFunctionsApplied()。
     * 两个方法都是 system-hidden API；untrusted_app 通常被 hidden-API 黑名单或权限拒绝。
     * 抛异常时把异常信息也作为 detail 写入 —— 异常本身就是信息（"被拒"也是判定线索）。
     */
    private UsbFrameworkScan scanUsbFrameworkRuntime() {
        UsbFrameworkScan s = new UsbFrameworkScan();
        StringBuilder sb = new StringBuilder();
        try {
            Object usbService = context.getSystemService("usb");
            if (usbService == null) {
                s.detail = "Context.USB_SERVICE 不可用";
                return s;
            }
            s.available = true;
            try {
                Object o = invokeNoArg(usbService, "getCurrentFunctions");
                if (o instanceof Number) {
                    long bits = ((Number) o).longValue();
                    String decoded = decodeUsbFunctions(bits);
                    s.adbRuntime = (USB_FUNCTION_ADB & bits) != 0
                            || containsAdbFunctionLoose(decoded);
                    sb.append("currentFunctions=").append(bits)
                            .append(" [").append(decoded).append("]");
                } else {
                    sb.append("getCurrentFunctions 返回 ")
                            .append(o == null ? "null" : o.toString());
                }
            } catch (Throwable t) {
                sb.append("getCurrentFunctions 不可用: ").append(simpleError(t));
            }
            try {
                Object o2 = invokeNoArg(usbService, "getCurrentFunctionsApplied");
                if (sb.length() > 0) sb.append("\n");
                sb.append("currentFunctionsApplied=").append(o2);
            } catch (Throwable t) {
                if (sb.length() > 0) sb.append("\n");
                sb.append("getCurrentFunctionsApplied 不可用: ").append(simpleError(t));
            }
            s.detail = sb.length() == 0 ? "USB framework 未返回 runtime 信息" : sb.toString();
        } catch (Throwable t) {
            s.detail = "USB framework 检测失败: " + simpleError(t);
        }
        return s;
    }

    /**
     * sysfs/configfs 三类扫描：
     *  1. /sys/class/android_usb/android0/*  文本读，含 adb 视为命中
     *  2. /config/usb_gadget/g1/configs/b.1/ 目录列举，子项名/symlink target 含 adb 视为命中
     *  3. /dev/usb-ffs/adb/ep0 等 FFS 端点存在性
     */
    private UsbRuntimeScan scanUsbRuntimeFiles(DetectionItem item) {
        UsbRuntimeScan s = new UsbRuntimeScan();

        // === 1) sysfs 文本读 (Java + syscall 兜底) ===
        for (String path : USB_RUNTIME_VALUE_PATHS) {
            String content = readSmallTextLayered(path);
            if (content != null && !content.isEmpty()) {
                s.readableCount++;
                boolean hit = containsAdbFunctionLoose(content);
                if (hit) s.adbRuntime = true;
                item.addDetectionDetail("📂 sysfs", path,
                        trimDisplay(content),
                        DetectionLayer.SYSCALL, hit ? "🚨" : "✅");
            } else {
                s.unreadableCount++;
            }
        }

        // === 2) configfs 目录列举 ===
        for (String dir : USB_CONFIGFS_CONFIG_DIRS) {
            File[] entries = null;
            try {
                entries = new File(dir).listFiles();
            } catch (Throwable ignored) {
            }
            if (entries == null) {
                s.unreadableCount++;
                continue;
            }
            s.readableCount++;
            if (entries.length == 0) {
                item.addDetectionDetail("📂 configfs", dir, "目录可读但配置为空",
                        DetectionLayer.JAVA, "✅");
                continue;
            }
            for (File f : entries) {
                String canonical = safeCanonicalPath(f);
                String detail = "entry=" + f.getName()
                        + (canonical.isEmpty() ? "" : "\ntarget=" + canonical);
                boolean hit = containsAdbFunctionLoose(f.getName())
                        || containsAdbFunctionLoose(canonical);
                if (hit) s.adbRuntime = true;
                item.addDetectionDetail("📂 configfs", dir + "/" + f.getName(),
                        detail, DetectionLayer.JAVA, hit ? "🚨" : "📁");
            }
        }

        // === 3) FFS / configfs 端点存在性 (Java + syscall 兜底) ===
        for (String path : USB_RUNTIME_EXISTENCE_PATHS) {
            FileExistResult r = fileExistsLayered(path);
            if (r.exists) {
                s.ffsEvidence = true;
                // /configs/ 路径或 /ep0 端点 → 当前激活的 ADB function，强信号
                boolean isActiveConfig = path.contains("/configs/") || path.endsWith("/ep0");
                if (isActiveConfig) s.adbRuntime = true;
                item.addDetectionDetail("📍 FFS 证据", path,
                        "存在 (" + r.source + ")",
                        r.layer, isActiveConfig ? "🚨" : "⚠️");
            } else {
                s.unreadableCount++;
            }
        }

        if (s.readableCount == 0 && s.unreadableCount > 0) {
            item.addDetectionDetail("ℹ️ 访问限制", "USB sysfs/configfs 不可读",
                    "普通 app 当前无法读 USB sysfs/configfs（已尝试 Java + syscall 两路）",
                    DetectionLayer.SYSCALL, "ℹ️");
        }
        return s;
    }

    private static class FileExistResult {
        final boolean exists;
        final String source;
        final DetectionLayer layer;
        FileExistResult(boolean exists, String source, DetectionLayer layer) {
            this.exists = exists; this.source = source; this.layer = layer;
        }
    }

    /** 文件存在性双路检查：Java File.exists 先，native fileExistsSyscall 兜底。 */
    private FileExistResult fileExistsLayered(String path) {
        try {
            if (new File(path).exists()) {
                return new FileExistResult(true, "java", DetectionLayer.JAVA);
            }
        } catch (Throwable ignored) {
        }
        try {
            if (nativeDetector.fileExistsSyscall(path)) {
                return new FileExistResult(true, "syscall", DetectionLayer.SYSCALL);
            }
        } catch (Throwable ignored) {
        }
        return new FileExistResult(false, "", DetectionLayer.SYSCALL);
    }

    private static String safeCanonicalPath(File f) {
        try {
            return f.getCanonicalPath();
        } catch (Throwable t) {
            return "";
        }
    }

    private static String trimDisplay(String s) {
        if (s == null) return "";
        String trimmed = s.trim();
        if (trimmed.length() > 256) return trimmed.substring(0, 253) + "...";
        return trimmed;
    }

    private static String simpleError(Throwable t) {
        if (t == null) return "";
        String msg = t.getMessage();
        return t.getClass().getSimpleName() + (msg == null ? "" : ": " + msg);
    }

    /** 反射调对象的无参方法。遍历 getDeclaredMethods 走 superclass 链以匹配 hidden API。 */
    private static Object invokeNoArg(Object target, String methodName) throws Exception {
        Method m = findNoArgMethod(target.getClass(), methodName);
        if (m == null) throw new NoSuchMethodException(methodName);
        return m.invoke(target);
    }

    private static Method findNoArgMethod(Class<?> cls, String name) {
        for (Class<?> c = cls; c != null; c = c.getSuperclass()) {
            try {
                Method m = c.getDeclaredMethod(name);
                m.setAccessible(true);
                return m;
            } catch (NoSuchMethodException ignored) {
            }
        }
        return null;
    }

    // ===================== adbd runtime helpers =====================

    /**
     * adbd 进程扫描结果（学魔改版 DebugDetector$AdbdProcessScan 内部类的结构）。
     */
    private static class AdbdProcessScan {
        final List<String> matches = new ArrayList<>();
        boolean procReadable = false;
        int checkedPids = 0;
    }

    /**
     * 遍历 /proc/&lt;pid&gt; 找 adbd 进程，cmdline + comm 双源判定。
     *
     * 关键 anti-hook 设计：读 /proc/&lt;pid&gt;/cmdline 和 comm 走
     * {@link #readSmallTextLayered}（Java FileReader 先，syscall 兜底），
     * 即便 libc / Java FileSystem 被 hook 也能拿到原始数据。
     */
    private AdbdProcessScan scanAdbdProcesses() {
        AdbdProcessScan s = new AdbdProcessScan();
        File procDir = new File("/proc");
        File[] files;
        try {
            files = procDir.listFiles();
        } catch (Throwable t) {
            files = null;
        }
        if (files == null) {
            s.procReadable = false;
            return s;
        }
        s.procReadable = true;
        java.util.Set<String> seen = new HashSet<>();
        for (File f : files) {
            String name = f.getName();
            // 只看数字目录 (PID)
            if (name.isEmpty() || !isAllDigits(name)) continue;
            s.checkedPids++;
            String cmdline = normalizeProcText(readSmallTextLayered("/proc/" + name + "/cmdline"));
            String comm = normalizeProcText(readSmallTextLayered("/proc/" + name + "/comm"));
            if (isAdbdProcess(cmdline, comm) && seen.add(name)) {
                StringBuilder b = new StringBuilder("PID: ").append(name);
                if (!comm.isEmpty())    b.append("\nCOMM: ").append(comm);
                if (!cmdline.isEmpty()) b.append("\nCMD: ").append(cmdline);
                s.matches.add(b.toString());
            }
        }
        return s;
    }

    private static boolean isAllDigits(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    /** comm == "adbd" 或 cmdline 第一个 token 的 basename == "adbd"。 */
    private static boolean isAdbdProcess(String cmdline, String comm) {
        if ("adbd".equals(comm)) return true;
        if (cmdline == null || cmdline.isEmpty()) return false;
        String first = cmdline.split("\\s+", 2)[0];
        int slash = first.lastIndexOf('/');
        if (slash >= 0) first = first.substring(slash + 1);
        return "adbd".equals(first);
    }

    /** /proc/&lt;pid&gt;/cmdline 用 '\0' 分隔参数；comm 通常带末尾换行。 */
    private static String normalizeProcText(String s) {
        if (s == null) return "";
        return s.replace('\0', ' ').trim();
    }

    /**
     * Java FileReader 先读，失败/空走 native readFileSyscall (openat+read+close raw syscall)。
     * 这是魔改版的 anti-hook 惯用法：Java I/O 被 hook 时 syscall 还能拿到原始数据。
     */
    private String readSmallTextLayered(String path) {
        String java = readSmallTextJava(path);
        if (java != null && !java.isEmpty()) return java;
        try {
            String syscall = nativeDetector.readFileSyscall(path);
            if (syscall != null && !syscall.isEmpty()) return syscall;
        } catch (Throwable ignored) {
        }
        return "";
    }

    private static String readSmallTextJava(String path) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(path);
            byte[] buf = new byte[2048];
            StringBuilder sb = new StringBuilder();
            int n;
            while ((n = fis.read(buf)) > 0) {
                sb.append(new String(buf, 0, n, StandardCharsets.UTF_8));
                if (sb.length() > 8192) break;
            }
            return sb.toString();
        } catch (Throwable t) {
            return "";
        } finally {
            try { if (fis != null) fis.close(); } catch (Throwable ignored) {}
        }
    }

    /** 解析 ADB 端口属性（"-1"/"0"/空 → -1；合法 1-65535 → 原值；否则 -1）。 */
    private static int parseAdbPort(String v) {
        if (v == null || v.isEmpty()) return -1;
        try {
            int n = Integer.parseInt(v.trim());
            if (n <= 0 || n > 65535) return -1;
            return n;
        } catch (Throwable t) {
            return -1;
        }
    }

    /** 从三路属性源里挑首个合法端口；优先级 API > NativeMmap > JavaMmap。 */
    private static int bestAdbPort(Map<String, String> a, Map<String, String> b,
                                   Map<String, String> c, String key) {
        int va = parseAdbPort(a.get(key));
        if (va > 0) return va;
        int vc = parseAdbPort(c.get(key));
        if (vc > 0) return vc;
        int vb = parseAdbPort(b.get(key));
        return vb;
    }

    private static boolean probeLocalTcpPort(int port) {
        java.net.Socket socket = null;
        try {
            socket = new java.net.Socket();
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), 80);
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            try { if (socket != null) socket.close(); } catch (Throwable ignored) {}
        }
    }

    /**
     * 通过 mmap 直读 /dev/__properties__/u:object_r:debug_prop:s0 和 u:object_r:usb_prop:s0
     * 等 SELinux context 文件，检测 ADB / USB 调试是否处于开启状态。
     *
     * 三路并取，专项关注 ADB / 调试开关：
     *  · JAVA    层 — android.os.SystemProperties.get (反射，会被 Java hook 拦截)
     *  · NATIVE  层 — Native C 通过 syscall_open + mmap 按 context 文件读 prop_info 二进制
     *  · SYSCALL 层 — Java FileChannel.map 重做一次扫描，作为旁路核验
     * 任一来源命中风险或三路结果不一致即判 RISK，最大化抓住 hook / 假属性场景。
     *
     * 参考实现：com.jd.stat.common.kit.devproperties.c
     */
    public DetectionItem detectAdbAndDebugSwitch() {
        DetectionItem item = new DetectionItem("ADB / 调试开关",
                "mmap 直读 debug_prop / usb_prop 检测 USB 调试与 ADB 网络");

        String[] keys = propKeys(ADB_DEBUG_PROPS);

        // API 路径（SystemProperties.get 反射）总是可用，作为主驱动；
        // mmap 路径作为「能否旁证」用，失败时只降可信度，不再短路。
        Map<String, String> apiValues = readPropertiesViaApi(keys);
        Map<String, String> javaMmapValues = readPropertiesViaMmap(keys);
        Map<String, String> nativeMmapValues = readPropertiesByContext(ADB_DEBUG_PROPS);

        boolean javaOk = javaMmapValues != null && !javaMmapValues.isEmpty();
        boolean nativeOk = !nativeMmapValues.isEmpty();
        boolean mmapAvailable = javaOk || nativeOk;

        if (javaMmapValues == null) javaMmapValues = java.util.Collections.emptyMap();

        if (!mmapAvailable) {
            // mmap 整路都失败 — 加诊断信息，但不要早退，下面继续用 API 值判定
            String diag = "";
            try {
                diag = nativeDetector.probeDevPropertyAccess();
            } catch (Throwable ignored) {
            }
            if (diag == null) diag = "";
            item.addDetectionDetail("🚧 mmap 不可用",
                    "/dev/__properties__ 所有 context 文件均无法 open",
                    diag.isEmpty() ? "Native 诊断不可用" : diag.trim(),
                    DetectionLayer.NATIVE, "🚧");
        }

        boolean apiRisky = false;
        boolean nativeRisky = false;
        boolean javaRisky = false;
        StringBuilder summary = new StringBuilder();
        StringBuilder diff = new StringBuilder();
        int inconsistentCount = 0;

        for (String[] def : ADB_DEBUG_PROPS) {
            String key = def[0];
            String ctxHint = def[1] + (def.length > 2 && !def[2].isEmpty() ? "," + def[2] : "");

            String apiVal = apiValues.get(key);
            String nativeVal = nativeMmapValues.get(key);
            String javaVal = javaMmapValues.get(key);

            boolean apiHit = evaluateRisk(key, apiVal);
            boolean nativeHit = evaluateRisk(key, nativeVal);
            boolean javaHit = evaluateRisk(key, javaVal);

            if (apiHit) apiRisky = true;
            if (nativeHit) nativeRisky = true;
            if (javaHit) javaRisky = true;

            boolean consistent = consistentValues(apiVal, nativeVal, javaVal);
            boolean anyPresent = (apiVal != null) || isPresent(nativeVal) || (javaVal != null);

            if (anyPresent) {
                String display = "API     =" + formatValue(apiVal)
                        + "\nNative  =" + formatValue(nativeVal) + "  [" + ctxHint + "]"
                        + "\nJava    =" + formatValue(javaVal);
                String icon = (nativeHit || apiHit || javaHit) ? "⚠️" : (consistent ? "📄" : "🚨");
                item.addDetectionDetail("📄 ADB/调试属性", key, display,
                        DetectionLayer.NATIVE, icon);
            }

            if (!consistent) {
                inconsistentCount++;
                diff.append(key)
                        .append(": API=").append(formatValue(apiVal))
                        .append(" / Native=").append(formatValue(nativeVal))
                        .append(" / Java=").append(formatValue(javaVal))
                        .append("\n");
            }

            if (nativeHit) {
                summary.append(key).append("=").append(formatValue(nativeVal)).append("; ");
            } else if (apiHit) {
                summary.append(key).append("=").append(formatValue(apiVal)).append("; ");
            }
        }

        if (inconsistentCount > 0) {
            item.addDetectionDetail("⚠️ 异常情况",
                    "三路结果不一致 (疑似 SystemProperties 或 mmap 被 hook)",
                    diff.toString().trim(),
                    DetectionLayer.NATIVE, "🚨");
        }

        // init.rc 旁路扫描：极少检测会扫 /system/etc/init/hw/*.rc，把 adb/调试
        // 烤进固件的行就是这里现形 —— 即便活态属性看着干净，rc 写死也算 RISK。
        List<String[]> rcHits = scanRiskyInitRcDirectives();
        boolean rcRisky = !rcHits.isEmpty();
        for (String[] hit : rcHits) {
            String path = hit[0];
            String lineno = hit[1];
            String key = hit[2];
            String value = hit[3];
            String raw = hit[4];
            item.addDetectionDetail("📜 init.rc 烤入",
                    key + " = " + value + " @ " + path + ":" + lineno,
                    raw,
                    DetectionLayer.SYSCALL, "🚨");
            summary.append(key).append("=").append(value)
                    .append(" @ ").append(path).append(":").append(lineno).append("; ");
        }
        Log.i(TAG, "rc-scan: hits=" + rcHits.size());

        item.setLayerResult(DetectionLayer.JAVA, apiRisky);
        item.setLayerResult(DetectionLayer.NATIVE, nativeRisky);
        item.setLayerResult(DetectionLayer.SYSCALL, javaRisky || rcRisky);

        if (apiRisky || nativeRisky || javaRisky || inconsistentCount > 0 || rcRisky) {
            item.setStatus(DetectionStatus.RISK);
            if (summary.length() == 0) {
                summary.append("API / Native / Java 结果不一致 (疑似 hook)");
            } else if (inconsistentCount > 0) {
                summary.append(" 检测层不一致");
            }
            if (rcRisky) {
                summary.append(" (init.rc 命中 ").append(rcHits.size()).append(" 条)");
            }
            if (!mmapAvailable) {
                summary.append(" (mmap 不可用)");
            }
            item.setDetail(summary.toString().trim());
        } else if (!mmapAvailable) {
            // API 显示未开启，但 mmap 无法旁证 — 不能完全确认安全
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("API 显示未开启，但 /dev/__properties__ 不可访问，无法旁证");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("ADB / 调试开关未开启");
        }

        String summaryLine = "result status=" + item.getStatus()
                + " detail=" + item.getDetail()
                + " api=" + apiValues
                + " native=" + nativeMmapValues
                + " java=" + javaMmapValues;
        Log.i(TAG, summaryLine);
        try {
            File dir = context.getExternalFilesDir(null);
            if (dir != null) {
                File f = new File(dir, "adb_dbg_probe.log");
                java.io.FileWriter w = new java.io.FileWriter(f, false);
                w.write(new java.util.Date().toString() + "\n" + summaryLine + "\n");
                w.close();
            }
        } catch (Throwable ignored) {
        }

        return item;
    }

    /** 三路非空值是否一致。null 或 "" 视为缺失，缺失项不参与对比。 */
    private static boolean consistentValues(String a, String b, String c) {
        String pivot = null;
        String[] vals = {a, b, c};
        for (String v : vals) {
            if (!isPresent(v)) continue;
            if (pivot == null) {
                pivot = v;
            } else if (!pivot.equals(v)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isPresent(String v) {
        return v != null && !v.isEmpty();
    }

    // ===================== Java Layer Methods =====================

    // ===================== JDWP helper methods =====================

    /** App 自身是否被标记为可调试 (FLAG_DEBUGGABLE)。JDWP attach 的前置条件之一。 */
    private boolean isAppDebuggable() {
        try {
            android.content.pm.ApplicationInfo ai = context.getApplicationInfo();
            return (ai.flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Java 层枚举所有线程，按归类返回 JDWP 相关线程：
     *  · result[0] = control 类（pre-attach capability，"ADB-JDWP Connec" / "AdbConnection*"）
     *  · result[1] = transport 类（post-attach 真 attach 凭证："JDWP Transport*" / "JDWP Event*"
     *                              / "JDWP Command*" / "JDWP Helper*" / "JVMTI Agent*"）
     * 每个槽位是 "tid:name|tid:name" 形式。线程名在 Linux 上限 16 字节会截断，子串匹配。
     */
    private String[] scanJavaThreadsForJdwpByKind() {
        StringBuilder ctl = new StringBuilder();
        StringBuilder xport = new StringBuilder();
        try {
            ThreadGroup root = Thread.currentThread().getThreadGroup();
            while (root.getParent() != null) root = root.getParent();
            Thread[] all = new Thread[Math.max(root.activeCount() + 16, 64)];
            int n = root.enumerate(all, true);
            for (int i = 0; i < n; i++) {
                Thread t = all[i];
                if (t == null) continue;
                String name = t.getName();
                if (name == null) continue;
                int kind = classifyJdwpThreadName(name);
                if (kind == 0) continue;
                StringBuilder sink = (kind == 2) ? xport : ctl;
                if (sink.length() > 0) sink.append("|");
                sink.append(t.getId()).append(":").append(name);
            }
        } catch (Throwable ignored) {
        }
        return new String[]{ctl.toString(), xport.toString()};
    }

    /** 返回 0=NONE, 1=CONTROL, 2=TRANSPORT。和 Native 端 classifyJdwpThread 同语义。 */
    private static int classifyJdwpThreadName(String name) {
        if (name.contains("JDWP Transport") || name.contains("JDWP Event")
                || name.contains("JDWP Command") || name.contains("JDWP Helper")
                || name.contains("JVMTI Agent")) {
            return 2;
        }
        if (name.contains("ADB-JDWP") || name.contains("AdbConnection")) {
            return 1;
        }
        if (name.contains("JDWP") || name.contains("Jdwp")) {
            return 1;
        }
        return 0;
    }

    /**
     * Java 层读 /proc/net/unix 数 @jdwp 抽象 socket 总数。/proc/net/unix 在 untrusted_app
     * 域允许读（不像 /proc/net/tcp 在 A10+ 被锁）。每行末尾是 path 列；抽象 namespace
     * 在 procfs 里以 '@' 开头表示。
     *
     * 注意：这是**全局视图**，包含 adbd 的 @jdwp-control 与所有 debuggable 进程的
     * @jdwp-&lt;pid&gt;，不能用于判定当前进程是否被 attach —— 那应该用
     * {@link #countJdwpUnixSocketsForSelfJava()} 过滤当前 PID。
     */
    private int countJdwpUnixSocketsJava() {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader("/proc/net/unix"));
            int count = 0;
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("@jdwp")) count++;
            }
            return count;
        } catch (Throwable t) {
            return 0;
        } finally {
            try { if (reader != null) reader.close(); } catch (Throwable ignored) {}
        }
    }

    /** 只数 @jdwp-&lt;self_pid&gt; — 才是 "JDWP 已在我们这个进程 attach" 的可信信号。 */
    private int countJdwpUnixSocketsForSelfJava() {
        BufferedReader reader = null;
        try {
            String selfTag = "@jdwp-" + android.os.Process.myPid();
            reader = new BufferedReader(new FileReader("/proc/net/unix"));
            int count = 0;
            String line;
            while ((line = reader.readLine()) != null) {
                int idx = line.indexOf(selfTag);
                if (idx < 0) continue;
                int after = idx + selfTag.length();
                // 完整 token 校验：tag 后必须是行尾或空白，避免 pid=12 误吃 pid=123
                if (after >= line.length()) { count++; continue; }
                char c = line.charAt(after);
                if (c == ' ' || c == '\t' || c == '\r') count++;
            }
            return count;
        } catch (Throwable t) {
            return 0;
        } finally {
            try { if (reader != null) reader.close(); } catch (Throwable ignored) {}
        }
    }

    /** 解析 native 返回的 "KEY=VALUE\nKEY=VALUE" 报告。 */
    private static Map<String, String> parseKeyValueReport(String report) {
        Map<String, String> result = new LinkedHashMap<>();
        if (report == null || report.isEmpty()) return result;
        for (String line : report.split("\n")) {
            int eq = line.indexOf('=');
            if (eq <= 0) continue;
            result.put(line.substring(0, eq).trim(), line.substring(eq + 1));
        }
        return result;
    }

    private static int parseIntSafe(String v, int def) {
        if (v == null || v.isEmpty()) return def;
        try {
            return Integer.parseInt(v.trim());
        } catch (Throwable t) {
            return def;
        }
    }

    /**
     * Read TracerPid from /proc/self/status using Java API
     * @return TracerPid value, 0 if no debugger
     */
    private int readTracerPidJava() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String[] parts = line.split("\\s+");
                    if (parts.length > 1) {
                        reader.close();
                        return Integer.parseInt(parts[1]);
                    }
                }
            }
            reader.close();
        } catch (Exception e) {
            // Ignore
        }
        return 0;
    }

    /**
     * Read TracerPid via syscall (through native)
     * @return TracerPid value
     */
    private int readTracerPidSyscall() {
        try {
            // Read via syscall through native
            String status = nativeDetector.readFileSyscall("/proc/self/status");
            if (status != null && !status.isEmpty()) {
                String[] lines = status.split("\n");
                for (String line : lines) {
                    if (line.startsWith("TracerPid:")) {
                        String[] parts = line.split("\\s+");
                        if (parts.length > 1) {
                            return Integer.parseInt(parts[1]);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return 0;
    }

    /**
     * Check TracerPid for all threads
     * @return String describing any traced threads
     */
    private String checkAllThreadsTracerPid() {
        StringBuilder result = new StringBuilder();
        try {
            // Read /proc/self/task directory
            java.io.File taskDir = new java.io.File("/proc/self/task");
            java.io.File[] threads = taskDir.listFiles();

            if (threads != null) {
                int tracedThreads = 0;
                for (java.io.File thread : threads) {
                    if (!thread.isDirectory()) continue;

                    String tid = thread.getName();
                    String statusPath = "/proc/self/task/" + tid + "/status";

                    try {
                        BufferedReader reader = new BufferedReader(new FileReader(statusPath));
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (line.startsWith("TracerPid:")) {
                                String[] parts = line.split("\\s+");
                                if (parts.length > 1) {
                                    int tracerPid = Integer.parseInt(parts[1]);
                                    if (tracerPid > 0) {
                                        tracedThreads++;
                                        if (result.length() == 0) {
                                            result.append("被跟踪的线程: ");
                                        } else {
                                            result.append(", ");
                                        }
                                        result.append("TID:").append(tid).append("(").append(tracerPid).append(")");
                                    }
                                }
                                break;
                            }
                        }
                        reader.close();
                    } catch (Exception e) {
                        // Ignore individual thread errors
                    }
                }

                if (tracedThreads > 0) {
                    result.insert(0, tracedThreads + "个线程被跟踪 - ");
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return result.toString();
    }

    // ===================== Detail Collection Methods =====================

    /**
     * Collect USB debugging details
     */
    private void collectUsbDebuggingDetails(DetectionItem item,
                                            int adbEnabledSetting,
                                            Map<String, String> apiVals,
                                            Map<String, String> javaMmapVals,
                                            Map<String, String> nativeMmapVals) {
        // ADB Settings
        String adbDisplay = adbEnabledSetting < 0
                ? "<读取失败>"
                : adbEnabledSetting + " (1=开, 0=关)";
        item.addDetectionDetail("⚙️ 系统设置", "Settings.Global.ADB_ENABLED",
                "值: " + adbDisplay, DetectionLayer.JAVA, "🔧");

        // 开发者选项状态
        try {
            int devEnabled = Settings.Global.getInt(context.getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
            item.addDetectionDetail("⚙️ 系统设置", "开发者选项",
                    devEnabled == 1 ? "已开启" : "已关闭",
                    DetectionLayer.JAVA, "🛠️");
        } catch (Exception ignored) {
        }

        // USB function / adbd 三源对比
        String[] keys = {"sys.usb.config", "sys.usb.state", "init.svc.adbd", "persist.sys.usb.config"};
        for (String key : keys) {
            String api = apiVals.get(key);
            String nat = nativeMmapVals.get(key);
            String jav = javaMmapVals.get(key);
            if (api == null && nat == null && jav == null) continue;
            String display = "API     = " + formatValue(api)
                    + "\nNative  = " + formatValue(nat)
                    + "\nJava    = " + formatValue(jav);
            boolean hit = valueHits(api, key.equals("init.svc.adbd") ? VAL_EQ_RUNNING : VAL_CONTAINS_ADB)
                    || valueHits(nat, key.equals("init.svc.adbd") ? VAL_EQ_RUNNING : VAL_CONTAINS_ADB)
                    || valueHits(jav, key.equals("init.svc.adbd") ? VAL_EQ_RUNNING : VAL_CONTAINS_ADB);
            item.addDetectionDetail(hit ? "📡 USB 通道命中" : "📄 USB/ADB 属性",
                    key, display, DetectionLayer.NATIVE, hit ? "⚠️" : "📄");
        }

        // 兜底：扫 /proc/<pid>/cmdline 找 adbd 进程（在被 hook 时可作旁证）
        try {
            java.io.File procDir = new java.io.File("/proc");
            java.io.File[] procs = procDir.listFiles();
            if (procs != null) {
                for (java.io.File proc : procs) {
                    if (!proc.getName().matches("\\d+")) continue;
                    try {
                        java.io.File cmdlineFile = new java.io.File(proc, "cmdline");
                        if (!cmdlineFile.exists()) continue;
                        BufferedReader reader = new BufferedReader(new FileReader(cmdlineFile));
                        String cmdline = reader.readLine();
                        reader.close();
                        if (cmdline != null && cmdline.contains("adbd")) {
                            item.addDetectionDetail("🔄 ADB 进程", "adbd",
                                    "PID: " + proc.getName() + "\nCMD: " + cmdline,
                                    DetectionLayer.NATIVE, "⚙️");
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    /**
     * Collect debugger details
     */
    private void collectDebuggerDetails(DetectionItem item, boolean javaResult,
                                       boolean nativeResult, boolean syscallResult) {
        // 检测结果统计
        int detectionCount = 0;
        if (javaResult) detectionCount++;
        if (nativeResult) detectionCount++;
        if (syscallResult) detectionCount++;

        item.addDetectionDetail("📊 检测层统计", "检测到调试器的层数",
            detectionCount + " / 3",
            DetectionLayer.JAVA, "📈");

        // 调试器类型判断
        if (javaResult) {
            boolean isWaitingForDebugger = Debug.waitingForDebugger();
            String detail = "状态: 已连接";
            if (isWaitingForDebugger) {
                detail += "\n等待调试器: 是";
            }
            item.addDetectionDetail("☕ Java 调试", "Debug.isDebuggerConnected()",
                detail, DetectionLayer.JAVA, "🔗");
        }

        // 检测调试器进程
        try {
            java.io.File procDir = new java.io.File("/proc");
            java.io.File[] procs = procDir.listFiles();
            if (procs != null) {
                String[] debuggers = {"gdbserver", "lldb-server", "android_server", "ida"};
                for (java.io.File proc : procs) {
                    if (!proc.getName().matches("\\d+")) continue;

                    try {
                        java.io.File cmdlineFile = new java.io.File(proc, "cmdline");
                        if (cmdlineFile.exists()) {
                            BufferedReader reader = new BufferedReader(new FileReader(cmdlineFile));
                            String cmdline = reader.readLine();
                            reader.close();

                            if (cmdline != null) {
                                for (String debugger : debuggers) {
                                    if (cmdline.toLowerCase().contains(debugger)) {
                                        item.addDetectionDetail("🔄 调试器进程", debugger,
                                            "PID: " + proc.getName() + "\nCMD: " + cmdline,
                                            DetectionLayer.NATIVE, "⚙️");
                                    }
                                }
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {
        }

        // 检测调试端口
        int[] debugPorts = {5005, 8000, 8700, 23946}; // JDWP, IDA
        for (int port : debugPorts) {
            try {
                java.net.Socket socket = new java.net.Socket();
                socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), 100);
                socket.close();
                item.addDetectionDetail("🌐 调试端口", "端口 " + port,
                    "127.0.0.1:" + port + " 正在监听",
                    DetectionLayer.JAVA, "🔌");
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Collect JDWP details — 把分层证据全部塞进 DetectionItem.detail 列表里展示
     */
    private void collectJdwpDetails(DetectionItem item,
                                    boolean debuggerConnected,
                                    boolean waitingForDebugger,
                                    boolean appDebuggable,
                                    String javaThreadHitsCtl,
                                    String javaThreadHitsXport,
                                    int javaUnixSocketsTotal,
                                    int javaUnixSocketsSelf,
                                    boolean adbConnLoaded,
                                    boolean jvmtiLoaded,
                                    int nativeUnixSocketsTotal,
                                    int nativeUnixSocketsSelf,
                                    String nativeThreadHitsCtl,
                                    String nativeThreadHitsXport,
                                    String jdwpProvider,
                                    boolean adbdSockHit, int adbdSockErrno, String adbdSockName,
                                    boolean jdwpCtlHit,  int jdwpCtlErrno,  String jdwpCtlName) {

        // ===== JAVA 层证据 =====
        if (debuggerConnected || waitingForDebugger) {
            item.addDetectionDetail("☕ Java 调试 API", "Debug.isDebuggerConnected / waitingForDebugger",
                    "connected=" + debuggerConnected + ", waiting=" + waitingForDebugger,
                    DetectionLayer.JAVA, "🔗");
        }

        item.addDetectionDetail("🏷️ ApplicationInfo", "FLAG_DEBUGGABLE",
                appDebuggable ? "true (允许 JDWP attach)" : "false (不允许 JDWP attach)",
                DetectionLayer.JAVA, appDebuggable ? "⚠️" : "✅");

        // Java transport 线程（真 attach 凭证）
        if (!javaThreadHitsXport.isEmpty()) {
            item.addDetectionDetail("🧵 Java 线程命中", "JDWP transport / JVMTI Agent (真 attach 凭证)",
                    javaThreadHitsXport.replace("|", "\n")
                            + "\n注: post-attach 由 libopenjdkjvmti / JDWP agent 创建",
                    DetectionLayer.JAVA, "🚨");
        }
        // Java control 线程（capability，常驻）
        if (!javaThreadHitsCtl.isEmpty()) {
            item.addDetectionDetail("🧵 Java 线程命中", "ADB-JDWP / AdbConnection 控制线程 (capability)",
                    javaThreadHitsCtl.replace("|", "\n")
                            + "\n注: 控制线程在任何 debuggable app 都常驻，非 attach 凭证",
                    DetectionLayer.JAVA, "ℹ️");
        }

        if (javaUnixSocketsSelf > 0) {
            item.addDetectionDetail("🔌 抽象 socket (Java)", "@jdwp-<self_pid>",
                    "命中 " + javaUnixSocketsSelf + " 条 — 当前进程被 JDWP attach",
                    DetectionLayer.JAVA, "🚨");
        } else if (javaUnixSocketsTotal > 0) {
            item.addDetectionDetail("🔌 抽象 socket (Java)", "/proc/net/unix 全局 @jdwp 计数",
                    "总数 " + javaUnixSocketsTotal
                            + " (含 adbd @jdwp-control + 其他进程的 @jdwp-<pid>，非本进程 attach)",
                    DetectionLayer.JAVA, "ℹ️");
        }

        // ===== NATIVE 层证据 =====
        if (adbConnLoaded) {
            // ART 对任何 debuggable app 都会 dlopen，不是 attach 凭证；降级展示
            item.addDetectionDetail("📚 Native lib", "libadbconnection.so (capability)",
                    "已加载 — ART JDWP 通道库; 任何 debuggable app 都常驻，非 attach 凭证",
                    DetectionLayer.NATIVE, "ℹ️");
        }
        if (jvmtiLoaded) {
            item.addDetectionDetail("📚 Native lib", "libopenjdkjvmti.so / libjdwp.so",
                    "已加载 — JDWP / JVMTI agent attach 时才会 dlopen",
                    DetectionLayer.NATIVE, "🚨");
        }
        if (nativeUnixSocketsSelf > 0) {
            item.addDetectionDetail("🔌 抽象 socket (Native)", "syscall @jdwp-<self_pid>",
                    "命中 " + nativeUnixSocketsSelf + " 条 — 当前进程被 JDWP attach",
                    DetectionLayer.NATIVE, "🚨");
        } else if (nativeUnixSocketsTotal > 0) {
            item.addDetectionDetail("🔌 抽象 socket (Native)", "syscall /proc/net/unix 全局",
                    "总数 " + nativeUnixSocketsTotal
                            + " (含 adbd @jdwp-control + 其他进程 @jdwp-<pid>，非本进程 attach)",
                    DetectionLayer.NATIVE, "ℹ️");
        }
        // Native transport 线程（真 attach 凭证）
        if (!nativeThreadHitsXport.isEmpty()) {
            item.addDetectionDetail("🧵 Native 线程命中",
                    "syscall /proc/self/task/*/comm — JDWP transport / JVMTI Agent",
                    nativeThreadHitsXport.replace("|", "\n")
                            + "\n注: post-attach 由 libopenjdkjvmti / JDWP agent 创建",
                    DetectionLayer.NATIVE, "🚨");
        }
        // Native control 线程（capability）
        if (!nativeThreadHitsCtl.isEmpty()) {
            item.addDetectionDetail("🧵 Native 线程命中",
                    "syscall /proc/self/task/*/comm — ADB-JDWP / AdbConnection (capability)",
                    nativeThreadHitsCtl.replace("|", "\n")
                            + "\n注: 控制线程在任何 debuggable app 都常驻，非 attach 凭证",
                    DetectionLayer.NATIVE, "ℹ️");
        }

        // ===== SYSCALL 层证据 =====
        if (jdwpProvider != null && !jdwpProvider.isEmpty()) {
            String hint;
            if ("none".equalsIgnoreCase(jdwpProvider)) {
                hint = " (JDWP 已禁用)";
            } else if ("adbconnection".equalsIgnoreCase(jdwpProvider)) {
                hint = " (Android 9+ 默认，走 adbd)";
            } else if ("internal".equalsIgnoreCase(jdwpProvider)) {
                hint = " (旧版 ART 内置 JDWP)";
            } else {
                hint = "";
            }
            item.addDetectionDetail("⚙️ JDWP Provider", "dalvik.vm.jdwp-provider (mmap 直读)",
                    jdwpProvider + hint,
                    DetectionLayer.SYSCALL, "📋");
        }

        // ===== 主动 connect 探测（syscall 旁路，魔改版思路） =====
        // adbd 文件系统 socket
        {
            String adbdHint;
            String icon;
            if (adbdSockHit) {  // EACCES = adbd 活但 SELinux 不让连（user build 正常）
                adbdHint = "SELinux 拒，adbd 仍在监听（USB 调试很可能开）";
                icon = "⚠️";
            } else if (adbdSockErrno == 111) {  // ECONNREFUSED
                adbdHint = "adbd 进程不在监听（USB 调试关 / adbd 死）";
                icon = "✅";
            } else if (adbdSockErrno == 2) {    // ENOENT
                adbdHint = "/dev/socket/adbd 不存在";
                icon = "✅";
            } else if (adbdSockErrno == 0) {
                adbdHint = "connect 成功（异常 — 普通 untrusted_app 不应能连）";
                icon = "🚨";
            } else {
                adbdHint = "errno=" + adbdSockErrno;
                icon = "ℹ️";
            }
            item.addDetectionDetail("🔌 主动 connect", "/dev/socket/adbd (AF_UNIX/SOCK_DGRAM)",
                    "rc errno=" + adbdSockErrno + " (" + adbdSockName + ")\n" + adbdHint,
                    DetectionLayer.SYSCALL, icon);
        }
        // @jdwp-control abstract socket（魔改版核心信号）
        {
            String ctlHint;
            String icon;
            if (jdwpCtlHit) {  // connect 成功 = 系统侧 JDWP 通道就位、adbd 接受我们做对端
                ctlHint = "adbd accept 了我们的连接 → 系统侧 JDWP 控制通道已激活\n"
                        + "注: 仅 capability，attach 凭证看 libopenjdkjvmti.so / transport 线程";
                icon = "⚠️";
            } else if (jdwpCtlErrno == 111) {  // ECONNREFUSED
                ctlHint = "socket 在但 listener 没接（JDWP provider 可能关或 adbd 拒）";
                icon = "ℹ️";
            } else if (jdwpCtlErrno == 2) {    // ENOENT
                ctlHint = "abstract socket @jdwp-control 不存在（JDWP 未启用）";
                icon = "✅";
            } else if (jdwpCtlErrno == 13) {   // EACCES
                ctlHint = "SELinux 拒（非 debuggable app on user build 的正常情况）";
                icon = "✅";
            } else {
                ctlHint = "errno=" + jdwpCtlErrno;
                icon = "ℹ️";
            }
            item.addDetectionDetail("🔌 主动 connect", "@jdwp-control (AF_UNIX/SOCK_SEQPACKET)",
                    "rc errno=" + jdwpCtlErrno + " (" + jdwpCtlName + ")\n" + ctlHint,
                    DetectionLayer.SYSCALL, icon);
        }

        // 跨层 socket 数量不一致 (Java 看到 N1, Native 看到 N2) — hook 嫌疑
        // 主要比 self-pid，全局总数也对一下作为旁证
        if (javaUnixSocketsSelf != nativeUnixSocketsSelf
                || javaUnixSocketsTotal != nativeUnixSocketsTotal) {
            item.addDetectionDetail("⚠️ 异常情况",
                    "Java vs Native @jdwp socket 数不一致",
                    "self: Java=" + javaUnixSocketsSelf + ", Native=" + nativeUnixSocketsSelf
                            + "\ntotal: Java=" + javaUnixSocketsTotal + ", Native=" + nativeUnixSocketsTotal
                            + "\n（/proc/net/unix 读取可能被 hook 过滤）",
                    DetectionLayer.NATIVE, "🚨");
        }
    }

    /**
     * Collect ptrace details
     */
    private void collectPtraceDetails(DetectionItem item, int javaTracerPid,
                                     int nativeTracerPid, int syscallTracerPid) {
        // TracerPid 信息
        item.addDetectionDetail("🔍 TracerPid", "主进程",
            "TracerPid: " + syscallTracerPid,
            DetectionLayer.SYSCALL, "🎯");

        // 尝试获取 tracer 进程信息
        if (syscallTracerPid > 0) {
            try {
                String tracerCmdlinePath = "/proc/" + syscallTracerPid + "/cmdline";
                BufferedReader reader = new BufferedReader(new FileReader(tracerCmdlinePath));
                String cmdline = reader.readLine();
                reader.close();

                if (cmdline != null) {
                    item.addDetectionDetail("🔄 Tracer 进程", "调试器信息",
                        "PID: " + syscallTracerPid + "\nCMD: " + cmdline,
                        DetectionLayer.SYSCALL, "⚙️");
                }
            } catch (Exception ignored) {
            }
        }

        // 检测所有线程的 TracerPid
        try {
            java.io.File taskDir = new java.io.File("/proc/self/task");
            java.io.File[] threads = taskDir.listFiles();

            if (threads != null && threads.length > 0) {
                int tracedCount = 0;
                StringBuilder tracedThreads = new StringBuilder();

                for (java.io.File thread : threads) {
                    if (!thread.isDirectory()) continue;

                    String tid = thread.getName();
                    String statusPath = "/proc/self/task/" + tid + "/status";

                    try {
                        BufferedReader reader = new BufferedReader(new FileReader(statusPath));
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (line.startsWith("TracerPid:")) {
                                String[] parts = line.split("\\s+");
                                if (parts.length > 1) {
                                    int tracerPid = Integer.parseInt(parts[1]);
                                    if (tracerPid > 0) {
                                        tracedCount++;
                                        tracedThreads.append("\n• TID:").append(tid)
                                            .append(" TracerPid:").append(tracerPid);
                                    }
                                }
                                break;
                            }
                        }
                        reader.close();
                    } catch (Exception ignored) {}
                }

                if (tracedCount > 0) {
                    item.addDetectionDetail("🧵 被跟踪线程", "线程列表",
                        "总数: " + tracedCount + tracedThreads.toString(),
                        DetectionLayer.SYSCALL, "📋");
                }
            }
        } catch (Exception ignored) {
        }

        // 当前进程信息
        int myPid = android.os.Process.myPid();
        item.addDetectionDetail("📊 进程信息", "当前进程",
            "PID: " + myPid,
            DetectionLayer.JAVA, "🆔");
    }

    // ===================== /dev/__properties__ mmap helpers =====================

    private static final File DEV_PROPERTIES_ROOT = new File("/dev/__properties__");

    /**
     * untrusted_app 通常允许直接 open 这些 SELinux context 文件，但 readdir(/dev/__properties__)
     * 往往被拒。所以不依赖目录遍历，按已知 context 名字逐个 try-open。
     * 列表覆盖 AOSP 8~14 常见命名；多了无害（open 失败静默跳过），少了会漏 context。
     */
    private static final String[] KNOWN_PROP_CONTEXTS = {
            // 通用 / 默认
            "u:object_r:default_prop:s0",
            "u:object_r:exported_default_prop:s0",
            "u:object_r:exported2_default_prop:s0",
            "u:object_r:exported3_default_prop:s0",
            "u:object_r:exported_secure_prop:s0",
            "u:object_r:exported_system_prop:s0",
            "u:object_r:public_readable_default_prop:s0",
            "u:object_r:userdebug_or_eng_prop:s0",
            "u:object_r:safemode_prop:s0",
            // build.prop
            "u:object_r:build_prop:s0",
            "u:object_r:exported_secure_default_prop:s0",
            "u:object_r:system_prop:s0",
            "u:object_r:vendor_default_prop:s0",
            "u:object_r:vendor_security_patch_level_prop:s0",
            // init service status
            "u:object_r:init_service_status_prop:s0",
            "u:object_r:init_service_status_private_prop:s0",
            // debug 相关
            "u:object_r:debug_prop:s0",
            "u:object_r:exported_debug_prop:s0",
            "u:object_r:debuggerd_prop:s0",
            "u:object_r:device_logging_prop:s0",
            // ADB / USB
            "u:object_r:usb_prop:s0",
            "u:object_r:usb_control_prop:s0",
            "u:object_r:adbd_prop:s0",
            "u:object_r:adbd_config_prop:s0",
            "u:object_r:adb_prop:s0",
            "u:object_r:adb_service_prop:s0",
            "u:object_r:ctl_adbd_prop:s0",
            "u:object_r:ffs_prop:s0",
            // 京东 b.java 思路: bootloader / Riru 检测用
            "u:object_r:bootloader_prop:s0",
            "u:object_r:dalvik_config_prop:s0",
            "u:object_r:exported_dalvik_prop:s0",
            "u:object_r:dalvik_prop:s0",
    };

    /** PROP 文件 magic：'P','R','O','P' 以 native (LE) 解读为 int。 */
    private static final int PROP_FILE_MAGIC = 0x504F5250;

    /**
     * Bionic property_area 版本号。AOSP 实际使用 0xFC6ED0AB；JD c.java 里的 0xFC6ED0CB
     * 应该对应某个 fork / 旧版。两个都允许，避免依赖具体厂商 ROM。
     */
    private static final int PROP_AREA_VERSION_A = 0xFC6ED0AB;
    private static final int PROP_AREA_VERSION_B = 0xFC6ED0CB;

    /**
     * ADB / 调试相关属性 + 其所属的候选 SELinux context。
     * 每行格式: { key, primary_context, secondary_context (可空) }。
     *
     * 候选名单基于 Android 11~14 实测 + AOSP 主线 property_contexts。在小米 Android 13 上
     * 用 `getprop -Z <key>` 验证过实际 context，列在 primary。AOSP 旧版/其他 ROM 的命名
     * 列在 secondary。Native 读取按 primary→secondary 顺序定向 mmap；都没读到则
     * 降级到 readDevPropertyMmap 全目录扫描兜底。
     */
    private static final String[][] ADB_DEBUG_PROPS = {
            {"ro.debuggable",          "debug_prop",                "default_prop"},
            {"ro.secure",              "default_prop",              "build_prop"},
            {"ro.adb.secure",          "build_prop",                "default_prop"},
            {"persist.sys.usb.config", "system_prop",               "usb_prop"},
            {"sys.usb.config",         "usb_control_prop",          "usb_prop"},
            {"sys.usb.state",          "usb_control_prop",          "usb_prop"},
            {"service.adb.tcp.port",   "adbd_config_prop",          "usb_prop"},
            {"init.svc.adbd",          "init_service_status_prop",  "default_prop"},
    };

    // ===================== USB Functions Runtime detection =====================

    /** UsbManager.getCurrentFunctions() bitmask 中 ADB 的位 (AOSP frameworks/base) */
    private static final long USB_FUNCTION_ADB = 0x1L;

    /** 4 个 USB runtime 属性，三路属性源 (API / Native mmap / Java mmap) 对比 */
    private static final String[][] USB_RUNTIME_PROPS = {
            {"persist.sys.usb.config", "system_prop",      "usb_prop"},
            {"sys.usb.config",         "usb_control_prop", "usb_prop"},
            {"sys.usb.state",          "usb_control_prop", "usb_prop"},
            {"sys.usb.ffs.ready",      "ffs_prop",         "usb_prop"},
    };

    /** sysfs 文本：读内容看是否含 "adb"。Android 11- 旧的 android_usb 路径 */
    private static final String[] USB_RUNTIME_VALUE_PATHS = {
            "/sys/class/android_usb/android0/functions",
            "/sys/class/android_usb/android0/state",
            "/sys/class/android_usb/android0/enable",
    };

    /** configfs 目录：列举当前激活的 USB function (Android 11+ ConfigFS 风格) */
    private static final String[] USB_CONFIGFS_CONFIG_DIRS = {
            "/config/usb_gadget/g1/configs/b.1",
    };

    /** FunctionFS / configfs 存在性检查：含 "/configs/" 或以 "/ep0" 结尾的视为活跃 ADB function */
    private static final String[] USB_RUNTIME_EXISTENCE_PATHS = {
            "/dev/usb-ffs/adb/ep0",
            "/config/usb_gadget/g1/functions/ffs.adb",
    };

    private static class UsbFrameworkScan {
        boolean available = false;
        boolean adbRuntime = false;
        String detail = "";
    }

    private static class UsbRuntimeScan {
        boolean adbRuntime = false;
        boolean ffsEvidence = false;
        int readableCount = 0;
        int unreadableCount = 0;
    }

    private static boolean evaluateRisk(String key, String value) {
        if (value == null || value.isEmpty()) return false;
        switch (key) {
            case "ro.debuggable":
                return "1".equals(value);
            case "ro.secure":
            case "ro.adb.secure":
                return "0".equals(value);
            case "service.adb.tcp.port":
                return !"-1".equals(value) && !"0".equals(value);
            case "init.svc.adbd":
                return "running".equals(value);
            // 注意：persist.sys.usb.config 是「持久化偏好」，MIUI 等 ROM 关 USB 调试后
            // 不会立即复位，残留 "adb" 会导致误判。所以只看实时态 sys.usb.config / sys.usb.state，
            // persist 那个仅作为辅助证据展示，不参与风险判定。
            case "sys.usb.config":
            case "sys.usb.state":
                return value.contains("adb");
            default:
                return false;
        }
    }

    private static boolean safeEquals(String a, String b) {
        String x = a == null ? "" : a;
        String y = b == null ? "" : b;
        return x.equals(y);
    }

    private static String formatValue(String v) {
        if (v == null) return "<未设置>";
        if (v.isEmpty()) return "<空>";
        return v;
    }

    /**
     * Native 层按候选 SELinux context 直接 mmap 对应 /dev/__properties__/u:object_r:&lt;ctx&gt;:s0 文件。
     * 顺序：primary → secondary → 全目录扫描兜底。命中后即停。
     * 这条路径彻底绕过 Java + libc 的属性 API，仅依赖 syscall_open + mmap。
     */
    private Map<String, String> readPropertiesByContext(String[][] defs) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String[] def : defs) {
            String key = def[0];
            String primary = def.length > 1 ? def[1] : "";
            String secondary = def.length > 2 ? def[2] : "";

            String v = null;
            try {
                if (!primary.isEmpty()) {
                    v = nativeDetector.readPropertyFromContext(key, primary);
                }
                if ((v == null || v.isEmpty()) && !secondary.isEmpty()) {
                    v = nativeDetector.readPropertyFromContext(key, secondary);
                }
                if (v == null || v.isEmpty()) {
                    // 兜底：万一发行版把属性挪了 context，全目录扫描一遍
                    v = nativeDetector.readDevPropertyMmap(key);
                }
            } catch (Throwable ignored) {
                // Native 端不可用时降级，由调用方根据空 map 处理
            }
            if (v != null && !v.isEmpty()) {
                result.put(key, v);
            }
        }
        return result;
    }

    /**
     * 通过反射调用 android.os.SystemProperties.get(String) 读取属性。
     * 该路径走 Java API，可被常见 hook 框架篡改 —— 仅用来与 mmap 结果做一致性对比。
     */
    private static Map<String, String> readPropertiesViaApi(String[] keys) {
        Map<String, String> result = new LinkedHashMap<>();
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getDeclaredMethod("get", String.class);
            for (String key : keys) {
                try {
                    Object v = get.invoke(null, key);
                    if (v instanceof String) {
                        result.put(key, (String) v);
                    }
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
        return result;
    }

    /**
     * 仿照 com.jd.stat.common.kit.devproperties.c 的 a(String...) 设计：
     * 不依赖 listFiles / isFile 等需要 readdir/stat 权限的调用，
     * 直接按已知 context 名字逐个 try-open；open 成功就 mmap 扫描，失败的静默跳过。
     *
     * @return 命中的 key→value map；如果一个 context 文件都打不开返回 null。
     */
    private static Map<String, String> readPropertiesViaMmap(String[] keys) {
        Map<String, String> result = new LinkedHashMap<>();
        boolean anyOpened = false;

        // 旧版 Android：/dev/__properties__ 是单个文件
        ByteBuffer rootBuf = openPropertyMap(DEV_PROPERTIES_ROOT);
        if (rootBuf != null) {
            anyOpened = true;
            collectFromBuffer(rootBuf, keys, result);
        }

        // 新版 Android：按已知 context 名字逐个尝试，open 失败就跳过
        for (String ctxName : KNOWN_PROP_CONTEXTS) {
            ByteBuffer buf = openPropertyMap(new File(DEV_PROPERTIES_ROOT, ctxName));
            if (buf == null) continue;
            anyOpened = true;
            collectFromBuffer(buf, keys, result);
        }

        return anyOpened ? result : null;
    }

    private static void collectFromBuffer(ByteBuffer buf, String[] keys, Map<String, String> sink) {
        for (String key : keys) {
            String existing = sink.get(key);
            if (existing != null && !existing.isEmpty()) continue;
            String v = findValue(buf, key);
            if (v != null) {
                sink.put(key, v);
            }
        }
    }

    private static ByteBuffer openPropertyMap(File file) {
        FileChannel channel = null;
        FileInputStream fis = null;
        try {
            // 不用 file.length() —— File 上的 stat 在 untrusted_app 下可能被 SELinux 拒。
            // 用 FileInputStream 打开后，通过 channel.size() (走 fd 上的 fstat) 取大小。
            fis = new FileInputStream(file);
            channel = fis.getChannel();
            long length = channel.size();
            if (length <= 16 || length >= Integer.MAX_VALUE) return null;
            ByteBuffer buf = channel.map(FileChannel.MapMode.READ_ONLY, 0L, length)
                    .order(ByteOrder.nativeOrder());
            buf.getInt(); // serial
            buf.getInt(); // reserved
            int magic = buf.getInt();
            if (magic != PROP_FILE_MAGIC) return null;
            int version = buf.getInt();
            if (version != PROP_AREA_VERSION_A && version != PROP_AREA_VERSION_B) return null;
            // 跳过 28 字节 reserved
            buf.position(buf.position() + 28);
            return buf.slice();
        } catch (Throwable ignored) {
            return null;
        } finally {
            try { if (channel != null) channel.close(); } catch (Throwable ignored) {}
            try { if (fis != null) fis.close(); } catch (Throwable ignored) {}
        }
    }

    /**
     * 在已 slice 的属性数据区按字节扫描定位 key，校验 key 是空字符结尾才视为完整匹配，
     * 然后读取 key 之前 92 字节内的 value（null 结尾）。仅返回第一个匹配。
     */
    private static String findValue(ByteBuffer buf, String key) {
        List<String> all = findAllValues(buf, key);
        return all.isEmpty() ? null : all.get(0);
    }

    /**
     * 扫描整段 buffer 收集所有匹配。
     * 京东 c.java#a(String) 的等价实现 —— 用于反作弊检测：Bionic trie 设计下同一 key
     * 只应存在一份 prop_info，扫到多份就是双写/篡改痕迹。
     *
     * 边界校验（防止 needle 是更长 key 的子串导致误匹）：
     *  · key 之前必须是 NUL（prop_info name 字段起点），否则我们扫到的是更长 key 的尾部
     *    e.g. 扫 "sys.usb.config" 在 "persist.sys.usb.config\0" 里的偏移 8 处也能匹中，
     *         但前一字节是 '.' 而非 '\0' → 拦掉
     */
    private static List<String> findAllValues(ByteBuffer buf, String key) {
        List<String> hits = new ArrayList<>(2);
        byte[] needle = key.getBytes(StandardCharsets.UTF_8);
        int capacity = buf.capacity();
        int limit = capacity - needle.length - 1;
        // i 从 96 起（前面需要 prop_info 头）；同时 i-1 必须可读取
        int start = Math.max(96, 1);
        for (int i = start; i < limit; i++) {
            // 1. 边界：前一字节必须是 NUL，否则是更长 key 的子串
            if (buf.get(i - 1) != 0) continue;
            // 2. needle 完整匹配
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (buf.get(i + j) != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (!match) continue;
            // 3. 尾部 NUL：name 字段 null-terminated
            if (buf.get(i + needle.length) != 0) continue;
            // 4. prop_info serial flag 过滤（Bionic 经验值）
            if ((buf.getInt(i - 96) & 0x10000) != 0) continue;
            hits.add(readNullTerminated(buf, i - 92, 92));
        }
        return hits;
    }

    private static String readNullTerminated(ByteBuffer buf, int offset, int maxLen) {
        StringBuilder sb = new StringBuilder(16);
        for (int i = 0; i <= maxLen; i++) {
            try {
                byte b = buf.get(offset + i);
                if (b == 0) {
                    return sb.toString();
                }
                sb.append((char) b);
            } catch (IndexOutOfBoundsException e) {
                return sb.toString();
            }
        }
        return sb.toString();
    }

    // ===================== init.rc directive scan =====================

    /**
     * 常见 init script 目录。逐目录 listFiles 收集 *.rc；失败静默跳过。
     * /system/etc/init/hw/ 是 Android 8.0+ 主 init.rc 与 init.usb.rc 的归属地，
     * 也是 ROM/刷机包把 "setprop persist.sys.usb.config adb" 烤进固件最常见的位置。
     */
    private static final String[] INIT_RC_DIRS = {
            "/system/etc/init/hw",
            "/system/etc/init",
            "/vendor/etc/init/hw",
            "/vendor/etc/init",
            "/odm/etc/init",
            "/product/etc/init",
    };

    /** listFiles 失败时（readdir 被 SELinux 拒）按已知文件名兜底直 open。 */
    private static final String[] INIT_RC_FALLBACK_FILES = {
            "/init.rc",
            "/system/init.rc",
            "/system/etc/init/hw/init.rc",
            "/system/etc/init/hw/init.usb.rc",
            "/system/etc/init/hw/init.usb.configfs.rc",
            "/vendor/etc/init/hw/init.usb.rc",
            "/vendor/etc/init/hw/init.usb.configfs.rc",
    };

    /** 单条 rc hit：{path, lineno, key, value, raw line}。 */
    private static List<String[]> scanRiskyInitRcDirectives() {
        List<String[]> hits = new ArrayList<>();
        Set<String> visited = new HashSet<>();

        for (String dir : INIT_RC_DIRS) {
            File d = new File(dir);
            File[] children = null;
            try {
                children = d.listFiles();
            } catch (Throwable ignored) {
            }
            if (children == null) continue;
            for (File f : children) {
                if (f == null) continue;
                String name = f.getName();
                if (name == null || !name.endsWith(".rc")) continue;
                String canon;
                try {
                    canon = f.getCanonicalPath();
                } catch (Throwable t) {
                    canon = f.getPath();
                }
                if (!visited.add(canon)) continue;
                scanRcFileForRiskySetprop(f, hits);
            }
        }
        for (String path : INIT_RC_FALLBACK_FILES) {
            File f = new File(path);
            String canon;
            try {
                canon = f.getCanonicalPath();
            } catch (Throwable t) {
                canon = f.getPath();
            }
            if (!visited.add(canon)) continue;
            scanRcFileForRiskySetprop(f, hits);
        }
        return hits;
    }

    private static void scanRcFileForRiskySetprop(File f, List<String[]> hits) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(f));
            String line;
            int lineno = 0;
            // 块上下文：跟踪当前 on/service 块是否「条件触发」。AOSP 标准 init.usb.rc 把
            // "setprop persist.sys.usb.config adb" 这类行写在
            // `on property:ro.debuggable=1 && ...` 块里 —— 关 USB 调试时根本不执行，
            // 直接按字面命中会大量误报。规则：
            //  · `on` 头含 "property:" → 条件触发，跳过块内 setprop
            //  · `service ...` 块 → 跳过（service 块里的 setprop 是启停触发型）
            //  · 文件开头任何块之前 → 视作不确定，也跳过
            //  · value 含 ${...} 变量展开 → 跳过（实际值依赖运行时属性）
            boolean blockConditional = true;
            while ((line = br.readLine()) != null) {
                lineno++;
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.charAt(0) == '#') continue;

                boolean atColumnZero = !line.isEmpty()
                        && line.charAt(0) != ' ' && line.charAt(0) != '\t';
                if (atColumnZero) {
                    if (trimmed.startsWith("on ") || trimmed.equals("on")) {
                        // "on init" / "on boot" 无条件；"on property:..." 或带 "&& property:" 才算条件
                        blockConditional = trimmed.contains("property:");
                        continue;
                    } else if (trimmed.startsWith("service ")
                            || trimmed.startsWith("service\t")
                            || trimmed.equals("service")) {
                        blockConditional = true;
                        continue;
                    } else if (trimmed.startsWith("import ")) {
                        continue;
                    }
                }

                // 块内命令：要求 setprop 在行首（trim 之后），避免误吃 trigger 行
                if (!(trimmed.startsWith("setprop ") || trimmed.startsWith("setprop\t"))) {
                    continue;
                }
                if (blockConditional) continue;

                String tail = trimmed.substring("setprop".length()).trim();
                int kEnd = -1;
                for (int i = 0; i < tail.length(); i++) {
                    char c = tail.charAt(i);
                    if (c == ' ' || c == '\t') {
                        kEnd = i;
                        break;
                    }
                }
                if (kEnd <= 0) continue;
                String key = tail.substring(0, kEnd);
                String value = tail.substring(kEnd).trim();
                int hash = value.indexOf('#');
                if (hash >= 0) value = value.substring(0, hash).trim();
                // 去掉值两侧的引号: "adb" / 'adb'
                if (value.length() >= 2) {
                    char a = value.charAt(0);
                    char b = value.charAt(value.length() - 1);
                    if ((a == '"' && b == '"') || (a == '\'' && b == '\'')) {
                        value = value.substring(1, value.length() - 1);
                    }
                }
                // 变量展开值（${persist.sys.usb.config},adb 等）不是"硬写死"
                if (value.contains("${")) continue;

                if (isRiskyRcDirective(key, value)) {
                    hits.add(new String[]{f.getPath(), String.valueOf(lineno), key, value, trimmed});
                }
            }
        } catch (Throwable ignored) {
        } finally {
            try {
                if (br != null) br.close();
            } catch (Throwable ignored) {
            }
        }
    }

    /**
     * rc 文件里的 setprop 行只要满足下列任一就视为"把 adb/调试烤进固件"：
     *  · persist.sys.usb.config / sys.usb.config / sys.usb.state 值包含 "adb"
     *  · ro.debuggable=1
     *  · ro.secure=0 或 ro.adb.secure=0
     *  · service.adb.tcp.port 非 -1/0 (默认开 wireless adb)
     */
    private static boolean isRiskyRcDirective(String key, String value) {
        if (key == null || value == null) return false;
        switch (key) {
            case "persist.sys.usb.config":
            case "sys.usb.config":
            case "sys.usb.state":
                return value.contains("adb");
            case "ro.debuggable":
                return "1".equals(value);
            case "ro.secure":
            case "ro.adb.secure":
                return "0".equals(value);
            case "service.adb.tcp.port":
                return !"-1".equals(value) && !"0".equals(value);
            default:
                return false;
        }
    }
}
