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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
     * Detect USB debugging status
     */
    public DetectionItem detectUsbDebugging() {
        DetectionItem item = new DetectionItem("USB 调试", "检测 USB 调试是否开启");

        boolean enabled = false;
        try {
            enabled = Settings.Global.getInt(context.getContentResolver(),
                    Settings.Global.ADB_ENABLED, 0) == 1;
        } catch (Exception ignored) {
        }

        item.setLayerResult(DetectionLayer.JAVA, enabled);

        if (enabled) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("已开启");

            // 添加详细检测信息
            collectUsbDebuggingDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("已关闭");
        }

        return item;
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
     * Detect JDWP (Java Debug Wire Protocol)
     */
    public DetectionItem detectJdwp() {
        DetectionItem item = new DetectionItem("JDWP 检测", "检测 Java 调试协议");

        boolean detected = checkJdwp();
        item.setLayerResult(DetectionLayer.JAVA, detected);

        if (detected) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 JDWP");

            // 添加详细检测信息
            collectJdwpDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

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
//            Log.i(TAG,DEV_PROPERTIES_ROOT+"/"+ctxName);
            for (String key : sensitiveKeys) {
                List<String> all = findAllValues(buf, key);
                if (all.isEmpty()) continue;
                matrix.computeIfAbsent(key, k -> new LinkedHashMap<>()).put(ctxName, all);
//                Log.i(TAG,key + " : " + all.toString());
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

        String[] keys = new String[ADB_DEBUG_PROPS.length];
        for (int i = 0; i < ADB_DEBUG_PROPS.length; i++) {
            keys[i] = ADB_DEBUG_PROPS[i][0];
        }

        // API 路径（SystemProperties.get 反射）总是可用，作为主驱动；
        // mmap 路径作为「能否旁证」用，失败时只降可信度，不再短路。
        Map<String, String> apiValues = readPropertiesViaApi(keys);
        Log.i(TAG,apiValues.toString());
        Map<String, String> javaMmapValues = readPropertiesViaMmap(keys);
        Log.i(TAG,javaMmapValues.toString());
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

        item.setLayerResult(DetectionLayer.JAVA, apiRisky);
        item.setLayerResult(DetectionLayer.NATIVE, nativeRisky);
        item.setLayerResult(DetectionLayer.SYSCALL, javaRisky);

        if (apiRisky || nativeRisky || javaRisky || inconsistentCount > 0) {
            item.setStatus(DetectionStatus.RISK);
            if (summary.length() == 0) {
                summary.append("API / Native / Java 结果不一致 (疑似 hook)");
            } else if (inconsistentCount > 0) {
                summary.append(" 检测层不一致");
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

    private boolean checkJdwp() {
        // Check if JDWP is active by looking at /proc/self/status
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    int tracerPid = Integer.parseInt(line.split("\\s+")[1]);
                    reader.close();
                    return tracerPid > 0;
                }
            }
            reader.close();
        } catch (Exception ignored) {
        }
        return false;
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
    private void collectUsbDebuggingDetails(DetectionItem item) {
        // ADB 状态
        try {
            int adbEnabled = Settings.Global.getInt(context.getContentResolver(),
                Settings.Global.ADB_ENABLED, 0);
            item.addDetectionDetail("⚙️ 系统设置", "ADB_ENABLED",
                "值: " + adbEnabled + " (1=开启, 0=关闭)",
                DetectionLayer.JAVA, "🔧");
        } catch (Exception ignored) {
        }

        // 开发者选项状态
        try {
            int devEnabled = Settings.Global.getInt(context.getContentResolver(),
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
            item.addDetectionDetail("⚙️ 系统设置", "开发者选项",
                devEnabled == 1 ? "已开启" : "已关闭",
                DetectionLayer.JAVA, "🛠️");
        } catch (Exception ignored) {
        }

        // 检测 adbd 进程
        try {
            java.io.File procDir = new java.io.File("/proc");
            java.io.File[] procs = procDir.listFiles();
            if (procs != null) {
                for (java.io.File proc : procs) {
                    if (!proc.getName().matches("\\d+")) continue;

                    try {
                        java.io.File cmdlineFile = new java.io.File(proc, "cmdline");
                        if (cmdlineFile.exists()) {
                            BufferedReader reader = new BufferedReader(new FileReader(cmdlineFile));
                            String cmdline = reader.readLine();
                            reader.close();

                            if (cmdline != null && cmdline.contains("adbd")) {
                                item.addDetectionDetail("🔄 ADB 进程", "adbd",
                                    "PID: " + proc.getName() + "\nCMD: " + cmdline,
                                    DetectionLayer.NATIVE, "⚙️");
                            }
                        }
                    } catch (Exception ignored) {}
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
     * Collect JDWP details
     */
    private void collectJdwpDetails(DetectionItem item) {
        // 读取 /proc/self/status
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            StringBuilder statusInfo = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:") ||
                    line.startsWith("Name:") ||
                    line.startsWith("State:")) {
                    statusInfo.append(line).append("\n");
                }
            }
            reader.close();

            if (statusInfo.length() > 0) {
                item.addDetectionDetail("📄 进程状态", "/proc/self/status",
                    statusInfo.toString().trim(),
                    DetectionLayer.SYSCALL, "📋");
            }
        } catch (Exception ignored) {
        }

        // 检测 JDWP 端口
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/net/tcp"));
            String line;
            while ((line = reader.readLine()) != null) {
                // JDWP 通常使用 8000, 8700, 5005 等端口
                if (line.contains(":1F40") || // 8000
                    line.contains(":21FC") || // 8700
                    line.contains(":138D")) { // 5005
                    item.addDetectionDetail("🌐 JDWP 端口", "TCP 监听",
                        line.trim(),
                        DetectionLayer.SYSCALL, "🔍");
                }
            }
            reader.close();
        } catch (Exception ignored) {
        }

        // 检测 Android Studio 调试标记
        String debuggable = android.os.Build.TAGS;
        if (debuggable.contains("test-keys") || debuggable.contains("debug")) {
            item.addDetectionDetail("🏷️ Build Tags", "调试标记",
                "Build.TAGS: " + debuggable,
                DetectionLayer.JAVA, "🔖");
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
            Log.i(TAG,DEV_PROPERTIES_ROOT+"/"+ctxName);
            Log.i(TAG,keys + " : " +result);
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
     */
    private static List<String> findAllValues(ByteBuffer buf, String key) {
        List<String> hits = new ArrayList<>(2);
        byte[] needle = key.getBytes(StandardCharsets.UTF_8);
        int capacity = buf.capacity();
        int limit = capacity - needle.length - 1;
        for (int i = 0; i < limit; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (buf.get(i + j) != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (!match) continue;
            if (buf.get(i + needle.length) != 0) continue;
            if (i < 96) continue;
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
}
