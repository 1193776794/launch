package com.xff.launch.detector;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.ProxyInfo;
import android.net.RouteInfo;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 网络环境检测：VPN、系统代理、本地代理监听端口、路由/DNS。
 *
 * 设计原则：
 *  · 不强依赖 native（VPN/代理 native 信号是 nice-to-have，Java 三路足够）
 *  · /proc/net 读取走"试读"而不是 SDK 版本号判断（MIUI / 部分 ROM 在 Android 10+ 仍允许）
 *  · UDP 不进入端口扫描（UDP socket 在 /proc/net/udp 不区分 LISTEN，误判率高）
 *  · 主动 connect 探测和 /proc 扫描互补：connect 直接抓 listener，/proc 扫
 *    fd 状态；任一命中即视为强信号
 *  · DNS 私网地址额外纳入路由判定（VPN 常下发 10.x / 172.16-31.x DNS）
 */
public class NetworkDetector {

    private static final String TAG = "NetworkDetector";

    // ===== 常量 =====

    /** VPN 接口名前缀（lowercase）。匹配后还要尾部 word boundary，避免误中 "tunnel0" 这种。 */
    private static final String[] VPN_INTERFACE_PREFIXES = {"tun", "tap", "ppp", "wg", "ipsec"};

    /** 完整 VPN 接口名 regex：前缀 + 可选数字，或含 "vpn" 子串。 */
    private static final Pattern VPN_INTERFACE_PATTERN = Pattern.compile(
            "^(tun|tap|ppp|wg|ipsec)\\d*$|vpn", Pattern.CASE_INSENSITIVE);

    /** 常见本地代理监听端口：Clash / sing-box / V2Ray / Shadowsocks / HiddifyNG。 */
    private static final int[] COMMON_LOCAL_PROXY_PORTS = {
            1080, 1081,                       // SOCKS
            2080,                             // Clash 控制
            7890, 7891, 7892, 7893,           // Clash HTTP/SOCKS
            8080, 8888,                       // 通用 HTTP proxy
            9090, 9097,                       // Clash dashboard / sing-box
            10808, 10809,                     // v2rayN
            20170                             // HiddifyNG
    };

    private static final String[] LOCAL_PROXY_CONNECT_HOSTS = {"127.0.0.1", "::1"};
    private static final int LOCAL_PROXY_CONNECT_TIMEOUT_MS = 120;

    /** /proc/net 扫描：只扫 TCP（UDP 无 LISTEN 概念，误判率太高）。 */
    private static final String[] PROC_NET_TCP_FILES = {
            "/proc/net/tcp", "/proc/net/tcp6"
    };

    /** 单个 DetectionDetail 列表里最多展示多少条 route，避免刷屏。 */
    private static final int MAX_ROUTE_DETAIL_ROWS = 8;

    /** 系统代理相关属性 key。 */
    private static final String[][] SYS_PROXY_KEYS = {
            {"http.proxyHost",  "http.proxyPort"},
            {"https.proxyHost", "https.proxyPort"},
            {"socksProxyHost", "socksProxyPort"},
    };

    private final Context context;
    private final NativeDetector nativeDetector;

    public NetworkDetector(Context context) {
        this.context = context.getApplicationContext();
        this.nativeDetector = NativeDetector.getInstance();
    }

    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(detectVpnInterfaces());
        items.add(detectSystemProxy());
        items.add(detectLocalProxyPorts());
        items.add(detectNetworkRoutes());
        return items;
    }

    // ============================================================
    // 1. VPN 接口检测 (NetworkInterface + ConnectivityManager + sysfs)
    // ============================================================

    /**
     * 多路融合 VPN 检测：
     *  · JAVA 层 — NetworkInterface.getNetworkInterfaces() 枚举 + isUp()
     *  · JAVA 层 — ConnectivityManager.NetworkCapabilities.TRANSPORT_VPN（现代 API）
     *  · JAVA 层 — ConnectivityManager NetworkInfo.TYPE_VPN（兼容旧版）
     *  · SYSCALL 层 — /sys/class/net/&lt;iface&gt;/operstate 文件直读（绕 hook）
     *
     * 任一接口处于 up 状态命中 → RISK；仅看到名字未确认 up → WARNING。
     */
    public DetectionItem detectVpnInterfaces() {
        DetectionItem item = new DetectionItem("VPN 检测",
                "多路融合：NetworkInterface + ConnectivityManager + sysfs");

        List<String> upHits = new ArrayList<>();
        List<String> nameOnlyHits = new ArrayList<>();
        boolean javaUpHit = false;
        boolean syscallUpHit = false;
        boolean nativeUpHit = false;
        boolean javaApiOk = false;
        Set<String> javaSeenIfaces = new java.util.HashSet<>();  // 给 E) 段做 cross-check 用

        // === A) Java NetworkInterface 枚举 ===
        try {
            Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
            if (en != null) {
                javaApiOk = true;
                for (NetworkInterface ni : Collections.list(en)) {
                    String name = ni.getName();
                    if (name != null) javaSeenIfaces.add(name);
                    if (!isVpnInterfaceName(name)) continue;
                    boolean up = safeIsUp(ni);
                    String desc = "up=" + up
                            + ", loopback=" + safeIsLoopback(ni)
                            + ", mtu=" + safeMtu(ni)
                            + ", addr=" + formatAddresses(ni);
                    if (up) {
                        javaUpHit = true;
                        upHits.add("NetworkInterface " + name + " (" + desc + ")");
                    } else {
                        nameOnlyHits.add("NetworkInterface " + name + " (" + desc + ")");
                    }
                    item.addDetectionDetail(up ? "🔌 VPN 接口 up" : "🔌 VPN 接口名",
                            name, desc, DetectionLayer.JAVA, up ? "🚨" : "⚠️");
                }
            }
        } catch (Throwable t) {
            item.addDetectionDetail("⚠️ 网络接口枚举失败",
                    "NetworkInterface.getNetworkInterfaces",
                    simpleError(t), DetectionLayer.JAVA, "ℹ️");
        }

        // === B) ConnectivityManager.NetworkCapabilities ===
        boolean transportVpnHit = false;
        try {
            ConnectivityManager cm = getCm();
            if (cm != null) {
                Network active = safeActiveNetwork(cm);
                for (Network n : cm.getAllNetworks()) {
                    NetworkCapabilities caps = cm.getNetworkCapabilities(n);
                    if (caps == null) continue;
                    boolean hasVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                    boolean notVpn = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
                    LinkProperties lp = cm.getLinkProperties(n);
                    String desc = "transport_vpn=" + hasVpn
                            + ", not_vpn_capability=" + notVpn
                            + ", active=" + n.equals(active)
                            + ", iface=" + safeIfaceName(lp);
                    if (hasVpn) {
                        transportVpnHit = true;
                        javaUpHit = true;
                        upHits.add("NetworkCapabilities " + n + " (" + desc + ")");
                        item.addDetectionDetail("🌐 NetworkCapabilities VPN",
                                n.toString(), desc, DetectionLayer.JAVA, "🚨");
                    }
                }
            }
        } catch (Throwable t) {
            item.addDetectionDetail("⚠️ ConnectivityManager 读失败",
                    "getAllNetworks", simpleError(t), DetectionLayer.JAVA, "ℹ️");
        }

        // === C) Legacy NetworkInfo TYPE_VPN（部分老 ROM 还在用）===
        try {
            ConnectivityManager cm = getCm();
            if (cm != null) {
                NetworkInfo[] all = cm.getAllNetworkInfo();
                if (all != null) {
                    for (NetworkInfo ni : all) {
                        if (ni == null) continue;
                        if (ni.getType() == ConnectivityManager.TYPE_VPN
                                || (ni.getTypeName() != null
                                    && ni.getTypeName().toLowerCase(Locale.US).contains("vpn"))) {
                            boolean connected = ni.isConnected();
                            String desc = "type=" + ni.getType()
                                    + ", typeName=" + ni.getTypeName()
                                    + ", connected=" + connected;
                            if (connected) {
                                javaUpHit = true;
                                upHits.add("NetworkInfo " + ni.getTypeName() + " (" + desc + ")");
                            } else {
                                nameOnlyHits.add("NetworkInfo " + ni.getTypeName() + " (" + desc + ")");
                            }
                            item.addDetectionDetail("📡 Legacy NetworkInfo VPN",
                                    String.valueOf(ni.getTypeName()), desc,
                                    DetectionLayer.JAVA, connected ? "🚨" : "⚠️");
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
            // legacy API 在新版上可能 throw SecurityException，静默
        }

        // === D) sysfs /sys/class/net/<iface>/operstate ===
        List<String> sysfsIfaces = listSysfsInterfaces();
        for (String iface : sysfsIfaces) {
            if (!isVpnInterfaceName(iface)) continue;
            String state = readFirstLine("/sys/class/net/" + iface + "/operstate");
            boolean up = "up".equalsIgnoreCase(state);
            if (up) {
                syscallUpHit = true;
                upHits.add("sysfs " + iface + " (operstate=" + state + ")");
            } else {
                nameOnlyHits.add("sysfs " + iface + " (operstate=" + state + ")");
            }
            item.addDetectionDetail(up ? "📂 sysfs VPN up" : "📂 sysfs VPN 名",
                    iface, "operstate=" + state, DetectionLayer.SYSCALL,
                    up ? "🚨" : "⚠️");
        }

        // === E) 深层 Native: getifaddrs + netlink RTM_GETROUTE + syscall /proc/net/dev ===
        // 这是抗 hook 最强的一层 —— Frida/Xposed 在 Java/libc 层 hook 都拦不到 netlink raw socket。
        // 与上面 A-D 层 cross-check：任一不一致 → Java NetworkInterface 可能被 hook 隐藏 VPN。
        java.util.Map<String, String> nr;
        try {
            nr = parseKeyValueReport(nativeDetector.getNetworkNativeReport());
        } catch (Throwable t) {
            nr = java.util.Collections.emptyMap();
            item.addDetectionDetail("⚠️ Native 网络报告失败",
                    "getNetworkNativeReport", simpleError(t),
                    DetectionLayer.NATIVE, "ℹ️");
        }
        boolean ifaddrsOk = "1".equals(nr.get("IFADDRS_OK"));
        boolean netlinkOk = "1".equals(nr.get("NETLINK_OK"));
        boolean procNetOk = "1".equals(nr.get("PROC_NET_DEV_OK"));
        Log.i(TAG, "native-net: ifaddrs=" + ifaddrsOk
                + " ifaVpnUp=" + nr.getOrDefault("IFADDRS_VPN_UP", "")
                + " netlink=" + netlinkOk
                + " defOif=" + nr.getOrDefault("NETLINK_DEFAULT_OIF", "")
                + " defIface=" + nr.getOrDefault("NETLINK_DEFAULT_IFACE", "")
                + " defGw=" + nr.getOrDefault("NETLINK_DEFAULT_GW", "")
                + " procNet=" + procNetOk
                + " procIfaces=" + nr.getOrDefault("PROC_NET_DEV_IFACES", ""));

        // E1) getifaddrs() up 状态 VPN 接口（POSIX 直调，绕 NetworkInterface 反射）
        String ifaVpnUpCsv = nr.getOrDefault("IFADDRS_VPN_UP", "");
        if (!ifaVpnUpCsv.isEmpty()) {
            for (String name : ifaVpnUpCsv.split(",")) {
                if (name.isEmpty()) continue;
                nativeUpHit = true;
                upHits.add("getifaddrs " + name);
                item.addDetectionDetail("📡 getifaddrs UP",
                        name, "POSIX 直调，IFF_UP + VPN 命名命中",
                        DetectionLayer.NATIVE, "🚨");
            }
        }

        // E2) netlink RTM_GETROUTE 默认路由的 OIF → iface 名
        String netlinkIface = nr.getOrDefault("NETLINK_DEFAULT_IFACE", "");
        String netlinkGw = nr.getOrDefault("NETLINK_DEFAULT_GW", "");
        int netlinkOif = parseIntSafe(nr.get("NETLINK_DEFAULT_OIF"), -1);
        if (netlinkOk && netlinkOif > 0) {
            boolean ifaceIsVpn = isVpnInterfaceName(netlinkIface);
            String desc = "oif=" + netlinkOif + " iface=" + netlinkIface
                    + " gw=" + netlinkGw;
            if (ifaceIsVpn) {
                nativeUpHit = true;
                upHits.add("netlink default→" + netlinkIface);
                item.addDetectionDetail("📡 Netlink 默认路由→VPN",
                        netlinkIface,
                        desc + "\n→ RTM_GETROUTE 显示默认路由走 VPN 接口（抗 Frida/Xposed）",
                        DetectionLayer.NATIVE, "🚨");
            } else {
                item.addDetectionDetail("📡 Netlink 默认路由",
                        netlinkIface, desc,
                        DetectionLayer.NATIVE, "📋");
            }
        }

        // E3) /proc/net/dev cross-check（syscall 优先，Java FileReader 兜底）
        // Android 13 untrusted_app SELinux 通常拒 syscall direct read on proc_net 标签的文件，
        // 但 Java FileReader 走 sepolicy 不同路径有时能读到。两路任一成功即可。
        String procIfaceCsv = nr.getOrDefault("PROC_NET_DEV_IFACES", "");
        boolean procDevFromJava = false;
        if (!procNetOk || procIfaceCsv.isEmpty()) {
            procIfaceCsv = readProcNetDevJava();
            procDevFromJava = !procIfaceCsv.isEmpty();
        }
        Log.i(TAG, "proc-net-dev: syscallOk=" + procNetOk
                + " javaOk=" + procDevFromJava
                + " ifaces=" + (procIfaceCsv.length() > 200
                    ? procIfaceCsv.substring(0, 200) + "..." : procIfaceCsv));
        if (!procIfaceCsv.isEmpty()) {
            List<String> hidden = new ArrayList<>();
            for (String name : procIfaceCsv.split(",")) {
                if (name.isEmpty()) continue;
                if (javaApiOk && !javaSeenIfaces.contains(name)) {
                    // syscall 看到但 Java 没有 — 强 hook 嫌疑
                    hidden.add(name);
                }
            }
            if (!hidden.isEmpty()) {
                StringBuilder hd = new StringBuilder();
                for (int i = 0; i < hidden.size(); i++) {
                    if (i > 0) hd.append(",");
                    hd.append(hidden.get(i));
                }
                // 隐藏的 iface 里有 VPN 命名 → 强 RISK
                boolean hiddenHasVpn = false;
                for (String h : hidden) if (isVpnInterfaceName(h)) { hiddenHasVpn = true; break; }
                String src = procDevFromJava ? "Java FileReader" : "syscall direct";
                item.addDetectionDetail("🚨 NetworkInterface vs " + src + " 接口不一致",
                        "可能被 hook 隐藏",
                        src + " (/proc/net/dev) 看到 " + hidden.size()
                                + " 个 NetworkInterface 没看到的接口: " + hd
                                + (hiddenHasVpn ? "\n→ 含 VPN 命名，强 hook 嫌疑" : ""),
                        DetectionLayer.SYSCALL, "🚨");
                if (hiddenHasVpn) {
                    nativeUpHit = true;
                    upHits.add("syscall hidden VPN " + hd);
                }
            }
        }

        // 加诊断行：原生侧能力总览
        String procStatus = procNetOk ? "OK(syscall)"
                : (procDevFromJava ? "OK(Java兜底)" : "FAIL");
        item.addDetectionDetail("ℹ️ 深层 Native 能力",
                "getifaddrs + netlink + /proc/net/dev",
                "ifaddrs=" + (ifaddrsOk ? "OK" : "FAIL")
                        + ", netlink=" + (netlinkOk ? "OK" : "FAIL")
                        + ", /proc/net/dev=" + procStatus,
                DetectionLayer.NATIVE, "📋");

        // === 聚合 ===
        boolean anyUp = javaUpHit || syscallUpHit || nativeUpHit;
        item.setLayerResult(DetectionLayer.JAVA, javaUpHit || !nameOnlyHits.isEmpty());
        item.setLayerResult(DetectionLayer.SYSCALL, syscallUpHit);
        item.setLayerResult(DetectionLayer.NATIVE, nativeUpHit);

        if (anyUp) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("发现 up 状态 VPN 接口: " + summarize(upHits));
        } else if (!nameOnlyHits.isEmpty()) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("发现 VPN 接口名但未确认 up: " + summarize(nameOnlyHits));
        } else if (!javaApiOk && sysfsIfaces.isEmpty()) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("无法枚举网络接口");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未发现 VPN 虚拟网卡");
        }

        Log.i(TAG, "vpn: javaApiOk=" + javaApiOk + " up=" + upHits.size()
                + " nameOnly=" + nameOnlyHits.size() + " sysfsCount=" + sysfsIfaces.size()
                + " transportVpn=" + transportVpnHit);
        return item;
    }

    /**
     * Java 兜底读 /proc/net/dev，解析接口名 csv。
     * untrusted_app 域下 Java FileReader 与 syscall 直读权限可能不同，作为 cross-check。
     */
    private static String readProcNetDevJava() {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/net/dev"));
            StringBuilder out = new StringBuilder();
            String line;
            int lineNo = 0;
            boolean first = true;
            while ((line = r.readLine()) != null) {
                lineNo++;
                if (lineNo <= 2) continue;          // header
                int colon = line.indexOf(':');
                if (colon < 0) continue;
                String name = line.substring(0, colon).trim();
                if (name.isEmpty()) continue;
                if (!first) out.append(",");
                first = false;
                out.append(name);
            }
            return out.toString();
        } catch (Throwable t) {
            return "";
        } finally {
            try { if (r != null) r.close(); } catch (Throwable ignored) {}
        }
    }

    /** 解析 "KEY=VALUE\nKEY=VALUE" 报告（Native 端 multi-line 输出）。 */
    private static java.util.Map<String, String> parseKeyValueReport(String report) {
        java.util.Map<String, String> result = new java.util.LinkedHashMap<>();
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
        try { return Integer.parseInt(v.trim()); }
        catch (Throwable t) { return def; }
    }

    // ============================================================
    // 2. 系统代理检测
    // ============================================================

    /**
     * 系统代理多源融合：
     *  · Java system properties（http.proxyHost / https.proxyHost / socksProxyHost）
     *  · Settings.Global.HTTP_PROXY
     *  · ConnectivityManager.getDefaultProxy() + 每个 Network 的 LinkProperties.getHttpProxy()
     *  · ProxySelector.getDefault() 对 http://example.com 的解析
     *
     * 命中即 WARNING（不直接判 RISK——Charles/Fiddler 抓包等开发场景是合法的）。
     */
    public DetectionItem detectSystemProxy() {
        DetectionItem item = new DetectionItem("系统代理",
                "system property + Settings.Global + ConnectivityManager + ProxySelector");

        List<String> hits = new ArrayList<>();

        // === A) Java system property ===
        for (String[] pair : SYS_PROXY_KEYS) {
            String host = System.getProperty(pair[0]);
            String port = System.getProperty(pair[1]);
            if (isMeaningful(host) || isMeaningful(port)) {
                String desc = host + ":" + port;
                hits.add("System.getProperty " + pair[0] + "=" + desc);
                item.addDetectionDetail("⚙️ Java 系统属性", pair[0],
                        desc, DetectionLayer.JAVA, "⚠️");
            }
        }

        // === B) Settings.Global.HTTP_PROXY ===
        try {
            String settingsProxy = Settings.Global.getString(
                    context.getContentResolver(), Settings.Global.HTTP_PROXY);
            if (isMeaningful(settingsProxy)) {
                hits.add("Settings.Global.HTTP_PROXY=" + settingsProxy);
                item.addDetectionDetail("⚙️ Settings.Global", "HTTP_PROXY",
                        settingsProxy, DetectionLayer.JAVA, "⚠️");
            }
        } catch (Throwable t) {
            item.addDetectionDetail("⚠️ Settings.Global 读失败",
                    "HTTP_PROXY", simpleError(t), DetectionLayer.JAVA, "ℹ️");
        }

        // === C) ConnectivityManager.getDefaultProxy + per-network LinkProperties ===
        try {
            ConnectivityManager cm = getCm();
            if (cm != null) {
                ProxyInfo def = cm.getDefaultProxy();
                if (def != null && isMeaningfulProxyInfo(def)) {
                    hits.add("getDefaultProxy=" + formatProxyInfo(def));
                    item.addDetectionDetail("🌐 默认代理", "ConnectivityManager.getDefaultProxy",
                            formatProxyInfo(def), DetectionLayer.JAVA, "⚠️");
                }
                for (Network n : cm.getAllNetworks()) {
                    LinkProperties lp = cm.getLinkProperties(n);
                    if (lp == null) continue;
                    ProxyInfo np = lp.getHttpProxy();
                    if (np == null || !isMeaningfulProxyInfo(np)) continue;
                    hits.add("Network " + n + " proxy=" + formatProxyInfo(np));
                    item.addDetectionDetail("🌐 网络代理", n.toString(),
                            formatProxyInfo(np), DetectionLayer.JAVA, "⚠️");
                }
            }
        } catch (Throwable t) {
            item.addDetectionDetail("⚠️ ConnectivityManager 代理读失败",
                    "getDefaultProxy/LinkProperties", simpleError(t),
                    DetectionLayer.JAVA, "ℹ️");
        }

        // === D) ProxySelector.getDefault() ===
        try {
            ProxySelector sel = ProxySelector.getDefault();
            if (sel != null) {
                for (Proxy p : sel.select(URI.create("http://example.com/"))) {
                    if (p == null || p.type() == Proxy.Type.DIRECT) continue;
                    String desc = p.type().name() + " " + p.address();
                    hits.add("ProxySelector " + desc);
                    item.addDetectionDetail("🔀 ProxySelector", p.type().name(),
                            String.valueOf(p.address()), DetectionLayer.JAVA, "⚠️");
                }
            }
        } catch (Throwable t) {
            item.addDetectionDetail("⚠️ ProxySelector 失败",
                    "ProxySelector.select", simpleError(t),
                    DetectionLayer.JAVA, "ℹ️");
        }

        boolean anyHit = !hits.isEmpty();
        item.setLayerResult(DetectionLayer.JAVA, anyHit);

        if (anyHit) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("发现系统代理配置: " + summarize(hits));
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未发现系统代理配置");
        }

        Log.i(TAG, "proxy: hits=" + hits.size());
        return item;
    }

    // ============================================================
    // 3. 本地代理监听端口 (主动 connect + /proc/net 被动扫)
    // ============================================================

    /**
     * 本地代理端口检测，两条独立通道：
     *  · 主动 connect 探测 127.0.0.1 / ::1 的常见代理端口（最直接 — 能连接 = listener 存在）
     *  · /proc/net/tcp[6] 扫描 LISTEN 状态在常见代理端口（绕 hook 的 syscall 信号）
     *
     * UDP **不参与**扫描：UDP 无 LISTEN 概念，普通 app 绑同端口做 UDP 通信会误判。
     * /proc/net 在 SDK 29+ 通常被 SELinux 拒，按 try-read 而不是 SDK 号判定。
     */
    public DetectionItem detectLocalProxyPorts() {
        DetectionItem item = new DetectionItem("本地代理端口",
                "127.0.0.1/::1 主动 connect + /proc/net/tcp 被动扫双通道");

        boolean anyConnectHit = false;
        boolean anyProcHit = false;
        boolean procReadable = false;
        List<String> hits = new ArrayList<>();

        // === A) 主动 connect 探测 ===
        for (String host : LOCAL_PROXY_CONNECT_HOSTS) {
            for (int port : COMMON_LOCAL_PROXY_PORTS) {
                long startNs = System.nanoTime();
                boolean open = probeTcpConnect(host, port, LOCAL_PROXY_CONNECT_TIMEOUT_MS);
                long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;
                if (open) {
                    anyConnectHit = true;
                    String key = host + ":" + port;
                    hits.add("connect " + key + " (" + elapsedMs + "ms)");
                    item.addDetectionDetail("🌐 主动 connect 命中", key,
                            "connect=open, elapsed=" + elapsedMs + "ms\n"
                                    + "→ 该端口上有 listener，疑似本地代理",
                            DetectionLayer.JAVA, "🚨");
                }
            }
        }

        // === B) /proc/net/tcp[6] 扫描 LISTEN 状态 ===
        Set<String> commonPortSet = new LinkedHashSet<>();
        for (int p : COMMON_LOCAL_PROXY_PORTS) commonPortSet.add(Integer.toHexString(p).toUpperCase(Locale.US));

        for (String path : PROC_NET_TCP_FILES) {
            ProcNetScan scan = scanProcNetTcpListen(path, commonPortSet);
            if (scan == null) continue; // open 失败，跳
            procReadable = true;
            for (String hit : scan.hits) {
                anyProcHit = true;
                hits.add(path + " " + hit);
                item.addDetectionDetail("📂 /proc/net 命中", path + " " + hit,
                        "TCP LISTEN 在已知代理端口上\n→ 反映 socket 实际 fd 状态，比 connect 更接近内核态",
                        DetectionLayer.SYSCALL, "🚨");
            }
            if (scan.hits.isEmpty()) {
                item.addDetectionDetail("📂 /proc/net 已扫", path,
                        "扫了 " + scan.totalRows + " 行，无命中",
                        DetectionLayer.SYSCALL, "✅");
            }
        }
        if (!procReadable) {
            item.addDetectionDetail("ℹ️ /proc/net 不可读", "SELinux 限制",
                    "Android 10+ untrusted_app 通常被 SELinux 拒读 /proc/net/tcp*。"
                            + "本检测改靠主动 connect 探测，仍有效",
                    DetectionLayer.SYSCALL, "ℹ️");
        }

        item.setLayerResult(DetectionLayer.JAVA, anyConnectHit);
        item.setLayerResult(DetectionLayer.SYSCALL, anyProcHit);

        if (anyConnectHit || anyProcHit) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("发现本地代理端口监听: " + summarize(hits));
        } else if (!procReadable) {
            // connect 全失败 + proc 不可读：理论上还是 SAFE，但表达成"已尽力"
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未连接到任何已知本地代理端口（/proc/net 不可读，仅 connect 验证）");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未发现本地代理端口");
        }

        Log.i(TAG, "local-proxy: connectHit=" + anyConnectHit
                + " procHit=" + anyProcHit + " procReadable=" + procReadable);
        return item;
    }

    // ============================================================
    // 4. 路由 + DNS 检测
    // ============================================================

    /**
     * 路由与 DNS 分析。看默认路由是不是走 VPN 接口、DNS 是不是私网地址（VPN 常见下发）。
     *
     * 信号：
     *  · 0.0.0.0/0 默认路由走 tun/wg/ppp 等接口 → 流量被 VPN 接管 → RISK
     *  · DNS server 在 RFC1918 私网范围（10.x / 172.16-31.x / 192.168.x）→ 可能 VPN 下发 → WARNING
     *  · 所有网络的接口列表（informational）
     */
    public DetectionItem detectNetworkRoutes() {
        DetectionItem item = new DetectionItem("路由 / DNS",
                "默认路由 + DNS server 私网地址分析");

        boolean defaultViaVpn = false;
        boolean privateDns = false;
        int routeCount = 0;
        int dnsCount = 0;
        List<String> hits = new ArrayList<>();

        // === 额外：Settings.Global Private DNS (Android 9+ DoT/DoH) ===
        boolean privateDnsCustom = false;
        try {
            String mode = Settings.Global.getString(
                    context.getContentResolver(), "private_dns_mode");
            String specifier = Settings.Global.getString(
                    context.getContentResolver(), "private_dns_specifier");
            if (mode != null) {
                // mode 取值: "off" / "opportunistic" / "hostname"
                if ("hostname".equalsIgnoreCase(mode) && isMeaningful(specifier)) {
                    privateDnsCustom = true;
                    hits.add("Private DNS hostname=" + specifier);
                    item.addDetectionDetail("⚠️ 自定义 Private DNS",
                            "Settings.Global private_dns",
                            "mode=" + mode + ", specifier=" + specifier
                                    + "\n→ DNS-over-TLS 指向自定义服务器，潜在中间人风险",
                            DetectionLayer.JAVA, "⚠️");
                } else {
                    item.addDetectionDetail("ℹ️ Private DNS 模式",
                            "Settings.Global private_dns_mode",
                            "mode=" + mode + (isMeaningful(specifier)
                                    ? ", specifier=" + specifier : ""),
                            DetectionLayer.JAVA, "📋");
                }
            }
        } catch (Throwable t) {
            item.addDetectionDetail("⚠️ Private DNS 读失败",
                    "Settings.Global private_dns", simpleError(t),
                    DetectionLayer.JAVA, "ℹ️");
        }

        try {
            ConnectivityManager cm = getCm();
            if (cm == null) {
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("ConnectivityManager 不可用");
                return item;
            }
            Network active = safeActiveNetwork(cm);
            int routeShown = 0;
            for (Network n : cm.getAllNetworks()) {
                LinkProperties lp = cm.getLinkProperties(n);
                if (lp == null) continue;
                String iface = safeIfaceName(lp);
                boolean isActive = n.equals(active);
                List<RouteInfo> routes = lp.getRoutes();
                List<InetAddress> dns = lp.getDnsServers();
                routeCount += routes != null ? routes.size() : 0;
                dnsCount += dns != null ? dns.size() : 0;

                // 默认路由检查
                if (routes != null) {
                    for (RouteInfo r : routes) {
                        if (!r.isDefaultRoute()) continue;
                        boolean vpnIface = isVpnInterfaceName(iface);
                        String desc = "default via " + iface
                                + (isActive ? " (active)" : "")
                                + " gateway=" + r.getGateway();
                        if (vpnIface) {
                            defaultViaVpn = true;
                            hits.add(desc);
                            item.addDetectionDetail("🚨 默认路由走 VPN", iface,
                                    desc, DetectionLayer.JAVA, "🚨");
                        } else if (routeShown < MAX_ROUTE_DETAIL_ROWS) {
                            item.addDetectionDetail("🛣️ 默认路由", iface,
                                    desc, DetectionLayer.JAVA, "📋");
                            routeShown++;
                        }
                    }
                }

                // DNS 私网地址检查 —— 仅在 DNS 通过 VPN 命名接口下发时告警。
                // 家用 WiFi 的 router (192.168.x.x) 自身做 DNS 是常态，不是 VPN 特征。
                if (dns != null) {
                    boolean ifaceIsVpn = isVpnInterfaceName(iface);
                    for (InetAddress a : dns) {
                        boolean priv = isPrivateAddress(a);
                        if (priv && ifaceIsVpn) {
                            privateDns = true;
                            String desc = "DNS=" + a.getHostAddress()
                                    + " via " + iface + (isActive ? " (active)" : "");
                            hits.add(desc);
                            item.addDetectionDetail("⚠️ DNS 在私网", iface,
                                    desc, DetectionLayer.JAVA, "⚠️");
                        } else if (priv) {
                            // 普通私网 DNS（如家用 WiFi 路由器）- 仅展示，不告警
                            item.addDetectionDetail("ℹ️ 私网 DNS（正常）", iface,
                                    "DNS=" + a.getHostAddress() + " via " + iface
                                            + "（非 VPN 接口，可能是路由器/网关 DNS）",
                                    DetectionLayer.JAVA, "ℹ️");
                        }
                    }
                }

                // 接口汇总（informational）
                item.addDetectionDetail("🌐 Network", n.toString(),
                        "iface=" + iface + ", routes=" + (routes != null ? routes.size() : 0)
                                + ", dns=" + formatDnsList(dns)
                                + (isActive ? " [active]" : ""),
                        DetectionLayer.JAVA, "📋");
            }
        } catch (Throwable t) {
            item.addDetectionDetail("⚠️ 路由读取失败",
                    "ConnectivityManager", simpleError(t),
                    DetectionLayer.JAVA, "ℹ️");
        }

        item.setLayerResult(DetectionLayer.JAVA, defaultViaVpn || privateDns || privateDnsCustom);

        if (defaultViaVpn) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("默认路由走 VPN 接口: " + summarize(hits));
        } else if (privateDns || privateDnsCustom) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail("DNS 异常: " + summarize(hits));
        } else if (routeCount == 0 && dnsCount == 0) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("无法读取路由/DNS 信息");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("路由 + DNS 未见 VPN 特征");
        }

        Log.i(TAG, "routes: defaultViaVpn=" + defaultViaVpn + " privateDns=" + privateDns
                + " privateDnsCustom=" + privateDnsCustom
                + " routeCount=" + routeCount + " dnsCount=" + dnsCount);
        return item;
    }

    // ============================================================
    // ===== 工具函数 =====
    // ============================================================

    private ConnectivityManager getCm() {
        try {
            return (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Network safeActiveNetwork(ConnectivityManager cm) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) return cm.getActiveNetwork();
        } catch (Throwable ignored) {
        }
        return null;
    }

    /** VPN 接口名匹配：tun/tap/ppp/wg/ipsec + 数字 或 含 "vpn"。 */
    private static boolean isVpnInterfaceName(String name) {
        if (name == null || name.isEmpty()) return false;
        String low = name.toLowerCase(Locale.US);
        Matcher m = VPN_INTERFACE_PATTERN.matcher(low);
        return m.find();
    }

    private static boolean safeIsUp(NetworkInterface ni) {
        try { return ni.isUp(); } catch (Throwable t) { return false; }
    }

    private static boolean safeIsLoopback(NetworkInterface ni) {
        try { return ni.isLoopback(); } catch (Throwable t) { return false; }
    }

    private static int safeMtu(NetworkInterface ni) {
        try { return ni.getMTU(); } catch (Throwable t) { return -1; }
    }

    private static String formatAddresses(NetworkInterface ni) {
        StringBuilder sb = new StringBuilder();
        try {
            Enumeration<InetAddress> en = ni.getInetAddresses();
            int n = 0;
            while (en.hasMoreElements()) {
                InetAddress a = en.nextElement();
                if (sb.length() > 0) sb.append(", ");
                sb.append(a.getHostAddress());
                if (++n >= 4) {
                    sb.append("...");
                    break;
                }
            }
        } catch (Throwable ignored) {
        }
        return sb.length() == 0 ? "<none>" : sb.toString();
    }

    private static String safeIfaceName(LinkProperties lp) {
        try { return lp != null ? lp.getInterfaceName() : "<null>"; }
        catch (Throwable t) { return "<error>"; }
    }

    private static String formatDnsList(List<InetAddress> list) {
        if (list == null || list.isEmpty()) return "<none>";
        StringBuilder sb = new StringBuilder();
        for (InetAddress a : list) {
            if (sb.length() > 0) sb.append(",");
            sb.append(a.getHostAddress());
        }
        return sb.toString();
    }

    /** 列出 /sys/class/net 下所有接口名。失败返回空列表（不 throw）。 */
    private static List<String> listSysfsInterfaces() {
        List<String> out = new ArrayList<>();
        try {
            java.io.File dir = new java.io.File("/sys/class/net");
            java.io.File[] entries = dir.listFiles();
            if (entries != null) {
                for (java.io.File f : entries) {
                    if (f != null) out.add(f.getName());
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** 读小文本文件第一行（去尾换行）。失败返回 ""。 */
    private static String readFirstLine(String path) {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(path));
            String line = r.readLine();
            return line == null ? "" : line.trim();
        } catch (Throwable t) {
            return "";
        } finally {
            try { if (r != null) r.close(); } catch (Throwable ignored) {}
        }
    }

    /** 主动 TCP connect 探测；open=true 表示有 listener。 */
    private static boolean probeTcpConnect(String host, int port, int timeoutMs) {
        Socket s = null;
        try {
            s = new Socket();
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            if (s != null) {
                try { s.close(); } catch (Throwable ignored) {}
            }
        }
    }

    private static class ProcNetScan {
        List<String> hits = new ArrayList<>();
        int totalRows = 0;
    }

    /**
     * 扫 /proc/net/tcp 或 tcp6 找 LISTEN 状态（state=0A）且端口在 commonPortHexes 列表中的行。
     * 文件格式 (newline-split)：
     *   sl  local_address  rem_address  st  ...
     *   0:  0100007F:1F90  00000000:0000  0A  ...
     * 返回 null 表示 open 失败（SELinux 拒）；返回空 hits 表示扫了没命中。
     */
    private static ProcNetScan scanProcNetTcpListen(String path, Set<String> commonPortHexes) {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(path));
        } catch (Throwable t) {
            return null;
        }
        ProcNetScan scan = new ProcNetScan();
        try {
            String line;
            boolean first = true;
            while ((line = r.readLine()) != null) {
                if (first) { first = false; continue; } // skip header
                scan.totalRows++;
                String[] cols = line.trim().split("\\s+");
                if (cols.length < 4) continue;
                String[] localParts = cols[1].split(":");
                if (localParts.length != 2) continue;
                String addrHex = localParts[0].toUpperCase(Locale.US);
                String portHex = localParts[1].toUpperCase(Locale.US);
                if (!"0A".equalsIgnoreCase(cols[3])) continue;       // LISTEN only
                if (!isLoopbackOrAnyHex(addrHex)) continue;          // bound to 127.0.0.1 or 0.0.0.0
                if (!commonPortHexes.contains(portHex)) continue;
                int port = parseHexPortSafe(portHex);
                scan.hits.add("port=" + port + " addr=" + addrHex);
            }
        } catch (Throwable ignored) {
        } finally {
            try { r.close(); } catch (Throwable ignored) {}
        }
        return scan;
    }

    /** /proc/net/tcp 的地址是按 dword little-endian dump。检查 0.0.0.0 / 127.0.0.1 / [::] / ::1。 */
    private static boolean isLoopbackOrAnyHex(String hex) {
        if (hex == null || hex.isEmpty()) return false;
        // 全 0：0.0.0.0 (8 字符) / ::（32 字符）
        if (isAllZero(hex)) return true;
        // IPv4 127.0.0.1：LE-dump 是 "0100007F"（dword=0x7F000001）
        if ("0100007F".equals(hex)) return true;
        // IPv6 ::1：4 个 dword LE-dump，最后 dword=0x00000001 → LE = "01000000"，
        // 前 3 个 dword 全 0 → "00000000" x3，整体 "00000000000000000000000001000000"
        if ("00000000000000000000000001000000".equals(hex)) return true;
        return false;
    }

    private static boolean isAllZero(String s) {
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) != '0') return false;
        return s.length() > 0;
    }

    private static int parseHexPortSafe(String hex) {
        try { return Integer.parseInt(hex, 16); } catch (Throwable t) { return -1; }
    }

    /** RFC1918 私网地址 + 链路本地。VPN 下发 DNS 时经常落在这里。 */
    private static boolean isPrivateAddress(InetAddress addr) {
        if (addr == null) return false;
        if (addr.isLoopbackAddress()) return false;     // 127.x / ::1 不算 VPN 特征
        if (addr.isSiteLocalAddress()) return true;     // 10.x / 172.16-31 / 192.168
        if (addr.isLinkLocalAddress()) return false;    // 169.254 通常不是 VPN
        // 额外：IPv6 fc00::/7 (ULA) 与 fe80::/10 (link-local)
        String s = addr.getHostAddress();
        if (s != null) {
            s = s.toLowerCase(Locale.US);
            if (s.startsWith("fc") || s.startsWith("fd")) return true;
        }
        return false;
    }

    private static boolean isMeaningful(String v) {
        if (v == null) return false;
        v = v.trim();
        if (v.isEmpty()) return false;
        if ("0".equals(v) || "-1".equals(v) || "null".equalsIgnoreCase(v)) return false;
        return true;
    }

    private static boolean isMeaningfulProxyInfo(ProxyInfo p) {
        if (p == null) return false;
        String host = p.getHost();
        int port = p.getPort();
        return isMeaningful(host) || port > 0;
    }

    private static String formatProxyInfo(ProxyInfo p) {
        if (p == null) return "<null>";
        return p.getHost() + ":" + p.getPort()
                + " excl=" + Arrays.toString(p.getExclusionList());
    }

    private static String simpleError(Throwable t) {
        if (t == null) return "";
        String m = t.getMessage();
        return t.getClass().getSimpleName() + (m == null ? "" : ": " + m);
    }

    private static String summarize(List<String> hits) {
        if (hits == null || hits.isEmpty()) return "<none>";
        if (hits.size() == 1) return hits.get(0);
        return hits.get(0) + "; 另有 " + (hits.size() - 1) + " 项";
    }
}
