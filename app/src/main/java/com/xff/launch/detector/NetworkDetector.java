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
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Network environment detection for VPN and system proxy signals.
 */
@SuppressWarnings("deprecation")
public class NetworkDetector {

    private static final String TAG = "NetworkDetector";

    private static final String[] VPN_INTERFACE_PREFIXES = {
            "tun", "tap", "ppp", "wg", "ipsec", "vpn"
    };

    private static final String[] PROC_NET_FILES = {
            "/proc/net/dev",
            "/proc/net/if_inet6",
            "/proc/net/fib_trie"
    };

    private static final String[] LOCAL_PORT_FILES = {
            "/proc/net/tcp",
            "/proc/net/tcp6",
            "/proc/net/udp",
            "/proc/net/udp6"
    };

    private static final int[] COMMON_LOCAL_PROXY_PORTS = {
            1080, 1081, 2080, 7890, 7891, 7892, 7893, 8080, 8888, 9090,
            9097, 10808, 10809, 20170
    };

    private static final String[] LOCAL_PROXY_CONNECT_HOSTS = {
            "127.0.0.1", "::1"
    };

    private static final int MAX_ROUTE_DETAIL_ROWS = 8;
    private static final int LOCAL_PROXY_CONNECT_TIMEOUT_MS = 120;

    private static final Pattern VPN_INTERFACE_PATTERN = Pattern.compile(
            "(?i)(^|[^a-z0-9_])(tun\\d*|tap\\d*|ppp\\d*|wg\\d*|ipsec\\d*|vpn[a-z0-9_]*)(?=$|[^a-z0-9_])");

    private final Context context;
    private final NativeDetector nativeDetector;

    public NetworkDetector(Context context) {
        this.context = context.getApplicationContext();
        this.nativeDetector = NativeDetector.getInstance();
    }

    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        Log.i(TAG, "getAllDetections start");
        items.add(detectVpnTransport());
        items.add(detectLegacyNetworkInfo());
        items.add(detectLinkPropertiesRoutes());
        items.add(detectVpnInterfaces());
        items.add(detectNativeVpnInterfaces());
        items.add(detectProcNetExposure());
        items.add(detectLocalProxyPorts());
        items.add(detectLocalProxyConnectPorts());
        items.add(detectSystemProxy());
        items.add(detectRouteConsistency());
        Log.i(TAG, "getAllDetections end count=" + items.size());
        return items;
    }

    public DetectionItem detectVpnTransport() {
        DetectionItem item = new DetectionItem("VPN 连接状态", "通过 ConnectivityManager 检测系统 VPN 网络");

        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("ConnectivityManager 不可用");
                return item;
            }

            Network activeNetwork = cm.getActiveNetwork();
            Network[] networks = cm.getAllNetworks();
            boolean vpnDetected = false;
            boolean missingNotVpnCapability = false;
            int checked = 0;
            List<String> issues = new ArrayList<>();

            for (Network network : networks) {
                NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                if (caps == null) continue;
                checked++;

                boolean isVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                boolean notVpn = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
                if (isVpn) vpnDetected = true;
                if (!isVpn && !notVpn) missingNotVpnCapability = true;

                LinkProperties linkProperties = cm.getLinkProperties(network);
                String transportInfo = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                        && caps.getTransportInfo() != null
                        ? caps.getTransportInfo().getClass().getSimpleName()
                        : "<none>";
                String detail = "active=" + network.equals(activeNetwork)
                        + ", vpn=" + isVpn
                        + ", notVpn=" + notVpn
                        + ", interface=" + safeInterfaceName(linkProperties)
                        + ", dns=" + formatDns(linkProperties)
                        + ", transportInfo=" + transportInfo;

                if (isVpn) {
                    addIssue(item, issues, "NetworkCapabilities " + network,
                            "hasTransport(TRANSPORT_VPN)=true; " + detail, DetectionLayer.JAVA);
                } else if (!notVpn) {
                    addWarning(item, issues, "NetworkCapabilities " + network,
                            "未声明 NET_CAPABILITY_NOT_VPN; " + detail, DetectionLayer.JAVA);
                }
                item.addDetectionDetail("网络能力", network.toString(), detail,
                        DetectionLayer.JAVA, isVpn ? "VPN" : "NET");
            }

            item.setLayerResult(DetectionLayer.JAVA, vpnDetected);
            if (vpnDetected) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail(buildSummary(issues, "系统网络能力显示 VPN 已连接"));
            } else if (missingNotVpnCapability) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail(buildSummary(issues, "存在未声明 NOT_VPN 的网络能力，建议结合其他层结果判断"));
            } else if (checked == 0) {
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("未能读取到可用网络能力");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未发现 TRANSPORT_VPN 网络");
            }
        } catch (Throwable t) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("VPN 网络能力检测失败: " + t.getClass().getSimpleName());
            Log.w(TAG, "detectVpnTransport failed", t);
        }
        logItemResult(item);
        return item;
    }

    public DetectionItem detectLegacyNetworkInfo() {
        DetectionItem item = new DetectionItem("NetworkInfo VPN 类型", "检测旧版 NetworkInfo 是否暴露 TYPE_VPN");

        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("ConnectivityManager 不可用");
                return item;
            }

            boolean detected = false;
            boolean checked = false;
            List<String> issues = new ArrayList<>();

            NetworkInfo activeInfo = cm.getActiveNetworkInfo();
            if (activeInfo != null) {
                checked = true;
                boolean vpnType = isVpnNetworkInfo(activeInfo);
                boolean hit = isActiveVpnNetworkInfo(activeInfo);
                detected |= hit;
                if (hit) {
                    addIssue(item, issues, "ActiveNetworkInfo",
                            "当前网络暴露 VPN 类型; " + formatNetworkInfo(activeInfo),
                            DetectionLayer.JAVA);
                }
                item.addDetectionDetail("ActiveNetworkInfo", activeInfo.getTypeName(),
                        formatNetworkInfo(activeInfo), DetectionLayer.JAVA,
                        hit ? "VPN" : vpnType ? "INFO" : "NET");
            }

            NetworkInfo[] allInfo = cm.getAllNetworkInfo();
            boolean seenDisconnectedVpnType = false;
            if (allInfo != null) {
                for (NetworkInfo info : allInfo) {
                    if (info == null) continue;
                    checked = true;
                    boolean vpnType = isVpnNetworkInfo(info);
                    boolean hit = isActiveVpnNetworkInfo(info);
                    if (vpnType && !hit) seenDisconnectedVpnType = true;
                    detected |= hit;
                    if (hit) {
                        addIssue(item, issues, "AllNetworkInfo " + info.getTypeName(),
                                "type=" + info.getType() + " 命中 TYPE_VPN/ VPN typeName; "
                                        + formatNetworkInfo(info),
                                DetectionLayer.JAVA);
                    }
                    item.addDetectionDetail("AllNetworkInfo", info.getTypeName(),
                            formatNetworkInfo(info), DetectionLayer.JAVA,
                            hit ? "VPN" : vpnType ? "INFO" : "NET");
                }
            }

            item.setLayerResult(DetectionLayer.JAVA, detected);
            if (detected) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail(buildSummary(issues, "NetworkInfo 暴露 VPN 网络类型"));
            } else if (!checked) {
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("未能读取 NetworkInfo");
            } else if (seenDisconnectedVpnType) {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("仅发现未连接的 TYPE_VPN 记录，不作为风险");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("NetworkInfo 未发现 VPN 类型");
            }
        } catch (Throwable t) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("NetworkInfo 检测失败: " + t.getClass().getSimpleName());
            Log.w(TAG, "detectLegacyNetworkInfo failed", t);
        }
        logItemResult(item);
        return item;
    }

    public DetectionItem detectLinkPropertiesRoutes() {
        DetectionItem item = new DetectionItem("LinkProperties 路由", "检测接口名和路由是否指向 VPN 虚拟网卡");

        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("ConnectivityManager 不可用");
                return item;
            }

            boolean vpnDefaultRoute = false;
            boolean vpnInterface = false;
            boolean checked = false;
            int vpnRouteCount = 0;
            int vpnRouteDetailRows = 0;
            String firstVpnRoute = null;
            Set<String> vpnRouteIfaces = new HashSet<>();
            List<String> issues = new ArrayList<>();

            for (Network network : cm.getAllNetworks()) {
                LinkProperties props = cm.getLinkProperties(network);
                if (props == null) continue;
                checked = true;

                String iface = props.getInterfaceName();
                boolean ifaceHit = isVpnInterfaceName(iface);
                if (ifaceHit) vpnInterface = true;
                if (ifaceHit) {
                    addIssue(item, issues, "LinkProperties 接口 " + network,
                            "interface=" + iface + " 命中 VPN 虚拟接口名",
                            DetectionLayer.JAVA);
                }
                item.addDetectionDetail("LinkProperties 接口", network.toString(),
                        "interface=" + safeInterfaceName(props), DetectionLayer.JAVA,
                        ifaceHit ? "VPN" : "NET");

                for (RouteInfo route : props.getRoutes()) {
                    String routeIface = route.getInterface();
                    boolean defaultRoute = route.isDefaultRoute();
                    boolean routeHit = isVpnInterfaceName(routeIface);
                    if (routeHit) vpnInterface = true;
                    if (routeHit && defaultRoute) vpnDefaultRoute = true;
                    if (routeHit) {
                        vpnRouteCount++;
                        if (firstVpnRoute == null) firstVpnRoute = String.valueOf(route);
                        if (routeIface != null) vpnRouteIfaces.add(routeIface);
                        if (defaultRoute) {
                            addIssue(item, issues, "LinkProperties 默认路由",
                                    "默认路由经过 VPN 接口 " + routeIface + "; route=" + route,
                                    DetectionLayer.JAVA);
                        }
                    }
                    if (defaultRoute || (routeHit && vpnRouteDetailRows < MAX_ROUTE_DETAIL_ROWS)) {
                        item.addDetectionDetail("LinkProperties 路由", network.toString(),
                                "default=" + defaultRoute + ", iface=" + routeIface
                                        + ", route=" + route,
                                DetectionLayer.JAVA, routeHit ? "VPN" : "ROUTE");
                        if (routeHit) vpnRouteDetailRows++;
                    }
                }
            }

            if (vpnRouteCount > 0) {
                addWarning(item, issues, "LinkProperties 路由",
                        "发现 " + vpnRouteCount + " 条路由经过 VPN 接口 " + vpnRouteIfaces
                                + "; 示例=" + firstVpnRoute,
                        DetectionLayer.JAVA);
                if (vpnRouteCount > vpnRouteDetailRows) {
                    item.addDetectionDetail("LinkProperties 路由", "VPN 路由摘要",
                            "共 " + vpnRouteCount + " 条 VPN 接口路由，详情仅展示前 "
                                    + vpnRouteDetailRows + " 条",
                            DetectionLayer.JAVA, "VPN");
                }
            }

            item.setLayerResult(DetectionLayer.JAVA, vpnDefaultRoute || vpnInterface);
            if (vpnDefaultRoute) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail(buildSummary(issues, "LinkProperties 默认路由经过 VPN 接口"));
            } else if (vpnInterface) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail(buildSummary(issues, "LinkProperties 出现 VPN 接口或非默认路由"));
            } else if (!checked) {
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("未能读取 LinkProperties");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("LinkProperties 未发现 VPN 接口路由");
            }
        } catch (Throwable t) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("LinkProperties 路由检测失败: " + t.getClass().getSimpleName());
            Log.w(TAG, "detectLinkPropertiesRoutes failed", t);
        }
        logItemResult(item);
        return item;
    }

    public DetectionItem detectVpnInterfaces() {
        DetectionItem item = new DetectionItem("VPN 虚拟网卡", "检测 tun/wg/ppp/ipsec 等 VPN 虚拟接口");

        boolean suspicious = false;
        boolean javaSuspiciousUp = false;
        boolean sysfsSuspiciousUp = false;
        boolean checked = false;
        List<String> issues = new ArrayList<>();

        try {
            Enumeration<NetworkInterface> enumeration = NetworkInterface.getNetworkInterfaces();
            if (enumeration != null) {
                for (NetworkInterface networkInterface : Collections.list(enumeration)) {
                    checked = true;
                    String name = networkInterface.getName();
                    if (!isVpnInterfaceName(name)) continue;

                    suspicious = true;
                    boolean up = false;
                    try {
                        up = networkInterface.isUp();
                    } catch (SocketException ignored) {
                    }
                    if (up) javaSuspiciousUp = true;

                    String detail = "up=" + up
                            + ", loopback=" + safeIsLoopback(networkInterface)
                            + ", mtu=" + safeMtu(networkInterface)
                            + ", address=" + formatAddresses(networkInterface);
                    if (up) {
                        addIssue(item, issues, "NetworkInterface " + name,
                                "VPN 虚拟网卡处于 up 状态; " + detail,
                                DetectionLayer.JAVA);
                    } else {
                        addWarning(item, issues, "NetworkInterface " + name,
                                "发现 VPN 虚拟网卡名但未确认 up; " + detail,
                                DetectionLayer.JAVA);
                    }
                    item.addDetectionDetail("网络接口", name, detail,
                            DetectionLayer.JAVA, up ? "VPN" : "NET");
                }
            }
        } catch (Throwable t) {
            item.addDetectionDetail("网络接口", "NetworkInterface", "读取失败: "
                    + t.getClass().getSimpleName(), DetectionLayer.JAVA, "ERR");
        }

        List<String> sysfsNames = listSysfsInterfaces();
        for (String name : sysfsNames) {
            if (!isVpnInterfaceName(name)) continue;
            suspicious = true;
            boolean up = isInterfaceUpFromSysfs(name);
            if (up) sysfsSuspiciousUp = true;
            if (up) {
                addIssue(item, issues, "sysfs 接口 " + name,
                        "/sys/class/net/" + name + "/operstate=up",
                        DetectionLayer.SYSCALL);
            } else {
                addWarning(item, issues, "sysfs 接口 " + name,
                        "/sys/class/net/" + name + "/operstate="
                                + readFirstLine("/sys/class/net/" + name + "/operstate"),
                        DetectionLayer.SYSCALL);
            }
            item.addDetectionDetail("sysfs 接口", name, "state=" + readFirstLine(
                    "/sys/class/net/" + name + "/operstate"), DetectionLayer.SYSCALL, up ? "VPN" : "NET");
        }

        boolean suspiciousUp = javaSuspiciousUp || sysfsSuspiciousUp;
        item.setLayerResult(DetectionLayer.JAVA, javaSuspiciousUp);
        item.setLayerResult(DetectionLayer.SYSCALL, sysfsSuspiciousUp);

        if (suspiciousUp) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail(buildSummary(issues, "发现处于 up 状态的 VPN 虚拟网卡"));
        } else if (suspicious) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail(buildSummary(issues, "发现 VPN 虚拟网卡痕迹，但当前未确认处于 up 状态"));
        } else if (!checked && sysfsNames.isEmpty()) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("无法枚举网络接口");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未发现 VPN 虚拟网卡");
        }
        logItemResult(item);
        return item;
    }

    public DetectionItem detectNativeVpnInterfaces() {
        DetectionItem item = new DetectionItem("Native VPN 接口", "通过 ioctl(SIOCGIF*) 和 getifaddrs 检测 VPN 接口");

        try {
            String report = nativeDetector.getVpnNativeSignals();
            if (report == null || report.trim().isEmpty()) {
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("Native 未返回检测结果");
                return item;
            }

            boolean detected = report.contains("detected=1");
            boolean candidate = report.contains("ioctl.if=")
                    || report.contains("getifaddrs.if=")
                    || report.contains("if_nameindex.if=");
            List<String> issues = new ArrayList<>();
            collectNativeVpnIssues(item, issues, report);
            addNativeReportDetails(item, report);
            item.setLayerResult(DetectionLayer.NATIVE, detected);

            if (detected) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail(buildSummary(issues, "Native 接口枚举发现处于 up 状态的 VPN 接口"));
            } else if (candidate) {
                item.setStatus(DetectionStatus.WARNING);
                item.setDetail(buildSummary(issues, "Native 接口枚举发现 VPN 接口名，但未确认 up 状态"));
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("Native 接口枚举未发现 VPN 接口");
            }
        } catch (Throwable t) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("Native VPN 接口检测失败: " + t.getClass().getSimpleName());
            Log.w(TAG, "detectNativeVpnInterfaces failed", t);
        }
        logItemResult(item);
        return item;
    }

    public DetectionItem detectProcNetExposure() {
        DetectionItem item = new DetectionItem("/proc 网络痕迹", "检测 /proc/net/dev、if_inet6、fib_trie 中的 VPN 痕迹");

        if (isProcNetRestrictedByPlatform()) {
            markProcNetUnsupported(item, "/proc/net/dev、/proc/net/if_inet6、/proc/net/fib_trie");
            return item;
        }

        boolean readable = false;
        boolean suspicious = false;
        List<String> issues = new ArrayList<>();

        for (String path : PROC_NET_FILES) {
            ProcScanResult result = scanProcFileForVpnNames(path);
            readable |= result.readable;
            suspicious |= result.suspicious;
            if (result.suspicious) {
                addIssue(item, issues, path,
                        "文件内容出现 VPN 接口名 " + result.matches,
                        DetectionLayer.SYSCALL);
            }

            String value;
            if (!result.readable) {
                value = "读取失败或被 SELinux 拒绝";
            } else if (result.matches.isEmpty()) {
                value = "可读，未发现 VPN 接口名";
            } else {
                value = "命中: " + result.matches;
            }
            item.addDetectionDetail("/proc/net", path, value,
                    DetectionLayer.SYSCALL, result.suspicious ? "VPN" : "PROC");
        }

        item.setLayerResult(DetectionLayer.SYSCALL, suspicious);
        if (suspicious) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail(buildSummary(issues, "/proc/net 文件中发现 VPN 接口痕迹"));
        } else if (!readable) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("/proc/net 关键文件均不可读，无法旁证");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("/proc/net 未发现 VPN 接口痕迹");
        }
        logItemResult(item);
        return item;
    }

    public DetectionItem detectLocalProxyPorts() {
        DetectionItem item = new DetectionItem("本地代理端口", "检测 Clash/sing-box/V2Ray 等常见本地代理监听端口");

        if (isProcNetRestrictedByPlatform()) {
            markProcNetUnsupported(item, "/proc/net/tcp、/proc/net/tcp6、/proc/net/udp、/proc/net/udp6");
            return item;
        }

        boolean readable = false;
        boolean detected = false;
        List<String> issues = new ArrayList<>();

        for (String path : LOCAL_PORT_FILES) {
            PortScanResult result = scanLocalPortFile(path);
            readable |= result.readable;
            detected |= result.detected;
            if (result.detected) {
                addIssue(item, issues, path,
                        "发现常见本地代理监听端口 " + result.matches,
                        DetectionLayer.SYSCALL);
            }

            String value;
            if (!result.readable) {
                value = "读取失败或被 SELinux 拒绝";
            } else if (result.matches.isEmpty()) {
                value = "可读，未发现常见本地代理端口";
            } else {
                value = "命中: " + result.matches;
            }
            item.addDetectionDetail("本地端口", path, value,
                    DetectionLayer.SYSCALL, result.detected ? "PROXY" : "PORT");
        }

        item.setLayerResult(DetectionLayer.SYSCALL, detected);
        if (detected) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail(buildSummary(issues, "发现常见本地代理端口监听"));
        } else if (!readable) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("/proc/net/tcp/udp 均不可读，无法检测本地代理端口");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未发现常见本地代理端口");
        }
        logItemResult(item);
        return item;
    }

    public DetectionItem detectLocalProxyConnectPorts() {
        DetectionItem item = new DetectionItem("本地代理连通性", "主动连接本机常见代理监听端口");

        boolean detected = false;
        int checked = 0;
        List<String> issues = new ArrayList<>();

        item.addDetectionDetail("扫描范围", "目标地址",
                formatLoopbackConnectTargets(), DetectionLayer.JAVA, "INFO");
        item.addDetectionDetail("扫描范围", "连接超时",
                LOCAL_PROXY_CONNECT_TIMEOUT_MS + "ms", DetectionLayer.JAVA, "INFO");

        for (String host : LOCAL_PROXY_CONNECT_HOSTS) {
            for (int port : COMMON_LOCAL_PROXY_PORTS) {
                checked++;
                ConnectProbeResult result = probeLocalProxyPort(host, port);
                if (!result.open) continue;

                detected = true;
                String endpoint = host + ":" + port;
                String detail = "connect=open, elapsed=" + result.elapsedMs + "ms";
                addWarning(item, issues, endpoint,
                        "本地代理端口可连接; " + detail, DetectionLayer.JAVA);
                item.addDetectionDetail("开放端口", endpoint,
                        detail, DetectionLayer.JAVA, "PROXY");
            }
        }

        item.setLayerResult(DetectionLayer.JAVA, detected);
        if (detected) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail(buildSummary(issues, "发现可连接的本地代理端口"));
        } else if (checked == 0) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("未执行本地代理端口连通性检测");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未发现可连接的常见本地代理端口");
        }
        logItemResult(item);
        return item;
    }

    @SuppressWarnings("deprecation")
    public DetectionItem detectSystemProxy() {
        DetectionItem item = new DetectionItem("系统代理配置", "检测 HTTP/HTTPS/SOCKS 代理设置");

        boolean javaProxyDetected = false;
        boolean nativeProxyDetected = false;
        List<String> issues = new ArrayList<>();

        javaProxyDetected |= addSystemPropertyProxy(item, issues, "http.proxyHost", "http.proxyPort");
        javaProxyDetected |= addSystemPropertyProxy(item, issues, "https.proxyHost", "https.proxyPort");
        javaProxyDetected |= addSystemPropertyProxy(item, issues, "socksProxyHost", "socksProxyPort");
        javaProxyDetected |= addSettingsGlobalProxy(item, issues);
        javaProxyDetected |= addLegacyAndroidProxy(item, issues);

        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                ProxyInfo defaultProxy = cm.getDefaultProxy();
                if (defaultProxy != null) {
                    javaProxyDetected = true;
                    addWarning(item, issues, "ConnectivityManager.getDefaultProxy",
                            "系统默认代理=" + formatProxyInfo(defaultProxy), DetectionLayer.JAVA);
                    item.addDetectionDetail("系统代理", "ConnectivityManager.getDefaultProxy",
                            formatProxyInfo(defaultProxy), DetectionLayer.JAVA, "PROXY");
                }

                for (Network network : cm.getAllNetworks()) {
                    LinkProperties props = cm.getLinkProperties(network);
                    if (props == null || props.getHttpProxy() == null) continue;
                    javaProxyDetected = true;
                    addWarning(item, issues, "LinkProperties.getHttpProxy " + network,
                            "网络代理=" + formatProxyInfo(props.getHttpProxy()), DetectionLayer.JAVA);
                    item.addDetectionDetail("网络代理", network.toString(),
                            formatProxyInfo(props.getHttpProxy()), DetectionLayer.JAVA, "PROXY");
                }
            }
        } catch (Throwable t) {
            item.addDetectionDetail("系统代理", "ConnectivityManager", "读取失败: "
                    + t.getClass().getSimpleName(), DetectionLayer.JAVA, "ERR");
        }

        try {
            ProxySelector selector = ProxySelector.getDefault();
            if (selector != null) {
                List<Proxy> proxies = selector.select(new URI("http://example.com/"));
                for (Proxy proxy : proxies) {
                    if (proxy == null || proxy.type() == Proxy.Type.DIRECT) continue;
                    javaProxyDetected = true;
                    addWarning(item, issues, "ProxySelector " + proxy.type().name(),
                            "代理地址=" + proxy.address(), DetectionLayer.JAVA);
                    item.addDetectionDetail("代理选择器", proxy.type().name(),
                            String.valueOf(proxy.address()), DetectionLayer.JAVA, "PROXY");
                }
            }
        } catch (Throwable t) {
            item.addDetectionDetail("代理选择器", "ProxySelector", "读取失败: "
                    + t.getClass().getSimpleName(), DetectionLayer.JAVA, "ERR");
        }

        nativeProxyDetected = addNativeProxySignals(item, issues);

        boolean proxyDetected = javaProxyDetected || nativeProxyDetected;
        item.setLayerResult(DetectionLayer.JAVA, javaProxyDetected);
        item.setLayerResult(DetectionLayer.NATIVE, nativeProxyDetected);
        if (proxyDetected) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail(buildSummary(issues, "发现系统代理配置"));
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未发现系统代理配置");
        }
        logItemResult(item);
        return item;
    }

    private boolean addSettingsGlobalProxy(DetectionItem item, List<String> issues) {
        try {
            String value = Settings.Global.getString(context.getContentResolver(), "http_proxy");
            if (!isMeaningfulProxyValue(value)) {
                item.addDetectionDetail("系统代理", "Settings.Global http_proxy",
                        value == null ? "<empty>" : value, DetectionLayer.JAVA, "INFO");
                return false;
            }
            addWarning(item, issues, "Settings.Global http_proxy",
                    "系统全局代理=" + value, DetectionLayer.JAVA);
            item.addDetectionDetail("系统代理", "Settings.Global http_proxy",
                    value, DetectionLayer.JAVA, "PROXY");
            return true;
        } catch (Throwable t) {
            item.addDetectionDetail("系统代理", "Settings.Global http_proxy",
                    "读取失败: " + t.getClass().getSimpleName(), DetectionLayer.JAVA, "ERR");
            return false;
        }
    }

    @SuppressWarnings("deprecation")
    private boolean addLegacyAndroidProxy(DetectionItem item, List<String> issues) {
        try {
            String host = android.net.Proxy.getHost(context);
            int port = android.net.Proxy.getPort(context);
            String value = (host == null ? "<empty>" : host) + ":" + port;
            if (!isMeaningfulProxyHostPort(host, port)) {
                item.addDetectionDetail("系统代理", "android.net.Proxy",
                        value, DetectionLayer.JAVA, "INFO");
                return false;
            }

            addWarning(item, issues, "android.net.Proxy",
                    "旧版代理=" + value, DetectionLayer.JAVA);
            item.addDetectionDetail("系统代理", "android.net.Proxy",
                    value, DetectionLayer.JAVA, "PROXY");
            return true;
        } catch (Throwable t) {
            item.addDetectionDetail("系统代理", "android.net.Proxy",
                    "读取失败: " + t.getClass().getSimpleName(), DetectionLayer.JAVA, "ERR");
            return false;
        }
    }

    private boolean addNativeProxySignals(DetectionItem item, List<String> issues) {
        try {
            String report = nativeDetector.getProxyNativeSignals();
            if (report == null || report.trim().isEmpty()) {
                item.addDetectionDetail("Native 代理配置", "检测结果",
                        "Native 未返回代理配置结果", DetectionLayer.NATIVE, "ERR");
                return false;
            }

            boolean detected = report.contains("detected=1");
            String[] lines = report.split("\\r?\\n");
            for (String line : lines) {
                if (line == null || line.trim().isEmpty() || line.startsWith("detected=")) {
                    continue;
                }
                int split = line.indexOf('=');
                if (split <= 0) continue;

                String key = line.substring(0, split);
                String value = line.substring(split + 1);
                boolean hit = isMeaningfulProxyValue(value);
                if (hit) {
                    addWarning(item, issues, key, "Native代理=" + value, DetectionLayer.NATIVE);
                }
                item.addDetectionDetail("Native 代理配置", key,
                        hit ? value : "未设置", DetectionLayer.NATIVE, hit ? "PROXY" : "INFO");
            }
            return detected;
        } catch (Throwable t) {
            item.addDetectionDetail("Native 代理配置", "getProxyNativeSignals",
                    "读取失败: " + t.getClass().getSimpleName(), DetectionLayer.NATIVE, "ERR");
            return false;
        }
    }

    public DetectionItem detectRouteConsistency() {
        DetectionItem item = new DetectionItem("VPN 路由一致性", "通过 /proc 路由表旁证 VPN 默认路由");

        if (isProcNetRestrictedByPlatform()) {
            markProcNetUnsupported(item, "/proc/net/route、/proc/net/ipv6_route");
            return item;
        }

        List<String> issues = new ArrayList<>();
        RouteScanResult ipv4 = scanIpv4Routes(item, issues);
        RouteScanResult ipv6 = scanIpv6Routes(item, issues);

        boolean vpnDefaultRoute = ipv4.vpnDefaultRoute || ipv6.vpnDefaultRoute;
        boolean anyReadable = ipv4.readable || ipv6.readable;
        boolean anyDefaultRoute = ipv4.defaultRouteFound || ipv6.defaultRouteFound;

        item.setLayerResult(DetectionLayer.SYSCALL, vpnDefaultRoute);
        if (vpnDefaultRoute) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail(buildSummary(issues, "默认路由经过 VPN 虚拟接口"));
        } else if (!anyReadable) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("无法读取 /proc/net 路由表");
        } else if (!anyDefaultRoute) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("未在 /proc/net 路由表中找到默认路由");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("默认路由未经过 VPN 虚拟接口");
        }
        logItemResult(item);
        return item;
    }

    private static boolean addSystemPropertyProxy(DetectionItem item, List<String> issues,
                                                  String hostKey, String portKey) {
        String host = System.getProperty(hostKey);
        String port = System.getProperty(portKey);
        if (host == null || host.trim().isEmpty()) return false;

        String value = host + (port == null || port.trim().isEmpty() ? "" : ":" + port);
        addWarning(item, issues, hostKey, "系统属性代理=" + value, DetectionLayer.JAVA);
        item.addDetectionDetail("系统属性代理", hostKey, value, DetectionLayer.JAVA, "PROXY");
        return true;
    }

    private static void addIssue(DetectionItem item, List<String> issues, String point,
                                 String issue, DetectionLayer layer) {
        addFinding(item, issues, point, issue, layer, "RISK");
    }

    private static void addWarning(DetectionItem item, List<String> issues, String point,
                                   String issue, DetectionLayer layer) {
        addFinding(item, issues, point, issue, layer, "WARN");
    }

    private static void addFinding(DetectionItem item, List<String> issues, String point,
                                   String issue, DetectionLayer layer, String icon) {
        if (issues != null) issues.add(compactFinding(point, issue));
    }

    private static String buildSummary(List<String> issues, String fallback) {
        if (issues == null || issues.isEmpty()) return fallback;
        StringBuilder out = new StringBuilder(issues.get(0));
        if (issues.size() > 1) {
            out.append("; 另有 ").append(issues.size() - 1).append(" 项");
        }
        return out.toString();
    }

    private static String compactFinding(String point, String issue) {
        if (issue == null || issue.trim().isEmpty()) return point;

        String iface = extractFieldValue(issue, "interface=");
        if (iface == null) iface = extractFieldValue(issue, "接口=");
        if (iface == null) iface = extractFieldValue(issue, "默认路由接口=");
        if (iface == null) iface = extractFieldValue(issue, "ioctl.if=");
        if (iface == null) iface = extractFieldValue(issue, "getifaddrs.if=");
        if (iface == null) iface = extractFieldValue(issue, "if_nameindex.if=");

        if (issue.contains("TRANSPORT_VPN")) {
            return appendIface(point + " 检测到 VPN", iface);
        }
        if (issue.contains("TYPE_VPN") || issue.contains("VPN typeName") || issue.contains("VPN 类型")) {
            return point + " 检测到 VPN 类型";
        }
        if (issue.contains("VPN 虚拟网卡处于 up 状态") || issue.contains("up 状态")) {
            return appendIface(point + " 处于 up 状态", iface);
        }
        if (issue.contains("命中 VPN 虚拟接口名")) {
            return appendIface(point + " 命中 VPN 接口", iface);
        }
        if (issue.contains("路由经过 VPN 接口") || issue.contains("路由经过 VPN")) {
            return appendIface(point + " 经过 VPN 接口", iface);
        }
        if (issue.contains("文件内容出现 VPN 接口名")) {
            return point + " 出现 VPN 接口名";
        }
        if (issue.contains("本地代理监听端口")) {
            return point + " 发现本地代理端口";
        }
        if (issue.contains("本地代理端口可连接")) {
            return point + " 可连接";
        }
        if (issue.contains("系统属性代理=")) {
            return point + " " + extractAfter(issue, "系统属性代理=");
        }
        if (issue.contains("系统全局代理=")) {
            return point + " " + extractAfter(issue, "系统全局代理=");
        }
        if (issue.contains("旧版代理=")) {
            return point + " " + extractAfter(issue, "旧版代理=");
        }
        if (issue.contains("系统默认代理=")) {
            return point + " " + extractAfter(issue, "系统默认代理=");
        }
        if (issue.contains("网络代理=")) {
            return point + " " + extractAfter(issue, "网络代理=");
        }
        if (issue.contains("代理地址=")) {
            return point + " " + extractAfter(issue, "代理地址=");
        }
        if (issue.contains("Native代理=")) {
            return point + " " + extractAfter(issue, "Native代理=");
        }
        if (issue.contains("未声明 NET_CAPABILITY_NOT_VPN")) {
            return point + " 未声明 NOT_VPN";
        }

        String trimmed = issue.trim();
        if (trimmed.length() > 48) {
            trimmed = trimmed.substring(0, 48) + "...";
        }
        return point + ": " + trimmed;
    }

    private static String appendIface(String text, String iface) {
        if (iface == null || iface.isEmpty() || "<none>".equals(iface)) return text;
        return text + ": " + iface;
    }

    private static String extractAfter(String text, String marker) {
        int start = text.indexOf(marker);
        if (start < 0) return "";
        return text.substring(start + marker.length()).trim();
    }

    private static String extractFieldValue(String text, String marker) {
        int start = text.indexOf(marker);
        if (start < 0) return null;
        start += marker.length();
        int end = start;
        while (end < text.length()) {
            char c = text.charAt(end);
            if (c == ',' || c == ';' || Character.isWhitespace(c) || c == ']') break;
            end++;
        }
        if (end <= start) return null;
        return text.substring(start, end);
    }

    private static void collectNativeVpnIssues(DetectionItem item, List<String> issues, String report) {
        String[] lines = report.split("\\r?\\n");
        for (String line : lines) {
            if (line == null || line.trim().isEmpty()) continue;
            boolean ioctlLine = line.startsWith("ioctl.if=");
            boolean getifaddrsLine = line.startsWith("getifaddrs.if=");
            boolean nameIndexLine = line.startsWith("if_nameindex.if=");
            boolean ifaceLine = ioctlLine || getifaddrsLine || nameIndexLine;
            if (!ifaceLine) continue;

            DetectionLayer layer = DetectionLayer.NATIVE;
            String point = ioctlLine ? "Native ioctl"
                    : getifaddrsLine ? "Native getifaddrs"
                    : "Native if_nameindex";
            if (line.contains(" up=1")) {
                addIssue(item, issues, point,
                        "枚举到处于 up 状态的 VPN 接口; " + line, layer);
            } else {
                addWarning(item, issues, point,
                        "枚举到 VPN 接口名但未确认 up; " + line, layer);
            }
        }
    }

    private static void logItemResult(DetectionItem item) {
        if (item == null) return;
        Log.i(TAG, "result item=" + item.getName()
                + " status=" + item.getStatus()
                + " detail=" + item.getDetail()
                + " layers=" + item.getLayerResults());

        if (!item.hasDetails()) return;
        for (DetectionItem.DetectionDetail detail : item.getDetectionDetails()) {
            String value = detail.getValue();
            if (value != null && value.length() > 400) {
                value = value.substring(0, 400) + "...";
            }
            Log.i(TAG, "detail item=" + item.getName()
                    + " category=" + detail.getCategory()
                    + " key=" + detail.getItem()
                    + " value=" + value
                    + " layer=" + detail.getLayer()
                    + " icon=" + detail.getIcon());
        }
    }

    private static boolean isProcNetRestrictedByPlatform() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q;
    }

    private static void markProcNetUnsupported(DetectionItem item, String paths) {
        String detail = "Android 10+ 不支持普通 App 读取 " + paths
                + "，当前 API=" + Build.VERSION.SDK_INT + "，已跳过该检测";
        item.setLayerResult(DetectionLayer.SYSCALL, false);
        item.setStatus(DetectionStatus.SAFE);
        item.setDetail(detail);
        item.addDetectionDetail("平台限制", "Android API " + Build.VERSION.SDK_INT,
                detail, DetectionLayer.SYSCALL, "SKIP");
        logItemResult(item);
    }

    private static boolean isVpnNetworkInfo(NetworkInfo info) {
        if (info == null) return false;
        if (info.getType() == ConnectivityManager.TYPE_VPN) return true;
        String typeName = info.getTypeName();
        String subtypeName = info.getSubtypeName();
        return containsVpnText(typeName) || containsVpnText(subtypeName);
    }

    private static boolean isActiveVpnNetworkInfo(NetworkInfo info) {
        return isVpnNetworkInfo(info) && (info.isConnected() || info.isConnectedOrConnecting());
    }

    private static String formatNetworkInfo(NetworkInfo info) {
        return "type=" + info.getType()
                + ", typeName=" + info.getTypeName()
                + ", subtype=" + info.getSubtypeName()
                + ", connected=" + info.isConnected()
                + ", state=" + info.getState();
    }

    private static boolean containsVpnText(String value) {
        return value != null && value.toLowerCase(Locale.US).contains("vpn");
    }

    private static void addNativeReportDetails(DetectionItem item, String report) {
        String[] lines = report.split("\\r?\\n");
        int count = 0;
        for (String line : lines) {
            if (line == null || line.trim().isEmpty()) continue;
            if (line.startsWith("detected=")) continue;
            String category = line.startsWith("ioctl") ? "Native ioctl"
                    : line.startsWith("getifaddrs") ? "Native getifaddrs"
                    : line.startsWith("if_nameindex") ? "Native if_nameindex"
                    : "Native 网络";
            String icon = line.contains(".if=") ? "VPN" : line.contains("error") ? "ERR" : "NATIVE";
            item.addDetectionDetail(category, "检测向量", line, DetectionLayer.NATIVE, icon);
            count++;
            if (count >= 40) {
                item.addDetectionDetail(category, "检测向量", "结果过多，已截断",
                        DetectionLayer.NATIVE, "INFO");
                break;
            }
        }
    }

    private static ProcScanResult scanProcFileForVpnNames(String path) {
        ProcScanResult result = new ProcScanResult();
        String content = readFileLimited(path, 65536);
        if (content == null) return result;

        result.readable = true;
        result.matches.addAll(extractVpnInterfaceNames(content));
        result.suspicious = !result.matches.isEmpty();
        return result;
    }

    private static Set<String> extractVpnInterfaceNames(String content) {
        Set<String> matches = new HashSet<>();
        if (content == null || content.isEmpty()) return matches;

        Matcher matcher = VPN_INTERFACE_PATTERN.matcher(content);
        while (matcher.find()) {
            String name = matcher.group(2);
            if (name != null && !name.isEmpty()) {
                matches.add(name);
            }
        }
        return matches;
    }

    private static PortScanResult scanLocalPortFile(String path) {
        PortScanResult result = new PortScanResult();
        boolean tcp = path.contains("tcp");

        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            result.readable = true;
            String line;
            boolean first = true;
            while ((line = reader.readLine()) != null) {
                if (first) {
                    first = false;
                    continue;
                }
                String[] parts = line.trim().split("\\s+");
                if (parts.length < 4) continue;

                String[] local = parts[1].split(":");
                if (local.length != 2) continue;

                String addressHex = local[0].toUpperCase(Locale.US);
                int port = parseHexPort(local[1]);
                if (port < 0 || !isCommonLocalProxyPort(port)) continue;
                if (!isLoopbackOrAnyAddress(addressHex)) continue;
                if (tcp && !"0A".equalsIgnoreCase(parts[3])) continue;

                result.detected = true;
                result.matches.add(port + "@" + addressHex + " state=" + parts[3]);
            }
        } catch (IOException ignored) {
        }
        return result;
    }

    private static ConnectProbeResult probeLocalProxyPort(String host, int port) {
        long start = System.nanoTime();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), LOCAL_PROXY_CONNECT_TIMEOUT_MS);
            return new ConnectProbeResult(true, elapsedMillis(start));
        } catch (IOException | RuntimeException ignored) {
            return new ConnectProbeResult(false, elapsedMillis(start));
        }
    }

    private static long elapsedMillis(long startNano) {
        return Math.max(0L, (System.nanoTime() - startNano) / 1_000_000L);
    }

    private static String formatLoopbackConnectTargets() {
        return "hosts=" + java.util.Arrays.toString(LOCAL_PROXY_CONNECT_HOSTS)
                + ", ports=" + java.util.Arrays.toString(COMMON_LOCAL_PROXY_PORTS);
    }

    private static int parseHexPort(String value) {
        try {
            return Integer.parseInt(value, 16);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static boolean isCommonLocalProxyPort(int port) {
        for (int candidate : COMMON_LOCAL_PROXY_PORTS) {
            if (candidate == port) return true;
        }
        return false;
    }

    private static boolean isLoopbackOrAnyAddress(String addressHex) {
        if (addressHex == null || addressHex.isEmpty()) return false;
        if (isAllZeroHex(addressHex)) return true;
        if ("0100007F".equals(addressHex)) return true;
        return "00000000000000000000000001000000".equals(addressHex);
    }

    private static String safeInterfaceName(LinkProperties linkProperties) {
        if (linkProperties == null || linkProperties.getInterfaceName() == null) return "<none>";
        return linkProperties.getInterfaceName();
    }

    private static String formatDns(LinkProperties linkProperties) {
        if (linkProperties == null || linkProperties.getDnsServers().isEmpty()) return "[]";
        List<String> dns = new ArrayList<>();
        for (InetAddress address : linkProperties.getDnsServers()) {
            dns.add(address.getHostAddress());
        }
        return dns.toString();
    }

    private static String formatProxyInfo(ProxyInfo proxyInfo) {
        if (proxyInfo == null) return "<none>";
        String host = proxyInfo.getHost();
        int port = proxyInfo.getPort();
        String pac = proxyInfo.getPacFileUrl() == null ? "" : proxyInfo.getPacFileUrl().toString();
        if (host != null && !host.isEmpty()) return host + ":" + port;
        if (!pac.isEmpty() && !"".equals(pac)) return "PAC=" + pac;
        return proxyInfo.toString();
    }

    private static boolean isMeaningfulProxyValue(String value) {
        if (value == null) return false;
        String normalized = value.trim();
        if (normalized.isEmpty()) return false;
        if ("<empty>".equalsIgnoreCase(normalized)) return false;
        if ("null".equalsIgnoreCase(normalized)) return false;
        return !":0".equals(normalized);
    }

    private static boolean isMeaningfulProxyHostPort(String host, int port) {
        return isMeaningfulProxyValue(host) && port > 0;
    }

    private static boolean isVpnInterfaceName(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase(Locale.US);
        for (String prefix : VPN_INTERFACE_PREFIXES) {
            if (lower.startsWith(prefix)) return true;
        }
        return lower.contains("vpn");
    }

    private static boolean safeIsLoopback(NetworkInterface networkInterface) {
        try {
            return networkInterface.isLoopback();
        } catch (SocketException e) {
            return false;
        }
    }

    private static int safeMtu(NetworkInterface networkInterface) {
        try {
            return networkInterface.getMTU();
        } catch (SocketException e) {
            return -1;
        }
    }

    private static String formatAddresses(NetworkInterface networkInterface) {
        List<String> addresses = new ArrayList<>();
        for (InetAddress address : Collections.list(networkInterface.getInetAddresses())) {
            addresses.add(address.getHostAddress());
        }
        return addresses.toString();
    }

    private static List<String> listSysfsInterfaces() {
        File root = new File("/sys/class/net");
        String[] names = root.list();
        if (names == null) return Collections.emptyList();
        List<String> result = new ArrayList<>();
        Collections.addAll(result, names);
        return result;
    }

    private static boolean isInterfaceUpFromSysfs(String name) {
        String state = readFirstLine("/sys/class/net/" + name + "/operstate");
        return state != null && "up".equalsIgnoreCase(state.trim());
    }

    private static String readFirstLine(String path) {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            return reader.readLine();
        } catch (IOException e) {
            return null;
        }
    }

    private static String readFileLimited(String path, int maxChars) {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            StringBuilder out = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null && out.length() < maxChars) {
                out.append(line).append('\n');
            }
            return out.toString();
        } catch (IOException e) {
            return null;
        }
    }

    private static RouteScanResult scanIpv4Routes(DetectionItem item, List<String> issues) {
        RouteScanResult result = new RouteScanResult();
        File routeFile = new File("/proc/net/route");
        try (BufferedReader reader = new BufferedReader(new FileReader(routeFile))) {
            result.readable = true;
            String line;
            boolean first = true;
            while ((line = reader.readLine()) != null) {
                if (first) {
                    first = false;
                    continue;
                }
                String[] parts = line.trim().split("\\s+");
                if (parts.length < 8) continue;

                String iface = parts[0];
                String destination = parts[1];
                if (!"00000000".equals(destination)) continue;

                result.defaultRouteFound = true;
                boolean vpnIface = isVpnInterfaceName(iface);
                if (vpnIface) result.vpnDefaultRoute = true;
                if (vpnIface) {
                    addIssue(item, issues, "IPv4 默认路由",
                            "默认路由接口=" + iface + "; gateway=0x" + parts[2]
                                    + "; flags=0x" + parts[3],
                            DetectionLayer.SYSCALL);
                }

                item.addDetectionDetail("IPv4 默认路由", iface,
                        "gateway=0x" + parts[2] + ", flags=0x" + parts[3],
                        DetectionLayer.SYSCALL, vpnIface ? "VPN" : "ROUTE");
            }
        } catch (IOException e) {
            item.addDetectionDetail("IPv4 路由表", routeFile.getPath(), "读取失败",
                    DetectionLayer.SYSCALL, "ERR");
        }
        return result;
    }

    private static RouteScanResult scanIpv6Routes(DetectionItem item, List<String> issues) {
        RouteScanResult result = new RouteScanResult();
        File routeFile = new File("/proc/net/ipv6_route");
        try (BufferedReader reader = new BufferedReader(new FileReader(routeFile))) {
            result.readable = true;
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length < 10) continue;

                String destination = parts[0];
                String prefixLength = parts[1];
                String iface = parts[9];
                boolean isDefault = isAllZeroHex(destination) && "00000000".equals(prefixLength);
                if (!isDefault) continue;

                result.defaultRouteFound = true;
                boolean vpnIface = isVpnInterfaceName(iface);
                if (vpnIface) result.vpnDefaultRoute = true;
                if (vpnIface) {
                    addIssue(item, issues, "IPv6 默认路由",
                            "默认路由接口=" + iface + "; nextHop=" + parts[4]
                                    + "; metric=0x" + parts[5],
                            DetectionLayer.SYSCALL);
                }

                item.addDetectionDetail("IPv6 默认路由", iface,
                        "nextHop=" + parts[4] + ", metric=0x" + parts[5],
                        DetectionLayer.SYSCALL, vpnIface ? "VPN" : "ROUTE");
            }
        } catch (IOException e) {
            item.addDetectionDetail("IPv6 路由表", routeFile.getPath(), "读取失败",
                    DetectionLayer.SYSCALL, "ERR");
        }
        return result;
    }

    private static boolean isAllZeroHex(String value) {
        if (value == null || value.isEmpty()) return false;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) != '0') return false;
        }
        return true;
    }

    private static class RouteScanResult {
        boolean readable;
        boolean defaultRouteFound;
        boolean vpnDefaultRoute;
    }

    private static class ProcScanResult {
        boolean readable;
        boolean suspicious;
        Set<String> matches = new HashSet<>();
    }

    private static class PortScanResult {
        boolean readable;
        boolean detected;
        List<String> matches = new ArrayList<>();
    }

    private static class ConnectProbeResult {
        final boolean open;
        final long elapsedMs;

        ConnectProbeResult(boolean open, long elapsedMs) {
            this.open = open;
            this.elapsedMs = elapsedMs;
        }
    }
}
