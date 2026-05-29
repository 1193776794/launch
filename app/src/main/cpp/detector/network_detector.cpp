#include "network_detector.h"
#include "../syscall/syscall_wrapper.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

// ============================================================
// 通用 VPN 接口名判定：与 Java NetworkDetector.isVpnInterfaceName 保持一致
//   规则：lowercase 后匹配 ^(tun|tap|ppp|wg|ipsec)\d*$ 或包含 "vpn"
// ============================================================
bool starts_with(const std::string &s, const char *prefix) {
    size_t n = strlen(prefix);
    return s.size() >= n && memcmp(s.data(), prefix, n) == 0;
}

std::string to_lower(const std::string &s) {
    std::string out = s;
    for (char &c : out) if (c >= 'A' && c <= 'Z') c = (char) (c + 32);
    return out;
}

bool is_vpn_iface_name(const std::string &name) {
    if (name.empty()) return false;
    std::string low = to_lower(name);
    if (low.find("vpn") != std::string::npos) return true;
    static const char *prefixes[] = {"tun", "tap", "ppp", "wg", "ipsec"};
    for (const char *p : prefixes) {
        if (!starts_with(low, p)) continue;
        // 前缀后必须是纯数字或结尾，避免误中 "tunnel0"、"taproom" 等
        size_t plen = strlen(p);
        bool all_digits = true;
        for (size_t i = plen; i < low.size(); ++i) {
            if (low[i] < '0' || low[i] > '9') { all_digits = false; break; }
        }
        if (all_digits) return true;
    }
    return false;
}

// ============================================================
// A) getifaddrs() — POSIX 接口枚举 + flag 检查
// ============================================================
struct IfaddrsResult {
    bool ok = false;
    std::string all_summary;          // "name:f=0xhex|name:f=0xhex|..."
    std::string vpn_up_names;         // "name1,name2,..."
};

IfaddrsResult collectIfaddrs() {
    IfaddrsResult r;
    struct ifaddrs *ifap = nullptr;
    if (getifaddrs(&ifap) != 0) {
        return r;
    }
    r.ok = true;
    std::set<std::string> seen;
    std::vector<std::string> vpn_up;
    std::ostringstream all;
    bool first = true;
    for (struct ifaddrs *ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == nullptr) continue;
        std::string name(ifa->ifa_name);
        if (!seen.insert(name).second) continue;  // 同接口可能多 entry (一个 IPv4 + 一个 IPv6)，去重
        unsigned flags = ifa->ifa_flags;
        char buf[128];
        snprintf(buf, sizeof(buf), "%s:f=0x%x", name.c_str(), flags);
        if (!first) all << "|";
        first = false;
        all << buf;
        // IFF_UP & VPN 命名 = up 状态 VPN
        if ((flags & IFF_UP) && is_vpn_iface_name(name)) {
            vpn_up.push_back(name);
        }
    }
    freeifaddrs(ifap);
    r.all_summary = all.str();
    std::ostringstream vu;
    for (size_t i = 0; i < vpn_up.size(); ++i) {
        if (i > 0) vu << ",";
        vu << vpn_up[i];
    }
    r.vpn_up_names = vu.str();
    return r;
}

// ============================================================
// B) netlink RTM_GETROUTE — 拿默认路由的 OIF + iface name + gateway
// ============================================================
struct NetlinkRouteResult {
    bool ok = false;
    int default_oif = -1;
    std::string default_iface;     // if_indextoname(default_oif)
    std::string default_gateway;   // inet_ntop(gw)
};

// 单次 RTM_GETROUTE dump 查询，扫所有 table（Android 用 policy routing，VPN default
// 通常在 secondary table）。家族传 AF_INET 或 AF_INET6。
// found_oif 命中即立即返回；返回 false 表示无默认路由命中。
static bool netlink_dump_default(int family, int &out_oif, std::string &out_iface,
                                 std::string &out_gw, int &out_table) {
    int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sock < 0) return false;

    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type  = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq   = 1;
    req.nlh.nlmsg_pid   = 0;
    req.rtm.rtm_family  = family;

    if (send(sock, &req, sizeof(req), 0) < 0) {
        close(sock);
        return false;
    }

    char buf[16384];
    bool done = false;
    bool found = false;
    int iters = 0;
    while (!done && iters++ < 64) {
        ssize_t len = recv(sock, buf, sizeof(buf), 0);
        if (len <= 0) break;
        for (struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
             NLMSG_OK(nlh, (size_t) len);
             nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) { done = true; break; }
            if (nlh->nlmsg_type != RTM_NEWROUTE) continue;
            auto *rtm = (struct rtmsg *) NLMSG_DATA(nlh);
            // default route: rtm_dst_len == 0；不限 table（Android policy routing VPN 用
            // secondary table，常见 RT_TABLE_MAIN=254 / 1003 / 1100 等）
            if (rtm->rtm_dst_len != 0) continue;

            int oif = -1;
            char gw_buf[INET6_ADDRSTRLEN] = {0};
            bool has_gw = false;

            int rtl = (int) RTM_PAYLOAD(nlh);
            for (struct rtattr *attr = (struct rtattr *) RTM_RTA(rtm);
                 RTA_OK(attr, rtl);
                 attr = RTA_NEXT(attr, rtl)) {
                if (attr->rta_type == RTA_OIF) {
                    oif = *(int *) RTA_DATA(attr);
                } else if (attr->rta_type == RTA_GATEWAY) {
                    inet_ntop(family, RTA_DATA(attr), gw_buf, sizeof(gw_buf));
                    has_gw = true;
                }
            }
            if (oif > 0) {
                out_oif = oif;
                out_table = rtm->rtm_table;
                char ifn[IFNAMSIZ + 1] = {0};
                if (if_indextoname((unsigned) oif, ifn) != nullptr) {
                    out_iface = ifn;
                } else {
                    char idx[32];
                    snprintf(idx, sizeof(idx), "ifindex=%d", oif);
                    out_iface = idx;
                }
                out_gw = has_gw ? gw_buf : "0.0.0.0";
                found = true;
                done = true;
                break;
            }
        }
    }
    close(sock);
    return found;
}

NetlinkRouteResult queryNetlinkDefaultRoute() {
    NetlinkRouteResult r;
    // 先尝试创建 socket，无论后续是否命中，能创就视为 netlink 子系统可达
    int probe = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (probe < 0) return r;
    close(probe);
    r.ok = true;

    int table = -1;
    // IPv4 优先扫，没命中再 IPv6（家用网络一般 IPv4 默认路由先）
    if (!netlink_dump_default(AF_INET, r.default_oif, r.default_iface,
                              r.default_gateway, table)) {
        netlink_dump_default(AF_INET6, r.default_oif, r.default_iface,
                             r.default_gateway, table);
    }
    return r;
}

// ============================================================
// C) syscall_read_file("/proc/net/dev") — 直读 procfs 绕 libc
// ============================================================
struct ProcNetDevResult {
    bool ok = false;
    std::string iface_csv;  // "lo,wlan0,tun0,..."
};

ProcNetDevResult readProcNetDev() {
    ProcNetDevResult r;
    std::string content = syscall_read_file("/proc/net/dev", 65536);
    if (content.empty()) return r;
    r.ok = true;
    std::ostringstream out;
    bool first = true;
    int line_no = 0;
    size_t pos = 0;
    while (pos < content.size()) {
        size_t end = content.find('\n', pos);
        if (end == std::string::npos) end = content.size();
        std::string line = content.substr(pos, end - pos);
        pos = end + 1;
        line_no++;
        if (line_no <= 2) continue;  // /proc/net/dev 前两行是 header
        // 格式: "  iface: bytes packets ..."
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = line.substr(0, colon);
        // 去前后空白
        size_t start = name.find_first_not_of(" \t");
        size_t finish = name.find_last_not_of(" \t");
        if (start == std::string::npos) continue;
        name = name.substr(start, finish - start + 1);
        if (name.empty()) continue;
        if (!first) out << ",";
        first = false;
        out << name;
    }
    r.iface_csv = out.str();
    return r;
}

}  // namespace

std::string NetworkDetector::getNetworkNativeReport() {
    std::ostringstream out;

    IfaddrsResult ifa = collectIfaddrs();
    out << "IFADDRS_OK=" << (ifa.ok ? 1 : 0) << "\n";
    out << "IFADDRS_VPN_UP=" << ifa.vpn_up_names << "\n";
    out << "IFADDRS_ALL=" << ifa.all_summary << "\n";

    NetlinkRouteResult nl = queryNetlinkDefaultRoute();
    out << "NETLINK_OK=" << (nl.ok ? 1 : 0) << "\n";
    out << "NETLINK_DEFAULT_OIF=" << nl.default_oif << "\n";
    out << "NETLINK_DEFAULT_IFACE=" << nl.default_iface << "\n";
    out << "NETLINK_DEFAULT_GW=" << nl.default_gateway << "\n";

    ProcNetDevResult pnd = readProcNetDev();
    out << "PROC_NET_DEV_OK=" << (pnd.ok ? 1 : 0) << "\n";
    out << "PROC_NET_DEV_IFACES=" << pnd.iface_csv;

    return out.str();
}
