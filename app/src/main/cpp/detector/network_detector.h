#ifndef LAUNCH_NETWORK_DETECTOR_H
#define LAUNCH_NETWORK_DETECTOR_H

#include <string>

class NetworkDetector {
public:
    /**
     * 一次性聚合的"深层 native 网络报告"。多行 KEY=VALUE，Java 端 parseKeyValueReport。
     * 三路 ground truth：
     *   · A. getifaddrs() POSIX 接口枚举 + IFF_UP/IFF_POINTOPOINT/IFF_LOOPBACK flag
     *   · B. netlink RTM_GETROUTE dump 路由表，提取 default route 的 OIF + iface name + gateway
     *   · C. syscall_open + syscall_read 直读 /proc/net/dev，绕 libc inline hook
     *
     * 字段：
     *   IFADDRS_OK=0/1                              getifaddrs 是否成功
     *   IFADDRS_VPN_UP=name1,name2,...              up 状态的 VPN 命名接口
     *   IFADDRS_ALL=name1:f=0xhex|name2:f=0xhex     全部接口名 + flag (hex)
     *   NETLINK_OK=0/1                              netlink socket 能否建/发
     *   NETLINK_DEFAULT_OIF=N                       默认路由 OIF (interface index)
     *   NETLINK_DEFAULT_IFACE=name                  OIF → name via if_indextoname
     *   NETLINK_DEFAULT_GW=ip                       gateway IP (dotted decimal)
     *   PROC_NET_DEV_OK=0/1                         /proc/net/dev syscall read OK
     *   PROC_NET_DEV_IFACES=name1,name2,...         /proc/net/dev 枚举的接口名
     */
    static std::string getNetworkNativeReport();
};

#endif // LAUNCH_NETWORK_DETECTOR_H
