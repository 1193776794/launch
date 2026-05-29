#include "debug_detector.h"
#include "root_detector.h"
#include "../syscall/syscall_wrapper.h"
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cerrno>
#include <cstddef>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <android/log.h>

// linux_dirent64 for raw getdents64 — 不依赖 libc 提供的 <dirent.h> 内部结构
namespace {
struct linux_dirent64 {
    uint64_t       d_ino;
    int64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};
}

#define LOG_TAG "DebugDetector"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

int DebugDetector::getTracerPid() {
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) return -1;

    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            std::istringstream iss(line);
            std::string key;
            int pid;
            iss >> key >> pid;
            return pid;
        }
    }
    return 0;
}

bool DebugDetector::checkTracerPidNative() {
    int tracerPid = getTracerPid();
    if (tracerPid > 0) {
        LOGD("TracerPid is non-zero: %d (native)", tracerPid);
        return true;
    }
    return false;
}

bool DebugDetector::checkPtraceNative() {
    // Try to ptrace ourselves - if we're being traced, this will fail
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
        LOGD("PTRACE_TRACEME failed - possibly being traced (native)");
        return true;
    }
    // Detach
    ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
    return false;
}

bool DebugDetector::checkDebuggerNative() {
    // Check /proc/self/wchan for debugging related wait channels
    std::ifstream wchan("/proc/self/wchan");
    if (wchan.is_open()) {
        std::string content;
        std::getline(wchan, content);
        if (content.find("ptrace") != std::string::npos) {
            LOGD("ptrace found in wchan (native)");
            return true;
        }
    }
    return false;
}

bool DebugDetector::checkTracerPidSyscall() {
    std::string content = syscall_read_file("/proc/self/status", 4096);
    size_t pos = content.find("TracerPid:");
    if (pos != std::string::npos) {
        std::string line = content.substr(pos);
        size_t endPos = line.find('\n');
        if (endPos != std::string::npos) {
            line = line.substr(0, endPos);
        }
        // Parse TracerPid value
        std::istringstream iss(line);
        std::string key;
        int pid;
        iss >> key >> pid;
        if (pid > 0) {
            LOGD("TracerPid is non-zero: %d (syscall)", pid);
            return true;
        }
    }
    return false;
}

MultiLayerResult DebugDetector::detectDebugger() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkTracerPidNative() || checkDebuggerNative();
    result.syscallResult = checkTracerPidSyscall();
    return result;
}

MultiLayerResult DebugDetector::detectPtrace() {
    MultiLayerResult result;
    result.javaResult = false;
    result.nativeResult = checkPtraceNative();
    result.syscallResult = false; // Can't check ptrace via syscall reliably
    return result;
}

// ===================== JDWP Detection (native) =====================
//
// JDWP 在 Android 上的实际运行路径（AOSP 9+）：
//   adbd ──unix abstract socket(@jdwp-control)──> ART runtime
//                                                 │
//                                                 └── libadbconnection.so 起一个
//                                                     "ADB-JDWP Connection Control Thread"
//                                                     收到 attach 请求后 load libopenjdkjvmti.so
//
// 因此真正可信的 JDWP 指标是：
//   · libadbconnection.so 在 maps 里（系统启动 JDWP 通道才会加载）
//   · libopenjdkjvmti.so 在 maps 里（JDWP/Profiler attach 才加载）
//   · /proc/net/unix 出现 @jdwp- 抽象 socket
//   · /proc/self/task/*/comm 出现 JDWP 相关线程名 (TASK_COMM_LEN=16，被截断后仍含 JDWP/ADB-JDWP 前缀)
//
// 全部走 syscall_open + syscall_read，避开 libc 被 inline hook 屏蔽的场景。

// 在 /proc/self/maps 里 streaming 查找 needle，避免把整个文件读进内存
static bool maps_contains(const char *needle) {
    int fd = syscall_open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return false;

    const size_t BUF_SIZE = 8192;
    char buf[BUF_SIZE];
    size_t needle_len = strlen(needle);
    // 跨块匹配：保留前一块尾部 needle_len-1 字节，拼到新块前面
    std::string carry;
    carry.reserve(needle_len);
    bool found = false;
    ssize_t n;
    while ((n = syscall_read(fd, buf, BUF_SIZE)) > 0) {
        std::string chunk;
        chunk.reserve(carry.size() + (size_t) n);
        chunk.append(carry);
        chunk.append(buf, (size_t) n);
        if (chunk.find(needle) != std::string::npos) {
            found = true;
            break;
        }
        if (chunk.size() >= needle_len) {
            carry.assign(chunk, chunk.size() - (needle_len - 1), needle_len - 1);
        } else {
            carry = chunk;
        }
    }
    syscall_close(fd);
    return found;
}

bool DebugDetector::checkJdwpAdbConnectionLoaded() {
    // libadbconnection.so 是 Android 9+ ART 的 JDWP 通道库，App 启用 JDWP 才会被 dlopen
    return maps_contains("libadbconnection.so");
}

bool DebugDetector::checkJdwpJvmtiLoaded() {
    // libopenjdkjvmti.so 是 JVMTI 实现，JDWP / Profiler / AGP debug attach 才会加载
    // libjdwp.so 是 OpenJDK 风格 JDWP agent，少数厂商 ROM / SDK debug 模式会拉
    return maps_contains("libopenjdkjvmti.so") || maps_contains("libjdwp.so");
}

int DebugDetector::countJdwpAbstractSockets() {
    // /proc/net/unix 每行末尾是 path。抽象 namespace 在 procfs 里显示为 "@xxx"。
    // adbd 创建的控制 socket 是 "@jdwp-control"；attach 后 ART 端会再开 "@jdwp-<pid>"。
    // 文件通常 <64KB，直接读完即可
    std::string content = syscall_read_file("/proc/net/unix", 131072);
    if (content.empty()) return 0;
    int count = 0;
    size_t pos = 0;
    while ((pos = content.find("@jdwp", pos)) != std::string::npos) {
        count++;
        pos += 5;
    }
    return count;
}

// /proc/net/unix 是**全局视图**：包含 adbd 的 @jdwp-control、所有 debuggable
// 进程的 @jdwp-<pid>。把当前 PID 自己专属的 @jdwp-<pid> 单独算出来才能区分
// 「JDWP 系统可用」与「JDWP 已在我们这个进程上 attach」。
int DebugDetector::countJdwpAbstractSocketsForSelf() {
    std::string content = syscall_read_file("/proc/net/unix", 131072);
    if (content.empty()) return 0;
    char self_tag[32];
    int len = snprintf(self_tag, sizeof(self_tag), "@jdwp-%d", (int) getpid());
    if (len <= 0) return 0;
    int count = 0;
    size_t pos = 0;
    while ((pos = content.find(self_tag, pos)) != std::string::npos) {
        // 必须是完整 token：后接换行/空白/EOF；不能再跟数字（避免 pid=12 误吃 pid=123）
        size_t after = pos + (size_t) len;
        if (after >= content.size()) {
            count++;
            break;
        }
        char c = content[after];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == '\0') {
            count++;
        }
        pos = after;
    }
    return count;
}

// JDWP 线程归类：
//   CONTROL   — pre-attach 常驻控制线程（任何 debuggable app 都有）
//                · "ADB-JDWP Connec" (TASK_COMM_LEN=16 截断后的 "ADB-JDWP Connection Control Thread")
//                · "AdbConnection*"
//   TRANSPORT — post-attach 由 libopenjdkjvmti / JDWP agent 创建的传输/事件线程
//                · "JDWP Transport*"  (e.g. "JDWP Transport Listener: dt_socket")
//                · "JDWP Event*"      (e.g. "JDWP Event Helper Thread")
//                · "JDWP Command*"    (e.g. "JDWP Command Reader")
//                · "JDWP Helper*"
//                · "JVMTI Agent*"     (主动 attach-agent 注入的 agent worker)
//   兜底：含 "JDWP"/"Jdwp" 但未细分 → 归 CONTROL，保守不上 RISK
enum class JdwpThreadKind { NONE, CONTROL, TRANSPORT };

static JdwpThreadKind classifyJdwpThread(const char *c) {
    // 更具体的 transport 模式先匹配
    if (strstr(c, "JDWP Transport") || strstr(c, "JDWP Event")
        || strstr(c, "JDWP Command") || strstr(c, "JDWP Helper")
        || strstr(c, "JVMTI Agent")) {
        return JdwpThreadKind::TRANSPORT;
    }
    if (strstr(c, "ADB-JDWP") || strstr(c, "AdbConnection")) {
        return JdwpThreadKind::CONTROL;
    }
    if (strstr(c, "JDWP") || strstr(c, "Jdwp")) {
        return JdwpThreadKind::CONTROL;
    }
    return JdwpThreadKind::NONE;
}

// 把 control / transport 两类线程命中分别收集到对应字符串里
static void collectJdwpThreadsByKind(std::string &control, std::string &transport) {
    int task_fd = syscall_open("/proc/self/task", O_RDONLY | O_DIRECTORY);
    if (task_fd < 0) return;

    char dirent_buf[4096];
    int seen = 0;
    while (true) {
        long n = syscall_raw(__NR_getdents64, task_fd, (long) dirent_buf, sizeof(dirent_buf));
        if (n <= 0) break;
        long off = 0;
        while (off < n) {
            auto *de = reinterpret_cast<struct linux_dirent64 *>(dirent_buf + off);
            off += de->d_reclen;
            const char *name = de->d_name;
            bool is_num = (name[0] != '\0');
            for (const char *p = name; *p && is_num; ++p) {
                if (*p < '0' || *p > '9') { is_num = false; break; }
            }
            if (!is_num) continue;
            seen++;
            if (seen > 2048) { off = n; break; }

            char comm_path[64];
            snprintf(comm_path, sizeof(comm_path), "/proc/self/task/%s/comm", name);
            int cfd = syscall_open(comm_path, O_RDONLY);
            if (cfd < 0) continue;
            char comm[32];
            ssize_t cn = syscall_read(cfd, comm, sizeof(comm) - 1);
            syscall_close(cfd);
            if (cn <= 0) continue;
            comm[cn] = '\0';
            for (ssize_t i = cn - 1; i >= 0 && (comm[i] == '\n' || comm[i] == '\r'); --i) {
                comm[i] = '\0';
            }
            if (comm[0] == '\0') continue;

            JdwpThreadKind kind = classifyJdwpThread(comm);
            if (kind == JdwpThreadKind::NONE) continue;

            std::string &sink = (kind == JdwpThreadKind::TRANSPORT) ? transport : control;
            if (!sink.empty()) sink += "|";
            sink += name;
            sink += ":";
            sink += comm;
        }
    }
    syscall_close(task_fd);
}

// errno → 简短名映射（与魔改版字符串对齐，便于交叉验证 / 日志对比）
static const char *jdwpErrnoName(int e) {
    switch (e) {
        case 0:            return "OK";
        case EPERM:        return "EPERM";          // 1
        case ENOENT:       return "ENOENT";         // 2
        case EACCES:       return "EACCES";         // 13
        case EINVAL:       return "EINVAL";         // 22
        case EPROTOTYPE:   return "EPROTOTYPE";     // 91
        case ECONNREFUSED: return "ECONNREFUSED";   // 111
        default:           return "ERR";
    }
}

struct AdbSocketProbeResult {
    bool hit;       // 是否命中该 probe 的"信号"语义（每个 probe 自定义）
    int  rc;        // connect() 返回值
    int  err;       // errno
    const char *name;
};

// Probe 1: /dev/socket/adbd 文件系统 AF_UNIX SOCK_DGRAM
//   adbd 在跑时 socket 一定存在；untrusted_app 通常被 SELinux 拒 → EACCES。
//   hit 语义：errno == EACCES → 1（adbd 活着但不让我们连，user build 正常情况）
//   ECONNREFUSED / ENOENT → adbd 没在跑（USB 调试关 / adbd 被关）
static AdbSocketProbeResult probeAdbdSocket() {
    AdbSocketProbeResult p{};
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        p.rc = -1;
        p.err = errno;
        p.name = jdwpErrnoName(p.err);
        return p;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/dev/socket/adbd", sizeof(addr.sun_path) - 1);
    errno = 0;
    p.rc = connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
    p.err = (p.rc == 0) ? 0 : errno;
    p.name = jdwpErrnoName(p.err);
    p.hit = (p.rc < 0 && p.err == EACCES);
    close(fd);
    return p;
}

// Probe 2: @jdwp-control abstract namespace AF_UNIX SOCK_SEQPACKET
//   adbd 监听这个 abstract socket。accept 后做 SO_PEERCRED 鉴权 + /proc/<peer> 检查
//   debuggable 标记。connect 成功 = 系统侧明确允许我们作为 JDWP 控制连接的对端
//   → 强 "JDWP capability ready" 信号（仍非 attach 凭证，attach 看 libopenjdkjvmti.so）
//   失败 errno 含义:
//     ECONNREFUSED → socket 在但 listener 没接 / 队列满
//     ENOENT       → abstract socket 根本没建（JDWP provider=none / 系统未启用）
//     EACCES       → SELinux 拒（非 debuggable app on user build 正常情况）
static AdbSocketProbeResult probeJdwpControlSocket() {
    AdbSocketProbeResult p{};
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        p.rc = -1;
        p.err = errno;
        p.name = jdwpErrnoName(p.err);
        return p;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    // abstract namespace: sun_path[0] = '\0'，后接名字（不带尾 NUL）
    addr.sun_path[0] = '\0';
    const char *name = "jdwp-control";
    size_t nlen = strlen(name);
    memcpy(addr.sun_path + 1, name, nlen);
    socklen_t addrlen = static_cast<socklen_t>(
            offsetof(struct sockaddr_un, sun_path) + 1 + nlen);
    errno = 0;
    p.rc = connect(fd, reinterpret_cast<struct sockaddr *>(&addr), addrlen);
    p.err = (p.rc == 0) ? 0 : errno;
    p.name = jdwpErrnoName(p.err);
    p.hit = (p.rc == 0);
    close(fd);
    return p;
}

std::string DebugDetector::getJdwpDetectionReport() {
    std::ostringstream out;
    out << "ADBCONN=" << (checkJdwpAdbConnectionLoaded() ? 1 : 0) << "\n";
    out << "JVMTI="   << (checkJdwpJvmtiLoaded() ? 1 : 0) << "\n";
    out << "JDWP_SOCK=" << countJdwpAbstractSockets() << "\n";
    out << "JDWP_SOCK_SELF=" << countJdwpAbstractSocketsForSelf() << "\n";
    std::string ctl, xport;
    collectJdwpThreadsByKind(ctl, xport);
    out << "JDWP_THREADS_CTL=" << ctl << "\n";
    out << "JDWP_THREADS_XPORT=" << xport << "\n";

    // 主动 connect 探测（魔改版思路）
    AdbSocketProbeResult adbdProbe = probeAdbdSocket();
    out << "ADBD_SOCK_HIT="   << (adbdProbe.hit ? 1 : 0) << "\n";
    out << "ADBD_SOCK_ERRNO=" << adbdProbe.err << "\n";
    out << "ADBD_SOCK_NAME="  << adbdProbe.name << "\n";

    AdbSocketProbeResult ctlProbe = probeJdwpControlSocket();
    out << "JDWP_CTL_HIT="   << (ctlProbe.hit ? 1 : 0) << "\n";
    out << "JDWP_CTL_ERRNO=" << ctlProbe.err << "\n";
    out << "JDWP_CTL_NAME="  << ctlProbe.name;
    return out.str();
}
