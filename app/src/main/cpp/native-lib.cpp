#include <jni.h>
#include <string>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <unistd.h>
#include <dlfcn.h>
#include <vulkan/vulkan.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <algorithm>
#include <vector>
#include <set>
#include <sstream>
#include <cstdint>
#include <csignal>
#include <csetjmp>
#include <pthread.h>
#include <elf.h>
#include <link.h>
#include <sys/wait.h>
#include <poll.h>
#include <linux/limits.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include "detector/root_detector.h"
#include "detector/hook_detector.h"
#include "detector/emulator_detector.h"
#include "detector/debug_detector.h"
#include "detector/integrity_detector.h"
#include "detector/network_detector.h"
#include "syscall/syscall_wrapper.h"

// linux_dirent64 structure for getdents64 syscall
struct linux_dirent64 {
    uint64_t        d_ino;
    int64_t         d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[];
};

// Syscall number compatibility for different architectures
#if defined(__aarch64__)
    // ARM64 uses newfstatat
    #ifndef __NR_fstatat
        #define __NR_fstatat __NR_newfstatat
    #endif
#elif defined(__arm__)
    // ARM32 uses fstatat64
    #ifndef __NR_fstatat
        #define __NR_fstatat __NR_fstatat64
    #endif
#elif defined(__i386__)
    // x86 32-bit uses fstatat64
    #ifndef __NR_fstatat
        #define __NR_fstatat __NR_fstatat64
    #endif
#elif defined(__x86_64__)
    // x86_64 uses newfstatat
    #ifndef __NR_fstatat
        #define __NR_fstatat __NR_newfstatat
    #endif
#endif

#define LOG_TAG "NativeLib"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Forward declarations for helper functions
static std::string read_file_native(const char* path, size_t maxSize = 4096);
static std::string extract_value(const std::string& content, const std::string& key, char separator = ':');
static std::string extract_boot_param(const std::string& cmdline, const std::string& paramName);

extern "C" {

// ===================== Root Detection =====================

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkSuFilesNative(JNIEnv *env, jobject thiz) {
    return RootDetector::checkSuFilesNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkSuFilesSyscall(JNIEnv *env, jobject thiz) {
    return RootDetector::checkSuFilesSyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkMagiskNative(JNIEnv *env, jobject thiz) {
    return RootDetector::checkMagiskNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkMagiskSyscall(JNIEnv *env, jobject thiz) {
    return RootDetector::checkMagiskSyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkKernelSUNative(JNIEnv *env, jobject thiz) {
    return RootDetector::checkKernelSUNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkKernelSUSyscall(JNIEnv *env, jobject thiz) {
    return RootDetector::checkKernelSUSyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkAPatchNative(JNIEnv *env, jobject thiz) {
    return RootDetector::checkAPatchNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkAPatchSyscall(JNIEnv *env, jobject thiz) {
    return RootDetector::checkAPatchSyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkSukiSUNative(JNIEnv *env, jobject thiz) {
    return RootDetector::checkSukiSUNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkSukiSUSyscall(JNIEnv *env, jobject thiz) {
    return RootDetector::checkSukiSUSyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkRootHidingNative(JNIEnv *env, jobject thiz) {
    return RootDetector::checkRootHidingNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkRootHidingSyscall(JNIEnv *env, jobject thiz) {
    return RootDetector::checkRootHidingSyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkSuspiciousMountsNative(JNIEnv *env, jobject thiz) {
    return RootDetector::checkSuspiciousMountsNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkSuspiciousMountsSyscall(JNIEnv *env, jobject thiz) {
    return RootDetector::checkSuspiciousMountsSyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkMountInfoNative(JNIEnv *env, jobject thiz) {
    return RootDetector::checkMountInfoNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkMountInfoSyscall(JNIEnv *env, jobject thiz) {
    return RootDetector::checkMountInfoSyscall();
}

// ===================== Hook Detection =====================

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkXposedNative(JNIEnv *env, jobject thiz) {
    return HookDetector::checkXposedNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkXposedSyscall(JNIEnv *env, jobject thiz) {
    return HookDetector::checkXposedSyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkFridaNative(JNIEnv *env, jobject thiz) {
    return HookDetector::checkFridaNative() || HookDetector::checkFridaPortsNative() ||
           HookDetector::checkFridaMemoryNative() || HookDetector::checkFridaThreads();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkFridaSyscall(JNIEnv *env, jobject thiz) {
    return HookDetector::checkFridaSyscall() || HookDetector::checkFridaMemorySyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkLSPosedNative(JNIEnv *env, jobject thiz) {
    return HookDetector::checkLSPosedNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkLSPosedSyscall(JNIEnv *env, jobject thiz) {
    return HookDetector::checkLSPosedSyscall();
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getLSPosedDetails(JNIEnv *env, jobject thiz) {
    std::string details = HookDetector::getLSPosedDetails();
    return env->NewStringUTF(details.c_str());
}

// [XFF] 自读内存字节扫 Xposed 类名串(DetectEvilFrameworks 技术)
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkXposedMemoryStringsNative(JNIEnv *env, jobject thiz) {
    return HookDetector::checkXposedMemoryStrings();
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getXposedMemStringsDetails(JNIEnv *env, jobject thiz) {
    std::string details = HookDetector::getXposedMemStringsDetails();
    return env->NewStringUTF(details.c_str());
}

// [XFF-T2/T3] 模块注入痕迹:外来 dex/apk 映射 + 外来 fd 报告
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getModuleInjectionReport(JNIEnv *env, jobject thiz,
                                                                     jstring hostPkg, jstring hostApkDir) {
    const char *pkg = hostPkg ? env->GetStringUTFChars(hostPkg, nullptr) : nullptr;
    const char *dir = hostApkDir ? env->GetStringUTFChars(hostApkDir, nullptr) : nullptr;
    std::string r = HookDetector::getModuleInjectionReport(pkg ? pkg : "", dir ? dir : "");
    if (pkg) env->ReleaseStringUTFChars(hostPkg, pkg);
    if (dir) env->ReleaseStringUTFChars(hostApkDir, dir);
    return env->NewStringUTF(r.c_str());
}

// [XFF-T5] Hook 引擎 .so dlopen(RTLD_NOLOAD) 探测报告
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getArtHookLibReport(JNIEnv *env, jobject thiz) {
    std::string r = HookDetector::getArtHookLibReport();
    return env->NewStringUTF(r.c_str());
}

// ================= [XFF-T6] LSPlant hook 点 · ArtMethod 检测 =================
// jmethodID 在 ART 上就是 ArtMethod*。ArtMethod 头部布局跨 API 24-35 稳定:
//   +0  GcRoot<Class> declaring_class_ (4B, 压缩引用)
//   +4  uint32_t      access_flags_
// 尾部 entry_point_from_quick_compiled_code_ 偏移随版本变 → 不写死,扫头 0x30 字节里每个
// 指针槽,看谁落在"匿名可执行区"。正常方法入口只会落在 .oat(文件映射)/libart 解释器桥
// (文件映射)/JIT code-cache(/memfd:jit-cache 或 ashmem,有名字→非匿名)。只有 LSPlant/
// Frida 的 trampoline 在真正匿名可执行内存里 → 命中即被 hook。全程只读 ArtMethod 自身
// (合法可读、且先用 maps 区间校验 [am, am+0x38) 可读才读),只拿槽位值和 maps 区间比较、
// 绝不解引用槽位值 → 不可能崩。
struct XffHookRegion { uintptr_t start, end; bool exec, read, anon; };

static std::vector<XffHookRegion> xffParseSelfMaps() {
    std::vector<XffHookRegion> regs;
    std::string maps = syscall_read_file_full("/proc/self/maps");
    std::stringstream ss(maps);
    std::string line;
    while (std::getline(ss, line)) {
        unsigned long s = 0, e = 0;
        char perms[8] = {0};
        char path[512] = {0};
        int n = sscanf(line.c_str(), "%lx-%lx %7s %*x %*x:%*x %*u %511[^\n]",
                       &s, &e, perms, path);
        if (n < 3 || e <= s) continue;
        XffHookRegion r;
        r.start = (uintptr_t)s;
        r.end = (uintptr_t)e;
        r.read = perms[0] == 'r';
        r.exec = perms[2] == 'x';
        std::string p = (n >= 4) ? std::string(path) : std::string();
        r.anon = p.empty() || p[0] == '[';
        regs.push_back(r);
    }
    return regs;
}

// Android 11+ 用指针 tag(ARM64 TBI / heap tagging):native 堆指针顶字节带 tag,硬件解引用时忽略,
// 但软件层与 /proc/self/maps(未 tag)比较前必须抹掉顶字节。x86_64 无 tag,顶字节本就是 0 → 无害。
static inline uintptr_t xffUntag(uintptr_t p) { return p & 0x00FFFFFFFFFFFFFFULL; }

static bool xffAddrReadable(const std::vector<XffHookRegion> &regs, uintptr_t p, size_t len) {
    p = xffUntag(p);
    for (const auto &r : regs) {
        if (p >= r.start && p + len <= r.end) return r.read;
    }
    return false;
}

static bool xffAddrAnonExec(const std::vector<XffHookRegion> &regs, uintptr_t p) {
    p = xffUntag(p);
    if (p < 0x1000) return false;
    for (const auto &r : regs) {
        if (p >= r.start && p < r.end) return r.exec && r.anon;
    }
    return false;
}

// 检查单个 ArtMethod(=jmethodID)是否被 LSPlant/Frida hook:entry_point_from_quick_compiled_code_
// 被换成匿名可执行内存里的 trampoline。不写死 entrypoint 偏移(随版本变),扫 ArtMethod 头 0x38 字节
// 里每个指针槽,看谁落在"匿名可执行区"。正常方法入口只在 .oat/libart/JIT-cache(memfd 具名);
// 落在匿名可执行内存 = 被 inline 换头。全程先 maps 校验可读才读、只比较不解引用槽值 → 不崩。
static bool xffMethodHooked(const std::vector<XffHookRegion> &regs, jmethodID mid, uintptr_t *hitOut) {
    if (mid == nullptr) return false;
    uintptr_t am = reinterpret_cast<uintptr_t>(mid);
    if (!xffAddrReadable(regs, am, 0x38)) return false;
    for (size_t off = 8; off <= 0x30; off += sizeof(void *)) {
        uintptr_t slot = *reinterpret_cast<const uintptr_t *>(am + off);
        if (xffAddrAnonExec(regs, slot)) {
            if (hitOut) *hitOut = slot;
            return true;
        }
    }
    return false;
}

// [XFF-T6] LSPlant 方法级 hook 检测:反射枚举一批"常被 anti-detection / 设备伪装模块 hook"的框架类
// + 本 app 自身检测类的**全部方法**,逐个查 ArtMethod entrypoint 是否落在匿名可执行 trampoline。
// 现代 LSPosed 框架 loader 不进 class_loaders_(枚举抓不到),但它把 hook 打在**已注册的框架/app
// 方法**上 → 这些方法的 ArtMethod 就在类表里,entrypoint 被换 → 这是"hooks installed"绕不过的痕迹。
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getHookedMethodReport(JNIEnv *env, jobject thiz) {
    std::vector<XffHookRegion> regs = xffParseSelfMaps();
    std::string report;

    // 常被设备伪装 / 反检测模块 hook 的类 + 本 app 自身检测类(模块可能 hook 它来伪造检测结果)
    static const char *kClasses[] = {
        "android/os/SystemProperties", "android/os/Build", "android/os/Build$VERSION",
        "android/provider/Settings$Secure", "android/provider/Settings$System",
        "android/provider/Settings$Global",
        "android/telephony/TelephonyManager", "android/telephony/SubscriptionManager",
        "android/app/ApplicationPackageManager", "android/content/pm/PackageManager",
        "android/app/ActivityManager", "android/content/ContentResolver",
        "java/io/File", "java/lang/Runtime", "java/lang/System", "java/lang/Class",
        "dalvik/system/BaseDexClassLoader", "dalvik/system/PathClassLoader",
        "java/net/NetworkInterface", "android/net/wifi/WifiManager",
        "android/net/wifi/WifiInfo", "android/os/Debug",
        "android/hardware/SensorManager", "android/bluetooth/BluetoothAdapter",
        "android/webkit/WebSettings", "android/webkit/WebView",
        "android/media/MediaDrm", "android/app/ActivityThread",
        // 本 app 自身检测类(若模块 hook 它伪造结果,这里能抓到)
        "com/xff/launch/detector/NativeDetector", "com/xff/launch/detector/HookDetector",
        "com/xff/launch/detector/RootDetector", "com/xff/launch/detector/EmulatorDetector",
    };

    jclass clsClass = env->FindClass("java/lang/Class");
    jmethodID midGetMethods = clsClass ? env->GetMethodID(
            clsClass, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;") : nullptr;
    jclass methodClass = env->FindClass("java/lang/reflect/Method");
    jmethodID midGetName = methodClass ? env->GetMethodID(
            methodClass, "getName", "()Ljava/lang/String;") : nullptr;
    if (!midGetMethods) { env->ExceptionClear(); return env->NewStringUTF("UNSUPPORTED:no-reflect\n"); }

    int methodsScanned = 0, hits = 0;
    for (const char *cn : kClasses) {
        jclass c = env->FindClass(cn);
        if (c == nullptr) { env->ExceptionClear(); continue; }
        jobject arr = env->CallObjectMethod(c, midGetMethods);
        if (env->ExceptionCheck()) { env->ExceptionClear(); env->DeleteLocalRef(c); continue; }
        if (arr != nullptr) {
            jsize nm = env->GetArrayLength(reinterpret_cast<jobjectArray>(arr));
            for (jsize i = 0; i < nm; i++) {
                jobject m = env->GetObjectArrayElement(reinterpret_cast<jobjectArray>(arr), i);
                if (m == nullptr) { env->ExceptionClear(); continue; }
                jmethodID mid = env->FromReflectedMethod(m);
                methodsScanned++;
                uintptr_t hit = 0;
                if (xffMethodHooked(regs, mid, &hit)) {
                    hits++;
                    if (hits <= 30) {
                        std::string mname = "?";
                        if (midGetName) {
                            jstring ns = reinterpret_cast<jstring>(env->CallObjectMethod(m, midGetName));
                            if (ns) {
                                const char *nc = env->GetStringUTFChars(ns, nullptr);
                                if (nc) { mname = nc; env->ReleaseStringUTFChars(ns, nc); }
                                env->DeleteLocalRef(ns);
                            } else env->ExceptionClear();
                        }
                        char b[40];
                        snprintf(b, sizeof(b), " [entry=0x%lx]", (unsigned long) hit);
                        report += "HOOKED=" + std::string(cn) + "." + mname + b + "\n";
                        __android_log_print(ANDROID_LOG_WARN, "HookDetector",
                                            "[T6] hooked method: %s.%s", cn, mname.c_str());
                    }
                }
                env->DeleteLocalRef(m);
            }
            env->DeleteLocalRef(arr);
        }
        env->DeleteLocalRef(c);
    }
    if (clsClass) env->DeleteLocalRef(clsClass);
    if (methodClass) env->DeleteLocalRef(methodClass);

    // 附加:匿名可执行区扫描 —— LSPlant 用自带分配器 mmap 出可执行页放 trampoline(带守护页),
    // 这些区**完全无名**(空路径)。现代 ART 的合法可执行码要么 file-backed(.oat/.so)、要么
    // memfd(JIT)、要么具名 [anon:...];完全空路径的 exec 区 = 注入的 trampoline / InMemoryDex
    // 框架编译码。这抓的是 hook 引擎的代码本体,不依赖"猜中被 hook 的方法"。
    int anonExec = 0;
    {
        std::string maps = syscall_read_file_full("/proc/self/maps");
        std::stringstream ms(maps);
        std::string ln;
        while (std::getline(ms, ln)) {
            unsigned long s = 0, e = 0;
            char perms[8] = {0};
            char pth[512] = {0};
            int n = sscanf(ln.c_str(), "%lx-%lx %7s %*x %*x:%*x %*u %511[^\n]", &s, &e, perms, pth);
            if (n < 3 || perms[2] != 'x' || e <= s) continue;      // 必须可执行
            std::string p = (n >= 4) ? std::string(pth) : std::string();
            if (!p.empty()) continue;                              // 只认完全无名的 exec 区
            anonExec++;
            if (anonExec <= 20) {
                char b[64];
                snprintf(b, sizeof(b), "ANON_EXEC=0x%lx-0x%lx %s\n", s, e, perms);
                report += b;
                __android_log_print(ANDROID_LOG_WARN, "HookDetector",
                                    "[T6] anon exec region (injected code): 0x%lx-0x%lx %s", s, e, perms);
            }
        }
    }

    __android_log_print(ANDROID_LOG_DEBUG, "HookDetector",
                        "[T6] methodsScanned=%d hookHits=%d anonExecRegions=%d",
                        methodsScanned, hits, anonExec);
    if (report.empty()) report = "CLEAN\n";
    return env->NewStringUTF(report.c_str());
}

// ============ [XFF-T5b] 真·ClassLinker::VisitClassLoaders 旁支 ClassLoader 枚举 ============
// 通过 libart 导出符号 VisitClassLoaders 遍历进程内*所有* ClassLoader —— 包括 Java 反射父链
// 看不到的旁支:LSPosed 框架 InMemoryDex loader、LspModuleClassLoader。
// ClassLinker* 获取链:JNIEnv→GetJavaVM 得 JavaVMExt → runtime_(+0x8,跨版本稳定)→
//   Runtime.class_linker_(偏移随版本变)。不硬编码偏移表,改用"每线程 SIGSEGV 守护 +
//   ClassLoader 描述符判别"的自校准扫描:扫 Runtime 前 0x400 字节,哪个偏移让 VisitClassLoaders
//   枚举出的对象描述符全部含 "ClassLoader" 且不崩,就是 class_linker_。
// 安全性:ART 自身用 SIGSEGV 做隐式空指针检查 → 处理器只在本探测线程+守护窗口内 longjmp,
//   其它线程的 fault 一律链回 ART 原处理器,不破坏 ART。错误偏移只在本线程触发 fault→被捕获→
//   换下一个,绝不外泄崩溃。残留风险:遍历期间 GC 移动对象的窄竞态(一次性扫描,概率极低)。
typedef void (*XffVisitClassLoaders_t)(void *class_linker, void *visitor);
typedef void (*XffVisitClasses_t)(void *class_linker, void *visitor);
typedef const char *(*XffGetDescriptor_t)(void *klass, std::string *storage);

static XffVisitClassLoaders_t g_xffVisitCL = nullptr;
static XffVisitClasses_t      g_xffVisitClasses = nullptr;
static XffGetDescriptor_t     g_xffGetDesc = nullptr;
static std::vector<XffHookRegion> g_xffVclRegs;

static int         g_xffVclMode;    // 0=trial(校准), 1=collect
static int         g_xffVclCount, g_xffVclGood, g_xffVclBad, g_xffVclInMem;
static std::string g_xffVclReport;

// VisitClasses 用:枚举*已加载的类*找框架类描述符(比枚举 loader 可靠 —— 现代 LSPosed 的框架
// loader 不进 class_loaders_,但它定义的框架类必在类表里)。early-exit + 上限防超长遍历。
static int         g_xffClsCount;
static int         g_xffClsHits;
static std::string g_xffClsReport;

static sigjmp_buf            g_xffVclJb;
static volatile sig_atomic_t g_xffVclGuard = 0;

static pthread_t g_xffVclTid;

// 守护处理器【仅在 fork 出的子进程里安装】。守护窗口内本线程的任何致命信号(SEGV/BUS,以及
// 错误偏移把 libart 带进 CHECK/abort 的 SIGABRT/ILL 等)都 siglongjmp 回扫描循环换下一个;窗口外
// 的致命信号直接 _exit —— 子进程一次性、可弃,父进程读到空 pipe 记 child-crashed。主进程从不安装
// 此处理器,故不会打断 ART 的隐式 SIGSEGV 空指针检查、不会死锁主 app。
static void xffVclSegv(int sig, siginfo_t *si, void *uc) {
    (void) sig; (void) si; (void) uc;
    if (g_xffVclGuard && pthread_equal(pthread_self(), g_xffVclTid)) {
        siglongjmp(g_xffVclJb, 1);
    }
    _exit(42);
}

static bool xffVclReadable(void *p, size_t len) {
    return p && xffAddrReadable(g_xffVclRegs, (uintptr_t) p, len);
}

// 取 mirror::Object 的 klass_(offset 0, 32-bit 压缩引用;Android heap 低 4G → 零扩展即指针)
static void *xffVclKlass(void *obj) {
    if (!xffVclReadable(obj, 4)) return nullptr;
    uint32_t ref = *reinterpret_cast<uint32_t *>(obj);
    return reinterpret_cast<void *>((uintptr_t) ref);
}

static void xffVclNoop() {}

// vtable[2] = 本函数,匹配 ClassLoaderVisitor::Visit(ObjPtr<ClassLoader>) 的 ABI:x0=this, x1=loader
static void xffVclOnLoader(void *self, void *loader) {
    (void) self;
    if (g_xffVclCount > 4000) siglongjmp(g_xffVclJb, 2);   // 防错误偏移下的超长循环
    if (loader == nullptr) return;                          // 被 GC 的弱根,中性跳过
    g_xffVclCount++;
    void *klass = xffVclKlass(loader);
    if (!klass || !xffVclReadable(klass, 8)) { g_xffVclBad++; return; }
    std::string storage;
    const char *d = g_xffGetDesc(klass, &storage);         // 垃圾 klass→读到非法内存→本线程 fault→守护捕获
    std::string desc = d ? std::string(d) : storage;
    if (desc.find("ClassLoader") != std::string::npos) {
        g_xffVclGood++;
        if (g_xffVclMode == 1) {
            if (desc.find("InMemoryDexClassLoader") != std::string::npos) g_xffVclInMem++;
            std::string low = desc;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("lsposed") != std::string::npos ||
                low.find("xposed") != std::string::npos ||
                desc.find("LspModuleClassLoader") != std::string::npos) {
                g_xffVclReport += "VCL_FRAMEWORK=" + desc + "\n";
            }
        }
    } else {
        g_xffVclBad++;
    }
}

static void *g_xffVclVtbl[3] = {
        (void *) xffVclNoop,       // ~ClassLoaderVisitor complete (D1) —— 不会在 Visit 中被调
        (void *) xffVclNoop,       // ~ClassLoaderVisitor deleting (D0)
        (void *) xffVclOnLoader,   // Visit
};
struct XffVclVisitor { void *vptr; };

// ClassVisitor::operator()(ObjPtr<Class>) → bool(true=继续遍历)。x0=this, x1=klass, 返回值在 x0。
// 匹配框架类描述符即命中;命中够多或超上限就返回 false 提前结束(类表可能上十万,防超时)。
static bool xffClsOnClass(void *self, void *klass) {
    (void) self;
    if (++g_xffClsCount > 400000) return false;   // 上限保护
    if (!xffVclReadable(klass, 8)) return true;
    std::string storage;
    const char *d = g_xffGetDesc(klass, &storage);
    std::string desc = d ? std::string(d) : storage;
    // 框架/模块类描述符(Lde/robv/... 经典 Xposed API,Lorg/lsposed/... LSPosed 框架)
    if (desc.rfind("Lde/robv/android/xposed", 0) == 0 ||
        desc.rfind("Lorg/lsposed/", 0) == 0 ||
        desc.rfind("Lio/github/libxposed", 0) == 0 ||
        desc.find("LspModuleClassLoader") != std::string::npos) {
        g_xffClsHits++;
        if (g_xffClsHits <= 12) g_xffClsReport += "VCL_CLASS=" + desc + "\n";
        if (g_xffClsHits >= 12) return false;   // 够证明了,停
    }
    return true;
}

static void *g_xffClsVtbl[3] = {
        (void *) xffVclNoop,        // ~ClassVisitor complete
        (void *) xffVclNoop,        // ~ClassVisitor deleting
        (void *) xffClsOnClass,     // operator()
};
struct XffClsVisitor { void *vptr; };

// 从 /proc/self/maps 定位模块加载基址 + 磁盘路径(取最低映射地址 = ELF 头所在页)。
// Android 10+ libart 在 ART APEX 独立 linker namespace,dlopen(RTLD_NOLOAD) 看不到,
// 故绕过 linker 直接从 maps 拿基址、从磁盘 ELF 解析符号。
static bool xffFindModule(const char *soname, uintptr_t *base, std::string *path) {
    std::string maps = syscall_read_file_full("/proc/self/maps");
    std::stringstream ss(maps);
    std::string line;
    uintptr_t lo = 0;
    std::string p;
    while (std::getline(ss, line)) {
        if (line.find(soname) == std::string::npos) continue;
        size_t slash = line.find('/');
        if (slash == std::string::npos) continue;
        std::string fp = line.substr(slash);
        size_t del = fp.find(" (deleted)");
        if (del != std::string::npos) fp = fp.substr(0, del);
        while (!fp.empty() && (fp.back() == '\n' || fp.back() == ' ' || fp.back() == '\r'))
            fp.pop_back();
        // basename 精确匹配,排除 libartbase.so / libart-compiler.so 等
        size_t bslash = fp.rfind('/');
        std::string bn = (bslash == std::string::npos) ? fp : fp.substr(bslash + 1);
        if (bn != soname) continue;
        unsigned long s = 0, e = 0;
        if (sscanf(line.c_str(), "%lx-%lx", &s, &e) < 2) continue;
        if (lo == 0 || (uintptr_t) s < lo) lo = (uintptr_t) s;
        p = fp;
    }
    if (lo == 0) return false;
    *base = lo;
    *path = p;
    return true;
}

// 从磁盘 ELF 经 program header → PT_DYNAMIC → DT_SYMTAB/DT_STRTAB 解析动态符号
//(与 nm -D 同路径,不依赖 section headers —— apex libart 已裁掉 section headers)。
// 返回符号运行时地址 = base + st_value(PIE 首 PT_LOAD p_vaddr=0)。
static uintptr_t xffResolveInModule(uintptr_t base, const std::string &path, const char *sym) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) < 0 || (size_t) st.st_size < sizeof(ElfW(Ehdr))) { close(fd); return 0; }
    size_t sz = (size_t) st.st_size;
    void *map = mmap(nullptr, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return 0;

    uintptr_t result = 0;
    const uint8_t *p = (const uint8_t *) map;
    const ElfW(Ehdr) *eh = (const ElfW(Ehdr) *) p;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 && eh->e_phoff != 0 && eh->e_phnum > 0 &&
        eh->e_phoff + (size_t) eh->e_phnum * sizeof(ElfW(Phdr)) <= sz) {
        const ElfW(Phdr) *ph = (const ElfW(Phdr) *) (p + eh->e_phoff);
        const ElfW(Phdr) *dyn = nullptr;
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type == PT_DYNAMIC) { dyn = &ph[i]; break; }
        }
        // vaddr → 文件偏移(用 PT_LOAD 段换算)
        auto v2off = [&](uintptr_t vaddr) -> size_t {
            for (int i = 0; i < eh->e_phnum; i++) {
                if (ph[i].p_type == PT_LOAD && vaddr >= ph[i].p_vaddr &&
                    vaddr < ph[i].p_vaddr + ph[i].p_filesz) {
                    return (size_t) (ph[i].p_offset + (vaddr - ph[i].p_vaddr));
                }
            }
            return (size_t) -1;
        };
        if (dyn && dyn->p_offset + dyn->p_filesz <= sz) {
            const ElfW(Dyn) *d = (const ElfW(Dyn) *) (p + dyn->p_offset);
            uintptr_t symtabV = 0, strtabV = 0;
            size_t maxDyn = dyn->p_filesz / sizeof(ElfW(Dyn));
            for (size_t i = 0; i < maxDyn && d[i].d_tag != DT_NULL; i++) {
                if (d[i].d_tag == DT_SYMTAB) symtabV = (uintptr_t) d[i].d_un.d_ptr;
                else if (d[i].d_tag == DT_STRTAB) strtabV = (uintptr_t) d[i].d_un.d_ptr;
            }
            if (symtabV && strtabV && strtabV > symtabV) {
                size_t symOff = v2off(symtabV), strOff = v2off(strtabV);
                if (symOff != (size_t) -1 && strOff != (size_t) -1 && strOff < sz) {
                    // .dynsym 紧邻 .dynstr → 符号数 = (strtab - symtab)/sizeof(Sym)
                    size_t nsym = (strtabV - symtabV) / sizeof(ElfW(Sym));
                    const ElfW(Sym) *symtab = (const ElfW(Sym) *) (p + symOff);
                    const char *strtab = (const char *) (p + strOff);
                    for (size_t i = 0; i < nsym; i++) {
                        if (symtab[i].st_value == 0) continue;
                        if (strOff + symtab[i].st_name >= sz) continue;
                        if (strcmp(strtab + symtab[i].st_name, sym) == 0) {
                            result = base + (uintptr_t) symtab[i].st_value;
                            break;
                        }
                    }
                }
            }
        }
    }
    munmap(map, sz);
    return result;
}

// 【子进程·全部在这里做】危险的 ClassLinker 枚举**只能**在 fork 出的一次性子进程里做:
//   ① 校准 class_linker_ 偏移时,错误偏移会把 libart 带进 CHECK/abort(SIGABRT);
//   ② 即便偏移正确,在活 runtime 上遍历类表/GetDescriptor 也会触发 ART 正常的隐式 SIGSEGV
//      (read barrier 等),若在主进程 longjmp 打断它 → ART 内部锁不释放 → 整个 app 死锁转圈。
// 所以主进程绝不碰活 runtime、绝不装信号守护。子进程读 COW 内存,崩/卡都只影响子进程,
// 父进程 4s 超时杀掉。缺点:fork 后弱引用(class_loaders_ 存 GcRoot 弱根)部分解码不出 → 枚举
// 偏少;但现代 LSPosed 的框架 loader 本就不注册进 class_loaders_,活进程也照样枚举不到,
// 故这点损失对 LSPosed 检测无实质影响,换来的是**绝不卡死主 app**。
static std::string xffVclChildRun(void *runtime) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = xffVclSegv;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    const int sigs[] = {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGTRAP, SIGSYS};
    for (int s : sigs) sigaction(s, &sa, nullptr);

    g_xffVclTid = pthread_self();
    g_xffVclGuard = 1;

    // ① 自校准 class_linker_ 偏移
    void *classLinker = nullptr;
    for (size_t off = 0; off <= 0x2000 && classLinker == nullptr; off += sizeof(void *)) {
        void *cand = *reinterpret_cast<void **>((char *) runtime + off);
        if (!xffVclReadable(cand, 8)) continue;
        g_xffVclMode = 0;
        g_xffVclCount = g_xffVclGood = g_xffVclBad = 0;
        XffVclVisitor v;
        v.vptr = g_xffVclVtbl;
        if (sigsetjmp(g_xffVclJb, 1) == 0) {
            g_xffVisitCL(cand, &v);
            if (g_xffVclGood >= 5 && g_xffVclGood >= g_xffVclBad * 5 && g_xffVclCount <= 3000) {
                classLinker = cand;
            }
        }
    }
    if (classLinker == nullptr) {
        g_xffVclGuard = 0;
        return "UNSUPPORTED:offset-not-found\n";
    }

    // ② 枚举 ClassLoader
    g_xffVclMode = 1;
    g_xffVclCount = g_xffVclGood = g_xffVclBad = g_xffVclInMem = 0;
    g_xffVclReport.clear();
    XffVclVisitor v;
    v.vptr = g_xffVclVtbl;
    if (sigsetjmp(g_xffVclJb, 1) == 0) {
        g_xffVisitCL(classLinker, &v);
    }

    // ③ 枚举已加载类找框架类描述符(Lorg/lsposed/、Lde/robv/ 等)
    g_xffClsCount = g_xffClsHits = 0;
    g_xffClsReport.clear();
    if (g_xffVisitClasses) {
        XffClsVisitor cv;
        cv.vptr = g_xffClsVtbl;
        if (sigsetjmp(g_xffVclJb, 1) == 0) {
            g_xffVisitClasses(classLinker, &cv);
        }
    }
    g_xffVclGuard = 0;

    std::string result = "VCL_TOTAL=" + std::to_string(g_xffVclGood) + "\n";
    result += "VCL_INMEMORY=" + std::to_string(g_xffVclInMem) + "\n";
    result += "VCL_CLASSHITS=" + std::to_string(g_xffClsHits) + "\n";
    result += g_xffVclReport;
    result += g_xffClsReport;
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getVisitClassLoadersReport(JNIEnv *env, jobject thiz) {
    // Android 10+ libart 在 ART APEX 独立 namespace,dlopen 看不到 → 从 maps+磁盘 ELF 解析符号
    uintptr_t artBase = 0;
    std::string artPath;
    if (!xffFindModule("libart.so", &artBase, &artPath))
        return env->NewStringUTF("UNSUPPORTED:no-libart\n");

    // VisitClassLoaders:const / 非 const 两种签名
    static const char *kVisitCands[] = {
            "_ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE",
            "_ZN3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE",
    };
    // GetDescriptor(std::string*):std::__1 替换索引 NS2_/NS3_ 因工具链而异,多候选兜底
    static const char *kDescCands[] = {
            "_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE",
            "_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE",
            "_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE",
    };
    for (const char *s : kVisitCands) {
        g_xffVisitCL = (XffVisitClassLoaders_t) xffResolveInModule(artBase, artPath, s);
        if (g_xffVisitCL) break;
    }
    // VisitClasses(可选):枚举已加载类找框架类描述符
    g_xffVisitClasses = (XffVisitClasses_t) xffResolveInModule(
            artBase, artPath, "_ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE");
    for (const char *s : kDescCands) {
        g_xffGetDesc = (XffGetDescriptor_t) xffResolveInModule(artBase, artPath, s);
        if (g_xffGetDesc) break;
    }
    if (!g_xffVisitCL || !g_xffGetDesc)
        return env->NewStringUTF("UNSUPPORTED:no-symbol\n");

    JavaVM *vm = nullptr;
    if (env->GetJavaVM(&vm) != 0 || !vm)
        return env->NewStringUTF("UNSUPPORTED:no-vm\n");

    g_xffVclRegs = xffParseSelfMaps();
    // JavaVMExt.runtime_ 通常在 +sizeof(void*)(JavaVM 仅一个 functions 指针,JavaVMExt 首成员即
    // runtime_);个别版本布局有变,故 +0x8 / +0x10 都试,取首个 maps-可读者。
    void *runtime = nullptr;
    for (size_t roff = sizeof(void *); roff <= 2 * sizeof(void *); roff += sizeof(void *)) {
        void *cand = *reinterpret_cast<void **>((char *) vm + roff);
        if (runtime == nullptr && xffVclReadable(cand, 8)) runtime = cand;
    }
    if (!runtime)
        return env->NewStringUTF("UNSUPPORTED:bad-runtime\n");
    runtime = (void *) xffUntag((uintptr_t) runtime);   // 抹 tag,后续算术/解引用用规范地址

    // fork 子进程做危险的暴力校准+枚举:错误偏移把 libart 带崩(SEGV/abort)只死子进程,
    // 主 app 走 COW 不受影响。子进程读的是 fork 那一刻复制的内存(class_loaders_ 链完整可遍历)。
    int pipefd[2];
    if (pipe(pipefd) != 0)
        return env->NewStringUTF("UNSUPPORTED:no-pipe\n");

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return env->NewStringUTF("UNSUPPORTED:no-fork\n");
    }

    if (pid == 0) {
        // ---- 子进程:校准 + 全部枚举,回传完整报告 ----
        close(pipefd[0]);
        std::string rep = xffVclChildRun(runtime);
        size_t w = 0;
        while (w < rep.size()) {
            ssize_t k = write(pipefd[1], rep.data() + w, rep.size() - w);
            if (k <= 0) break;
            w += (size_t) k;
        }
        close(pipefd[1]);
        _exit(0);
    }

    // ---- 父进程:只读报告,绝不碰活 runtime、绝不装信号守护 → 永不卡死主 app ----
    close(pipefd[1]);
    std::string out;
    struct pollfd pfd;
    pfd.fd = pipefd[0];
    pfd.events = POLLIN;
    bool timedout = false;
    if (poll(&pfd, 1, 4000) > 0) {   // 子进程若死锁/慢,最多等 4s 后杀掉,父 app 不阻塞
        char buf[4096];
        ssize_t n;
        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
            out.append(buf, (size_t) n);
            if (out.size() > 65536) break;
        }
    } else {
        timedout = true;
    }
    close(pipefd[0]);
    if (timedout) kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);

    if (out.empty()) out = "UNSUPPORTED:child-crashed\n";
    __android_log_print(ANDROID_LOG_DEBUG, "HookDetector", "[T5b] result: %s", out.c_str());
    return env->NewStringUTF(out.c_str());
}

// Additional LSPosed detection JNI methods
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkLSPosedMemoryNative(JNIEnv *env, jobject thiz) {
    return HookDetector::checkLSPosedMemoryNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkLSPosedMemorySyscall(JNIEnv *env, jobject thiz) {
    return HookDetector::checkLSPosedMemorySyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkRiruZygiskNative(JNIEnv *env, jobject thiz) {
    return HookDetector::checkRiruZygiskNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkRiruZygiskSyscall(JNIEnv *env, jobject thiz) {
    return HookDetector::checkRiruZygiskSyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkLSPosedSystemWide(JNIEnv *env, jobject thiz) {
    return HookDetector::checkLSPosedSystemWide();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkAnonymousExecutableMemory(JNIEnv *env, jobject thiz) {
    return HookDetector::checkAnonymousExecutableMemory();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkMemoryHooksNative(JNIEnv *env, jobject thiz) {
    return HookDetector::checkMapsForHooks();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkMemoryHooksSyscall(JNIEnv *env, jobject thiz) {
    return HookDetector::checkMapsForHooksSyscall();
}

// SMAPS Integrity Check - 高级内存取证技术
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkSmapsIntegrity(JNIEnv *env, jobject thiz) {
    return HookDetector::checkSmapsIntegrity();
}

// Zygisk detection (通用检测: Magisk Zygisk, ReZygisk, Zygisk Next)
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkZygiskNative(JNIEnv *env, jobject thiz) {
    return HookDetector::checkZygiskNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkZygiskSyscall(JNIEnv *env, jobject thiz) {
    return HookDetector::checkZygiskSyscall();
}

// ===================== Emulator Detection =====================

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkEmulatorNative(JNIEnv *env, jobject thiz) {
    return EmulatorDetector::checkEmulatorFilesNative() || EmulatorDetector::checkQemuNative() ||
           EmulatorDetector::checkGenyMotionNative() || EmulatorDetector::checkNoxNative() ||
           EmulatorDetector::checkLdPlayerNative() || EmulatorDetector::checkMemuNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkEmulatorSyscall(JNIEnv *env, jobject thiz) {
    return EmulatorDetector::checkEmulatorFilesSyscall() || EmulatorDetector::checkQemuSyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkQemuNative(JNIEnv *env, jobject thiz) {
    return EmulatorDetector::checkQemuNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkQemuSyscall(JNIEnv *env, jobject thiz) {
    return EmulatorDetector::checkQemuSyscall();
}

// ===================== Debug Detection =====================

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkDebuggerNative(JNIEnv *env, jobject thiz) {
    return DebugDetector::checkTracerPidNative() || DebugDetector::checkDebuggerNative();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkDebuggerSyscall(JNIEnv *env, jobject thiz) {
    return DebugDetector::checkTracerPidSyscall();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkPtraceNative(JNIEnv *env, jobject thiz) {
    return DebugDetector::checkPtraceNative();
}

JNIEXPORT jint JNICALL
Java_com_xff_launch_detector_NativeDetector_getTracerPid(JNIEnv *env, jobject thiz) {
    return DebugDetector::getTracerPid();
}

// ===================== JDWP-specific Detection =====================

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getJdwpDetectionReport(JNIEnv *env, jobject thiz) {
    std::string report = DebugDetector::getJdwpDetectionReport();
    return env->NewStringUTF(report.c_str());
}

// ===================== Network Native Detection =====================
// getifaddrs + netlink RTM_GETROUTE + syscall /proc/net/dev 三路融合，
// 用于交叉验证 Java NetworkInterface 是否被 hook
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getNetworkNativeReport(JNIEnv *env, jobject thiz) {
    std::string report = NetworkDetector::getNetworkNativeReport();
    return env->NewStringUTF(report.c_str());
}

// ===================== File Operations via Syscall =====================

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_fileExistsNative(JNIEnv *env, jobject thiz, jstring path) {
    const char* pathStr = env->GetStringUTFChars(path, nullptr);
    bool exists = access(pathStr, F_OK) == 0;
    env->ReleaseStringUTFChars(path, pathStr);
    return exists;
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_fileExistsSyscall(JNIEnv *env, jobject thiz, jstring path) {
    const char* pathStr = env->GetStringUTFChars(path, nullptr);
    bool exists = syscall_file_exists(pathStr);
    env->ReleaseStringUTFChars(path, pathStr);
    return exists;
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_readFileSyscall(JNIEnv *env, jobject thiz, jstring path) {
    const char* pathStr = env->GetStringUTFChars(path, nullptr);
    std::string content = syscall_read_file(pathStr, 8192);
    env->ReleaseStringUTFChars(path, pathStr);
    return env->NewStringUTF(content.c_str());
}

// ===================== Readlink Detection (Syscall-based) =====================

// Suspicious keywords to check in paths
static const char* SUSPICIOUS_KEYWORDS[] = {
    "magisk", "su", "supersu", "superuser", "busybox",
    "ksu", "kernelsu", "apatch", "lsposed", "edxposed",
    "xposed", "riru", "zygisk", "shamiko", "hide",
    "frida", "substrate", "cydia"
};
static const int SUSPICIOUS_KEYWORDS_COUNT = 18;

static bool contains_suspicious(const std::string& path) {
    if (path.empty()) return false;
    std::string lower = path;
    for (char& c : lower) {
        c = tolower(c);
    }
    for (int i = 0; i < SUSPICIOUS_KEYWORDS_COUNT; i++) {
        if (lower.find(SUSPICIOUS_KEYWORDS[i]) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// Read symlink using libc readlink
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_readlinkNative(JNIEnv *env, jobject thiz, jstring path) {
    const char* pathStr = env->GetStringUTFChars(path, nullptr);

    char buffer[PATH_MAX] = {0};
    ssize_t len = readlink(pathStr, buffer, sizeof(buffer) - 1);

    env->ReleaseStringUTFChars(path, pathStr);

    if (len > 0) {
        buffer[len] = '\0';
        return env->NewStringUTF(buffer);
    }
    return env->NewStringUTF("");
}

// Read symlink using direct syscall
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_readlinkSyscall(JNIEnv *env, jobject thiz, jstring path) {
    const char* pathStr = env->GetStringUTFChars(path, nullptr);

    char buffer[PATH_MAX] = {0};
    ssize_t len = syscall(__NR_readlinkat, AT_FDCWD, pathStr, buffer, sizeof(buffer) - 1);

    env->ReleaseStringUTFChars(path, pathStr);

    if (len > 0) {
        buffer[len] = '\0';
        return env->NewStringUTF(buffer);
    }
    return env->NewStringUTF("");
}

// Check if path is symlink using libc lstat
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_isSymlinkNative(JNIEnv *env, jobject thiz, jstring path) {
    const char* pathStr = env->GetStringUTFChars(path, nullptr);

    struct stat st;
    int result = lstat(pathStr, &st);

    env->ReleaseStringUTFChars(path, pathStr);

    if (result == 0) {
        return S_ISLNK(st.st_mode);
    }
    return false;
}

// Check if path is symlink using direct syscall
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_isSymlinkSyscall(JNIEnv *env, jobject thiz, jstring path) {
    const char* pathStr = env->GetStringUTFChars(path, nullptr);

    struct stat st;
    int result = syscall(__NR_fstatat, AT_FDCWD, pathStr, &st, AT_SYMLINK_NOFOLLOW);

    env->ReleaseStringUTFChars(path, pathStr);

    if (result == 0) {
        return S_ISLNK(st.st_mode);
    }
    return false;
}

// Get realpath using libc
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_realpathNative(JNIEnv *env, jobject thiz, jstring path) {
    const char* pathStr = env->GetStringUTFChars(path, nullptr);

    char resolved[PATH_MAX] = {0};
    char* result = realpath(pathStr, resolved);

    env->ReleaseStringUTFChars(path, pathStr);

    if (result != nullptr) {
        return env->NewStringUTF(resolved);
    }
    return env->NewStringUTF("");
}

// Get realpath using syscalls only (manual symlink resolution)
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_realpathSyscall(JNIEnv *env, jobject thiz, jstring path) {
    const char* pathStr = env->GetStringUTFChars(path, nullptr);

    std::string current = pathStr;
    char buffer[PATH_MAX];
    int depth = 0;
    const int MAX_DEPTH = 40;  // Prevent infinite loops

    while (depth < MAX_DEPTH) {
        // Check if current path is a symlink
        struct stat st;
        if (syscall(__NR_fstatat, AT_FDCWD, current.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
            break;
        }

        if (!S_ISLNK(st.st_mode)) {
            break;  // Not a symlink, we're done
        }

        // Read the symlink
        memset(buffer, 0, sizeof(buffer));
        ssize_t len = syscall(__NR_readlinkat, AT_FDCWD, current.c_str(), buffer, sizeof(buffer) - 1);
        if (len <= 0) {
            break;
        }
        buffer[len] = '\0';

        // Handle relative vs absolute path
        if (buffer[0] == '/') {
            current = buffer;
        } else {
            // Relative path - combine with parent directory
            size_t lastSlash = current.rfind('/');
            if (lastSlash != std::string::npos) {
                current = current.substr(0, lastSlash + 1) + buffer;
            } else {
                current = buffer;
            }
        }

        depth++;
    }

    env->ReleaseStringUTFChars(path, pathStr);
    return env->NewStringUTF(current.c_str());
}

// Check proc file accessibility via syscall
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_checkProcFileSyscall(JNIEnv *env, jobject thiz, jstring path) {
    const char* pathStr = env->GetStringUTFChars(path, nullptr);

    // Try to open and read the file via syscall
    int fd = syscall(__NR_openat, AT_FDCWD, pathStr, O_RDONLY);
    std::string result;

    if (fd >= 0) {
        char buffer[256];
        ssize_t len = syscall(__NR_read, fd, buffer, sizeof(buffer) - 1);
        if (len > 0) {
            buffer[len] = '\0';
            result = buffer;
        }
        syscall(__NR_close, fd);
    }

    env->ReleaseStringUTFChars(path, pathStr);
    return env->NewStringUTF(result.c_str());
}

// Check for hidden memory mappings
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkHiddenMapsSyscall(JNIEnv *env, jobject thiz) {
    // Read /proc/self/maps via syscall
    std::string maps = syscall_read_file("/proc/self/maps", 65536);

    // Check for signs of hidden mappings (gaps in address space, suspicious libraries)
    bool suspicious = false;

    // Check for Frida, Xposed, etc. in maps
    suspicious |= (maps.find("frida") != std::string::npos);
    suspicious |= (maps.find("xposed") != std::string::npos);
    suspicious |= (maps.find("substrate") != std::string::npos);
    suspicious |= (maps.find("lsposed") != std::string::npos);
    suspicious |= (maps.find("edxposed") != std::string::npos);
    suspicious |= (maps.find("riru") != std::string::npos);

    // Also check via /proc/self/smaps for more detailed info
    std::string smaps = syscall_read_file("/proc/self/smaps", 131072);
    suspicious |= (smaps.find("frida") != std::string::npos);

    return suspicious;
}

// Check suspicious file descriptors via native
JNIEXPORT jint JNICALL
Java_com_xff_launch_detector_NativeDetector_checkSuspiciousFdsNative(JNIEnv *env, jobject thiz) {
    int suspiciousCount = 0;
    char linkPath[64];
    char targetPath[PATH_MAX];

    DIR* dir = opendir("/proc/self/fd");
    if (dir != nullptr) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;

            snprintf(linkPath, sizeof(linkPath), "/proc/self/fd/%s", entry->d_name);
            ssize_t len = readlink(linkPath, targetPath, sizeof(targetPath) - 1);

            if (len > 0) {
                targetPath[len] = '\0';
                if (contains_suspicious(targetPath)) {
                    suspiciousCount++;
                    LOGD("Suspicious FD found: %s -> %s", linkPath, targetPath);
                }
            }
        }
        closedir(dir);
    }

    return suspiciousCount;
}

// Check suspicious file descriptors via syscall
JNIEXPORT jint JNICALL
Java_com_xff_launch_detector_NativeDetector_checkSuspiciousFdsSyscall(JNIEnv *env, jobject thiz) {
    int suspiciousCount = 0;
    char linkPath[64];
    char targetPath[PATH_MAX];

    // Open /proc/self/fd using syscall
    int dirFd = syscall(__NR_openat, AT_FDCWD, "/proc/self/fd", O_RDONLY | O_DIRECTORY);
    if (dirFd < 0) return 0;

    // Read directory entries
    char buffer[4096];
    while (true) {
        int nread = syscall(__NR_getdents64, dirFd, buffer, sizeof(buffer));
        if (nread <= 0) break;

        int pos = 0;
        while (pos < nread) {
            struct linux_dirent64* d = (struct linux_dirent64*)(buffer + pos);

            if (d->d_name[0] != '.') {
                snprintf(linkPath, sizeof(linkPath), "/proc/self/fd/%s", d->d_name);

                ssize_t len = syscall(__NR_readlinkat, AT_FDCWD, linkPath,
                                      targetPath, sizeof(targetPath) - 1);
                if (len > 0) {
                    targetPath[len] = '\0';
                    if (contains_suspicious(targetPath)) {
                        suspiciousCount++;
                    }
                }
            }

            pos += d->d_reclen;
        }
    }

    syscall(__NR_close, dirFd);
    return suspiciousCount;
}

// Check mount namespace via native
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkMountNamespaceNative(JNIEnv *env, jobject thiz) {
    // Read our mount namespace
    char selfNs[PATH_MAX] = {0};
    char initNs[PATH_MAX] = {0};

    ssize_t selfLen = readlink("/proc/self/ns/mnt", selfNs, sizeof(selfNs) - 1);
    ssize_t initLen = readlink("/proc/1/ns/mnt", initNs, sizeof(initNs) - 1);

    if (selfLen > 0 && initLen > 0) {
        selfNs[selfLen] = '\0';
        initNs[initLen] = '\0';

        // If namespace differs from init, could indicate isolation
        // But this alone isn't necessarily bad
        return strcmp(selfNs, initNs) == 0;
    }

    // Also check /proc/self/mounts for suspicious entries
    FILE* fp = fopen("/proc/self/mounts", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "magisk") || strstr(line, "ksu") ||
                strstr(line, "apatch") || strstr(line, "overlay")) {
                fclose(fp);
                return false;  // Suspicious mount found
            }
        }
        fclose(fp);
    }

    return true;
}

// Check mount namespace via syscall
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkMountNamespaceSyscall(JNIEnv *env, jobject thiz) {
    char selfNs[PATH_MAX] = {0};
    char initNs[PATH_MAX] = {0};

    // Read namespace links via syscall
    ssize_t selfLen = syscall(__NR_readlinkat, AT_FDCWD, "/proc/self/ns/mnt",
                              selfNs, sizeof(selfNs) - 1);
    ssize_t initLen = syscall(__NR_readlinkat, AT_FDCWD, "/proc/1/ns/mnt",
                              initNs, sizeof(initNs) - 1);

    // Read mount info via syscall
    std::string mounts = syscall_read_file("/proc/self/mounts", 32768);

    // Check for suspicious mounts
    bool suspicious = false;
    suspicious |= (mounts.find("magisk") != std::string::npos);
    suspicious |= (mounts.find("/su") != std::string::npos);
    suspicious |= (mounts.find("supersu") != std::string::npos);
    suspicious |= (mounts.find("ksu") != std::string::npos);
    suspicious |= (mounts.find("apatch") != std::string::npos);

    // Check for overlay on system partitions (common root hiding technique)
    bool overlayOnSystem = false;
    size_t pos = 0;
    while ((pos = mounts.find("overlay", pos)) != std::string::npos) {
        size_t lineEnd = mounts.find('\n', pos);
        std::string line = mounts.substr(pos, lineEnd - pos);
        if (line.find("/system") != std::string::npos ||
            line.find("/vendor") != std::string::npos ||
            line.find("/product") != std::string::npos) {
            overlayOnSystem = true;
            break;
        }
        pos = lineEnd;
    }

    if (suspicious || overlayOnSystem) {
        return false;  // Risk detected
    }

    // Check namespace difference
    if (selfLen > 0 && initLen > 0) {
        selfNs[selfLen] = '\0';
        initNs[initLen] = '\0';
        // Namespace check (being different isn't always bad on modern Android)
    }

    return true;  // Looks OK
}

// ===================== Zygote Injection Detection =====================

// Zygote/Zygisk/Riru injection keywords
static const char* ZYGOTE_KEYWORDS[] = {
    "zygisk", "libzygisk", "riru", "libriru", "lsposed", "liblsposed",
    "edxposed", "libedxposed", "xposed", "dreamland", "libwhale",
    "libsandhook", "libpine", "libdobby", "substrate"
};
static const int ZYGOTE_KEYWORDS_COUNT = 15;

// Check if maps content contains Zygote-related injection
static int check_maps_for_zygote(const std::string& maps) {
    int count = 0;
    std::string mapsLower = maps;
    for (char& c : mapsLower) {
        c = tolower(c);
    }

    for (int i = 0; i < ZYGOTE_KEYWORDS_COUNT; i++) {
        if (mapsLower.find(ZYGOTE_KEYWORDS[i]) != std::string::npos) {
            count++;
        }
    }
    return count;
}

// Zygisk detection functions are now defined earlier in the file (lines 226-235)
// Old implementations removed to avoid redefinition errors

// Check for Riru via native
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkRiruNative(JNIEnv *env, jobject thiz) {
    std::string maps = read_file_native("/proc/self/maps", 65536);
    std::string mapsLower = maps;
    for (char& c : mapsLower) c = tolower(c);

    bool found = mapsLower.find("riru") != std::string::npos ||
                 mapsLower.find("libriru") != std::string::npos ||
                 mapsLower.find("libriruloader") != std::string::npos;

    // Check Riru paths
    if (!found) {
        found = access("/data/adb/riru", F_OK) == 0 ||
                access("/dev/riru", F_OK) == 0;
    }

    return found;
}

// Check for Riru via syscall
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkRiruSyscall(JNIEnv *env, jobject thiz) {
    std::string maps = syscall_read_file("/proc/self/maps", 65536);
    std::string mapsLower = maps;
    for (char& c : mapsLower) c = tolower(c);

    bool found = mapsLower.find("riru") != std::string::npos ||
                 mapsLower.find("libriru") != std::string::npos;

    if (!found) {
        found = syscall_file_exists("/data/adb/riru") ||
                syscall_file_exists("/dev/riru");
    }

    return found;
}

// Get SELinux context via native
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getSELinuxContextNative(JNIEnv *env, jobject thiz) {
    std::string context = read_file_native("/proc/self/attr/prev", 256);
    if (context.empty()) {
        context = read_file_native("/proc/self/attr/current", 256);
    }
    return env->NewStringUTF(context.c_str());
}

// 取文件的 SELinux 标签：lgetxattr(path, "security.selinux")。
// 用于检测 Magisk 改过的文件 context 异常（如 magisk_file / su_exec）。
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getFileSelinuxContextNative(JNIEnv *env, jobject thiz, jstring jpath) {
    (void) thiz;
    if (!jpath) return env->NewStringUTF("");
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    char buf[256] = {0};
    std::string result;
    if (path) {
        ssize_t n = lgetxattr(path, "security.selinux", buf, sizeof(buf) - 1);
        if (n > 0) {
            size_t len = (size_t) n;
            while (len > 0 && buf[len - 1] == '\0') len--;  // 去掉尾部 NUL
            result.assign(buf, len);
        }
        env->ReleaseStringUTFChars(jpath, path);
    }
    return env->NewStringUTF(result.c_str());
}

// Check suspicious maps via native
JNIEXPORT jint JNICALL
Java_com_xff_launch_detector_NativeDetector_checkSuspiciousMapsNative(JNIEnv *env, jobject thiz) {
    std::string maps = read_file_native("/proc/self/maps", 65536);
    return check_maps_for_zygote(maps);
}

// Check suspicious maps via syscall
JNIEXPORT jint JNICALL
Java_com_xff_launch_detector_NativeDetector_checkSuspiciousMapsSyscall(JNIEnv *env, jobject thiz) {
    std::string maps = syscall_read_file("/proc/self/maps", 65536);
    return check_maps_for_zygote(maps);
}

// Check app_process integrity via native
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkAppProcessNative(JNIEnv *env, jobject thiz) {
    // /system/bin/app_process is NORMALLY a symlink to app_process32 or app_process64
    // This is the standard Android design, NOT an anomaly!

    const char* main_process = "/system/bin/app_process";
    const char* process32 = "/system/bin/app_process32";
    const char* process64 = "/system/bin/app_process64";

    struct stat st;

    // Check main app_process
    if (lstat(main_process, &st) == 0) {
        // It should be a symlink
        if (S_ISLNK(st.st_mode)) {
            // Read the symlink target
            char target[256] = {0};
            ssize_t len = readlink(main_process, target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                // Check if it points to a legitimate target
                // Should be "app_process32" or "app_process64"
                if (strstr(target, "app_process32") || strstr(target, "app_process64")) {
                    // This is NORMAL, not an anomaly
                } else if (strstr(target, "/data/") || strstr(target, "/sdcard/") || strstr(target, "/tmp/")) {
                    // Suspicious: pointing to writable location
                    return false;
                }
            }
        }
    }

    // Check app_process32 and app_process64 - these should be regular files
    const char* binaries[] = {process32, process64};
    for (const char* path : binaries) {
        if (lstat(path, &st) == 0) {
            // These should be regular files, NOT symlinks
            if (S_ISLNK(st.st_mode)) {
                // If these are symlinks, it's suspicious
                char target[256] = {0};
                ssize_t len = readlink(path, target, sizeof(target) - 1);
                if (len > 0) {
                    target[len] = '\0';
                    // Check if pointing to suspicious location
                    if (strstr(target, "/data/") || strstr(target, "/sdcard/") || strstr(target, "/tmp/")) {
                        return false;
                    }
                }
            }
        }
    }

    return true;
}

// Check app_process integrity via syscall
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkAppProcessSyscall(JNIEnv *env, jobject thiz) {
    // Same logic as above, but using syscalls

    const char* main_process = "/system/bin/app_process";
    const char* process32 = "/system/bin/app_process32";
    const char* process64 = "/system/bin/app_process64";

    struct stat st;

    // Check main app_process
    if (syscall(__NR_fstatat, AT_FDCWD, main_process, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (S_ISLNK(st.st_mode)) {
            // Read symlink target using syscall
            char target[256] = {0};
            ssize_t len = syscall(__NR_readlinkat, AT_FDCWD, main_process, target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                // Should point to app_process32 or app_process64
                if (strstr(target, "app_process32") || strstr(target, "app_process64")) {
                    // Normal
                } else if (strstr(target, "/data/") || strstr(target, "/sdcard/") || strstr(target, "/tmp/")) {
                    // Suspicious
                    return false;
                }
            }
        }
    }

    // Check binaries
    const char* binaries[] = {process32, process64};
    for (const char* path : binaries) {
        if (syscall(__NR_fstatat, AT_FDCWD, path, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            if (S_ISLNK(st.st_mode)) {
                char target[256] = {0};
                ssize_t len = syscall(__NR_readlinkat, AT_FDCWD, path, target, sizeof(target) - 1);
                if (len > 0) {
                    target[len] = '\0';
                    if (strstr(target, "/data/") || strstr(target, "/sdcard/") || strstr(target, "/tmp/")) {
                        return false;
                    }
                }
            }
        }
    }

    return true;
}

// Check file integrity via syscall
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkFileIntegritySyscall(JNIEnv *env, jobject thiz, jstring path) {
    const char* pathStr = env->GetStringUTFChars(path, nullptr);

    struct stat st;
    bool ok = true;

    if (syscall(__NR_fstatat, AT_FDCWD, pathStr, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        // Check if it's a symlink (unexpected for system files)
        if (S_ISLNK(st.st_mode)) {
            ok = false;
        }
    }

    env->ReleaseStringUTFChars(path, pathStr);
    return ok;
}

// Count Zygisk modules via syscall
JNIEXPORT jint JNICALL
Java_com_xff_launch_detector_NativeDetector_countZygiskModulesSyscall(JNIEnv *env, jobject thiz) {
    int count = 0;

    // Open modules directory
    int dirFd = syscall(__NR_openat, AT_FDCWD, "/data/adb/modules", O_RDONLY | O_DIRECTORY);
    if (dirFd < 0) return 0;

    char buffer[4096];
    while (true) {
        int nread = syscall(__NR_getdents64, dirFd, buffer, sizeof(buffer));
        if (nread <= 0) break;

        int pos = 0;
        while (pos < nread) {
            struct linux_dirent64* d = (struct linux_dirent64*)(buffer + pos);

            if (d->d_type == DT_DIR && d->d_name[0] != '.') {
                // Check if module has zygisk folder
                char modulePath[512];
                snprintf(modulePath, sizeof(modulePath), "/data/adb/modules/%s/zygisk", d->d_name);

                if (syscall_file_exists(modulePath)) {
                    count++;
                }
            }

            pos += d->d_reclen;
        }
    }

    syscall(__NR_close, dirFd);
    return count;
}

// Check memory integrity (PLT/GOT) via native
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkMemoryIntegrityNative(JNIEnv *env, jobject thiz) {
    // Read maps and check for suspicious writeable sections
    std::string maps = read_file_native("/proc/self/maps", 65536);

    // Look for r-xp sections that have been modified
    // This is a simplified check
    bool suspicious = false;

    // Check for hook libraries
    suspicious |= (maps.find("libdobby") != std::string::npos);
    suspicious |= (maps.find("libwhale") != std::string::npos);
    suspicious |= (maps.find("libsandhook") != std::string::npos);
    suspicious |= (maps.find("libpine") != std::string::npos);

    return !suspicious;
}

// Check memory integrity via syscall
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkMemoryIntegritySyscall(JNIEnv *env, jobject thiz) {
    std::string maps = syscall_read_file("/proc/self/maps", 65536);

    bool suspicious = false;
    suspicious |= (maps.find("libdobby") != std::string::npos);
    suspicious |= (maps.find("libwhale") != std::string::npos);
    suspicious |= (maps.find("libsandhook") != std::string::npos);
    suspicious |= (maps.find("libpine") != std::string::npos);

    return !suspicious;
}

// Check for inline hooks via syscall
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkInlineHooksSyscall(JNIEnv *env, jobject thiz) {
    // Check /proc/self/smaps for suspicious private dirty pages in system libraries
    std::string smaps = syscall_read_file("/proc/self/smaps", 131072);

    // Look for r--p sections with Private_Dirty > 0 in system libraries
    // This indicates memory modification (potential hooks)
    bool inSystemSection = false;
    bool hasPrivateDirty = false;

    size_t pos = 0;
    while (pos < smaps.length()) {
        size_t lineEnd = smaps.find('\n', pos);
        if (lineEnd == std::string::npos) break;

        std::string line = smaps.substr(pos, lineEnd - pos);
        pos = lineEnd + 1;

        // Check if this is a system library section
        if (line.find("/system/") != std::string::npos ||
            line.find("/apex/") != std::string::npos) {
            if (line.find("r--p") != std::string::npos ||
                line.find("r-xp") != std::string::npos) {
                inSystemSection = true;
            }
        } else if (line.find("Private_Dirty:") != std::string::npos && inSystemSection) {
            // Check if Private_Dirty > 0
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string valueStr = line.substr(colonPos + 1);
                // Trim
                while (!valueStr.empty() && valueStr[0] == ' ') valueStr.erase(0, 1);
                int value = atoi(valueStr.c_str());
                if (value > 0) {
                    hasPrivateDirty = true;
                    break;
                }
            }
            inSystemSection = false;
        } else if (line.empty() || (line[0] >= '0' && line[0] <= '9')) {
            inSystemSection = false;
        }
    }

    return hasPrivateDirty;
}

// Check for suspicious anonymous memory via syscall
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkSuspiciousAnonMemorySyscall(JNIEnv *env, jobject thiz) {
    std::string maps = syscall_read_file("/proc/self/maps", 65536);

    // Look for anonymous executable memory (potential code injection)
    // Format: address perms offset dev inode pathname
    // Anonymous memory has no pathname

    int suspiciousCount = 0;
    size_t pos = 0;

    while (pos < maps.length()) {
        size_t lineEnd = maps.find('\n', pos);
        if (lineEnd == std::string::npos) lineEnd = maps.length();

        std::string line = maps.substr(pos, lineEnd - pos);
        pos = lineEnd + 1;

        // Check for executable anonymous memory (r-xp or rwxp with no path)
        if ((line.find("r-xp") != std::string::npos || line.find("rwxp") != std::string::npos)) {
            // Check if it's anonymous (no path at end)
            size_t lastSpace = line.rfind(' ');
            if (lastSpace != std::string::npos) {
                std::string pathPart = line.substr(lastSpace + 1);
                // Trim
                while (!pathPart.empty() && pathPart[0] == ' ') pathPart.erase(0, 1);

                // Anonymous memory or suspicious paths
                if (pathPart.empty() || pathPart[0] == '[' ||
                    pathPart.find("deleted") != std::string::npos) {
                    // This could be JIT or legitimate, but high count is suspicious
                    suspiciousCount++;
                }
            }
        }
    }

    // More than 5 anonymous executable regions is suspicious
    return suspiciousCount > 5;
}

// Check libc hooks via syscall
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkLibcHooksSyscall(JNIEnv *env, jobject thiz) {
    std::string maps = syscall_read_file("/proc/self/maps", 65536);

    // Check if libc.so has suspicious modifications
    // This is a simplified check - real implementation would check GOT/PLT

    bool suspicious = false;

    // Look for hook framework signatures near libc
    size_t libcPos = maps.find("libc.so");
    if (libcPos != std::string::npos) {
        // Check surrounding entries for hook libraries
        size_t searchStart = (libcPos > 2000) ? libcPos - 2000 : 0;
        size_t searchEnd = (libcPos + 2000 < maps.length()) ? libcPos + 2000 : maps.length();
        std::string surrounding = maps.substr(searchStart, searchEnd - searchStart);

        suspicious |= (surrounding.find("frida") != std::string::npos);
        suspicious |= (surrounding.find("substrate") != std::string::npos);
        suspicious |= (surrounding.find("libdobby") != std::string::npos);
    }

    return suspicious;
}

// Check libart hooks via syscall
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkArtHooksSyscall(JNIEnv *env, jobject thiz) {
    std::string maps = syscall_read_file("/proc/self/maps", 65536);

    bool suspicious = false;

    // Check for xposed-related hooks in ART
    suspicious |= (maps.find("libxposed") != std::string::npos);
    suspicious |= (maps.find("liblsposed") != std::string::npos);
    suspicious |= (maps.find("libedxposed") != std::string::npos);
    suspicious |= (maps.find("libwhale") != std::string::npos);
    suspicious |= (maps.find("libsandhook") != std::string::npos);
    suspicious |= (maps.find("libpine") != std::string::npos);

    return suspicious;
}

// Check library hooks via native
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkLibraryHooksNative(JNIEnv *env, jobject thiz) {
    std::string maps = read_file_native("/proc/self/maps", 65536);

    bool suspicious = false;
    suspicious |= (maps.find("libdobby") != std::string::npos);
    suspicious |= (maps.find("libwhale") != std::string::npos);
    suspicious |= (maps.find("libsandhook") != std::string::npos);
    suspicious |= (maps.find("libpine") != std::string::npos);
    suspicious |= (maps.find("substrate") != std::string::npos);
    suspicious |= (maps.find("frida") != std::string::npos);

    return !suspicious;
}

// ===================== Zygote Process Detection =====================

/**
 * Find zygote process PID
 * @return zygote process PID, or -1 if not found
 */
static int find_zygote_pid() {
    DIR* dir = opendir("/proc");
    if (!dir) return -1;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // Skip non-numeric directories
        if (!isdigit(entry->d_name[0])) continue;

        // Read /proc/[pid]/cmdline
        char cmdline_path[256];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);

        int fd = syscall(__NR_openat, AT_FDCWD, cmdline_path, O_RDONLY);
        if (fd < 0) continue;

        char cmdline[256] = {0};
        ssize_t len = syscall(__NR_read, fd, cmdline, sizeof(cmdline) - 1);
        syscall(__NR_close, fd);

        if (len > 0) {
            // Check if it's zygote or zygote64
            if (strcmp(cmdline, "zygote") == 0 || strcmp(cmdline, "zygote64") == 0) {
                int pid = atoi(entry->d_name);
                closedir(dir);
                return pid;
            }
        }
    }

    closedir(dir);
    return -1;
}

/**
 * Get parent PID of a process
 * @param pid Process ID
 * @return Parent PID, or -1 if error
 */
static int get_parent_pid(int pid) {
    char stat_path[256];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);

    std::string stat_content = syscall_read_file(stat_path, 512);
    if (stat_content.empty()) return -1;

    // Format: pid (comm) state ppid ...
    // Find the closing parenthesis of comm
    size_t paren_close = stat_content.rfind(')');
    if (paren_close == std::string::npos) return -1;

    // Parse after closing parenthesis
    int state_char, ppid;
    if (sscanf(stat_content.c_str() + paren_close + 1, " %c %d", (char*)&state_char, &ppid) == 2) {
        return ppid;
    }

    return -1;
}

/**
 * Check if zygote has abnormal parent process
 * Normal: zygote's parent should be init (PID 1)
 * Abnormal: zygote's parent is not init -> Zygisk injection
 */
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkZygoteParentNative(JNIEnv *env, jobject thiz) {
    int zygote_pid = find_zygote_pid();
    if (zygote_pid <= 0) {
        return false;  // Zygote not found, no risk
    }

    int parent_pid = get_parent_pid(zygote_pid);

    // Normal case: parent should be init (PID 1)
    // Abnormal: parent is something else (e.g., zygisk daemon)
    return parent_pid != 1;
}

/**
 * Get zygote PID and parent PID for display
 * Returns: "zygote_pid:parent_pid" or "not_found"
 */
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getZygoteInfo(JNIEnv *env, jobject thiz) {
    int zygote_pid = find_zygote_pid();
    if (zygote_pid <= 0) {
        return env->NewStringUTF("not_found");
    }

    int parent_pid = get_parent_pid(zygote_pid);

    char info[128];
    snprintf(info, sizeof(info), "%d:%d", zygote_pid, parent_pid);
    return env->NewStringUTF(info);
}

// ===================== Anonymous Executable Memory Detection =====================

/**
 * Count anonymous rwxp (readable, writable, executable) memory regions
 * These are suspicious as they could be injected code
 *
 * @return Number of anonymous rwxp regions found
 */
JNIEXPORT jint JNICALL
Java_com_xff_launch_detector_NativeDetector_countAnonymousRwxMemory(JNIEnv *env, jobject thiz) {
    std::string maps = syscall_read_file("/proc/self/maps", 131072);  // 128KB buffer
    if (maps.empty()) return 0;

    int count = 0;
    size_t pos = 0;

    while (pos < maps.length()) {
        size_t line_end = maps.find('\n', pos);
        if (line_end == std::string::npos) break;

        std::string line = maps.substr(pos, line_end - pos);
        pos = line_end + 1;

        // Format: address permissions offset dev inode pathname
        // Example: 7e8b96b000-7e8b96c000 rwxp 00000000 00:00 0

        // Check if rwxp permission
        if (line.find("rwxp") == std::string::npos) continue;

        // Parse the line to check if it's anonymous (no pathname)
        // Split by whitespace
        size_t ws1 = line.find(' ');
        if (ws1 == std::string::npos) continue;

        size_t ws2 = line.find(' ', ws1 + 1);  // After permissions
        if (ws2 == std::string::npos) continue;

        size_t ws3 = line.find(' ', ws2 + 1);  // After offset
        if (ws3 == std::string::npos) continue;

        size_t ws4 = line.find(' ', ws3 + 1);  // After dev
        if (ws4 == std::string::npos) continue;

        size_t ws5 = line.find(' ', ws4 + 1);  // After inode

        // Get the part after inode
        std::string pathname;
        if (ws5 != std::string::npos) {
            pathname = line.substr(ws5 + 1);
            // Trim leading spaces
            while (!pathname.empty() && pathname[0] == ' ') {
                pathname.erase(0, 1);
            }
        }

        // Anonymous memory: no pathname or empty pathname
        if (pathname.empty() || pathname[0] == '\n' || pathname[0] == '\r') {
            count++;

            // Log for debugging
            LOGD("Found anonymous rwxp: %s", line.c_str());
        }
    }

    return count;
}

/**
 * Get detailed info about anonymous rwxp regions
 * Returns JSON-like string with details
 */
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getAnonymousRwxDetails(JNIEnv *env, jobject thiz) {
    std::string maps = syscall_read_file("/proc/self/maps", 131072);
    if (maps.empty()) return env->NewStringUTF("[]");

    std::string result = "[";
    int count = 0;
    size_t pos = 0;

    while (pos < maps.length() && count < 10) {  // Limit to first 10
        size_t line_end = maps.find('\n', pos);
        if (line_end == std::string::npos) break;

        std::string line = maps.substr(pos, line_end - pos);
        pos = line_end + 1;

        if (line.find("rwxp") == std::string::npos) continue;

        // Parse address range
        size_t dash_pos = line.find('-');
        size_t space_pos = line.find(' ');

        if (dash_pos != std::string::npos && space_pos != std::string::npos) {
            std::string start_addr = line.substr(0, dash_pos);
            std::string end_addr = line.substr(dash_pos + 1, space_pos - dash_pos - 1);

            // Check if anonymous (simplified check)
            size_t last_space = line.rfind(' ');
            bool is_anon = (last_space == std::string::npos ||
                           line.substr(last_space + 1).find('/') == std::string::npos);

            if (is_anon) {
                if (count > 0) result += ",";
                result += "{\"start\":\"" + start_addr + "\",\"end\":\"" + end_addr + "\"}";
                count++;
            }
        }
    }

    result += "]";
    return env->NewStringUTF(result.c_str());
}

// ===================== Timing Attack Detection =====================

/**
 * Benchmark openat() syscall timing
 * @param iterations Number of calls to measure
 * @return Average time per call in nanoseconds
 */
JNIEXPORT jlong JNICALL
Java_com_xff_launch_detector_NativeDetector_benchmarkSyscallOpenat(JNIEnv *env, jobject thiz, jint iterations) {
    return (jlong)benchmark_syscall_openat(iterations);
}

/**
 * Benchmark openat() libc timing
 */
JNIEXPORT jlong JNICALL
Java_com_xff_launch_detector_NativeDetector_benchmarkLibcOpenat(JNIEnv *env, jobject thiz, jint iterations) {
    return (jlong)benchmark_libc_openat(iterations);
}

/**
 * Benchmark access() syscall timing
 */
JNIEXPORT jlong JNICALL
Java_com_xff_launch_detector_NativeDetector_benchmarkSyscallAccess(JNIEnv *env, jobject thiz, jint iterations) {
    return (jlong)benchmark_syscall_access(iterations);
}

/**
 * Benchmark access() libc timing
 */
JNIEXPORT jlong JNICALL
Java_com_xff_launch_detector_NativeDetector_benchmarkLibcAccess(JNIEnv *env, jobject thiz, jint iterations) {
    return (jlong)benchmark_libc_access(iterations);
}

/**
 * Benchmark stat() syscall timing
 */
JNIEXPORT jlong JNICALL
Java_com_xff_launch_detector_NativeDetector_benchmarkSyscallStat(JNIEnv *env, jobject thiz, jint iterations) {
    return (jlong)benchmark_syscall_stat(iterations);
}

/**
 * Benchmark stat() libc timing
 */
JNIEXPORT jlong JNICALL
Java_com_xff_launch_detector_NativeDetector_benchmarkLibcStat(JNIEnv *env, jobject thiz, jint iterations) {
    return (jlong)benchmark_libc_stat(iterations);
}

/**
 * Detect timing anomaly
 * @param syscallTime Average syscall time (ns)
 * @param libcTime Average libc time (ns)
 * @param threshold Multiplier threshold (e.g., 3.0)
 * @return true if anomaly detected
 */
JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_detectTimingAnomaly(JNIEnv *env, jobject thiz,
                                                                 jlong syscallTime, jlong libcTime,
                                                                 jfloat threshold) {
    return (jboolean)detect_timing_anomaly(syscallTime, libcTime, threshold);
}

// ===================== System Property =====================

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getSystemProperty(JNIEnv *env, jobject thiz, jstring key) {
    const char* keyStr = env->GetStringUTFChars(key, nullptr);

    char value[256] = {0};
    __system_property_get(keyStr, value);

    env->ReleaseStringUTFChars(key, keyStr);
    return env->NewStringUTF(value);
}

// ===================== Fingerprint =====================

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getBuildPropertyNative(JNIEnv *env, jobject thiz, jstring propName) {
    const char* propStr = env->GetStringUTFChars(propName, nullptr);

    char value[256] = {0};
    __system_property_get(propStr, value);

    env->ReleaseStringUTFChars(propName, propStr);
    return env->NewStringUTF(value);
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getBuildPropertySyscall(JNIEnv *env, jobject thiz, jstring propName) {
    const char* propStr = env->GetStringUTFChars(propName, nullptr);

    // Read from /system/build.prop using syscall
    std::string buildProp = syscall_read_file("/system/build.prop", 32768);

    std::string searchKey = std::string(propStr) + "=";
    size_t pos = buildProp.find(searchKey);
    std::string result;

    if (pos != std::string::npos) {
        size_t valueStart = pos + searchKey.length();
        size_t valueEnd = buildProp.find('\n', valueStart);
        if (valueEnd != std::string::npos) {
            result = buildProp.substr(valueStart, valueEnd - valueStart);
        } else {
            result = buildProp.substr(valueStart);
        }
    }

    env->ReleaseStringUTFChars(propName, propStr);
    return env->NewStringUTF(result.c_str());
}

// ===================== Property Enumeration (__system_property_foreach, JD field 10-3) =====================
//
// 对照 JD field 10-3 (native cmd=10)：用 __system_property_foreach + __system_property_read_callback
// 遍历整个 /dev/__properties__ 属性区，而非 __system_property_get(name) 单点查询。
// 价值：这是与 __system_property_get 不同的 libc 入口，hook 单点查询对它无效 →
// 作为属性类指纹项的"枚举全量"交叉校验路；两路取值不一致即暴露属性系统被 hook。

struct PropMatchCtx {
    const char* target;
    std::string value;
    bool found;
};

static void prop_match_read_cb(void* cookie, const char* name, const char* value, uint32_t /*serial*/) {
    auto* ctx = (PropMatchCtx*) cookie;
    if (!ctx->found && name && ctx->target && strcmp(name, ctx->target) == 0) {
        ctx->value = value ? value : "";
        ctx->found = true;
    }
}

static void prop_match_foreach_cb(const prop_info* pi, void* cookie) {
    __system_property_read_callback(pi, prop_match_read_cb, cookie);
}

// 遍历全部属性，取出 name 对应的值（绕过 __system_property_get 单点 hook）
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getPropForeachNative(JNIEnv *env, jobject thiz, jstring propName) {
    (void) thiz;
    const char* propStr = env->GetStringUTFChars(propName, nullptr);
    PropMatchCtx ctx{ propStr, "", false };
    __system_property_foreach(prop_match_foreach_cb, &ctx);
    if (propStr) env->ReleaseStringUTFChars(propName, propStr);
    return env->NewStringUTF(ctx.value.c_str());
}

struct PropDumpCtx {
    std::vector<std::string> lines;
};

static void prop_dump_read_cb(void* cookie, const char* name, const char* value, uint32_t /*serial*/) {
    auto* ctx = (PropDumpCtx*) cookie;
    // 仅收集 ro.* 只读属性（开机后稳定，构建级软件指纹），剔除运行时易变的 net.*/persist.* 等
    if (name && strncmp(name, "ro.", 3) == 0) {
        ctx->lines.emplace_back(std::string(name) + "=" + (value ? value : ""));
    }
}

static void prop_dump_foreach_cb(const prop_info* pi, void* cookie) {
    __system_property_read_callback(pi, prop_dump_read_cb, cookie);
}

// 全量遍历 ro.* 属性，排序后拼成 "k=v\n" 原始串（Java 侧统一做 djb2，避免重复实现哈希）
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getRoPropDumpNative(JNIEnv *env, jobject thiz) {
    (void) thiz;
    PropDumpCtx ctx;
    __system_property_foreach(prop_dump_foreach_cb, &ctx);
    std::sort(ctx.lines.begin(), ctx.lines.end());
    std::string out;
    for (const auto& line : ctx.lines) {
        out += line;
        out += '\n';
    }
    return env->NewStringUTF(out.c_str());
}

// ===================== Kernel File Reading =====================

// Helper function to read file using native libc
static std::string read_file_native(const char* path, size_t maxSize) {
    FILE* fp = fopen(path, "r");
    if (!fp) return "";

    std::string content;
    char buffer[256];
    size_t totalRead = 0;

    while (fgets(buffer, sizeof(buffer), fp) && totalRead < maxSize) {
        content += buffer;
        totalRead += strlen(buffer);
    }

    fclose(fp);

    // Trim trailing whitespace/newlines
    while (!content.empty() && (content.back() == '\n' || content.back() == '\r' || content.back() == ' ')) {
        content.pop_back();
    }

    return content;
}

// Helper to extract value from key=value or "key : value" format
static std::string extract_value(const std::string& content, const std::string& key, char separator) {
    size_t pos = content.find(key);
    if (pos == std::string::npos) return "";

    pos = content.find(separator, pos);
    if (pos == std::string::npos) return "";

    pos++; // Skip separator

    // Skip whitespace
    while (pos < content.length() && (content[pos] == ' ' || content[pos] == '\t')) {
        pos++;
    }

    size_t end = content.find('\n', pos);
    if (end == std::string::npos) {
        return content.substr(pos);
    }

    std::string result = content.substr(pos, end - pos);

    // Trim trailing whitespace
    while (!result.empty() && (result.back() == ' ' || result.back() == '\t' || result.back() == '\r')) {
        result.pop_back();
    }

    return result;
}

// Helper to extract boot param from cmdline
static std::string extract_boot_param(const std::string& cmdline, const std::string& paramName) {
    std::string searchKey = paramName + "=";
    size_t pos = cmdline.find(searchKey);
    if (pos == std::string::npos) return "";

    pos += searchKey.length();
    size_t end = cmdline.find(' ', pos);
    if (end == std::string::npos) {
        return cmdline.substr(pos);
    }
    return cmdline.substr(pos, end - pos);
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_readKernelFile(JNIEnv *env, jobject thiz, jstring path) {
    const char* pathStr = env->GetStringUTFChars(path, nullptr);
    std::string content = read_file_native(pathStr);
    env->ReleaseStringUTFChars(path, pathStr);
    return env->NewStringUTF(content.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getCpuSerial(JNIEnv *env, jobject thiz) {
    std::string cpuinfo = read_file_native("/proc/cpuinfo", 8192);
    std::string serial = extract_value(cpuinfo, "Serial", ':');
    return env->NewStringUTF(serial.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getCpuSerialSyscall(JNIEnv *env, jobject thiz) {
    std::string cpuinfo = syscall_read_file("/proc/cpuinfo", 8192);
    std::string serial = extract_value(cpuinfo, "Serial", ':');
    return env->NewStringUTF(serial.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getCpuHardware(JNIEnv *env, jobject thiz) {
    std::string cpuinfo = read_file_native("/proc/cpuinfo", 8192);
    std::string hardware = extract_value(cpuinfo, "Hardware", ':');
    return env->NewStringUTF(hardware.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getCpuHardwareSyscall(JNIEnv *env, jobject thiz) {
    std::string cpuinfo = syscall_read_file("/proc/cpuinfo", 8192);
    std::string hardware = extract_value(cpuinfo, "Hardware", ':');
    return env->NewStringUTF(hardware.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getBootParam(JNIEnv *env, jobject thiz, jstring paramName) {
    const char* paramStr = env->GetStringUTFChars(paramName, nullptr);
    std::string cmdline = read_file_native("/proc/cmdline", 4096);
    std::string value = extract_boot_param(cmdline, paramStr);
    env->ReleaseStringUTFChars(paramName, paramStr);
    return env->NewStringUTF(value.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getBootParamSyscall(JNIEnv *env, jobject thiz, jstring paramName) {
    const char* paramStr = env->GetStringUTFChars(paramName, nullptr);
    std::string cmdline = syscall_read_file("/proc/cmdline", 4096);
    std::string value = extract_boot_param(cmdline, paramStr);
    env->ReleaseStringUTFChars(paramName, paramStr);
    return env->NewStringUTF(value.c_str());
}

// ===================== Extended Fingerprint Collection =====================

// --- 1. MAC Address ---

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getMacAddressNative(JNIEnv *env, jobject thiz) {
    // Try wlan0 first, then eth0
    const char* paths[] = {
        "/sys/class/net/wlan0/address",
        "/sys/class/net/eth0/address"
    };
    for (const char* path : paths) {
        std::string mac = read_file_native(path, 64);
        if (!mac.empty() && mac != "00:00:00:00:00:00") {
            return env->NewStringUTF(mac.c_str());
        }
    }
    return env->NewStringUTF("");
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getMacAddressSyscall(JNIEnv *env, jobject thiz) {
    const char* paths[] = {
        "/sys/class/net/wlan0/address",
        "/sys/class/net/eth0/address"
    };
    for (const char* path : paths) {
        std::string mac = syscall_read_file(path, 64);
        // Trim whitespace
        while (!mac.empty() && (mac.back() == '\n' || mac.back() == '\r' || mac.back() == ' ')) {
            mac.pop_back();
        }
        if (!mac.empty() && mac != "00:00:00:00:00:00") {
            return env->NewStringUTF(mac.c_str());
        }
    }
    return env->NewStringUTF("");
}

// --- 2. Total RAM ---

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getTotalRamNative(JNIEnv *env, jobject thiz) {
    long pages = sysconf(_SC_PHYS_PAGES);
    long pageSize = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && pageSize > 0) {
        long totalMB = (pages / 1024) * (pageSize / 1024);
        std::string result = std::to_string(totalMB) + " MB";
        return env->NewStringUTF(result.c_str());
    }
    return env->NewStringUTF("");
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getTotalRamSyscall(JNIEnv *env, jobject thiz) {
    std::string meminfo = syscall_read_file("/proc/meminfo", 4096);
    // Parse "MemTotal:       XXXXX kB"
    std::string memTotal = extract_value(meminfo, "MemTotal", ':');
    if (!memTotal.empty()) {
        // Extract numeric part (value is in kB)
        long kb = 0;
        for (char c : memTotal) {
            if (c >= '0' && c <= '9') {
                kb = kb * 10 + (c - '0');
            } else if (kb > 0) {
                break; // Stop at first non-digit after digits
            }
        }
        if (kb > 0) {
            long mb = kb / 1024;
            std::string result = std::to_string(mb) + " MB";
            return env->NewStringUTF(result.c_str());
        }
    }
    return env->NewStringUTF("");
}

// --- 3. Screen Info ---

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getScreenInfoNative(JNIEnv *env, jobject thiz) {
    std::string info = read_file_native("/sys/class/graphics/fb0/virtual_size", 64);
    return env->NewStringUTF(info.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getScreenInfoSyscall(JNIEnv *env, jobject thiz) {
    std::string info = syscall_read_file("/sys/class/graphics/fb0/virtual_size", 64);
    // Trim
    while (!info.empty() && (info.back() == '\n' || info.back() == '\r' || info.back() == ' ')) {
        info.pop_back();
    }
    return env->NewStringUTF(info.c_str());
}

// --- 4. CPU ABI ---

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getCpuAbiNative(JNIEnv *env, jobject thiz) {
    char value[256] = {0};
    __system_property_get("ro.product.cpu.abi", value);
    return env->NewStringUTF(value);
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getCpuAbiSyscall(JNIEnv *env, jobject thiz) {
    // Try /system/build.prop first, then /vendor/build.prop
    const char* propFiles[] = {
        "/system/build.prop",
        "/vendor/build.prop",
        "/default.prop"
    };
    for (const char* file : propFiles) {
        std::string content = syscall_read_file(file, 32768);
        std::string searchKey = "ro.product.cpu.abi=";
        size_t pos = content.find(searchKey);
        if (pos != std::string::npos) {
            size_t start = pos + searchKey.length();
            size_t end = content.find('\n', start);
            std::string val = (end != std::string::npos) ?
                content.substr(start, end - start) : content.substr(start);
            // Trim
            while (!val.empty() && (val.back() == '\r' || val.back() == ' ')) {
                val.pop_back();
            }
            if (!val.empty()) {
                return env->NewStringUTF(val.c_str());
            }
        }
    }
    return env->NewStringUTF("");
}

// --- 5. Sensor List ---

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getSensorListNative(JNIEnv *env, jobject thiz) {
    std::string result;
    // Try /sys/class/sensors/ directory
    DIR* dir = opendir("/sys/class/sensors");
    if (dir) {
        std::vector<std::string> names;
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name[0] != '.') {
                names.push_back(entry->d_name);
            }
        }
        closedir(dir);
        std::sort(names.begin(), names.end());
        for (size_t i = 0; i < names.size(); i++) {
            if (i > 0) result += ",";
            result += names[i];
        }
    }
    // Fallback: try /sys/bus/iio/devices/ for some devices
    if (result.empty()) {
        DIR* dir2 = opendir("/sys/bus/iio/devices");
        if (dir2) {
            std::vector<std::string> names;
            struct dirent* entry;
            while ((entry = readdir(dir2)) != nullptr) {
                if (entry->d_name[0] != '.') {
                    names.push_back(entry->d_name);
                }
            }
            closedir(dir2);
            std::sort(names.begin(), names.end());
            for (size_t i = 0; i < names.size(); i++) {
                if (i > 0) result += ",";
                result += names[i];
            }
        }
    }
    return env->NewStringUTF(result.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getSensorListSyscall(JNIEnv *env, jobject thiz) {
    std::string result;
    // Use syscall to open and enumerate /sys/class/sensors/
    const char* sensorDirs[] = {"/sys/class/sensors", "/sys/bus/iio/devices"};
    for (const char* dirPath : sensorDirs) {
        int fd = syscall(__NR_openat, AT_FDCWD, dirPath, O_RDONLY | O_DIRECTORY);
        if (fd >= 0) {
            char buf[4096];
            std::vector<std::string> names;
            int nread;
            while ((nread = syscall(__NR_getdents64, fd, buf, sizeof(buf))) > 0) {
                int offset = 0;
                while (offset < nread) {
                    struct linux_dirent64* de = (struct linux_dirent64*)(buf + offset);
                    if (de->d_name[0] != '.') {
                        names.push_back(de->d_name);
                    }
                    offset += de->d_reclen;
                }
            }
            syscall(__NR_close, fd);
            std::sort(names.begin(), names.end());
            for (size_t i = 0; i < names.size(); i++) {
                if (i > 0) result += ",";
                result += names[i];
            }
            if (!result.empty()) break;
        }
    }
    return env->NewStringUTF(result.c_str());
}

// --- 6. /proc/self/maps hash ---

static uint32_t simple_hash(const std::string& str) {
    uint32_t hash = 5381;
    for (char c : str) {
        hash = ((hash << 5) + hash) + (uint32_t)c;
    }
    return hash;
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getMapsHashNative(JNIEnv *env, jobject thiz) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return env->NewStringUTF("");

    std::set<std::string> libs;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        // Extract library path: last field after spaces, starting with /
        char* path = strrchr(line, '/');
        if (path) {
            // Trim newline
            char* nl = strchr(path, '\n');
            if (nl) *nl = '\0';
            libs.insert(path);
        }
    }
    fclose(fp);

    // Concatenate sorted lib names and hash
    std::string combined;
    for (const auto& lib : libs) {
        combined += lib;
        combined += ";";
    }

    uint32_t hash = simple_hash(combined);
    char hashStr[32];
    snprintf(hashStr, sizeof(hashStr), "%08x", hash);
    return env->NewStringUTF(hashStr);
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getMapsHashSyscall(JNIEnv *env, jobject thiz) {
    std::string maps = syscall_read_file("/proc/self/maps", 262144);
    if (maps.empty()) return env->NewStringUTF("");

    std::set<std::string> libs;
    size_t pos = 0;
    while (pos < maps.size()) {
        size_t lineEnd = maps.find('\n', pos);
        if (lineEnd == std::string::npos) lineEnd = maps.size();

        std::string line = maps.substr(pos, lineEnd - pos);
        size_t slashPos = line.rfind('/');
        if (slashPos != std::string::npos) {
            std::string libPath = line.substr(slashPos);
            // Trim trailing whitespace
            while (!libPath.empty() && (libPath.back() == ' ' || libPath.back() == '\r')) {
                libPath.pop_back();
            }
            libs.insert(libPath);
        }
        pos = lineEnd + 1;
    }

    std::string combined;
    for (const auto& lib : libs) {
        combined += lib;
        combined += ";";
    }

    uint32_t hash = simple_hash(combined);
    char hashStr[32];
    snprintf(hashStr, sizeof(hashStr), "%08x", hash);
    return env->NewStringUTF(hashStr);
}

// --- 7. uname info ---

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getUnameInfoNative(JNIEnv *env, jobject thiz) {
    struct utsname info;
    if (uname(&info) == 0) {
        // Format: "machine sysname" to match Java's os.arch + os.name
        std::string result = std::string(info.machine) + " " +
                             std::string(info.sysname);
        return env->NewStringUTF(result.c_str());
    }
    return env->NewStringUTF("");
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getUnameInfoSyscall(JNIEnv *env, jobject thiz) {
    struct utsname info;
    memset(&info, 0, sizeof(info));
    long ret = syscall(__NR_uname, &info);
    if (ret == 0) {
        // Format: "machine sysname" to match Java's os.arch + os.name
        std::string result = std::string(info.machine) + " " +
                             std::string(info.sysname);
        return env->NewStringUTF(result.c_str());
    }
    return env->NewStringUTF("");
}

// --- 8. Total Storage ---

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getTotalStorageNative(JNIEnv *env, jobject thiz) {
    struct statfs sf;
    if (statfs("/data", &sf) == 0) {
        long long totalBytes = (long long)sf.f_blocks * (long long)sf.f_bsize;
        long long totalGB = totalBytes / (1024LL * 1024LL * 1024LL);
        std::string result = std::to_string(totalGB) + " GB";
        return env->NewStringUTF(result.c_str());
    }
    return env->NewStringUTF("");
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getTotalStorageSyscall(JNIEnv *env, jobject thiz) {
    struct statfs sf;
    memset(&sf, 0, sizeof(sf));
    long ret = syscall(__NR_statfs, "/data", &sf);
    if (ret == 0 && sf.f_blocks > 0) {
        long long totalBytes = (long long)sf.f_blocks * (long long)sf.f_bsize;
        long long totalGB = totalBytes / (1024LL * 1024LL * 1024LL);
        std::string result = std::to_string(totalGB) + " GB";
        return env->NewStringUTF(result.c_str());
    }
    return env->NewStringUTF("");
}

// --- 9. Device-tree Serial ---

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getDeviceTreeSerialNative(JNIEnv *env, jobject thiz) {
    std::string serial = read_file_native("/proc/device-tree/serial-number", 256);
    // Remove null bytes that may exist in device-tree strings
    serial.erase(std::remove(serial.begin(), serial.end(), '\0'), serial.end());
    return env->NewStringUTF(serial.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getDeviceTreeSerialSyscall(JNIEnv *env, jobject thiz) {
    std::string serial = syscall_read_file("/proc/device-tree/serial-number", 256);
    // Trim trailing whitespace/nulls
    while (!serial.empty() && (serial.back() == '\n' || serial.back() == '\r' ||
           serial.back() == ' ' || serial.back() == '\0')) {
        serial.pop_back();
    }
    return env->NewStringUTF(serial.c_str());
}

// ===================== SVC Fingerprint: Runtime Verification =====================

// --- CPU Frequency Pattern ---

static std::string collect_cpu_freq(bool use_syscall) {
    std::string result;
    for (int i = 0; i < 16; i++) {
        char path[128];
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", i);
        std::string freq = use_syscall
            ? syscall_read_file(path, 32)
            : read_file_native(path, 32);
        while (!freq.empty() && (freq.back() == '\n' || freq.back() == '\r' || freq.back() == ' ')) {
            freq.pop_back();
        }
        if (freq.empty()) break;
        if (!result.empty()) result += ",";
        result += freq;
    }
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getCpuFreqPatternNative(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(collect_cpu_freq(false).c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getCpuFreqPatternSyscall(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(collect_cpu_freq(true).c_str());
}

// --- /etc/hosts Hash ---

static std::string compute_hosts_hash(bool use_syscall) {
    const char* paths[] = {"/etc/hosts", "/system/etc/hosts"};
    for (const char* path : paths) {
        std::string content = use_syscall
            ? syscall_read_file(path, 16384)
            : read_file_native(path, 16384);
        // Normalize: remove \r, trim trailing whitespace for consistent cross-layer hashing
        content.erase(std::remove(content.begin(), content.end(), '\r'), content.end());
        while (!content.empty() && (content.back() == '\n' || content.back() == ' ' || content.back() == '\t')) {
            content.pop_back();
        }
        if (!content.empty()) {
            uint32_t hash = simple_hash(content);
            char buf[16];
            snprintf(buf, sizeof(buf), "%08x", hash);
            return buf;
        }
    }
    return "";
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getHostsHashNative(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(compute_hosts_hash(false).c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getHostsHashSyscall(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(compute_hosts_hash(true).c_str());
}

// --- SELinux Fingerprint ---

static std::string collect_selinux_fp(bool use_syscall) {
    std::string enforce = use_syscall
        ? syscall_read_file("/sys/fs/selinux/enforce", 8)
        : read_file_native("/sys/fs/selinux/enforce", 8);
    while (!enforce.empty() && (enforce.back() == '\n' || enforce.back() == '\r' || enforce.back() == ' ')) {
        enforce.pop_back();
    }

    std::string context = use_syscall
        ? syscall_read_file("/proc/self/attr/current", 256)
        : read_file_native("/proc/self/attr/current", 256);
    while (!context.empty() && (context.back() == '\0' || context.back() == '\n' ||
           context.back() == '\r' || context.back() == ' ')) {
        context.pop_back();
    }

    // ⚠️ Enforcing 下 App 常被拒读 enforce（返回空）。空且有合法上下文 → 推断 Enforcing，
    //    不能直接当 Permissive（修复旧逻辑把"拒读"误报成 Permissive 的 bug）。
    std::string state;
    if (enforce == "1") state = "Enforcing";
    else if (enforce == "0") state = "Permissive";
    else state = (context.rfind("u:", 0) == 0) ? "Enforcing" : "Unknown";

    // Truncate at 3rd colon: "u:r:untrusted_app:s0:c512" -> "u:r:untrusted_app"
    int colonCount = 0;
    for (size_t i = 0; i < context.size(); i++) {
        if (context[i] == ':') {
            colonCount++;
            if (colonCount == 3) {
                context = context.substr(0, i);
                break;
            }
        }
    }

    return state + "|" + context;
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getSELinuxFingerprintNative(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(collect_selinux_fp(false).c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getSELinuxFingerprintSyscall(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(collect_selinux_fp(true).c_str());
}

// --- Process Cmdline (Package Name) ---

static std::string read_cmdline(bool use_syscall) {
    std::string cmdline = use_syscall
        ? syscall_read_file("/proc/self/cmdline", 256)
        : read_file_native("/proc/self/cmdline", 256);
    std::string clean;
    for (char c : cmdline) {
        if (c == '\0') break;
        clean += c;
    }
    while (!clean.empty() && (clean.back() == '\n' || clean.back() == '\r' || clean.back() == ' ')) {
        clean.pop_back();
    }
    return clean;
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getCmdlineNative(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(read_cmdline(false).c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getCmdlineSyscall(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(read_cmdline(true).c_str());
}

// ===================== Runtime Integrity Indicators =====================

// --- System Property mmap Direct Read ---

static std::string mmap_read_property(const char* prop_name) {
    const char* prop_files[] = {
        "/system/build.prop",
        "/vendor/build.prop",
        "/system/default.prop",
        "/vendor/default.prop",
        "/odm/build.prop"
    };

    std::string search_key = std::string(prop_name) + "=";

    for (const char* file : prop_files) {
        int fd = syscall_open(file, O_RDONLY);
        if (fd < 0) continue;

        struct stat st;
        if (syscall_stat(file, &st) != 0 || st.st_size <= 0) {
            syscall_close(fd);
            continue;
        }

        void* mapped = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        syscall_close(fd);

        if (mapped == MAP_FAILED) continue;

        std::string content((const char*)mapped, st.st_size);
        munmap(mapped, st.st_size);

        size_t pos = content.find(search_key);
        if (pos != std::string::npos) {
            size_t val_start = pos + search_key.length();
            size_t val_end = content.find('\n', val_start);
            std::string val = (val_end != std::string::npos)
                ? content.substr(val_start, val_end - val_start)
                : content.substr(val_start);
            while (!val.empty() && (val.back() == '\r' || val.back() == ' ')) {
                val.pop_back();
            }
            if (!val.empty()) return val;
        }
    }
    return "";
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getPropertyMmap(JNIEnv *env, jobject thiz, jstring propName) {
    const char* name = env->GetStringUTFChars(propName, nullptr);
    std::string val = mmap_read_property(name);
    env->ReleaseStringUTFChars(propName, name);
    return env->NewStringUTF(val.c_str());
}

JNIEXPORT jint JNICALL
Java_com_xff_launch_detector_NativeDetector_checkPropertyMmapConsistency(JNIEnv *env, jobject thiz) {
    const char* keys[] = {
        "ro.serialno",
        "ro.product.model",
        "ro.product.brand",
        "ro.build.fingerprint",
        "ro.product.device"
    };

    int mismatch = 0;
    for (const char* key : keys) {
        char native_val[256] = {0};
        __system_property_get(key, native_val);

        std::string mmap_val = mmap_read_property(key);

        if (!mmap_val.empty() && strlen(native_val) > 0) {
            if (mmap_val != std::string(native_val)) {
                mismatch++;
            }
        }
    }
    return mismatch;
}

// --- /dev/__properties__ Direct Binary mmap Read ---
//
// Bionic 的属性服务以 trie 结构把每条属性记录组织在 /dev/__properties__ 下的
// per-context 文件里 (u:object_r:<ctx>:s0)。每条 prop_info 记录的二进制布局：
//   uint32_t serial                 // 高位 flags，bit 16 (0x10000) 表示 hidden/pending
//   char     value[DEV_PROP_VALUE_MAX]  // 92 字节，null 结尾
//   char     name[]                 // 变长 key，null 结尾
// 文件头 44 字节：4 ints (serial / reserved / magic 'PROP' / version) + 28 bytes reserved。
//
// 通过 syscall_open + mmap 直接读 prop_info 内存，可以同时绕过：
//  · Java 层 SystemProperties.get() / Settings 的 hook
//  · libc 中 __system_property_get / __system_property_find 的 inline hook
// 仅 mmap 系统调用 + 字节扫描即可拿到真值。

static constexpr uint32_t PROP_FILE_MAGIC = 0x504F5250u;  // 'P','R','O','P' (LE)
// AOSP 实际使用 0xFC6ED0AB；JD c.java 里写的 0xFC6ED0CB 是另一个 fork 的值。两个都允许。
static constexpr uint32_t PROP_AREA_VERSION_A = 0xFC6ED0ABu;
static constexpr uint32_t PROP_AREA_VERSION_B = 0xFC6ED0CBu;
static constexpr size_t PROP_HEADER_SIZE = 44;            // 4 ints + 28 reserved
static constexpr size_t DEV_PROP_VALUE_MAX = 92;

static std::string scan_property_area(const uint8_t* data, size_t size, const std::string& key) {
    if (size < PROP_HEADER_SIZE + 96 + key.size() + 1) return "";

    uint32_t magic = 0, version = 0;
    memcpy(&magic, data + 8, 4);
    memcpy(&version, data + 12, 4);
    if (magic != PROP_FILE_MAGIC) return "";
    if (version != PROP_AREA_VERSION_A && version != PROP_AREA_VERSION_B) return "";

    const uint8_t* body = data + PROP_HEADER_SIZE;
    size_t body_size = size - PROP_HEADER_SIZE;
    const uint8_t* needle = reinterpret_cast<const uint8_t*>(key.data());
    size_t needle_len = key.size();

    if (body_size < needle_len + 96) return "";

    for (size_t i = 96; i + needle_len < body_size; i++) {
        if (body[i] != needle[0]) continue;                       // fast path
        if (memcmp(body + i, needle, needle_len) != 0) continue;
        if (body[i + needle_len] != 0) continue;                  // exact key match

        uint32_t flags = 0;
        memcpy(&flags, body + i - 96, 4);
        if ((flags & 0x10000u) != 0) continue;                    // hidden/pending

        const uint8_t* val_start = body + i - DEV_PROP_VALUE_MAX;
        size_t val_len = 0;
        while (val_len < DEV_PROP_VALUE_MAX && val_start[val_len] != 0) val_len++;
        return std::string(reinterpret_cast<const char*>(val_start), val_len);
    }
    return "";
}

// untrusted_app 通常允许直接 open /dev/__properties__/u:object_r:<ctx>:s0 文件，
// 但 readdir(/dev/__properties__) 会被 SELinux 拒。所以做两步：
//   1) 试图 getdents 枚举（root/system_app 可能可以）
//   2) 列举失败或没有结果时，回退到一份已知 context 名单逐个 try-open。
static const char* const KNOWN_PROP_CONTEXTS_C[] = {
        "u:object_r:default_prop:s0",
        "u:object_r:exported_default_prop:s0",
        "u:object_r:exported2_default_prop:s0",
        "u:object_r:exported3_default_prop:s0",
        "u:object_r:exported_secure_prop:s0",
        "u:object_r:exported_system_prop:s0",
        "u:object_r:public_readable_default_prop:s0",
        "u:object_r:userdebug_or_eng_prop:s0",
        "u:object_r:safemode_prop:s0",
        "u:object_r:build_prop:s0",
        "u:object_r:exported_secure_default_prop:s0",
        "u:object_r:system_prop:s0",
        "u:object_r:vendor_default_prop:s0",
        "u:object_r:vendor_security_patch_level_prop:s0",
        "u:object_r:init_service_status_prop:s0",
        "u:object_r:init_service_status_private_prop:s0",
        "u:object_r:debug_prop:s0",
        "u:object_r:exported_debug_prop:s0",
        "u:object_r:debuggerd_prop:s0",
        "u:object_r:device_logging_prop:s0",
        "u:object_r:usb_prop:s0",
        "u:object_r:usb_control_prop:s0",
        "u:object_r:adbd_prop:s0",
        "u:object_r:adbd_config_prop:s0",
        "u:object_r:adb_prop:s0",
        "u:object_r:adb_service_prop:s0",
        "u:object_r:ctl_adbd_prop:s0",
        "u:object_r:ffs_prop:s0",
        "u:object_r:bootloader_prop:s0",
        "u:object_r:dalvik_config_prop:s0",
        "u:object_r:exported_dalvik_prop:s0",
        "u:object_r:dalvik_prop:s0",
};

static std::string scan_file_for_key(const std::string& path, const std::string& key) {
    int fd = syscall_open(path.c_str(), O_RDONLY);
    if (fd < 0) return "";
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size <= (off_t)PROP_HEADER_SIZE) {
        syscall_close(fd);
        return "";
    }
    void* mapped = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    syscall_close(fd);
    if (mapped == MAP_FAILED) return "";
    std::string val = scan_property_area(
            static_cast<const uint8_t*>(mapped),
            static_cast<size_t>(st.st_size),
            key);
    munmap(mapped, st.st_size);
    return val;
}

static std::string read_dev_property_mmap(const std::string& key) {
    const char* root_path = "/dev/__properties__";

    // 旧版 Android（pre-O）属性区是单文件 —— 直接 try open。
    {
        std::string val = scan_file_for_key(root_path, key);
        if (!val.empty()) return val;
    }

    // 尝试 getdents 枚举所有 context 文件（root/system_app 通常允许）
    char buffer[8192];
    int n = syscall_getdents(root_path, buffer, sizeof(buffer));
    if (n > 0) {
        int pos = 0;
        while (pos < n) {
            auto* d = reinterpret_cast<linux_dirent64*>(buffer + pos);
            if (d->d_reclen == 0) break;
            const char* nm = d->d_name;
            if (nm[0] != '.' || (nm[1] != '\0' && (nm[1] != '.' || nm[2] != '\0'))) {
                std::string val = scan_file_for_key(std::string(root_path) + "/" + nm, key);
                if (!val.empty()) return val;
            }
            pos += d->d_reclen;
        }
    }

    // Fallback：untrusted_app readdir 被拒时，按已知 context 名字逐个 try-open
    for (const char* ctx : KNOWN_PROP_CONTEXTS_C) {
        std::string val = scan_file_for_key(std::string(root_path) + "/" + ctx, key);
        if (!val.empty()) return val;
    }

    return "";
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_readDevPropertyMmap(
        JNIEnv* env, jobject /*thiz*/, jstring propName) {
    if (propName == nullptr) return env->NewStringUTF("");
    const char* name = env->GetStringUTFChars(propName, nullptr);
    if (name == nullptr) return env->NewStringUTF("");
    std::string val = read_dev_property_mmap(name);
    env->ReleaseStringUTFChars(propName, name);
    return env->NewStringUTF(val.c_str());
}

// 直接读指定 SELinux context 的属性文件，例如 u:object_r:debug_prop:s0 / usb_prop:s0。
// ADB/调试开关绝大多数都在 debug_prop / usb_prop / adbd_prop 这几个上下文里，定向读比全目录
// 扫描快、且能避免不同 context 同名键的误匹配。
static std::string read_property_from_context(const std::string& key, const std::string& ctx_name) {
    std::string path = "/dev/__properties__/u:object_r:" + ctx_name + ":s0";
    int fd = syscall_open(path.c_str(), O_RDONLY);
    if (fd < 0) return "";
    // 使用 fstat(fd) 而非 stat(path)。untrusted_app 通常允许 open 这些 prop_file，但
    // 路径维度的 stat/readdir 可能被 SELinux 拒。fstat 走 fd 检查，能继续工作。
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size <= (off_t)PROP_HEADER_SIZE) {
        syscall_close(fd);
        return "";
    }
    void* mapped = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    syscall_close(fd);
    if (mapped == MAP_FAILED) return "";
    std::string val = scan_property_area(
            static_cast<const uint8_t*>(mapped),
            static_cast<size_t>(st.st_size),
            key);
    munmap(mapped, st.st_size);
    return val;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_readPropertyFromContext(
        JNIEnv* env, jobject /*thiz*/, jstring jKey, jstring jContext) {
    if (jKey == nullptr || jContext == nullptr) return env->NewStringUTF("");
    const char* key = env->GetStringUTFChars(jKey, nullptr);
    const char* ctx = env->GetStringUTFChars(jContext, nullptr);
    std::string val;
    if (key != nullptr && ctx != nullptr) {
        val = read_property_from_context(key, ctx);
    }
    if (key != nullptr) env->ReleaseStringUTFChars(jKey, key);
    if (ctx != nullptr) env->ReleaseStringUTFChars(jContext, ctx);
    return env->NewStringUTF(val.c_str());
}

// 诊断函数：对 /dev/__properties__ 下所有已知 context 文件依次尝试 openat，
// 返回每条路径的状态（ok / errno 名）。让用户看清楚到底是没文件还是被 SELinux 拒。
// 注意：ARM64 的 syscall_open 用 inline svc，不写 libc errno，需要直接读 syscall_raw 返回值。
extern "C" JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_probeDevPropertyAccess(
        JNIEnv* env, jobject /*thiz*/) {
    std::string out;
    auto errno_name = [](int e) -> const char* {
        switch (e) {
            case EACCES: return "EACCES";
            case EPERM:  return "EPERM";
            case ENOENT: return "ENOENT";
            case EISDIR: return "EISDIR";
            case ENOTDIR:return "ENOTDIR";
            case EMFILE: return "EMFILE";
            case ENFILE: return "ENFILE";
            case ENAMETOOLONG: return "ENAMETOOLONG";
            default:     return "ERR";
        }
    };
    auto try_open = [&](const char* path, int extraFlags, const char* tag) {
        long rc = syscall_raw(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | extraFlags, 0);
        if (rc >= 0) {
            struct stat st{};
            long size = -1;
            if (fstat((int)rc, &st) == 0) size = (long)st.st_size;
            syscall_close((int)rc);
            out += "[ok ] ";
            out += tag;
            out += " size=";
            out += std::to_string(size);
            out += "\n";
        } else {
            int err = (int)(-rc);
            out += "[err] ";
            out += tag;
            out += ": ";
            out += errno_name(err);
            out += "(";
            out += std::to_string(err);
            out += ")\n";
        }
    };

    try_open("/dev/__properties__", O_DIRECTORY, "/dev/__properties__ (dir)");
    try_open("/dev/__properties__", 0,           "/dev/__properties__ (file)");
    for (const char* ctx : KNOWN_PROP_CONTEXTS_C) {
        std::string path = "/dev/__properties__/";
        path += ctx;
        try_open(path.c_str(), 0, ctx);
    }
    return env->NewStringUTF(out.c_str());
}

// --- /dev/urandom Integrity Check ---

static std::string read_urandom_hex(bool use_syscall) {
    unsigned char buf[16] = {0};
    if (use_syscall) {
        int fd = syscall_open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            syscall_read(fd, buf, 16);
            syscall_close(fd);
        }
    } else {
        FILE* fp = fopen("/dev/urandom", "rb");
        if (fp) {
            fread(buf, 1, 16, fp);
            fclose(fp);
        }
    }
    char hex[33] = {0};
    for (int i = 0; i < 16; i++) {
        snprintf(hex + i * 2, 3, "%02x", buf[i]);
    }
    return hex;
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_readUrandomNative(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(read_urandom_hex(false).c_str());
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_readUrandomSyscall(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(read_urandom_hex(true).c_str());
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkUrandomIntegrity(JNIEnv *env, jobject thiz) {
    std::string r1 = read_urandom_hex(true);
    std::string r2 = read_urandom_hex(true);
    std::string r3 = read_urandom_hex(true);

    bool all_zero = (r1 == "00000000000000000000000000000000");
    bool all_same = (r1 == r2 && r2 == r3);

    return (jboolean)(all_zero || all_same);
}

// ===================== System Library Integrity Detection =====================

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkLibcIntegrity(JNIEnv *env, jobject thiz) {
    return IntegrityDetector::checkLibcIntegrity();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkLibartIntegrity(JNIEnv *env, jobject thiz) {
    return IntegrityDetector::checkLibartIntegrity();
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkAndroidRuntimeIntegrity(JNIEnv *env, jobject thiz) {
    return IntegrityDetector::checkAndroidRuntimeIntegrity();
}

JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_checkAllSystemLibrariesIntegrity(JNIEnv *env, jobject thiz) {
    std::string report = IntegrityDetector::getIntegrityReport();
    return env->NewStringUTF(report.c_str());
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkLibraryIntegrity(JNIEnv *env, jobject thiz, jstring libName) {
    const char* lib_str = env->GetStringUTFChars(libName, nullptr);
    bool result = IntegrityDetector::checkLibraryIntegrity(lib_str);
    env->ReleaseStringUTFChars(libName, lib_str);
    return result;
}

JNIEXPORT jboolean JNICALL
Java_com_xff_launch_detector_NativeDetector_checkFunctionHook(JNIEnv *env, jobject thiz,
                                                               jstring libName, jstring funcName) {
    const char* lib_str = env->GetStringUTFChars(libName, nullptr);
    const char* func_str = env->GetStringUTFChars(funcName, nullptr);
    bool result = IntegrityDetector::checkFunctionHook(lib_str, func_str);
    env->ReleaseStringUTFChars(libName, lib_str);
    env->ReleaseStringUTFChars(funcName, func_str);
    return result;
}

// ===================== Vulkan 硬件指纹 =====================
// 通过 dlopen libvulkan.so 枚举物理设备，读取 VkPhysicalDeviceProperties 与
// VkPhysicalDeviceIDProperties.deviceUUID。deviceUUID 规范保证跨重启/进程/驱动版本不变。
// 输出: "vendorID|deviceID|driverVersion|deviceUUID|driverUUID"
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getVulkanFingerprintNative(JNIEnv *env, jobject thiz) {
    (void) thiz;
    void* lib = dlopen("libvulkan.so", RTLD_NOW | RTLD_LOCAL);
    if (!lib) return env->NewStringUTF("");

    auto pfnCreate = (PFN_vkCreateInstance) dlsym(lib, "vkCreateInstance");
    auto pfnEnum = (PFN_vkEnumeratePhysicalDevices) dlsym(lib, "vkEnumeratePhysicalDevices");
    auto pfnProps2 = (PFN_vkGetPhysicalDeviceProperties2) dlsym(lib, "vkGetPhysicalDeviceProperties2");
    auto pfnProps = (PFN_vkGetPhysicalDeviceProperties) dlsym(lib, "vkGetPhysicalDeviceProperties");
    auto pfnDestroy = (PFN_vkDestroyInstance) dlsym(lib, "vkDestroyInstance");
    if (!pfnCreate || !pfnEnum || !pfnProps) {
        dlclose(lib);
        return env->NewStringUTF("");
    }

    std::string result;
    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.apiVersion = VK_API_VERSION_1_1;
    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &appInfo;

    VkInstance inst = VK_NULL_HANDLE;
    if (pfnCreate(&ci, nullptr, &inst) == VK_SUCCESS && inst != VK_NULL_HANDLE) {
        uint32_t count = 0;
        pfnEnum(inst, &count, nullptr);
        if (count > 0) {
            std::vector<VkPhysicalDevice> devs(count);
            pfnEnum(inst, &count, devs.data());
            char buf[600];
            if (pfnProps2) {
                VkPhysicalDeviceIDProperties idp{};
                idp.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES;
                VkPhysicalDeviceProperties2 p2{};
                p2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
                p2.pNext = &idp;
                pfnProps2(devs[0], &p2);
                char devUuid[33], drvUuid[33];
                for (int i = 0; i < VK_UUID_SIZE; i++) snprintf(devUuid + i * 2, 3, "%02x", idp.deviceUUID[i]);
                for (int i = 0; i < VK_UUID_SIZE; i++) snprintf(drvUuid + i * 2, 3, "%02x", idp.driverUUID[i]);
                snprintf(buf, sizeof(buf), "%u|%u|%u|%s|%s",
                         p2.properties.vendorID, p2.properties.deviceID,
                         p2.properties.driverVersion, devUuid, drvUuid);
            } else {
                VkPhysicalDeviceProperties p{};
                pfnProps(devs[0], &p);
                snprintf(buf, sizeof(buf), "%u|%u|%u", p.vendorID, p.deviceID, p.driverVersion);
            }
            result = buf;
        }
        if (pfnDestroy) pfnDestroy(inst, nullptr);
    }
    dlclose(lib);
    return env->NewStringUTF(result.c_str());
}

// ===================== Widevine DRM Device ID (native JNI reflection) =====================

// 在 native 侧用 JNI 反射调用 MediaDrm.getPropertyByteArray("deviceUniqueId")，
// 绕过 Java 层对 MediaDrm 的 hook。与 Java 侧 drm_id 同源，服务端/本地交叉校验：
// 两路 hex 不一致 → 暴露 Java 层 MediaDrm hook。
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getDrmDeviceIdNative(JNIEnv *env, jobject thiz) {
    (void) thiz;
    // 任一步抛异常即清理并返回空串
    #define DRM_FAIL() do { if (env->ExceptionCheck()) env->ExceptionClear(); return env->NewStringUTF(""); } while (0)

    // Widevine 标准 UUID = EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED
    const jlong msb = (jlong) 0xEDEF8BA979D64ACEULL;
    const jlong lsb = (jlong) 0xA3C827DCD51D21EDULL;

    // 1) new java.util.UUID(msb, lsb)
    jclass uuidCls = env->FindClass("java/util/UUID");
    if (env->ExceptionCheck() || !uuidCls) DRM_FAIL();
    jmethodID uuidCtor = env->GetMethodID(uuidCls, "<init>", "(JJ)V");
    if (env->ExceptionCheck() || !uuidCtor) DRM_FAIL();
    jobject uuid = env->NewObject(uuidCls, uuidCtor, msb, lsb);
    if (env->ExceptionCheck() || !uuid) DRM_FAIL();

    // 2) new android.media.MediaDrm(uuid)
    jclass drmCls = env->FindClass("android/media/MediaDrm");
    if (env->ExceptionCheck() || !drmCls) DRM_FAIL();
    jmethodID drmCtor = env->GetMethodID(drmCls, "<init>", "(Ljava/util/UUID;)V");
    if (env->ExceptionCheck() || !drmCtor) DRM_FAIL();
    jobject drm = env->NewObject(drmCls, drmCtor, uuid);
    if (env->ExceptionCheck() || !drm) DRM_FAIL();

    // 3) byte[] getPropertyByteArray("deviceUniqueId")
    jmethodID getProp = env->GetMethodID(drmCls, "getPropertyByteArray", "(Ljava/lang/String;)[B");
    if (env->ExceptionCheck() || !getProp) DRM_FAIL();
    jstring key = env->NewStringUTF("deviceUniqueId");
    jbyteArray arr = (jbyteArray) env->CallObjectMethod(drm, getProp, key);
    bool threw = env->ExceptionCheck();

    std::string hex;
    if (!threw && arr) {
        jsize len = env->GetArrayLength(arr);
        jbyte *bytes = env->GetByteArrayElements(arr, nullptr);
        if (bytes && len > 0) {
            static const char *HEX = "0123456789abcdef";
            hex.reserve(len * 2);
            for (jsize i = 0; i < len; i++) {
                unsigned char b = (unsigned char) bytes[i];
                hex.push_back(HEX[b >> 4]);
                hex.push_back(HEX[b & 0x0F]);
            }
            env->ReleaseByteArrayElements(arr, bytes, JNI_ABORT);
        }
    }
    if (env->ExceptionCheck()) env->ExceptionClear();

    // 4) 释放 MediaDrm：close()(API28+) 优先，否则 release()
    jmethodID closeM = env->GetMethodID(drmCls, "close", "()V");
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (closeM) {
        env->CallVoidMethod(drm, closeM);
    } else {
        jmethodID releaseM = env->GetMethodID(drmCls, "release", "()V");
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (releaseM) env->CallVoidMethod(drm, releaseM);
    }
    if (env->ExceptionCheck()) env->ExceptionClear();

    return env->NewStringUTF(hex.c_str());
    #undef DRM_FAIL
}

// ===================== Wi-Fi 接入信息 (native JNI reflection) =====================

// 在 native 侧用 JNI 反射调用 WifiManager.getConnectionInfo().getBSSID()/getSSID()，
// 绕过 Java 层对 android.net.wifi.WifiInfo 的 hook。对照 JD field 7-2(native) vs 7-3(Java)：
// 两路 BSSID 不一致 → 暴露 Java 层 WifiInfo hook。返回 "BSSID|SSID"。
JNIEXPORT jstring JNICALL
Java_com_xff_launch_detector_NativeDetector_getWifiInfoNative(JNIEnv *env, jobject thiz, jobject ctx) {
    (void) thiz;
    #define WIFI_FAIL() do { if (env->ExceptionCheck()) env->ExceptionClear(); return env->NewStringUTF(""); } while (0)
    if (!ctx) return env->NewStringUTF("");

    // ctx.getSystemService("wifi")
    jclass ctxCls = env->GetObjectClass(ctx);
    if (env->ExceptionCheck() || !ctxCls) WIFI_FAIL();
    jmethodID getSvc = env->GetMethodID(ctxCls, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
    if (env->ExceptionCheck() || !getSvc) WIFI_FAIL();
    jstring svcName = env->NewStringUTF("wifi");
    jobject wm = env->CallObjectMethod(ctx, getSvc, svcName);
    if (env->ExceptionCheck() || !wm) WIFI_FAIL();

    // wm.getConnectionInfo() -> WifiInfo
    jclass wmCls = env->FindClass("android/net/wifi/WifiManager");
    if (env->ExceptionCheck() || !wmCls) WIFI_FAIL();
    jmethodID getConn = env->GetMethodID(wmCls, "getConnectionInfo", "()Landroid/net/wifi/WifiInfo;");
    if (env->ExceptionCheck() || !getConn) WIFI_FAIL();
    jobject wi = env->CallObjectMethod(wm, getConn);
    if (env->ExceptionCheck() || !wi) WIFI_FAIL();

    // wi.getBSSID() / wi.getSSID()
    jclass wiCls = env->FindClass("android/net/wifi/WifiInfo");
    if (env->ExceptionCheck() || !wiCls) WIFI_FAIL();
    jmethodID getBssid = env->GetMethodID(wiCls, "getBSSID", "()Ljava/lang/String;");
    jmethodID getSsid = env->GetMethodID(wiCls, "getSSID", "()Ljava/lang/String;");
    if (env->ExceptionCheck() || !getBssid || !getSsid) WIFI_FAIL();

    std::string result;
    jstring bssid = (jstring) env->CallObjectMethod(wi, getBssid);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (bssid) {
        const char *b = env->GetStringUTFChars(bssid, nullptr);
        if (b) { result += b; env->ReleaseStringUTFChars(bssid, b); }
    }
    result += "|";
    jstring ssid = (jstring) env->CallObjectMethod(wi, getSsid);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (ssid) {
        const char *s = env->GetStringUTFChars(ssid, nullptr);
        if (s) { result += s; env->ReleaseStringUTFChars(ssid, s); }
    }

    return env->NewStringUTF(result.c_str());
    #undef WIFI_FAIL
}

// ===================== Compatibility Method =====================

JNIEXPORT jstring JNICALL
Java_com_xff_launch_MainActivity_stringFromJNI(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF("Launch - 设备环境检测");
}

} // extern "C"
