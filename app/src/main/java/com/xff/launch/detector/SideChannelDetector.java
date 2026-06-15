package com.xff.launch.detector;

import android.content.Context;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;
import com.xff.launch.util.ReflectionUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * 运行时完整性检测 (Runtime Integrity Detection)
 *
 * 检测维度:
 * 1. SELinux 安全状态
 * 2. 系统库代码完整性 (libc/libart/libandroid_runtime 磁盘-内存比对)
 * 3. 函数级 Inline Hook 检测 (检测函数序言是否被篡改)
 * 4. GOT/PLT Hook 检测 (检测全局偏移表是否被修改)
 * 5. RWX 匿名内存检测 (代码注入标志)
 * 6. Syscall vs Libc 时序分析 (辅助验证 Hook 存在)
 *
 * 技术原理参考: 阿里 sgmain SecGuard SDK 逆向分析
 * - Stage 13: libc.so ELF 符号表完整性校验 (19 个关键函数 hash 比对)
 * - Stage 6:  linker + libdl.so ELF header 校验
 * - 338 轮循环扫描, 每轮 4 个 SO × 19 个函数
 */
public class SideChannelDetector {

    private final Context context;
    private final NativeDetector nativeDetector;

    public SideChannelDetector(Context context) {
        this.context = context;
        this.nativeDetector = NativeDetector.getInstance();
    }

    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();

        // 1. SELinux 安全状态
        items.add(checkSELinux());

        // 1b. SELinux 文件标签 (lgetxattr — Magisk 改文件 context 异常)
        items.add(checkSELinuxFileLabels());

        // 2. 系统库代码完整性 (核心检测 - 对齐 sgmain Stage 13)
        items.add(checkSystemLibIntegrity());

        // 3. 函数级 Inline Hook 检测
        items.add(checkInlineHooks());

        // 4. GOT/PLT Hook 检测
        items.add(checkGotPltHooks());

        // 5. RWX 匿名内存区域检测
        items.add(checkAnonymousRwxMemory());

        // 6. Syscall 时序分析 (综合, 不再拆成 3 个独立项)
        items.add(checkSyscallTiming());

        return items;
    }

    // ===================== 1. SELinux 检测 =====================

    private DetectionItem checkSELinux() {
        DetectionItem item = new DetectionItem("SELinux 状态", "强制模式 + 进程上下文 + 反伪造交叉");

        // --- 1) 进程上下文（先取，用于状态推断 + 异常判定）---
        String ctx = trimOrEmpty(nativeDetector.getSELinuxContextNative());
        if (ctx.isEmpty()) ctx = trimOrEmpty(nativeDetector.readFileSyscall("/proc/self/attr/current"));
        String domain = seDomain(ctx);
        boolean hasCtx = !domain.isEmpty();
        boolean rootCtx = !ctx.isEmpty() && (domain.equals("su") || domain.contains("magisk")
                || domain.equals("shell") || ctx.contains(":su:") || ctx.toLowerCase().contains("magisk"));
        boolean missingCat = !ctx.isEmpty() && domain.startsWith("untrusted_app") && !hasCategory(ctx);

        // --- 2) enforce 状态：syscall + Java 双路 ---
        // ⚠️ Enforcing 下 untrusted_app 常被拒读 /sys/fs/selinux/enforce（读返回空）。
        //    "读被拒 + 有合法 SELinux 上下文" → 推断 Enforcing（Permissive 不会拒读）。
        String enfSys = trimOrEmpty(nativeDetector.readFileSyscall("/sys/fs/selinux/enforce"));
        String enfJava = trimOrEmpty(ReflectionUtils.readFileFirstLine("/sys/fs/selinux/enforce"));
        boolean mounted = nativeDetector.fileExistsSyscall("/sys/fs/selinux/enforce")
                || nativeDetector.fileExistsSyscall("/sys/fs/selinux");
        String enf = !enfSys.isEmpty() ? enfSys : enfJava;

        String state;
        boolean inferred = false;
        if ("1".equals(enf)) state = "Enforcing";
        else if ("0".equals(enf)) state = "Permissive";
        else if (hasCtx) { state = "Enforcing"; inferred = true; }  // 拒读 + 有上下文 → 推断强制
        else if (mounted) state = "Unknown";
        else state = "Disabled";

        // --- 3) 反伪造交叉：运行时 enforce vs 启动参数/命令行 ---
        String bootSel = trimOrEmpty(nativeDetector.getBuildPropertyNative("ro.boot.selinux")).toLowerCase();
        String cmdlineSel = trimOrEmpty(nativeDetector.getBootParamSyscall("androidboot.selinux")).toLowerCase();
        boolean bootSaysPermissive = bootSel.contains("permissive") || cmdlineSel.contains("permissive");
        // 运行时显示强制，但启动参数是 permissive → 疑似 setenforce 0 后 resetprop 伪造
        boolean spoof = "Enforcing".equals(state) && bootSaysPermissive;

        // --- 4) enforce 可写探测（应用本不该可写）---
        boolean enforceWritable = false;
        try {
            enforceWritable = mounted && new File("/sys/fs/selinux/enforce").canWrite();
        } catch (Exception ignored) {}

        boolean risk = "Permissive".equals(state) || "Disabled".equals(state) || rootCtx || spoof || enforceWritable;
        boolean warn = "Unknown".equals(state) || missingCat;

        // 明细
        item.addDetectionDetail("Enforcing".equals(state) ? "🔒 enforce" : "🔓 enforce",
                "/sys/fs/selinux/enforce",
                "syscall=" + (enfSys.isEmpty() ? "拒读/N/A" : enfSys) + " java=" + (enfJava.isEmpty() ? "拒读/N/A" : enfJava)
                        + " → " + state + (inferred ? " (推断:拒读=强制)" : ""),
                DetectionLayer.SYSCALL, "Enforcing".equals(state) ? "🟢" : "🔴");
        if (!ctx.isEmpty()) {
            item.addDetectionDetail(rootCtx ? "⚠️ 进程上下文" : (missingCat ? "🟡 进程上下文" : "🏷️ 进程上下文"),
                    ctx,
                    rootCtx ? "root/shell 上下文 — 以特权运行" : (missingCat ? "缺 category，上下文异常" : "当前进程 SELinux 上下文 (域: " + domain + ")"),
                    DetectionLayer.NATIVE, rootCtx ? "🔴" : (missingCat ? "🟡" : "🟢"));
        }
        if (!bootSel.isEmpty()) item.addDetectionDetail("⚙️ ro.boot.selinux", bootSel, "启动参数", DetectionLayer.NATIVE, "🔧");
        if (!cmdlineSel.isEmpty()) item.addDetectionDetail("📋 androidboot.selinux", cmdlineSel, "内核命令行", DetectionLayer.SYSCALL, "🔧");
        if (spoof) item.addDetectionDetail("⚠️ 伪造嫌疑", "运行时 Enforcing 但启动为 permissive",
                "疑似 setenforce 0 + resetprop 伪造 enforce", DetectionLayer.SYSCALL, "🔴");
        if (enforceWritable) item.addDetectionDetail("⚠️ enforce 可写", "/sys/fs/selinux/enforce",
                "应用可写 enforce — 异常（已 root / 无 SELinux 约束）", DetectionLayer.SYSCALL, "🔴");

        item.setLayerResult(DetectionLayer.JAVA, risk);
        item.setLayerResult(DetectionLayer.NATIVE, risk);
        item.setLayerResult(DetectionLayer.SYSCALL, risk);

        if (risk) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail(rootCtx ? ("进程以特权上下文运行: " + domain)
                    : spoof ? "SELinux 状态疑似被伪造"
                    : enforceWritable ? "enforce 可写（无 SELinux 约束）"
                    : ("SELinux " + state + " (非强制)"));
        } else if (warn) {
            item.setStatus(DetectionStatus.WARNING);
            item.setDetail(missingCat ? "进程上下文缺 category（异常）" : "SELinux 状态未知（受限不可读）");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("Enforcing 模式" + (domain.isEmpty() ? "" : " (" + domain + ")"));
        }
        return item;
    }

    // ===================== 1b. SELinux 文件标签 =====================

    /**
     * 用 lgetxattr 读关键文件的 SELinux 标签（security.selinux）。
     * Magisk magic mount / overlay 改过的文件 context 会带 magisk/su 标记。
     * 仅对明确的 magisk/su_exec 标记报警，避免不同 ROM 标签差异导致误报。
     */
    private DetectionItem checkSELinuxFileLabels() {
        DetectionItem item = new DetectionItem("SELinux 文件标签", "关键文件 security.selinux 标签 (Magisk 改文件 context 异常)");
        String[] paths = {
                "/system/bin/app_process64",
                "/system/build.prop",
                "/system/bin/sh",
                context.getApplicationInfo().sourceDir,
        };
        boolean anomaly = false;
        int readCount = 0;
        for (String path : paths) {
            if (path == null || path.isEmpty()) continue;
            String label = trimOrEmpty(nativeDetector.getFileSelinuxContextNative(path));
            if (label.isEmpty()) continue;
            readCount++;
            String low = label.toLowerCase();
            boolean bad = low.contains("magisk") || low.contains("su_exec") || low.contains(":su:");
            if (bad) anomaly = true;
            item.addDetectionDetail(bad ? "⚠️ " + path : "🏷️ " + path, label,
                    bad ? "含 Magisk/su 标记 — 文件被改" : "SELinux 标签", DetectionLayer.NATIVE, bad ? "🔴" : "🟢");
        }

        item.setLayerResult(DetectionLayer.JAVA, anomaly);
        item.setLayerResult(DetectionLayer.NATIVE, anomaly);
        item.setLayerResult(DetectionLayer.SYSCALL, anomaly);
        if (anomaly) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("关键文件 SELinux 标签含 Magisk/su 标记");
        } else if (readCount == 0) {
            item.setStatus(DetectionStatus.UNKNOWN);
            item.setDetail("无法读取文件 SELinux 标签");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("关键文件 SELinux 标签正常 (" + readCount + " 项)");
        }
        return item;
    }

    private static String trimOrEmpty(String s) {
        return s == null ? "" : s.trim();
    }

    /** 从 "u:r:DOMAIN:s0:c.." 取 type/domain（第3段）。 */
    private static String seDomain(String ctx) {
        if (ctx == null || ctx.isEmpty()) return "";
        String[] p = ctx.split(":");
        return p.length >= 3 ? p[2] : "";
    }

    /** untrusted_app 正常应带 MLS category（第5段以 c 开头，如 :s0:c107,c257）。 */
    private static boolean hasCategory(String ctx) {
        if (ctx == null) return false;
        String[] p = ctx.split(":");
        return p.length >= 5 && p[4].startsWith("c");
    }

    // ===================== 2. 系统库代码完整性 =====================

    /**
     * 系统库代码完整性校验 — 对齐 sgmain Stage 13
     *
     * 原理: 通过 Native 层比对系统 SO 在磁盘上的原始字节与内存中的运行时字节。
     * 如果 Frida/Xposed/LSPosed 做了 inline hook, 内存中的代码段会被修改,
     * 与磁盘文件不一致。
     *
     * sgmain 检测的 4 个核心库:
     * - libc.so: open/openat/read/access/stat 等 (被 Frida PLT hook)
     * - libart.so: InvokeXposedHandleHookedMethod 等 (被 Xposed/LSPosed hook)
     * - libandroid_runtime.so: Zygote 相关函数
     * - libselinux.so: selinux_android_setcontext
     */
    private DetectionItem checkSystemLibIntegrity() {
        DetectionItem item = new DetectionItem("系统库完整性", "libc/libart/libandroid_runtime 磁盘-内存比对");

        boolean libcTampered = false;
        boolean libartTampered = false;
        boolean runtimeTampered = false;

        // libc.so 完整性
        // NOTE: Native层 checkLibcIntegrity() 返回 true = clean (没被hook)
        // 所以 tampered = !result
        try {
            boolean libcClean = nativeDetector.checkLibcIntegrity();
            libcTampered = !libcClean;
            item.addDetectionDetail(
                libcTampered ? "⚠️ libc.so" : "✅ libc.so",
                libcTampered ? "代码被篡改" : "代码完整",
                "检测 open/openat/read/access/stat 等关键函数",
                DetectionLayer.NATIVE,
                libcTampered ? "🔴" : "🟢");
        } catch (Exception e) {
            item.addDetectionDetail("❓ libc.so", "检测异常", e.getMessage(), DetectionLayer.NATIVE, "⚪");
        }

        // libart.so 完整性
        try {
            boolean libartClean = nativeDetector.checkLibartIntegrity();
            libartTampered = !libartClean;
            item.addDetectionDetail(
                libartTampered ? "⚠️ libart.so" : "✅ libart.so",
                libartTampered ? "代码被篡改" : "代码完整",
                "检测 ART 运行时函数 (Xposed/LSPosed hook 目标)",
                DetectionLayer.NATIVE,
                libartTampered ? "🔴" : "🟢");
        } catch (Exception e) {
            item.addDetectionDetail("❓ libart.so", "检测异常", e.getMessage(), DetectionLayer.NATIVE, "⚪");
        }

        // libandroid_runtime.so 完整性
        try {
            boolean runtimeClean = nativeDetector.checkAndroidRuntimeIntegrity();
            runtimeTampered = !runtimeClean;
            item.addDetectionDetail(
                runtimeTampered ? "⚠️ libandroid_runtime.so" : "✅ libandroid_runtime.so",
                runtimeTampered ? "代码被篡改" : "代码完整",
                "检测 Zygote 相关函数",
                DetectionLayer.NATIVE,
                runtimeTampered ? "🔴" : "🟢");
        } catch (Exception e) {
            item.addDetectionDetail("❓ libandroid_runtime.so", "检测异常", e.getMessage(), DetectionLayer.NATIVE, "⚪");
        }

        // 综合报告
        String fullReport = null;
        try {
            fullReport = nativeDetector.checkAllSystemLibrariesIntegrity();
            if (fullReport != null && !fullReport.isEmpty()) {
                item.addDetectionDetail("📋 完整报告", "全量检测结果", fullReport, DetectionLayer.NATIVE, "📊");
            }
        } catch (Exception ignored) {}

        boolean anyTampered = libcTampered || libartTampered || runtimeTampered;

        item.setLayerResult(DetectionLayer.JAVA, false);
        item.setLayerResult(DetectionLayer.NATIVE, anyTampered);
        item.setLayerResult(DetectionLayer.SYSCALL, anyTampered);

        if (anyTampered) {
            item.setStatus(DetectionStatus.RISK);
            StringBuilder sb = new StringBuilder("检测到系统库被篡改:");
            if (libcTampered) sb.append(" libc");
            if (libartTampered) sb.append(" libart");
            if (runtimeTampered) sb.append(" runtime");
            item.setDetail(sb.toString());
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("系统库代码段完整 (libc/libart/runtime)");
        }

        return item;
    }

    // ===================== 3. 函数级 Inline Hook 检测 =====================

    /**
     * 函数序言检测 — 检测关键函数入口是否被替换为跳转指令
     *
     * ARM64 inline hook 典型模式:
     *   LDR X16, #8; BR X16; <target_addr>  (16字节替换)
     *   或 MOV X16, imm; MOVK X16, imm; BR X16
     *
     * 检测方法: 读取函数前 16-32 字节, 检查是否包含非预期的跳转指令
     */
    private DetectionItem checkInlineHooks() {
        DetectionItem item = new DetectionItem("Inline Hook 检测", "检测关键函数序言是否被跳转指令替换");

        boolean inlineDetected = false;
        boolean libcHooked = false;
        boolean artHooked = false;

        // 通用 inline hook 检测
        try {
            inlineDetected = nativeDetector.checkInlineHooksSyscall();
            if (inlineDetected) {
                item.addDetectionDetail("⚠️ Inline Hook", "检测到跳转指令替换",
                    "函数入口被修改为 trampoline 跳转", DetectionLayer.SYSCALL, "🔴");
            }
        } catch (Exception ignored) {}

        // libc 函数 hook 检测
        try {
            libcHooked = nativeDetector.checkLibcHooksSyscall();
            item.addDetectionDetail(
                libcHooked ? "⚠️ libc Hooks" : "✅ libc Hooks",
                libcHooked ? "libc 函数被 hook" : "libc 函数正常",
                "检测 open/read/access/stat/connect 等",
                DetectionLayer.SYSCALL,
                libcHooked ? "🔴" : "🟢");
        } catch (Exception ignored) {}

        // ART hook 检测
        try {
            artHooked = nativeDetector.checkArtHooksSyscall();
            item.addDetectionDetail(
                artHooked ? "⚠️ ART Hooks" : "✅ ART Hooks",
                artHooked ? "ART 函数被 hook" : "ART 函数正常",
                "检测 ART 虚拟机内部函数",
                DetectionLayer.SYSCALL,
                artHooked ? "🔴" : "🟢");
        } catch (Exception ignored) {}

        // 特定函数 hook 检测
        // 包含 dlopen/android_dlopen_ext — Frida 常见 hook 目标
        String[][] criticalFunctions = {
            {"libc.so", "open"},
            {"libc.so", "openat"},
            {"libc.so", "read"},
            {"libc.so", "access"},
            {"libc.so", "stat"},
            {"libc.so", "connect"},
            {"libc.so", "dlopen"},
            {"libc.so", "dlsym"},
            {"libdl.so", "dlopen"},
            {"libdl.so", "dlsym"},
            {"libdl.so", "android_dlopen_ext"},
            {"libc.so", "mmap"},
            {"libc.so", "mprotect"},
            {"libc.so", "ptrace"}
        };

        int hookedCount = 0;
        for (String[] func : criticalFunctions) {
            try {
                boolean hooked = nativeDetector.checkFunctionHook(func[0], func[1]);
                if (hooked) {
                    hookedCount++;
                    item.addDetectionDetail("🎯 " + func[0] + ":" + func[1],
                        "函数被 hook", "序言指令被替换",
                        DetectionLayer.NATIVE, "⚠️");
                }
            } catch (Exception ignored) {}
        }

        boolean anyHooked = inlineDetected || libcHooked || artHooked || hookedCount > 0;

        item.setLayerResult(DetectionLayer.JAVA, false);
        item.setLayerResult(DetectionLayer.NATIVE, anyHooked);
        item.setLayerResult(DetectionLayer.SYSCALL, inlineDetected || libcHooked || artHooked);

        if (anyHooked) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail(String.format("检测到 Inline Hook (%d 个函数被篡改)", hookedCount));
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("关键函数序言完整, 未检测到 Inline Hook");
        }

        return item;
    }

    // ===================== 4. GOT/PLT Hook 检测 =====================

    /**
     * GOT/PLT 表完整性检测
     *
     * 原理: Frida Interceptor 通过修改 GOT 表项, 将函数指针重定向到 hook handler。
     * 检测方法: 验证 GOT 表中的函数指针是否指向对应 SO 的 .text 段范围。
     * 如果 GOT[open] 指向匿名 mmap 区域而非 libc.so, 则被 PLT hook。
     */
    private DetectionItem checkGotPltHooks() {
        DetectionItem item = new DetectionItem("GOT/PLT 检测", "检测全局偏移表是否被修改 (PLT Hook)");

        boolean memoryHooksNative = false;
        boolean memoryHooksSyscall = false;
        boolean libraryHooks = false;

        try {
            memoryHooksNative = nativeDetector.checkMemoryHooksNative();
            if (memoryHooksNative) {
                item.addDetectionDetail("⚠️ 内存 Hook (Native)", "检测到 GOT/PLT 修改",
                    "通过 Native 层检测到函数指针重定向", DetectionLayer.NATIVE, "🔴");
            }
        } catch (Exception ignored) {}

        try {
            memoryHooksSyscall = nativeDetector.checkMemoryHooksSyscall();
            if (memoryHooksSyscall) {
                item.addDetectionDetail("⚠️ 内存 Hook (Syscall)", "检测到 GOT/PLT 修改",
                    "通过 Syscall 层检测到函数指针重定向", DetectionLayer.SYSCALL, "🔴");
            }
        } catch (Exception ignored) {}

        // NOTE: checkLibraryHooksNative() returns true = clean (no hooks), false = hooked
        try {
            boolean libClean = nativeDetector.checkLibraryHooksNative();
            libraryHooks = !libClean;
            if (libraryHooks) {
                item.addDetectionDetail("⚠️ 库函数 Hook", "检测到系统库函数被劫持",
                    "内存中发现 Dobby/Whale/SandHook/Pine/Substrate/Frida", DetectionLayer.NATIVE, "🔴");
            }
        } catch (Exception ignored) {}

        // SMAPS 完整性检测 (检测 .text 段的 Private_Dirty 页)
        boolean smapsTampered = false;
        try {
            smapsTampered = nativeDetector.checkSmapsIntegrity();
            if (smapsTampered) {
                item.addDetectionDetail("⚠️ SMAPS 异常", "代码段有脏页",
                    "r-xp 代码段出现 Private_Dirty > 0, 表明代码被修改 (Inline Hook)",
                    DetectionLayer.NATIVE, "🔴");
            } else {
                item.addDetectionDetail("✅ SMAPS", "代码段干净",
                    "r-xp 代码段无脏页", DetectionLayer.NATIVE, "🟢");
            }
        } catch (Exception ignored) {}

        boolean anyHooked = memoryHooksNative || memoryHooksSyscall || libraryHooks || smapsTampered;

        item.setLayerResult(DetectionLayer.JAVA, false);
        item.setLayerResult(DetectionLayer.NATIVE, memoryHooksNative || libraryHooks || smapsTampered);
        item.setLayerResult(DetectionLayer.SYSCALL, memoryHooksSyscall);

        if (anyHooked) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 GOT/PLT 被修改或代码段脏页");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("GOT/PLT 表完整, 代码段无篡改");
        }

        return item;
    }

    // ===================== 5. RWX 匿名内存检测 =====================

    /**
     * RWX 匿名内存区域检测
     *
     * 正常 Android 进程不应存在 rwxp (可读可写可执行) 匿名内存区域。
     * Frida agent 需要 rwxp 内存存放 trampoline 代码。
     * JIT 编译器的 rwxp 会在已知路径下, 可区分。
     */
    private DetectionItem checkAnonymousRwxMemory() {
        DetectionItem item = new DetectionItem("RWX 内存检测", "检测可疑的匿名可执行内存区域");

        int rwxCount = 0;
        boolean anonSuspicious = false;

        // 使用 Native 接口统计
        try {
            rwxCount = nativeDetector.countAnonymousRwxMemory();
        } catch (Exception ignored) {}

        // 获取详情
        String rwxDetails = null;
        try {
            rwxDetails = nativeDetector.getAnonymousRwxDetails();
        } catch (Exception ignored) {}

        // 通过 syscall 层检测可疑匿名内存
        try {
            anonSuspicious = nativeDetector.checkSuspiciousAnonMemorySyscall();
        } catch (Exception ignored) {}

        // 解析 /proc/self/maps 补充信息
        int totalRwxp = 0;
        int anonRwxp = 0;
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("rwxp")) {
                    totalRwxp++;
                    // 匿名区域 (无文件路径, 或 [anon:] 前缀)
                    if (!line.contains("/") || line.contains("[anon:")) {
                        anonRwxp++;
                        if (anonRwxp <= 3) {
                            String[] parts = line.split("\\s+");
                            String addr = parts.length > 0 ? parts[0] : "?";
                            String size = "";
                            try {
                                String[] addrParts = addr.split("-");
                                long start = Long.parseUnsignedLong(addrParts[0], 16);
                                long end = Long.parseUnsignedLong(addrParts[1], 16);
                                size = String.format(" (%d KB)", (end - start) / 1024);
                            } catch (Exception ignored) {}
                            item.addDetectionDetail("⚠️ 匿名 RWX", addr + size,
                                "可读写可执行匿名内存 (代码注入标志)", DetectionLayer.NATIVE, "🔴");
                        }
                    }
                }
            }
            reader.close();
        } catch (Exception ignored) {}

        if (anonRwxp > 3) {
            item.addDetectionDetail("📊 RWX 统计",
                String.format("总 RWX: %d / 匿名 RWX: %d", totalRwxp, anonRwxp),
                "匿名 RWX 区域数量异常", DetectionLayer.NATIVE, "📈");
        }

        if (rwxDetails != null && !rwxDetails.isEmpty()) {
            item.addDetectionDetail("📋 Native 报告", "RWX 详情", rwxDetails, DetectionLayer.NATIVE, "📊");
        }

        boolean detected = rwxCount > 5 || anonRwxp > 3 || anonSuspicious;

        item.setLayerResult(DetectionLayer.JAVA, false);
        item.setLayerResult(DetectionLayer.NATIVE, rwxCount > 5 || anonSuspicious);
        item.setLayerResult(DetectionLayer.SYSCALL, anonSuspicious);

        if (detected) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail(String.format("发现 %d 个匿名 RWX 区域 (总 RWX: %d)", anonRwxp, totalRwxp));
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail(String.format("RWX 内存正常 (总: %d, 匿名: %d)", totalRwxp, anonRwxp));
        }

        return item;
    }

    // ===================== 6. Syscall 时序分析 (综合) =====================

    /**
     * Syscall vs Libc 时序分析 — 综合检测
     *
     * 原理: 如果 libc 函数被 Hook (Frida Interceptor / PLT hook),
     * 通过 libc 调用会因 trampoline 跳转产生额外开销, 导致 libc 调用
     * 比直接 syscall 慢数倍。
     *
     * 注: 这是辅助验证手段, 不是主要检测方式。
     * sgmain 中 clock_gettime 仅 53 次/2883 总 syscall (1.8%),
     * 核心检测是 ELF 比对 + maps 扫描。
     */
    private DetectionItem checkSyscallTiming() {
        DetectionItem item = new DetectionItem("Syscall 时序分析", "检测 libc 函数调用是否存在异常延迟");

        final int ITERATIONS = 5000;
        final float THRESHOLD = 3.0f;

        int anomalyCount = 0;
        int totalTests = 0;
        StringBuilder details = new StringBuilder();

        // Test 1: openat
        try {
            long syscallTime = nativeDetector.benchmarkSyscallOpenat(ITERATIONS);
            long libcTime = nativeDetector.benchmarkLibcOpenat(ITERATIONS);
            boolean hooked = nativeDetector.detectTimingAnomaly(syscallTime, libcTime, THRESHOLD);
            float ratio = (syscallTime > 0) ? (float) libcTime / (float) syscallTime : 0;
            totalTests++;

            if (hooked) {
                anomalyCount++;
                item.addDetectionDetail("⚠️ openat()", String.format("%.1fx 倍", ratio),
                    String.format("Syscall: %dns / Libc: %dns", syscallTime, libcTime),
                    DetectionLayer.NATIVE, "🔴");
            } else {
                item.addDetectionDetail("✅ openat()", String.format("%.1fx 倍", ratio),
                    String.format("Syscall: %dns / Libc: %dns", syscallTime, libcTime),
                    DetectionLayer.NATIVE, "🟢");
            }
        } catch (Exception ignored) {}

        // Test 2: access
        try {
            long syscallTime = nativeDetector.benchmarkSyscallAccess(ITERATIONS);
            long libcTime = nativeDetector.benchmarkLibcAccess(ITERATIONS);
            boolean hooked = nativeDetector.detectTimingAnomaly(syscallTime, libcTime, THRESHOLD);
            float ratio = (syscallTime > 0) ? (float) libcTime / (float) syscallTime : 0;
            totalTests++;

            if (hooked) {
                anomalyCount++;
                item.addDetectionDetail("⚠️ access()", String.format("%.1fx 倍", ratio),
                    String.format("Syscall: %dns / Libc: %dns", syscallTime, libcTime),
                    DetectionLayer.NATIVE, "🔴");
            } else {
                item.addDetectionDetail("✅ access()", String.format("%.1fx 倍", ratio),
                    String.format("Syscall: %dns / Libc: %dns", syscallTime, libcTime),
                    DetectionLayer.NATIVE, "🟢");
            }
        } catch (Exception ignored) {}

        // Test 3: stat
        try {
            long syscallTime = nativeDetector.benchmarkSyscallStat(ITERATIONS);
            long libcTime = nativeDetector.benchmarkLibcStat(ITERATIONS);
            boolean hooked = nativeDetector.detectTimingAnomaly(syscallTime, libcTime, THRESHOLD);
            float ratio = (syscallTime > 0) ? (float) libcTime / (float) syscallTime : 0;
            totalTests++;

            if (hooked) {
                anomalyCount++;
                item.addDetectionDetail("⚠️ stat()", String.format("%.1fx 倍", ratio),
                    String.format("Syscall: %dns / Libc: %dns", syscallTime, libcTime),
                    DetectionLayer.NATIVE, "🔴");
            } else {
                item.addDetectionDetail("✅ stat()", String.format("%.1fx 倍", ratio),
                    String.format("Syscall: %dns / Libc: %dns", syscallTime, libcTime),
                    DetectionLayer.NATIVE, "🟢");
            }
        } catch (Exception ignored) {}

        boolean detected = anomalyCount > 0;

        item.setLayerResult(DetectionLayer.JAVA, false);
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        item.setLayerResult(DetectionLayer.SYSCALL, !detected);

        if (detected) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail(String.format("检测到 %d/%d 函数时序异常 (libc 被 Hook)", anomalyCount, totalTests));
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail(String.format("全部 %d 个函数时序正常", totalTests));
        }

        return item;
    }
}
