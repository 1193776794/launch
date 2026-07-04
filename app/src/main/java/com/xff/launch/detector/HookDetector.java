package com.xff.launch.detector;

import android.content.Context;
import android.content.pm.PackageManager;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Hook framework detection with multi-layer support
 */
public class HookDetector {

    private final Context context;
    private final NativeDetector nativeDetector;

    // Xposed related packages
    private static final String[] XPOSED_PACKAGES = {
            "de.robv.android.xposed.installer",
            "de.robv.android.xposed",
            "org.lsposed.manager",
            "org.meowcat.edxposed.manager"
    };

    // SandHook framework signatures (from sgmain heap dump)
    private static final String[] SANDHOOK_SIGNATURES = {
            "SandHooker",
            "SandHookerNew_",
            "com.swift.sandhook",
            "libsandhook.edxp.so",
            "Lcom/swift/sandhook/SandHook;"
    };

    // Pine Hook framework (LSPosed底层hook引擎)
    private static final String[] PINE_SIGNATURES = {
            "libpine.so"
    };

    // Hook function prefix signatures (from sgmain heap dump)
    private static final String[] HOOK_FUNC_PREFIXES = {
            "LspHooker_",
            "LLSPHooker_",
            "EdHooker_",
            "BugHooker_",
            "ParagonHelpers",
            "ParagonBridge",
            "LppiHelpers",
            "DexposedBridge",
            "SekiroXposedRequestHandler"
    };

    // ART internal Xposed symbols (from sgmain heap dump - libart detection)
    private static final String[] ART_XPOSED_SYMBOLS = {
            "_ZN3art30InvokeXposedHandleHookedMethod",
            "_ZN3art9ArtMethod16EnableXposedHook",
            "_ZNK3art7OatFile11XposedBeginEv"
    };

    // VirtualXposed paths (from sgmain heap dump)
    private static final String[] VIRTUAL_XPOSED_PATHS = {
            "/data/data/io.va.exposed/virtual/data/app/",
            "/data/data/io.va.exposed/virtual/data/app/fuckcode.xposedtemplete"
    };

    // Additional Hook framework packages (from sgmain heap dump)
    private static final String[] ADDITIONAL_HOOK_PACKAGES = {
            "io.va.exposed",
            "com.sl.whale",
            "com.sollyu.xposed.hook.model",
            "com.rong.xposed.fakelocation",
            "com.swift.sandhook"
    };

    // Xposed memory signatures (from sgmain heap dump - /proc/self/maps)
    private static final String[] XPOSED_MEMORY_SIGNATURES = {
            "XposedBridge.invokeOriginalMethodNative",
            "system@framework@XposedBridge.jar@classes.dex",
            "XposedHelpers.callMethod",
            "XposedHelpers.callStaticMethod",
            "XposedInit",
            "XposedHelpers"
    };

    // Frida thread names for thread scanning (from sgmain - 401 thread scan)
    private static final String[] FRIDA_THREAD_NAMES = {
            "gmain",
            "gdbus",
            "gum-js-loop",
            "pool-frida",
            "linjector",
            "frida"
    };

    // VMOS Xposed property
    private static final String VMOS_XPOSED_PROP = "persist.vmos.xposed.enable";

    public HookDetector(Context context) {
        this.context = context;
        this.nativeDetector = NativeDetector.getInstance();
    }

    /**
     * Detect Xposed framework
     */
    public DetectionItem detectXposed() {
        DetectionItem item = new DetectionItem("Xposed 框架", "检测 Xposed/EdXposed");

        // Java layer
        boolean javaResult = checkXposedJava();
        item.setLayerResult(DetectionLayer.JAVA, javaResult);

        // Native layer
        boolean nativeResult = nativeDetector.checkXposedNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer
        boolean syscallResult = nativeDetector.checkXposedSyscall();
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 Xposed 框架");

            // 添加详细检测信息
            collectXposedDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        if (item.hasInconsistentResults()) {
            item.setDetail(item.getDetail() + " (检测层不一致)");
        }

        return item;
    }

    /**
     * [XFF] 自读内存字节 · Xposed/LSPosed 类名串扫描(DetectEvilFrameworks 技术)。
     * 现有 Xposed/LSPosed 检测只查 maps 文件名 + 文件路径,注入已把这些痕迹全藏 → 绕过。
     * 本项改扫内存“字节内容”:读 /proc/self/maps 拿匿名/dalvik 区地址 → native 直接指针 memmem
     * 找加载进本进程的框架/模块类名串。no-hook 模块实测:只要有模块被 scope 进来(哪怕不 hook),
     * 这些串就在 dalvik 区必被扫到。内核 proc-mem 伪装拦不住(进程自读 V3)。
     */
    public DetectionItem detectXposedMemStrings() {
        DetectionItem item = new DetectionItem("Xposed 内存串扫描 [自读]",
                "自读内存原始字节扫 Xposed/LSPosed 类名串");

        boolean nativeResult = nativeDetector.checkXposedMemoryStringsNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        if (nativeResult) {
            item.setStatus(DetectionStatus.RISK);
            String details = nativeDetector.getXposedMemStringsDetails();
            item.setDetail("内存命中 Xposed/LSPosed 类名串:\n" + details);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未在内存中发现 Xposed/LSPosed 类名串");
        }
        return item;
    }

    /**
     * [XFF-T1+T2+T3] 模块注入痕迹检测(外来 DEX/APK/FD)。
     * Java 层(T1):遍历宿主自身 ClassLoader 的 pathList.dexElements,任何 dexFile 路径不属于
     *   宿主 base.apk/split 且非 /system|/apex 的 = 被 path-based 注入追加进来的模块 dex。
     * Native 层(T2/T3):扫 /proc/self/maps 外来代码容器映射 + /proc/self/fd 外来打开文件。
     *   dex 要执行必被 mmap、模块 apk 的 fd 常开 → 藏了 maps 关键词也藏不掉文件本体。
     */
    public DetectionItem detectModuleInjectionArtifacts() {
        DetectionItem item = new DetectionItem("模块注入痕迹 [外来DEX/FD]",
                "扫宿主 dexElements + maps/fd 里的外来模块文件");

        // ---- T1: 宿主 dexElements 外来 dex ----
        boolean javaDetected = false;
        try {
            java.util.Set<String> hostPaths = getHostApkPaths();
            ClassLoader loader = context.getClassLoader();
            while (loader != null) {
                for (String dp : extractDexElementPaths(loader)) {
                    if (dp == null || dp.isEmpty()) continue;
                    if (isHostOrSystemPath(dp, hostPaths)) continue;
                    javaDetected = true;
                    item.addDetectionDetail("📦 外来DEX", "宿主ClassLoader注入",
                            dp, DetectionLayer.JAVA, "⚠️");
                }
                loader = loader.getParent();
            }
        } catch (Exception e) {
            android.util.Log.d("HookDetector", "T1 dexElements scan error: " + e.getMessage());
        }
        item.setLayerResult(DetectionLayer.JAVA, javaDetected);

        // ---- T2/T3: native maps/fd 外来文件 ----
        boolean nativeDetected = false;
        try {
            String hostPkg = context.getPackageName();
            String hostApkDir = context.getApplicationInfo().sourceDir;
            String report = nativeDetector.getModuleInjectionReport(hostPkg, hostApkDir);
            if (report != null) {
                for (String ln : report.split("\n")) {
                    ln = ln.trim();
                    if (ln.isEmpty() || ln.equals("CLEAN")) continue;
                    int eq = ln.indexOf('=');
                    if (eq <= 0) continue;
                    String kind = ln.substring(0, eq);
                    String val = ln.substring(eq + 1);
                    nativeDetected = true;
                    String cat;
                    if (kind.equals("ANON_DEX_FW")) cat = "🧬 内存框架DEX";
                    else if (kind.startsWith("FD")) cat = "🔗 外来FD";
                    else if (kind.contains("MEMDEX")) cat = "🧬 内存DEX";
                    else cat = "💾 外来映射";
                    item.addDetectionDetail(cat, kind, val, DetectionLayer.NATIVE, "🔍");
                }
            }
        } catch (Exception e) {
            android.util.Log.d("HookDetector", "T2/T3 native report error: " + e.getMessage());
        }
        item.setLayerResult(DetectionLayer.NATIVE, nativeDetected);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到外来模块文件(注入痕迹)");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未发现外来 DEX/APK/FD");
        }
        return item;
    }

    /**
     * [XFF-T4+T5] ClassLoader 旁支枚举 + Hook 引擎 .so 探测。
     * 现有父链 walk 只看 getParent(),看不到 LSPosed 的框架/模块 loader(旁支)。
     * Java 层(T4):从 Thread.getAllStackTraces() 各线程 contextClassLoader + 已加载框架类的
     *   defining loader 收集全量 loader,查 InMemoryDexClassLoader 是否定义了 org.lsposed.* /
     *   LspModuleClassLoader。Native 层(T5):dlopen(RTLD_NOLOAD) 命中已加载的引擎库。
     */
    public DetectionItem detectClassLoaderEnumeration() {
        DetectionItem item = new DetectionItem("ClassLoader 旁支枚举",
                "枚举全量 ClassLoader + 探测 Hook 引擎 .so");

        boolean javaDetected = false;
        try {
            for (ClassLoader cl : collectAllClassLoaders()) {
                if (cl == null) continue;
                String cn = cl.getClass().getName();
                if (cn.contains("LspModuleClassLoader") || cn.toLowerCase().contains("lsposed")) {
                    javaDetected = true;
                    item.addDetectionDetail("🧩 旁支ClassLoader", cn, cl.toString(),
                            DetectionLayer.JAVA, "⚠️");
                    continue;
                }
                if (cn.contains("InMemoryDexClassLoader")) {
                    String probe = classLoaderDefinesFramework(cl);
                    if (probe != null) {
                        javaDetected = true;
                        item.addDetectionDetail("🧬 内存框架DEX", cn,
                                "该 loader 直接定义: " + probe, DetectionLayer.JAVA, "🚨");
                    }
                }
            }
            try {
                Class.forName("org.lsposed.lspd.util.LspModuleClassLoader");
                javaDetected = true;
                item.addDetectionDetail("🧩 框架类", "LspModuleClassLoader",
                        "org.lsposed.lspd.util.LspModuleClassLoader 已加载",
                        DetectionLayer.JAVA, "🚨");
            } catch (ClassNotFoundException ignored) {
            }
        } catch (Exception e) {
            android.util.Log.d("HookDetector", "T4 classloader enum error: " + e.getMessage());
        }
        item.setLayerResult(DetectionLayer.JAVA, javaDetected);

        // ---- T5: native 引擎 .so 探测 ----
        boolean nativeDetected = false;
        try {
            String report = nativeDetector.getArtHookLibReport();
            if (report != null) {
                for (String ln : report.split("\n")) {
                    ln = ln.trim();
                    if (ln.isEmpty() || ln.equals("CLEAN")) continue;
                    int eq = ln.indexOf('=');
                    if (eq <= 0) continue;
                    nativeDetected = true;
                    item.addDetectionDetail("🔧 Hook引擎库", ln.substring(eq + 1),
                            "dlopen(RTLD_NOLOAD) 命中(已加载本进程)", DetectionLayer.NATIVE, "⚙️");
                }
            }
        } catch (Exception e) {
            android.util.Log.d("HookDetector", "T5 native lib probe error: " + e.getMessage());
        }

        // ---- T5b: native 真·VisitClassLoaders 旁支枚举 ----
        try {
            String vcl = nativeDetector.getVisitClassLoadersReport();
            if (vcl != null && !vcl.startsWith("UNSUPPORTED")) {
                for (String ln : vcl.split("\n")) {
                    ln = ln.trim();
                    if (ln.isEmpty()) continue;
                    if (ln.startsWith("VCL_FRAMEWORK=")) {
                        nativeDetected = true;
                        item.addDetectionDetail("🧬 旁支框架Loader", ln.substring("VCL_FRAMEWORK=".length()),
                                "VisitClassLoaders 枚举到框架 ClassLoader", DetectionLayer.NATIVE, "🚨");
                    } else if (ln.startsWith("VCL_CLASS=")) {
                        nativeDetected = true;
                        item.addDetectionDetail("🧬 已加载框架类", ln.substring("VCL_CLASS=".length()),
                                "VisitClasses 在 ART 类表命中框架类(框架 loader 不进 class_loaders_ 也能抓)",
                                DetectionLayer.NATIVE, "🚨");
                    } else if (ln.startsWith("VCL_TOTAL=") || ln.startsWith("VCL_INMEMORY=")
                            || ln.startsWith("VCL_CLASSHITS=")) {
                        item.addDetectionDetail("📊 ClassLoader统计", ln,
                                "native 全量枚举计数", DetectionLayer.NATIVE, "🔢");
                    }
                }
            } else {
                android.util.Log.d("HookDetector", "T5b VisitClassLoaders: " + vcl);
            }
        } catch (Throwable t) {
            android.util.Log.d("HookDetector", "T5b VisitClassLoaders error: " + t.getMessage());
        }
        item.setLayerResult(DetectionLayer.NATIVE, nativeDetected);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 Hook 框架 ClassLoader/引擎库");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未发现旁支框架 ClassLoader / 引擎库");
        }
        return item;
    }

    /**
     * [XFF-T6] LSPlant/Frida hook 点检测:敏感方法的 ArtMethod entrypoint 是否落在匿名可执行区。
     * jmethodID=ArtMethod*,查 access_flags kAccNative + 头部指针槽是否指向匿名可执行内存(trampoline)。
     * 正常方法入口只在 .oat/libart/JIT-cache(均文件或具名映射);落在匿名可执行区=被 inline 换头。
     */
    public DetectionItem detectLSPlantHookedMethods() {
        DetectionItem item = new DetectionItem("LSPlant Hook点 [ArtMethod]",
                "查敏感方法 entrypoint 是否落在匿名可执行区");

        boolean detected = false;
        int hookCount = 0;
        try {
            String report = nativeDetector.getHookedMethodReport();
            if (report != null && !report.trim().equals("CLEAN")
                    && !report.startsWith("UNSUPPORTED")) {
                for (String ln : report.split("\n")) {
                    ln = ln.trim();
                    if (ln.isEmpty() || ln.equals("CLEAN")) continue;
                    detected = true;
                    hookCount++;
                    if (ln.startsWith("ANON_EXEC=")) {
                        item.addDetectionDetail("🧨 注入代码区", ln.substring("ANON_EXEC=".length()),
                                "无名匿名可执行区 = LSPlant trampoline / InMemoryDex 框架编译码(注入代码本体)",
                                DetectionLayer.NATIVE, "🚨");
                    } else {
                        String val = ln.startsWith("HOOKED=") ? ln.substring("HOOKED=".length()) : ln;
                        item.addDetectionDetail("🎯 被Hook方法", val,
                                "该方法 ArtMethod entrypoint 落在匿名可执行内存(LSPlant/Frida trampoline)",
                                DetectionLayer.NATIVE, "🚨");
                    }
                }
            }
        } catch (Exception e) {
            android.util.Log.d("HookDetector", "T6 hooked method report error: " + e.getMessage());
        }
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        item.setLayerResult(DetectionLayer.SYSCALL, detected);

        if (detected) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 " + hookCount + " 个方法被 LSPlant/Frida hook");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("已扫描框架方法, entrypoint 均正常");
        }
        return item;
    }

    /**
     * [XFF-A] 函数级 inline-hook 检测:关键 libc/libart/linker 函数的内存首字节 vs 磁盘 ELF 原始
     * 首字节比对,不一致=被 inline-hook(头部改成跳 trampoline 的分支/ret)。序言位置无关不受
     * 重定位影响,比对可靠。另匹配具名 hook 框架 anon 区(shadowhook/bytehook/Frida gum 等)。
     */
    public DetectionItem detectFunctionInlineHooks() {
        DetectionItem item = new DetectionItem("函数级 inline-hook [字节比对]",
                "关键函数内存字节 vs 磁盘 ELF 字节比对");
        boolean detected = false;
        try {
            String report = nativeDetector.getFunctionHookReport();
            if (report != null && !report.trim().equals("CLEAN")) {
                for (String ln : report.split("\n")) {
                    ln = ln.trim();
                    if (ln.isEmpty() || ln.equals("CLEAN")) continue;
                    detected = true;
                    if (ln.startsWith("NAMED_HOOK=")) {
                        item.addDetectionDetail("🧨 Hook框架区", ln.substring("NAMED_HOOK=".length()),
                                "maps 命中具名 hook 框架内存区(shadowhook/bytehook/Frida 等)",
                                DetectionLayer.NATIVE, "🚨");
                    } else {
                        String val = ln.startsWith("FUNC_HOOK=") ? ln.substring("FUNC_HOOK=".length()) : ln;
                        item.addDetectionDetail("🎯 被Hook函数", val,
                                "内存首字节 ≠ 磁盘 ELF 原始字节 = inline hook",
                                DetectionLayer.NATIVE, "🚨");
                    }
                }
            }
        } catch (Exception e) {
            android.util.Log.d("HookDetector", "A func-hook report error: " + e.getMessage());
        }
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        item.setLayerResult(DetectionLayer.SYSCALL, detected);
        if (detected) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到关键函数被 inline-hook");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("关键函数字节与磁盘一致, 未见 inline-hook");
        }
        return item;
    }

    /**
     * [XFF-B] 反 DBI/模拟器探针:SMC 自修改代码执行一致性(反 Frida/QBDI)+ mincore demand-paging
     * 一致性(反模拟器/replay)+ 内存写入 CNTVCT 计时(信息性)。前两项异常判 RISK,计时仅作详情。
     */
    public DetectionItem detectAntiDBI() {
        DetectionItem item = new DetectionItem("反 DBI/模拟器探针",
                "SMC 执行一致性 + demand-paging + 内存计时");
        boolean detected = false;
        try {
            int smc = nativeDetector.smcExecProbe();
            if (smc == 1) {
                detected = true;
                item.addDetectionDetail("🧬 SMC 执行异常", "自修改代码返回值发散",
                        "运行期写入并执行的指令结果对不上 = Frida/QBDI 等 DBI 跟不进自修改代码",
                        DetectionLayer.NATIVE, "🚨");
            } else if (smc == -1) {
                item.addDetectionDetail("ℹ️ SMC 探针", "无法测试",
                        "mprotect(RX) 被 SELinux 拒(execmem 受限)", DetectionLayer.NATIVE, "🔒");
            }

            int dp = nativeDetector.demandPagingAnomaly();
            if (dp == 1) {
                detected = true;
                item.addDetectionDetail("🧬 内存分页异常", "demand-paging 语义异常",
                        "匿名页触碰前已驻留/触碰后不驻留 = 模拟器/被插桩内存",
                        DetectionLayer.NATIVE, "🚨");
            }

            long cyc = nativeDetector.memWriteTimingCycles();
            if (cyc > 0) {
                item.addDetectionDetail("⏱️ 内存写入计时", cyc + " cycles/round",
                        "40MB×100轮打散写周期数(信息性,模拟器/单步会暴涨)",
                        DetectionLayer.NATIVE, "📊");
            }
        } catch (Exception e) {
            android.util.Log.d("HookDetector", "B anti-DBI probe error: " + e.getMessage());
        }
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        if (detected) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 DBI 插桩/模拟器内存异常");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("SMC 执行一致, 内存分页正常");
        }
        return item;
    }

    // ---- T1/T4 辅助方法 ----

    /** 宿主自身合法 apk/lib 路径集合(base.apk + splits + nativeLibDir) */
    private java.util.Set<String> getHostApkPaths() {
        java.util.Set<String> s = new java.util.HashSet<>();
        try {
            android.content.pm.ApplicationInfo ai = context.getApplicationInfo();
            if (ai.sourceDir != null) s.add(ai.sourceDir);
            if (ai.publicSourceDir != null) s.add(ai.publicSourceDir);
            if (ai.splitSourceDirs != null) {
                for (String sp : ai.splitSourceDirs) if (sp != null) s.add(sp);
            }
            if (ai.nativeLibraryDir != null) s.add(ai.nativeLibraryDir);
        } catch (Exception ignored) {
        }
        return s;
    }

    /** 路径是否属于宿主自身或系统 framework(命中即非注入) */
    private boolean isHostOrSystemPath(String p, java.util.Set<String> hostPaths) {
        if (hostPaths.contains(p)) return true;
        String pkg = context.getPackageName();
        if (pkg != null && p.contains(pkg)) return true;   // 宿主 apk 目录/oat 均含包名
        return p.startsWith("/system/") || p.startsWith("/apex/") ||
                p.startsWith("/vendor/") || p.startsWith("/product/") ||
                p.startsWith("/system_ext/") || p.contains("/dalvik-cache/");
    }

    /** 反射取 BaseDexClassLoader.pathList.dexElements[*] 的文件路径 */
    private java.util.List<String> extractDexElementPaths(ClassLoader loader) {
        java.util.List<String> out = new java.util.ArrayList<>();
        try {
            Class<?> bdcl = Class.forName("dalvik.system.BaseDexClassLoader");
            if (!bdcl.isInstance(loader)) return out;
            java.lang.reflect.Field pathListField = bdcl.getDeclaredField("pathList");
            pathListField.setAccessible(true);
            Object pathList = pathListField.get(loader);
            if (pathList == null) return out;
            java.lang.reflect.Field dexElementsField = pathList.getClass().getDeclaredField("dexElements");
            dexElementsField.setAccessible(true);
            Object[] elements = (Object[]) dexElementsField.get(pathList);
            if (elements == null) return out;
            for (Object el : elements) {
                String path = null;
                // 新版 Element.path (File)
                try {
                    java.lang.reflect.Field pathField = el.getClass().getDeclaredField("path");
                    pathField.setAccessible(true);
                    Object f = pathField.get(el);
                    if (f != null) path = f.toString();
                } catch (NoSuchFieldException ignored) {
                }
                // 回退: Element.dexFile.mFileName
                if (path == null || path.isEmpty()) {
                    try {
                        java.lang.reflect.Field dexFileField = el.getClass().getDeclaredField("dexFile");
                        dexFileField.setAccessible(true);
                        Object dexFile = dexFileField.get(el);
                        if (dexFile != null) {
                            java.lang.reflect.Field nameField = dexFile.getClass().getDeclaredField("mFileName");
                            nameField.setAccessible(true);
                            Object nm = nameField.get(dexFile);
                            if (nm != null) path = nm.toString();
                        }
                    } catch (Exception ignored) {
                    }
                }
                if (path != null && !path.isEmpty() && !path.equals("null")) out.add(path);
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    /** 收集全量 ClassLoader(父链 + 线程 contextClassLoader + 框架类 defining loader) */
    private java.util.Set<ClassLoader> collectAllClassLoaders() {
        java.util.Set<ClassLoader> set = new java.util.HashSet<>();
        ClassLoader l = context.getClassLoader();
        while (l != null) {
            set.add(l);
            l = l.getParent();
        }
        try {
            for (Thread t : Thread.getAllStackTraces().keySet()) {
                try {
                    ClassLoader ccl = t.getContextClassLoader();
                    while (ccl != null) {
                        set.add(ccl);
                        ccl = ccl.getParent();
                    }
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
        String[] fw = {
                "de.robv.android.xposed.XposedBridge",
                "org.lsposed.lspd.core.Startup",
                "io.github.lsposed.lspd.core.Startup",
                "io.github.libxposed.api.XposedInterface"
        };
        for (String cn : fw) {
            try {
                ClassLoader cl = Class.forName(cn).getClassLoader();
                while (cl != null) {
                    set.add(cl);
                    cl = cl.getParent();
                }
            } catch (Throwable ignored) {
            }
        }
        return set;
    }

    /** loader 是否"直接定义"(非委托父链)了框架类 → InMemoryDex 框架核心的实锤 */
    private String classLoaderDefinesFramework(ClassLoader cl) {
        String[] probes = {
                "org.lsposed.lspd.core.Startup",
                "org.lsposed.lspd.service.ILSPApplicationService",
                "de.robv.android.xposed.XposedBridge",
                "io.github.libxposed.api.XposedInterface"
        };
        for (String p : probes) {
            try {
                Class<?> c = cl.loadClass(p);
                if (c.getClassLoader() == cl) return p;   // 由该 loader 直接定义
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    /**
     * Detect Frida
     */
    public DetectionItem detectFrida() {
        DetectionItem item = new DetectionItem("Frida 检测", "检测 Frida 注入框架");

        // Java layer - limited detection via port check
        boolean javaResult = checkFridaJava();
        item.setLayerResult(DetectionLayer.JAVA, javaResult);

        // Native layer
        boolean nativeResult = nativeDetector.checkFridaNative();
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer
        boolean syscallResult = nativeDetector.checkFridaSyscall();
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到 Frida");

            // 添加详细检测信息
            collectFridaDetails(item);
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        if (item.hasInconsistentResults()) {
            item.setDetail(item.getDetail() + " (检测层不一致)");
        }

        return item;
    }

    /**
     * Detect LSPosed
     */
    public DetectionItem detectLSPosed() {
        android.util.Log.d("HookDetector", "=== detectLSPosed() START ===");
        DetectionItem item = new DetectionItem("LSPosed 检测", "检测 LSPosed 框架");

        // Java layer - enhanced detection
        boolean javaResult = checkLSPosedJava();
        android.util.Log.d("HookDetector", "Java layer result: " + javaResult);
        item.setLayerResult(DetectionLayer.JAVA, javaResult);

        // Native layer - combine all Native detection methods
        boolean nativeBasic = nativeDetector.checkLSPosedNative();
        boolean nativeMemory = nativeDetector.checkLSPosedMemoryNative();
        boolean nativeRiru = nativeDetector.checkRiruZygiskNative();
        boolean nativeSystemWide = nativeDetector.checkLSPosedSystemWide();
        boolean nativeAnon = nativeDetector.checkAnonymousExecutableMemory();

        android.util.Log.d("HookDetector", "Native basic: " + nativeBasic);
        android.util.Log.d("HookDetector", "Native memory: " + nativeMemory);
        android.util.Log.d("HookDetector", "Native Riru: " + nativeRiru);
        android.util.Log.d("HookDetector", "Native system-wide: " + nativeSystemWide);
        android.util.Log.d("HookDetector", "Native anon memory: " + nativeAnon);

        boolean nativeResult = nativeBasic || nativeMemory || nativeRiru || nativeSystemWide || nativeAnon;
        android.util.Log.d("HookDetector", "Native layer COMBINED result: " + nativeResult);
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer - combine all Syscall detection methods
        boolean syscallResult = nativeDetector.checkLSPosedSyscall() ||
                               nativeDetector.checkLSPosedMemorySyscall() ||
                               nativeDetector.checkRiruZygiskSyscall();
        android.util.Log.d("HookDetector", "Syscall layer result: " + syscallResult);
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        boolean finalResult = item.getMostTrustworthyResult();
        android.util.Log.d("HookDetector", "getMostTrustworthyResult(): " + finalResult);

        if (finalResult) {
            android.util.Log.w("HookDetector", "!!! LSPosed DETECTED - Setting RISK status !!!");
            item.setStatus(DetectionStatus.RISK);

            // Get detailed injection information
            String injectionDetails = nativeDetector.getLSPosedDetails();

            StringBuilder details = new StringBuilder();
            int detectionCount = 0;

            if (javaResult) {
                detectionCount++;
                details.append("• Java层检测到\n");
            }
            if (nativeResult) {
                detectionCount++;
                details.append("• Native层检测到\n");
            }
            if (syscallResult) {
                detectionCount++;
                details.append("• Syscall层检测到\n");
            }

            // Build final detail message
            String finalDetail = String.format("检测到 LSPosed (%d层确认)\n%s",
                    detectionCount, details.toString().trim());

            // Add injection module details if available
            if (injectionDetails != null && !injectionDetails.isEmpty()) {
                finalDetail += "\n\n" + injectionDetails;
            }

            android.util.Log.d("HookDetector", "Final detail: " + finalDetail);
            item.setDetail(finalDetail);

            // === 添加详细检测信息 ===
            collectLSPosedDetails(item, nativeBasic, nativeMemory, nativeRiru, nativeSystemWide, nativeAnon);

        } else {
            android.util.Log.d("HookDetector", "LSPosed NOT detected - Setting SAFE status");
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        android.util.Log.d("HookDetector", "=== detectLSPosed() END - Status: " + item.getStatus() + " ===");
        return item;
    }

    private boolean checkLSPosedJava() {
        // 0. Check loaded DexFile objects and LSPosed classes
        if (checkLoadedDexFiles()) {
            return true;
        }

        // 0b. Check for InMemoryDexClassLoader (strongest signature)
        if (checkInMemoryDexClassLoader()) {
            return true;
        }

        // 1. Check package manager (LSPosed Manager installed)
        if (isPackageInstalled("org.lsposed.manager")) {
            return true;
        }
        if (isPackageInstalled("org.meowcat.edxposed.manager")) {
            return true;
        }

        // 2. Check data directory existence (even if hidden from PackageManager)
        try {
            java.io.File lsposedDataDir = new java.io.File("/data/user/0/org.lsposed.manager");
            if (lsposedDataDir.exists()) {
                return true;
            }
        } catch (Exception ignored) {
        }

        // 3. Check for XposedBridge class (LSPosed uses it)
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            return true;
        } catch (ClassNotFoundException ignored) {
        }

        // 4. Check for LSPosed specific classes
        try {
            Class.forName("org.lsposed.lspd.core.Startup");
            return true;
        } catch (ClassNotFoundException ignored) {
        }

        try {
            Class.forName("org.lsposed.lspd.nativebridge.NativeAPI");
            return true;
        } catch (ClassNotFoundException ignored) {
        }

        try {
            Class.forName("io.github.lsposed.lspd.core.Startup");
            return true;
        } catch (ClassNotFoundException ignored) {
        }

        // 5. Check for XposedBridge fields (even if class not loaded)
        try {
            Class<?> bridgeClass = Class.forName("de.robv.android.xposed.XposedBridge");
            // If we can access XposedBridge, LSPosed is present
            bridgeClass.getField("disableHooks");
            return true;
        } catch (Exception ignored) {
        }

        // 6. Check system property
        try {
            String xposedProp = System.getProperty("xposed.bridge.version");
            if (xposedProp != null && !xposedProp.isEmpty()) {
                return true;
            }
        } catch (Exception ignored) {
        }

        // 7. Check ClassLoader chain for LSPosed
        try {
            ClassLoader loader = context.getClassLoader();
            while (loader != null) {
                String loaderName = loader.getClass().getName();
                if (loaderName.contains("lsposed") ||
                    loaderName.contains("LSPosed") ||
                    loaderName.contains("edxposed") ||
                    loaderName.contains("EdXposed")) {
                    return true;
                }
                loader = loader.getParent();
            }
        } catch (Exception ignored) {
        }

        // 8. Check stack trace for LSPosed
        try {
            throw new Exception("LSPosed check");
        } catch (Exception e) {
            for (StackTraceElement element : e.getStackTrace()) {
                String className = element.getClassName();
                if (className.contains("lsposed") ||
                    className.contains("LSPosed") ||
                    className.contains("edxposed") ||
                    className.contains("EdXposed") ||
                    className.contains("lspd")) {
                    return true;
                }
            }
        }

        // 9. Check /proc/self/maps via Java (for comparison with native)
        try {
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.FileReader("/proc/self/maps"));
            String line;
            while ((line = reader.readLine()) != null) {
                String upperLine = line.toUpperCase();
                if (upperLine.contains("LSPOSED") ||
                    upperLine.contains("XPOSEDBRIDGE") ||
                    upperLine.contains("LSPLANT") ||
                    upperLine.contains("LIBXPOSED")) {
                    reader.close();
                    return true;
                }
                // Check for zygisk lsposed module pattern
                if (line.contains("/data/adb/modules/") && line.contains("/zygisk/")) {
                    if (line.contains("lsposed") || line.contains("edxposed")) {
                        reader.close();
                        return true;
                    }
                }
            }
            reader.close();
        } catch (Exception ignored) {
        }

        return false;
    }

    // 10. Check for InMemoryDexClassLoader and DexFile bytecode signatures
    private boolean checkInMemoryDexClassLoader() {
        try {
            ClassLoader loader = context.getClassLoader();
            int suspiciousCount = 0;

            android.util.Log.d("HookDetector", "=== Starting ClassLoader Analysis ===");

            while (loader != null) {
                String loaderClassName = loader.getClass().getName();
                String loaderStr = loader.toString();

                android.util.Log.d("HookDetector", "Analyzing ClassLoader: " + loaderClassName);

                // Method 1: Check class name
                if (loaderClassName.contains("InMemoryDexClassLoader")) {
                    suspiciousCount++;
                    android.util.Log.w("HookDetector", "[DETECTED] InMemoryDexClassLoader by class name: " + loader);
                }

                // Method 2: Check toString() for InMemoryDexFile
                if (loaderStr.contains("InMemoryDexFile")) {
                    suspiciousCount++;
                    android.util.Log.w("HookDetector", "[DETECTED] InMemoryDexFile in toString: " + loaderStr);
                }

                // Method 3: Deep reflection - check BaseDexClassLoader internals
                if (loader.getClass().getName().contains("BaseDexClassLoader") ||
                    loader.getClass().getSuperclass().getName().contains("BaseDexClassLoader")) {

                    try {
                        // Get pathList field from BaseDexClassLoader
                        java.lang.reflect.Field pathListField = null;
                        Class<?> clazz = loader.getClass();
                        while (clazz != null) {
                            try {
                                pathListField = clazz.getDeclaredField("pathList");
                                break;
                            } catch (NoSuchFieldException e) {
                                clazz = clazz.getSuperclass();
                            }
                        }

                        if (pathListField != null) {
                            pathListField.setAccessible(true);
                            Object pathList = pathListField.get(loader);

                            if (pathList != null) {
                                // Get dexElements from DexPathList
                                java.lang.reflect.Field dexElementsField =
                                    pathList.getClass().getDeclaredField("dexElements");
                                dexElementsField.setAccessible(true);
                                Object[] dexElements = (Object[]) dexElementsField.get(pathList);

                                if (dexElements != null) {
                                    android.util.Log.d("HookDetector", "Found " + dexElements.length + " dexElements");

                                    for (int i = 0; i < dexElements.length; i++) {
                                        Object element = dexElements[i];

                                        // Get dexFile from Element
                                        java.lang.reflect.Field dexFileField =
                                            element.getClass().getDeclaredField("dexFile");
                                        dexFileField.setAccessible(true);
                                        Object dexFile = dexFileField.get(element);

                                        if (dexFile != null) {
                                            String dexFileStr = dexFile.toString();
                                            android.util.Log.d("HookDetector", "  DexFile[" + i + "]: " + dexFileStr);

                                            // Check for in-memory DEX signatures
                                            if (dexFileStr.contains("InMemoryDexFile") ||
                                                dexFileStr.contains("cookie=")) {

                                                // Try to get the file name
                                                try {
                                                    java.lang.reflect.Method getNameMethod =
                                                        dexFile.getClass().getDeclaredMethod("getName");
                                                    getNameMethod.setAccessible(true);
                                                    String fileName = (String) getNameMethod.invoke(dexFile);

                                                    android.util.Log.d("HookDetector", "    DexFile name: " + fileName);

                                                    // In-memory DEX has no real file path
                                                    if (fileName == null || fileName.isEmpty() ||
                                                        fileName.equals("null") ||
                                                        !fileName.startsWith("/")) {
                                                        suspiciousCount++;
                                                        android.util.Log.w("HookDetector",
                                                            "[DETECTED] In-memory DEX with no file path: " + dexFileStr);
                                                    }
                                                } catch (Exception e) {
                                                    android.util.Log.d("HookDetector", "    Could not get DexFile name: " + e.getMessage());
                                                }

                                                // Check cookie value (in-memory DEX has special cookie)
                                                if (dexFileStr.contains("cookie=")) {
                                                    suspiciousCount++;
                                                    android.util.Log.w("HookDetector",
                                                        "[DETECTED] In-memory DEX cookie signature: " + dexFileStr);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        android.util.Log.d("HookDetector", "Error in deep reflection: " + e.getMessage());
                    }
                }

                loader = loader.getParent();
            }

            android.util.Log.d("HookDetector", "=== ClassLoader Analysis Complete: " + suspiciousCount + " suspicious items ===");

            return suspiciousCount > 0;

        } catch (Exception e) {
            android.util.Log.e("HookDetector", "Error in checkInMemoryDexClassLoader", e);
        }

        return false;
    }

    // 11. Check all loaded DexFile objects via VMDebug/VMRuntime
    private boolean checkLoadedDexFiles() {
        try {
            android.util.Log.d("HookDetector", "=== Starting VMRuntime DexFile Analysis ===");

            // Method 1: Try to get all loaded classes and analyze their sources
            try {
                Class<?> vmDebugClass = Class.forName("dalvik.system.VMDebug");
                java.lang.reflect.Method getRuntimeStatsMethod =
                    vmDebugClass.getDeclaredMethod("getRuntimeStats");
                getRuntimeStatsMethod.setAccessible(true);

                @SuppressWarnings("unchecked")
                java.util.Map<String, String> stats =
                    (java.util.Map<String, String>) getRuntimeStatsMethod.invoke(null);

                if (stats != null) {
                    android.util.Log.d("HookDetector", "VMDebug stats: " + stats);
                }
            } catch (Exception e) {
                android.util.Log.d("HookDetector", "VMDebug method failed: " + e.getMessage());
            }

            // Method 2: Enumerate all loaded classes and check for suspicious patterns
            try {
                Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
                java.lang.reflect.Method getRuntimeMethod =
                    vmRuntimeClass.getDeclaredMethod("getRuntime");
                getRuntimeMethod.setAccessible(true);
                Object runtime = getRuntimeMethod.invoke(null);

                if (runtime != null) {
                    // Try to get target SDK version (sanity check)
                    try {
                        java.lang.reflect.Method getTargetSdkVersionMethod =
                            vmRuntimeClass.getDeclaredMethod("getTargetSdkVersion");
                        getTargetSdkVersionMethod.setAccessible(true);
                        int targetSdk = (int) getTargetSdkVersionMethod.invoke(runtime);
                        android.util.Log.d("HookDetector", "Target SDK: " + targetSdk);
                    } catch (Exception ignored) {}
                }
            } catch (Exception e) {
                android.util.Log.d("HookDetector", "VMRuntime method failed: " + e.getMessage());
            }

            // Method 3: Check current thread's context ClassLoader hierarchy
            int inMemoryCount = 0;
            ClassLoader threadLoader = Thread.currentThread().getContextClassLoader();
            android.util.Log.d("HookDetector", "Thread context ClassLoader: " +
                (threadLoader != null ? threadLoader.getClass().getName() : "null"));

            if (threadLoader != null) {
                String loaderStr = threadLoader.toString();
                if (loaderStr.contains("InMemoryDex") || loaderStr.contains("cookie=")) {
                    inMemoryCount++;
                    android.util.Log.w("HookDetector",
                        "[DETECTED] Thread context loader has InMemoryDex: " + loaderStr);
                }
            }

            // Method 4: Try to access DexFile class and enumerate instances
            try {
                Class<?> dexFileClass = Class.forName("dalvik.system.DexFile");
                android.util.Log.d("HookDetector", "DexFile class loaded: " + dexFileClass);

                // Try to get internal fields
                java.lang.reflect.Field[] fields = dexFileClass.getDeclaredFields();
                for (java.lang.reflect.Field field : fields) {
                    android.util.Log.d("HookDetector", "  DexFile field: " + field.getName() +
                        " type: " + field.getType().getName());
                }
            } catch (Exception e) {
                android.util.Log.d("HookDetector", "DexFile class analysis failed: " + e.getMessage());
            }

            // Method 5: Check if there are suspicious classes loaded
            try {
                // Try to detect LSPosed bridge classes
                String[] lsposedClasses = {
                    "de.robv.android.xposed.XposedBridge",
                    "de.robv.android.xposed.XposedHelpers",
                    "org.lsposed.lspd.core.Startup",
                    "org.lsposed.lspd.hooker.HandleBindAppHooker",
                    "io.github.lsposed.lsplant.LSPlant"
                };

                for (String className : lsposedClasses) {
                    try {
                        Class<?> clazz = Class.forName(className);
                        inMemoryCount++;
                        android.util.Log.w("HookDetector",
                            "[DETECTED] LSPosed class found: " + className);

                        // Try to get the ClassLoader of this class
                        ClassLoader clazzLoader = clazz.getClassLoader();
                        if (clazzLoader != null) {
                            android.util.Log.w("HookDetector",
                                "  Loaded by: " + clazzLoader.getClass().getName());
                            android.util.Log.w("HookDetector",
                                "  Loader details: " + clazzLoader);
                        }
                    } catch (ClassNotFoundException ignored) {
                        // Class not found, which is good
                    }
                }
            } catch (Exception e) {
                android.util.Log.d("HookDetector", "LSPosed class check failed: " + e.getMessage());
            }

            android.util.Log.d("HookDetector", "=== VMRuntime Analysis Complete: " +
                inMemoryCount + " suspicious items ===");

            return inMemoryCount > 0;

        } catch (Exception e) {
            android.util.Log.e("HookDetector", "Error in checkLoadedDexFiles", e);
        }

        return false;
    }

    /**
     * Detect Zygisk (通用检测: Magisk Zygisk, ReZygisk, Zygisk Next)
     */
    public DetectionItem detectZygisk() {
        android.util.Log.d("HookDetector", "=== detectZygisk() START ===");
        DetectionItem item = new DetectionItem("Zygisk 检测", "检测 Zygisk 注入框架");

        // Java layer - file and process detection
        boolean javaResult = checkZygiskJava();
        android.util.Log.d("HookDetector", "Java layer result: " + javaResult);
        item.setLayerResult(DetectionLayer.JAVA, javaResult);

        // Native layer - file system detection
        boolean nativeResult = nativeDetector.checkZygiskNative();
        android.util.Log.d("HookDetector", "Native layer result: " + nativeResult);
        item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

        // Syscall layer - direct file access
        boolean syscallResult = nativeDetector.checkZygiskSyscall();
        android.util.Log.d("HookDetector", "Syscall layer result: " + syscallResult);
        item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

        boolean finalResult = item.getMostTrustworthyResult();
        android.util.Log.d("HookDetector", "getMostTrustworthyResult(): " + finalResult);

        if (finalResult) {
            android.util.Log.w("HookDetector", "!!! Zygisk DETECTED - Setting RISK status !!!");
            item.setStatus(DetectionStatus.RISK);

            StringBuilder details = new StringBuilder();
            int detectionCount = 0;

            if (javaResult) {
                detectionCount++;
                details.append("• Java层检测到\n");
            }
            if (nativeResult) {
                detectionCount++;
                details.append("• Native层检测到\n");
            }
            if (syscallResult) {
                detectionCount++;
                details.append("• Syscall层检测到\n");
            }

            String finalDetail = String.format("检测到 Zygisk (%d层确认)\n%s",
                    detectionCount, details.toString().trim());

            android.util.Log.d("HookDetector", "Final detail: " + finalDetail);
            item.setDetail(finalDetail);

            // 添加详细检测信息
            collectZygiskDetails(item);

        } else {
            // Check if detection was limited by system restrictions
            boolean wasRestricted = !javaResult && !nativeResult && !syscallResult;

            if (wasRestricted) {
                android.util.Log.w("HookDetector", "Zygisk detection RESTRICTED by system - Setting UNKNOWN status");
                item.setStatus(DetectionStatus.UNKNOWN);
                item.setDetail("检测受限\n" +
                        "• SELinux阻止文件/进程访问\n" +
                        "• 应用不在Zygisk注入范围\n" +
                        "• 无法确认Zygisk状态\n\n" +
                        "💡 提示：将此应用添加到LSPosed作用域可启用完整检测");

                // 添加说明性检测详情
                item.addDetectionDetail("⚠️ 检测限制",
                        "系统安全限制",
                        "SELinux Enforcing模式阻止应用访问:\n" +
                        "• /data/adb/ 目录 (root权限)\n" +
                        "• Root进程信息 (/proc/[pid])\n" +
                        "• 系统级进程列表",
                        DetectionLayer.SYSCALL,
                        "🔒");

                item.addDetectionDetail("ℹ️ 注入范围",
                        "Zygisk作用域",
                        "当前应用不在Zygisk注入范围内\n" +
                        "• 应用内存中无libzygisk.so\n" +
                        "• 无法检测Zygisk注入特征\n\n" +
                        "如需完整检测，请在LSPosed管理器中:\n" +
                        "1. 打开'作用域'设置\n" +
                        "2. 将'Launch'添加到作用域\n" +
                        "3. 重启应用",
                        DetectionLayer.JAVA,
                        "📋");

            } else {
                android.util.Log.d("HookDetector", "Zygisk NOT detected - Setting SAFE status");
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未检测到");
            }
        }

        android.util.Log.d("HookDetector", "=== detectZygisk() END - Status: " + item.getStatus() + " ===");
        return item;
    }


    /**
     * Get all hook detection items
     */
    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(detectXposed());
        items.add(detectFrida());
        items.add(detectLSPosed());
        items.add(detectXposedMemStrings());   // [XFF] 自读内存字节扫类名串
        items.add(detectModuleInjectionArtifacts());  // [XFF-T1/T2/T3] 外来 DEX/APK/FD
        items.add(detectClassLoaderEnumeration());    // [XFF-T4/T5] ClassLoader 旁支 + 引擎库
        items.add(detectLSPlantHookedMethods());      // [XFF-T6] ArtMethod hook 点
        items.add(detectFunctionInlineHooks());       // [XFF-A] 函数级 inline-hook(字节比对)
        items.add(detectAntiDBI());                   // [XFF-B] 反 DBI/模拟器探针
        items.add(detectZygisk());
        // detectSmapsHook / detectMemoryIntegrity 已去重:SMAPS 由 SideChannel.checkGotPltHooks 覆盖,
        // 系统库完整性由 SideChannel.checkSystemLibIntegrity 覆盖(见项目去重整理)。
        items.add(detectAdvancedHookFrameworks());
        items.add(detectFridaThreads());
        return items;
    }

    /**
     * Detect advanced hook frameworks: SandHook, Pine, Whale, Dexposed, VirtualXposed
     * Based on sgmain SecGuard heap dump analysis
     */
    public DetectionItem detectAdvancedHookFrameworks() {
        DetectionItem item = new DetectionItem("高级Hook框架", "检测 SandHook/Pine/Whale/VirtualXposed 等");

        boolean javaDetected = false;
        boolean nativeDetected = false;

        // Java layer: check packages
        for (String pkg : ADDITIONAL_HOOK_PACKAGES) {
            if (isPackageInstalled(pkg)) {
                javaDetected = true;
                item.addDetectionDetail("📦 Hook 包名", pkg, "已安装", DetectionLayer.JAVA, "📱");
            }
        }

        // Java layer: check stack trace for hook prefixes
        try {
            throw new Exception("hook check");
        } catch (Exception e) {
            for (StackTraceElement el : e.getStackTrace()) {
                String cls = el.getClassName();
                for (String prefix : HOOK_FUNC_PREFIXES) {
                    if (cls.contains(prefix)) {
                        javaDetected = true;
                        item.addDetectionDetail("🔗 Hook 函数", prefix, "类名: " + cls, DetectionLayer.JAVA, "⚡");
                    }
                }
            }
        }

        // Java layer: check VMOS Xposed property
        try {
            String vmosVal = System.getProperty(VMOS_XPOSED_PROP);
            if (vmosVal != null && !vmosVal.isEmpty()) {
                javaDetected = true;
                item.addDetectionDetail("🎮 VMOS Xposed", VMOS_XPOSED_PROP, "值: " + vmosVal, DetectionLayer.JAVA, "📱");
            }
        } catch (Exception ignored) {}

        // [去重迁入·原 ZygoteDetector.checkNativeBridge] ro.dalvik.vm.native.bridge 值检测:
        // 正常为 "0";若为 libhoudini(x86 二进制翻译/模拟器)或 libriruloader(Riru 注入)= 可疑。
        try {
            String nb = nativeDetector.getSystemProperty("ro.dalvik.vm.native.bridge");
            if (nb != null && !nb.isEmpty() && !nb.equals("0")) {
                String low = nb.toLowerCase();
                if (low.contains("riru") || low.contains("houdini") || low.contains("ndk_translation")) {
                    javaDetected = true;
                    item.addDetectionDetail("🌉 Native Bridge", "ro.dalvik.vm.native.bridge",
                            "值: " + nb + "(riru 注入 / houdini 模拟器翻译)", DetectionLayer.NATIVE, "⚠️");
                }
            }
        } catch (Exception ignored) {}

        // Java layer: check VirtualXposed paths
        for (String path : VIRTUAL_XPOSED_PATHS) {
            if (new File(path).exists()) {
                javaDetected = true;
                item.addDetectionDetail("📁 VirtualXposed", path, "文件存在", DetectionLayer.JAVA, "📂");
            }
        }

        item.setLayerResult(DetectionLayer.JAVA, javaDetected);

        // Native layer: scan /proc/self/maps for SandHook/Pine/ART Xposed symbols
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase();
                // SandHook
                for (String sig : SANDHOOK_SIGNATURES) {
                    if (lower.contains(sig.toLowerCase())) {
                        nativeDetected = true;
                        item.addDetectionDetail("💾 SandHook 内存", sig, "映射: " + line.trim(), DetectionLayer.NATIVE, "🔍");
                    }
                }
                // Pine
                for (String sig : PINE_SIGNATURES) {
                    if (lower.contains(sig.toLowerCase())) {
                        nativeDetected = true;
                        item.addDetectionDetail("💾 Pine 内存", sig, "映射: " + line.trim(), DetectionLayer.NATIVE, "🔍");
                    }
                }
                // ART Xposed symbols
                for (String sym : ART_XPOSED_SYMBOLS) {
                    if (line.contains(sym)) {
                        nativeDetected = true;
                        item.addDetectionDetail("🧬 ART Xposed 符号", sym, "映射: " + line.trim(), DetectionLayer.NATIVE, "⚠️");
                    }
                }
            }
            reader.close();
        } catch (Exception ignored) {}

        // Native layer: check VirtualXposed paths via native
        for (String path : VIRTUAL_XPOSED_PATHS) {
            if (nativeDetector.fileExistsNative(path)) {
                nativeDetected = true;
            }
        }

        item.setLayerResult(DetectionLayer.NATIVE, nativeDetected);

        // Syscall layer
        boolean syscallDetected = false;
        for (String path : VIRTUAL_XPOSED_PATHS) {
            if (nativeDetector.fileExistsSyscall(path)) {
                syscallDetected = true;
            }
        }
        item.setLayerResult(DetectionLayer.SYSCALL, syscallDetected);

        if (item.getMostTrustworthyResult()) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail("检测到高级Hook框架");
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail("未检测到");
        }

        return item;
    }

    /**
     * Detect Frida via thread name scanning (sgmain 401-thread scan technique)
     * Scans /proc/self/task/TID/comm for Frida-specific thread names
     */
    public DetectionItem detectFridaThreads() {
        DetectionItem item = new DetectionItem("Frida 线程扫描", "扫描全部线程检测 Frida 特征线程名");

        boolean detected = false;
        int totalThreads = 0;
        int suspiciousThreads = 0;

        try {
            File taskDir = new File("/proc/self/task");
            File[] tasks = taskDir.listFiles();
            if (tasks != null) {
                totalThreads = tasks.length;
                for (File task : tasks) {
                    try {
                        // Read thread name from comm
                        File commFile = new File(task, "comm");
                        if (commFile.exists()) {
                            BufferedReader reader = new BufferedReader(new FileReader(commFile));
                            String threadName = reader.readLine();
                            reader.close();

                            if (threadName != null) {
                                String lower = threadName.trim().toLowerCase();
                                for (String fridaName : FRIDA_THREAD_NAMES) {
                                    if (lower.contains(fridaName.toLowerCase())) {
                                        detected = true;
                                        suspiciousThreads++;
                                        item.addDetectionDetail("🧵 可疑线程", threadName.trim(),
                                            "TID: " + task.getName() + "\n匹配: " + fridaName,
                                            DetectionLayer.JAVA, "🔗");
                                    }
                                }
                            }
                        }

                        // Also check TracerPid in status
                        File statusFile = new File(task, "status");
                        if (statusFile.exists()) {
                            BufferedReader reader = new BufferedReader(new FileReader(statusFile));
                            String line;
                            while ((line = reader.readLine()) != null) {
                                if (line.startsWith("TracerPid:")) {
                                    String pidStr = line.substring(10).trim();
                                    int tracerPid = Integer.parseInt(pidStr);
                                    if (tracerPid > 0) {
                                        detected = true;
                                        item.addDetectionDetail("🔍 TracerPid", "线程被追踪",
                                            "TID: " + task.getName() + "\nTracerPid: " + tracerPid,
                                            DetectionLayer.JAVA, "⚠️");
                                    }
                                    break;
                                }
                            }
                            reader.close();
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {}

        // D-Bus protocol detection - send AUTH message to detect Frida
        boolean dbusDetected = false;
        int[] checkPorts = {27042, 27043, 27044, 27045};
        for (int port : checkPorts) {
            try {
                java.net.Socket socket = new java.net.Socket();
                socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), 200);
                socket.setSoTimeout(200);

                // Send D-Bus AUTH message
                java.io.OutputStream out = socket.getOutputStream();
                out.write("\0AUTH\r\n".getBytes());
                out.flush();

                // Read response - Frida responds with "REJECTED"
                byte[] buf = new byte[128];
                int n = socket.getInputStream().read(buf);
                if (n > 0) {
                    String response = new String(buf, 0, n);
                    if (response.contains("REJECT")) {
                        dbusDetected = true;
                        detected = true;
                        item.addDetectionDetail("🌐 D-Bus 协议", "端口 " + port,
                            "D-Bus AUTH 响应: REJECTED (Frida特征)",
                            DetectionLayer.JAVA, "🔌");
                    }
                }
                socket.close();
            } catch (Exception ignored) {}
        }

        item.setLayerResult(DetectionLayer.JAVA, detected);
        item.setLayerResult(DetectionLayer.NATIVE, detected);
        item.setLayerResult(DetectionLayer.SYSCALL, detected);

        if (detected) {
            item.setStatus(DetectionStatus.RISK);
            item.setDetail(String.format("扫描 %d 线程, 发现 %d 可疑%s",
                totalThreads, suspiciousThreads,
                dbusDetected ? " + D-Bus协议检测" : ""));
        } else {
            item.setStatus(DetectionStatus.SAFE);
            item.setDetail(String.format("已扫描 %d 线程, 未发现异常", totalThreads));
        }

        return item;
    }

    // ===================== Java Layer Methods =====================

    private boolean checkXposedJava() {
        // Check package
        for (String pkg : XPOSED_PACKAGES) {
            if (isPackageInstalled(pkg)) {
                return true;
            }
        }

        // Check stack trace for Xposed
        try {
            throw new Exception("Xposed check");
        } catch (Exception e) {
            for (StackTraceElement element : e.getStackTrace()) {
                if (element.getClassName().contains("xposed") ||
                        element.getClassName().contains("Xposed")) {
                    return true;
                }
            }
        }

        // Check class loader
        try {
            ClassLoader.getSystemClassLoader().loadClass("de.robv.android.xposed.XposedBridge");
            return true;
        } catch (ClassNotFoundException ignored) {
        }

        return false;
    }

    private boolean checkFridaJava() {
        // Check for Frida server on default port
        try {
            java.net.Socket socket = new java.net.Socket();
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", 27042), 100);
            socket.close();
            return true;
        } catch (Exception ignored) {
        }
        return false;
    }

    private boolean isPackageInstalled(String packageName) {
        try {
            context.getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }


    /**
     * Get detailed integrity report for all system libraries
     * Returns a comprehensive JSON report
     */
    public String getSystemLibrariesIntegrityReport() {
        try {
            return nativeDetector.checkAllSystemLibrariesIntegrity();
        } catch (Exception e) {
            android.util.Log.e("HookDetector", "Error getting integrity report", e);
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }

    /**
     * Collect detailed LSPosed detection information
     */
    private void collectLSPosedDetails(DetectionItem item, boolean nativeBasic, boolean nativeMemory,
                                      boolean nativeRiru, boolean nativeSystemWide, boolean nativeAnon) {
        android.util.Log.d("HookDetector", "=== collectLSPosedDetails() START ===");
        android.util.Log.d("HookDetector", "Flags: nativeMemory=" + nativeMemory + ", nativeRiru=" + nativeRiru);
        try {
            // 检测文件特征
            if (nativeMemory || nativeRiru) {
                android.util.Log.d("HookDetector", "Collecting file features...");

                // 检测Zygisk模块
                java.io.File zygiskDir = new java.io.File("/data/adb/modules");
                if (zygiskDir.exists()) {
                    java.io.File[] modules = zygiskDir.listFiles();
                    if (modules != null) {
                        for (java.io.File module : modules) {
                            java.io.File zygiskFile = new java.io.File(module, "zygisk");
                            if (zygiskFile.exists()) {
                                item.addDetectionDetail("📁 文件特征",
                                    "Zygisk 模块",
                                    module.getName(),
                                    DetectionLayer.NATIVE,
                                    "📦");
                            }
                        }
                    }
                }

                // 检测LSPosed数据目录
                java.io.File lsposedData = new java.io.File("/data/adb/lspd");
                if (lsposedData.exists()) {
                    item.addDetectionDetail("📁 文件特征",
                        "LSPosed 数据目录",
                        "/data/adb/lspd",
                        DetectionLayer.NATIVE,
                        "📂");
                }
            }

            // 检测内存特征
            if (nativeMemory) {
                // 读取/proc/self/maps查找LSPosed模块
                try {
                    java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.FileReader("/proc/self/maps"));
                    String line;
                    int moduleCount = 0;
                    while ((line = reader.readLine()) != null) {
                        if (line.contains("/data/adb/modules") &&
                            (line.contains("zygisk") || line.contains(".so"))) {
                            moduleCount++;
                            // 提取模块路径
                            int pathStart = line.indexOf("/data/adb/modules");
                            if (pathStart != -1) {
                                String modulePath = line.substring(pathStart);
                                modulePath = modulePath.split("\\s+")[0];

                                // 提取内存地址
                                String[] parts = line.split("\\s+");
                                if (parts.length > 0) {
                                    String addrRange = parts[0];
                                    item.addDetectionDetail("💾 内存特征",
                                        "注入模块",
                                        modulePath + "\n地址: " + addrRange,
                                        DetectionLayer.NATIVE,
                                        "🔍");
                                }
                            }
                        }
                    }
                    reader.close();

                    if (moduleCount > 0) {
                        item.addDetectionDetail("💾 内存特征",
                            "模块数量",
                            String.valueOf(moduleCount) + " 个",
                            DetectionLayer.NATIVE,
                            "📊");
                    }
                } catch (Exception e) {
                    android.util.Log.e("HookDetector", "Error reading maps", e);
                }
            }

            // 检测匿名可执行内存
            if (nativeAnon) {
                try {
                    java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.FileReader("/proc/self/maps"));
                    String line;
                    int rwxpCount = 0;
                    while ((line = reader.readLine()) != null) {
                        if (line.contains(" rwxp ") &&
                            (line.contains("[anon]") || line.contains(" 00:00 0"))) {
                            rwxpCount++;
                            if (rwxpCount <= 3) { // 只记录前3个
                                String[] parts = line.split("\\s+");
                                if (parts.length > 0) {
                                    item.addDetectionDetail("⚠️ 可疑内存",
                                        "匿名可执行区域",
                                        "地址: " + parts[0] + "\n权限: rwxp",
                                        DetectionLayer.NATIVE,
                                        "🚨");
                                }
                            }
                        }
                    }
                    reader.close();

                    if (rwxpCount > 3) {
                        item.addDetectionDetail("⚠️ 可疑内存",
                            "匿名rwxp总数",
                            String.valueOf(rwxpCount) + " 个",
                            DetectionLayer.NATIVE,
                            "📈");
                    }
                } catch (Exception e) {
                    android.util.Log.e("HookDetector", "Error reading maps for rwxp", e);
                }
            }

            // 检测进程特征
            if (nativeSystemWide) {
                // 检测LSPosed进程
                try {
                    java.io.File procDir = new java.io.File("/proc");
                    java.io.File[] procs = procDir.listFiles();
                    if (procs != null) {
                        for (java.io.File proc : procs) {
                            if (!proc.getName().matches("\\d+")) continue;

                            try {
                                java.io.File cmdlineFile = new java.io.File(proc, "cmdline");
                                if (cmdlineFile.exists()) {
                                    java.io.BufferedReader reader = new java.io.BufferedReader(
                                        new java.io.FileReader(cmdlineFile));
                                    String cmdline = reader.readLine();
                                    reader.close();

                                    if (cmdline != null &&
                                        (cmdline.contains("lspd") || cmdline.contains("lsposed"))) {
                                        item.addDetectionDetail("🔄 进程特征",
                                            "LSPosed 守护进程",
                                            "PID: " + proc.getName() + "\nCMD: " + cmdline,
                                            DetectionLayer.NATIVE,
                                            "⚙️");
                                    }
                                }
                            } catch (Exception ignored) {}
                        }
                    }
                } catch (Exception e) {
                    android.util.Log.e("HookDetector", "Error checking processes", e);
                }
            }

            // 检测类加载器特征
            try {
                ClassLoader loader = context.getClassLoader();
                int suspiciousLoaders = 0;
                while (loader != null) {
                    String loaderName = loader.getClass().getName();
                    if (loaderName.contains("InMemoryDexClassLoader") ||
                        loaderName.contains("XposedBridge")) {
                        suspiciousLoaders++;
                        item.addDetectionDetail("☕ Java层特征",
                            "可疑类加载器",
                            loaderName,
                            DetectionLayer.JAVA,
                            "🔗");
                    }
                    loader = loader.getParent();
                }

                if (suspiciousLoaders > 0) {
                    item.addDetectionDetail("☕ Java层特征",
                        "可疑加载器数量",
                        String.valueOf(suspiciousLoaders) + " 个",
                        DetectionLayer.JAVA,
                        "📊");
                }
            } catch (Exception e) {
                android.util.Log.e("HookDetector", "Error checking classloaders", e);
            }

        } catch (Exception e) {
            android.util.Log.e("HookDetector", "Error collecting LSPosed details", e);
        }

        android.util.Log.d("HookDetector", "=== collectLSPosedDetails() END - Total details: " +
            (item.hasDetails() ? item.getDetectionDetails().size() : 0) + " ===");
    }

    /**
     * Collect detailed Xposed detection information
     */
    private void collectXposedDetails(DetectionItem item) {
        // 检测 Xposed 包
        String[] xposedPackages = {
            "de.robv.android.xposed.installer",
            "de.robv.android.xposed",
            "org.meowcat.edxposed.manager"
        };

        for (String pkg : xposedPackages) {
            if (isPackageInstalled(pkg)) {
                try {
                    android.content.pm.PackageInfo pkgInfo =
                        context.getPackageManager().getPackageInfo(pkg, 0);
                    String detail = "包名: " + pkg +
                        "\n版本: " + pkgInfo.versionName;
                    item.addDetectionDetail("📱 Xposed 应用", pkg,
                        detail, DetectionLayer.JAVA, "📦");
                } catch (Exception ignored) {
                }
            }
        }

        // 检测 Xposed Bridge 类
        try {
            Class<?> bridgeClass = Class.forName("de.robv.android.xposed.XposedBridge");
            String detail = "类名: de.robv.android.xposed.XposedBridge\n状态: 已加载";
            try {
                java.lang.reflect.Field versionField = bridgeClass.getField("XPOSED_BRIDGE_VERSION");
                versionField.setAccessible(true);
                int version = (int) versionField.get(null);
                detail += "\nBridge版本: " + version;
            } catch (Exception ignored) {
            }
            item.addDetectionDetail("☕ Xposed Bridge", "XposedBridge 类",
                detail, DetectionLayer.JAVA, "🔗");
        } catch (ClassNotFoundException ignored) {
        }

        // 检测 Xposed 文件
        String[] xposedFiles = {
            "/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so",
            "/system/xposed.prop"
        };

        for (String path : xposedFiles) {
            java.io.File file = new java.io.File(path);
            if (file.exists()) {
                String detail = "路径: " + path +
                    "\n类型: " + (file.isDirectory() ? "目录" : "文件") +
                    "\n大小: " + (file.length() / 1024) + " KB";
                item.addDetectionDetail("📁 Xposed 文件", path,
                    detail, DetectionLayer.NATIVE, "📄");
            }
        }

        // 检测堆栈中的 Xposed
        try {
            throw new Exception("Xposed check");
        } catch (Exception e) {
            for (StackTraceElement element : e.getStackTrace()) {
                String className = element.getClassName();
                if (className.toLowerCase().contains("xposed")) {
                    item.addDetectionDetail("🔍 堆栈特征", "Xposed 类",
                        "类名: " + className + "\n方法: " + element.getMethodName(),
                        DetectionLayer.JAVA, "📚");
                    break;
                }
            }
        }
    }

    /**
     * Check ReZygisk in Java layer (ENHANCED with more detection points)
     * Note: SELinux may block direct file/process access
     */
    private boolean checkZygiskJava() {
        android.util.Log.d("HookDetector", "=== checkZygiskJava() START ===");
        int detectionPoints = 0;
        StringBuilder blockedChecks = new StringBuilder();

        // 1. Check module directory
        try {
            java.io.File moduleDir = new java.io.File("/data/adb/modules/rezygisk");
            if (moduleDir.exists() && moduleDir.isDirectory()) {
                android.util.Log.d("HookDetector", "✓ ReZygisk module directory found");
                detectionPoints++;
                return true;
            } else {
                android.util.Log.d("HookDetector", "✗ Module directory not accessible");
                blockedChecks.append("Module dir blocked; ");
            }
        } catch (SecurityException e) {
            android.util.Log.w("HookDetector", "⚠ SELinux blocked module dir access");
            blockedChecks.append("SELinux module; ");
        } catch (Exception e) {
            android.util.Log.w("HookDetector", "⚠ Error checking module dir: " + e.getMessage());
            blockedChecks.append("Module error; ");
        }

        // 2. Check zygisk marker file
        try {
            java.io.File zygiskFile = new java.io.File("/data/adb/modules/rezygisk/zygisk");
            if (zygiskFile.exists()) {
                android.util.Log.d("HookDetector", "✓ ReZygisk zygisk marker found");
                detectionPoints++;
                return true;
            }
        } catch (SecurityException e) {
            android.util.Log.w("HookDetector", "⚠ SELinux blocked zygisk marker access");
            blockedChecks.append("SELinux marker; ");
        } catch (Exception e) {
            blockedChecks.append("Marker error; ");
        }

        // 3. ALTERNATIVE: Use 'ps' command instead of direct /proc access (works under SELinux)
        try {
            android.util.Log.d("HookDetector", "Trying 'ps' command for process detection...");
            Process psProcess = Runtime.getRuntime().exec(new String[]{"ps", "-A"});
            java.io.BufferedReader psReader = new java.io.BufferedReader(
                new java.io.InputStreamReader(psProcess.getInputStream()));
            String psLine;
            int psCount = 0;
            StringBuilder firstFewLines = new StringBuilder();
            while ((psLine = psReader.readLine()) != null) {
                psCount++;
                // Log first 10 lines for debugging
                if (psCount <= 10) {
                    firstFewLines.append(psLine).append("\n");
                }

                String lowerPs = psLine.toLowerCase();
                // Check for ReZygisk related processes
                if (lowerPs.contains("rezygiskd") || lowerPs.contains("zygiskd") ||
                    lowerPs.contains("zygisk-ptrace") || lowerPs.contains("ptracer")) {
                    android.util.Log.w("HookDetector", "✓ ReZygisk process found via ps: " + psLine);
                    detectionPoints++;
                    psReader.close();
                    psProcess.destroy();
                    return true;
                }
            }
            android.util.Log.d("HookDetector", "✗ No ReZygisk process in ps output (" + psCount + " processes scanned)");
            android.util.Log.d("HookDetector", "First few ps lines:\n" + firstFewLines.toString());
            psReader.close();
            psProcess.waitFor();

            // If ps shows very few processes, try alternative command
            if (psCount < 50) {
                android.util.Log.w("HookDetector", "⚠ ps only showed " + psCount + " processes, trying alternative...");
                blockedChecks.append("ps restricted; ");

                // Try ps without -A flag
                Process ps2 = Runtime.getRuntime().exec("ps");
                java.io.BufferedReader ps2Reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(ps2.getInputStream()));
                String ps2Line;
                int ps2Count = 0;
                while ((ps2Line = ps2Reader.readLine()) != null) {
                    ps2Count++;
                    String lowerPs2 = ps2Line.toLowerCase();
                    if (lowerPs2.contains("rezygiskd") || lowerPs2.contains("zygiskd") ||
                        lowerPs2.contains("zygisk-ptrace") || lowerPs2.contains("ptracer")) {
                        android.util.Log.w("HookDetector", "✓ ReZygisk process found via ps (no -A): " + ps2Line);
                        detectionPoints++;
                        ps2Reader.close();
                        ps2.destroy();
                        return true;
                    }
                }
                android.util.Log.d("HookDetector", "ps without -A: " + ps2Count + " processes");
                ps2Reader.close();
                ps2.waitFor();
            }
        } catch (Exception e) {
            android.util.Log.w("HookDetector", "⚠ ps command failed: " + e.getMessage());
            blockedChecks.append("ps failed; ");
        }

        // 3b. Fallback: Try to read /proc directly (may be blocked by SELinux)
        try {
            java.io.File procDir = new java.io.File("/proc");
            java.io.File[] procs = procDir.listFiles();
            if (procs != null) {
                int accessibleProcs = 0;
                for (java.io.File proc : procs) {
                    if (!proc.getName().matches("\\d+")) continue;

                    try {
                        java.io.File cmdlineFile = new java.io.File(proc, "cmdline");
                        if (cmdlineFile.exists() && cmdlineFile.canRead()) {
                            accessibleProcs++;
                            java.io.BufferedReader reader = new java.io.BufferedReader(
                                new java.io.FileReader(cmdlineFile));
                            String cmdline = reader.readLine();
                            reader.close();

                            if (cmdline != null) {
                                // Check for rezygiskd specifically
                                if (cmdline.contains("rezygiskd") || cmdline.contains("zygiskd")) {
                                    android.util.Log.w("HookDetector", "✓ rezygiskd daemon found: " + cmdline);
                                    detectionPoints++;
                                    return true;
                                }

                                // Check for ptracer (ReZygisk uses ptracer)
                                if (cmdline.contains("ptracer")) {
                                    android.util.Log.w("HookDetector", "✓ ptracer found: " + cmdline);
                                    detectionPoints++;
                                    return true;
                                }
                            }
                        }

                        // Also check /proc/[pid]/comm
                        java.io.File commFile = new java.io.File(proc, "comm");
                        if (commFile.exists() && commFile.canRead()) {
                            java.io.BufferedReader reader = new java.io.BufferedReader(
                                new java.io.FileReader(commFile));
                            String comm = reader.readLine();
                            reader.close();

                            if (comm != null && (comm.contains("rezygiskd") ||
                                comm.contains("zygiskd") || comm.contains("ptracer"))) {
                                android.util.Log.w("HookDetector", "✓ ReZygisk daemon found via comm: " + comm);
                                detectionPoints++;
                                return true;
                            }
                        }
                    } catch (SecurityException e) {
                        // SELinux blocked, expected for root processes
                    } catch (Exception ignored) {}
                }
                android.util.Log.d("HookDetector", "✗ /proc scan: " + accessibleProcs + " processes accessible, no ReZygisk found");
                if (accessibleProcs < 10) {
                    android.util.Log.w("HookDetector", "⚠ Very few processes accessible, SELinux likely blocking");
                    blockedChecks.append("SELinux proc; ");
                }
            }
        } catch (Exception e) {
            android.util.Log.w("HookDetector", "⚠ /proc scan failed: " + e.getMessage());
            blockedChecks.append("/proc error; ");
        }

        // 4. Check memory maps for libzygisk.so (KEY: this is the actual library)
        // This is the MOST RELIABLE detection when app is in Zygisk scope
        try {
            android.util.Log.d("HookDetector", "Scanning /proc/self/maps for Zygisk libraries...");
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.FileReader("/proc/self/maps"));
            String line;
            int lineCount = 0;
            boolean foundZygiskLib = false;
            StringBuilder zygiskRelatedMaps = new StringBuilder();

            while ((line = reader.readLine()) != null) {
                lineCount++;
                String lowerLine = line.toLowerCase();

                // Check for libzygisk.so specifically (HIGHEST priority)
                if (lowerLine.contains("libzygisk.so")) {
                    foundZygiskLib = true;
                    zygiskRelatedMaps.append("✓ libzygisk.so: ").append(line.trim()).append("\n");
                    android.util.Log.w("HookDetector", "✓✓✓ CRITICAL: libzygisk.so found in maps!");
                    detectionPoints += 10; // High weight
                }

                // Check for ReZygisk dependencies
                if (lowerLine.contains("lsplt")) {
                    zygiskRelatedMaps.append("✓ lsplt: ").append(line.trim()).append("\n");
                    android.util.Log.w("HookDetector", "✓ LSPLt library found (ReZygisk dependency)");
                    detectionPoints++;
                }

                if (lowerLine.contains("csoloader")) {
                    zygiskRelatedMaps.append("✓ csoloader: ").append(line.trim()).append("\n");
                    android.util.Log.w("HookDetector", "✓ CSOLoader found (ReZygisk dependency)");
                    detectionPoints++;
                }

                // Check for module path
                if (lowerLine.contains("/data/adb/modules/rezygisk/")) {
                    zygiskRelatedMaps.append("✓ module path: ").append(line.trim()).append("\n");
                    android.util.Log.w("HookDetector", "✓ ReZygisk module path found in maps");
                    detectionPoints += 5; // Medium-high weight
                }

                // Generic rezygisk string
                if (lowerLine.contains("rezygisk") && !lowerLine.contains("/data/adb/modules/rezygisk/")) {
                    zygiskRelatedMaps.append("✓ rezygisk: ").append(line.trim()).append("\n");
                    android.util.Log.w("HookDetector", "✓ 'rezygisk' string found in maps");
                    detectionPoints++;
                }

                // Check for zygisk (generic)
                if (lowerLine.contains("zygisk") && !lowerLine.contains("zygote")) {
                    zygiskRelatedMaps.append("• zygisk: ").append(line.trim()).append("\n");
                    android.util.Log.d("HookDetector", "• Generic 'zygisk' found: " + line.trim());
                    detectionPoints++;
                }
            }
            reader.close();

            android.util.Log.d("HookDetector", "Scanned " + lineCount + " memory mappings");
            if (zygiskRelatedMaps.length() > 0) {
                android.util.Log.w("HookDetector", "Zygisk-related mappings found:\n" + zygiskRelatedMaps.toString());
            } else {
                android.util.Log.d("HookDetector", "✗ No Zygisk-related libraries in app memory");
                android.util.Log.d("HookDetector", "  → App likely not in Zygisk injection scope");
            }

            if (foundZygiskLib) {
                android.util.Log.w("HookDetector", "✓✓✓ ReZygisk DETECTED via memory injection!");
                return true;
            }
        } catch (Exception e) {
            android.util.Log.w("HookDetector", "⚠ Error reading /proc/self/maps: " + e.getMessage());
            blockedChecks.append("maps error; ");
        }

        // 5. Check for ReZygisk library files
        String[] libPaths = {
            "/data/adb/modules/rezygisk/zygisk/arm64-v8a.so",
            "/data/adb/modules/rezygisk/zygisk/armeabi-v7a.so",
            "/data/adb/modules/rezygisk/zygisk/x86_64.so",
            "/data/adb/modules/rezygisk/zygisk/x86.so",
            "/system/lib64/libzygisk.so",
            "/system/lib/libzygisk.so"
        };
        for (String path : libPaths) {
            java.io.File libFile = new java.io.File(path);
            if (libFile.exists()) {
                android.util.Log.d("HookDetector", "ReZygisk library file found: " + path);
                return true;
            }
        }

        // 6. Check module.prop for ReZygisk signature
        try {
            java.io.File moduleProp = new java.io.File("/data/adb/modules/rezygisk/module.prop");
            if (moduleProp.exists()) {
                java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.FileReader(moduleProp));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.toLowerCase().contains("rezygisk")) {
                        reader.close();
                        android.util.Log.d("HookDetector", "ReZygisk signature found in module.prop");
                        return true;
                    }
                }
                reader.close();
            }
        } catch (Exception ignored) {
        }

        // 7. Check TracerPid in /proc/self/status (ReZygisk uses ptrace)
        try {
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.FileReader("/proc/self/status"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String pidStr = line.substring(10).trim();
                    int pid = Integer.parseInt(pidStr);
                    if (pid > 0) {
                        // We have a tracer, check if it's ReZygisk
                        try {
                            java.io.File tracerCmdline = new java.io.File("/proc/" + pid + "/cmdline");
                            if (tracerCmdline.exists()) {
                                java.io.BufferedReader tracerReader = new java.io.BufferedReader(
                                    new java.io.FileReader(tracerCmdline));
                                String cmdline = tracerReader.readLine();
                                tracerReader.close();
                                if (cmdline != null && (cmdline.contains("rezygisk") ||
                                    cmdline.contains("zygisk") || cmdline.contains("ptracer"))) {
                                    reader.close();
                                    android.util.Log.d("HookDetector", "ReZygisk tracer detected: " + cmdline);
                                    return true;
                                }
                            }
                        } catch (Exception ignored2) {}
                    }
                    break;
                }
            }
            reader.close();
        } catch (Exception ignored) {
        }

        // 8. CHECK /proc/self/mountinfo for Zygisk traces (HIGHLY EFFECTIVE!)
        // This is a KEY method used by other detection apps
        try {
            android.util.Log.d("HookDetector", "Checking /proc/self/mountinfo for Zygisk traces...");
            java.io.BufferedReader mountReader = new java.io.BufferedReader(
                new java.io.FileReader("/proc/self/mountinfo"));
            String mountLine;
            int mountLineCount = 0;
            int zygiskMountCount = 0;

            while ((mountLine = mountReader.readLine()) != null) {
                mountLineCount++;
                String lowerMount = mountLine.toLowerCase();

                // Check for Zygisk-related mounts
                if (lowerMount.contains("zygisk") || lowerMount.contains("rezygisk")) {
                    zygiskMountCount++;
                    android.util.Log.w("HookDetector", "✓✓✓ Zygisk mount detected: " + mountLine.trim());
                    detectionPoints += 5; // High weight
                }

                // Check for module mounts (indirect evidence)
                if (lowerMount.contains("/data/adb/modules/") &&
                    (lowerMount.contains("zygisk") || lowerMount.contains("lsposed"))) {
                    android.util.Log.w("HookDetector", "✓ Module mount detected: " + mountLine.trim());
                    detectionPoints++;
                }

                // Check for tmpfs mounts with Zygisk characteristics
                if (lowerMount.contains("tmpfs") && lowerMount.contains("zygisk")) {
                    android.util.Log.w("HookDetector", "✓ tmpfs Zygisk mount: " + mountLine.trim());
                    detectionPoints += 2;
                }
            }
            mountReader.close();

            android.util.Log.d("HookDetector", "Scanned " + mountLineCount + " mount entries");
            if (zygiskMountCount > 0) {
                android.util.Log.w("HookDetector", "✓✓✓ FOUND " + zygiskMountCount + " Zygisk-related mounts!");
                android.util.Log.w("HookDetector", "→ This is STRONG evidence of Zygisk injection");
            } else {
                android.util.Log.d("HookDetector", "✗ No Zygisk mounts in mountinfo");
            }
        } catch (Exception e) {
            android.util.Log.w("HookDetector", "⚠ Error reading mountinfo: " + e.getMessage());
            blockedChecks.append("mountinfo error; ");
        }

        // 9. CROSS-DETECTION: Check root solution to infer Zygisk presence
        // If Magisk/KernelSU detected → high probability of Zygisk/ReZygisk
        try {
            android.util.Log.d("HookDetector", "Cross-checking root solution for Zygisk inference...");

            // Check for KernelSU (commonly paired with ReZygisk)
            boolean kernelSUNative = nativeDetector.checkKernelSUNative();
            boolean kernelSUSyscall = nativeDetector.checkKernelSUSyscall();
            boolean kernelSUDetected = kernelSUNative || kernelSUSyscall;

            android.util.Log.d("HookDetector", "KernelSU check: Native=" + kernelSUNative +
                              ", Syscall=" + kernelSUSyscall + ", Detected=" + kernelSUDetected);

            // Check for Magisk (has native Zygisk support)
            boolean magiskNative = nativeDetector.checkMagiskNative();
            boolean magiskSyscall = nativeDetector.checkMagiskSyscall();
            boolean magiskDetected = magiskNative || magiskSyscall;

            android.util.Log.d("HookDetector", "Magisk check: Native=" + magiskNative +
                              ", Syscall=" + magiskSyscall + ", Detected=" + magiskDetected);

            if (kernelSUDetected) {
                android.util.Log.w("HookDetector", "✓✓ KernelSU detected → High probability of ReZygisk");
                android.util.Log.w("HookDetector", "  → KernelSU users typically install ReZygisk for module support");
                detectionPoints += 4; // Moderate-high confidence
                blockedChecks.append("kernelsu_inference; ");
            }

            if (magiskDetected) {
                android.util.Log.w("HookDetector", "✓ Magisk detected → Possible Zygisk (native or ReZygisk)");
                android.util.Log.w("HookDetector", "  → Magisk has built-in Zygisk support");
                detectionPoints += 2; // Lower confidence (Magisk has native Zygisk)
            }

            if (!kernelSUDetected && !magiskDetected) {
                android.util.Log.d("HookDetector", "✗ No root solution detected (may be hidden or access blocked)");

                // FALLBACK: Check system properties that indicate root/modification
                try {
                    // Use reflection to access SystemProperties (hidden API)
                    Class<?> systemPropertiesClass = Class.forName("android.os.SystemProperties");
                    java.lang.reflect.Method getMethod = systemPropertiesClass.getMethod("get",
                                                                                          String.class, String.class);

                    String bootFlashLocked = (String) getMethod.invoke(null, "ro.boot.flash.locked", "1");
                    String bootVerifiedState = (String) getMethod.invoke(null, "ro.boot.verifiedbootstate", "green");

                    android.util.Log.d("HookDetector", "Boot properties: flash.locked=" + bootFlashLocked +
                                      ", verifiedbootstate=" + bootVerifiedState);

                    // flash.locked=0 and verifiedbootstate=orange indicates unlocked bootloader
                    // This is REQUIRED for KernelSU/Magisk installation
                    if ("0".equals(bootFlashLocked) && "orange".equals(bootVerifiedState)) {
                        android.util.Log.w("HookDetector", "✓ Unlocked bootloader detected (flash.locked=0, verifiedbootstate=orange)");
                        android.util.Log.w("HookDetector", "  → System is modified, likely rooted");
                        android.util.Log.w("HookDetector", "  → If /data/adb/modules/rezygisk exists, ReZygisk is HIGHLY LIKELY");
                        detectionPoints += 2; // Moderate confidence
                        blockedChecks.append("bootloader_inference; ");
                    }
                } catch (Exception propEx) {
                    android.util.Log.d("HookDetector", "Could not read boot properties: " + propEx.getMessage());
                }
            }
        } catch (Exception e) {
            android.util.Log.w("HookDetector", "⚠ Root solution check failed: " + e.getMessage());
        }

        // 10. INDIRECT DETECTION: Check for LSPosed (Zygisk variant)
        // If LSPosed (Zygisk version) is detected, it means Zygisk API is available
        // which indicates ReZygisk is likely running
        try {
            android.util.Log.d("HookDetector", "Checking for LSPosed (Zygisk variant) as indirect evidence...");

            // Check LSPosed package
            boolean lsposedInstalled = isPackageInstalled("org.lsposed.manager") ||
                                      isPackageInstalled("io.github.lsposed.manager");

            // Check for LSPosed framework classes (injected if app is in scope)
            boolean lsposedFramework = false;
            try {
                Class.forName("org.lsposed.lspd.core.Startup");
                lsposedFramework = true;
                android.util.Log.w("HookDetector", "✓ LSPosed framework detected in app");
            } catch (ClassNotFoundException ignored) {
            }

            // Check memory for LSPosed
            boolean lsposedInMemory = false;
            try {
                java.io.BufferedReader mapsReader = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/self/maps"));
                String mapsLine;
                while ((mapsLine = mapsReader.readLine()) != null) {
                    if (mapsLine.toLowerCase().contains("lsposed") ||
                        mapsLine.toLowerCase().contains("lspd")) {
                        lsposedInMemory = true;
                        android.util.Log.w("HookDetector", "✓ LSPosed detected in memory: " + mapsLine.trim());
                        break;
                    }
                }
                mapsReader.close();
            } catch (Exception ignored) {
            }

            if (lsposedInstalled || lsposedFramework || lsposedInMemory) {
                android.util.Log.w("HookDetector", "✓ LSPosed detected (Manager=" + lsposedInstalled +
                                  ", Framework=" + lsposedFramework + ", Memory=" + lsposedInMemory + ")");
                android.util.Log.w("HookDetector", "→ LSPosed (Zygisk edition) requires Zygisk API");
                android.util.Log.w("HookDetector", "→ Strong evidence suggests Zygisk/ReZygisk is present");

                // Add moderate weight for indirect detection
                detectionPoints += 3;
                blockedChecks.append("indirect_lsposed; ");
            }
        } catch (Exception e) {
            android.util.Log.w("HookDetector", "⚠ LSPosed check failed: " + e.getMessage());
        }

        // SUMMARY: Log detection results
        android.util.Log.d("HookDetector", "=== checkReZygiskJava() END ===");
        android.util.Log.d("HookDetector", "Detection points found: " + detectionPoints);
        if (blockedChecks.length() > 0) {
            android.util.Log.w("HookDetector", "Blocked checks: " + blockedChecks.toString());
            android.util.Log.w("HookDetector", "⚠ Some detection methods were blocked (likely SELinux Enforcing)");
            if (detectionPoints == 0) {
                android.util.Log.w("HookDetector", "⚠ ReZygisk may be present but undetectable due to system restrictions");
                android.util.Log.w("HookDetector", "  → App not in Zygisk injection scope");
                android.util.Log.w("HookDetector", "  → Direct file/process access blocked by SELinux");
            }
        }
        android.util.Log.d("HookDetector", "Final result: " + (detectionPoints > 0 ? "DETECTED" : "NOT DETECTED"));
        return detectionPoints > 0;
    }

    /**
     * Collect detailed ReZygisk detection information
     */
    private void collectZygiskDetails(DetectionItem item) {
        android.util.Log.d("HookDetector", "=== collectReZygiskDetails() START ===");
        try {
            // 检测模块文件
            java.io.File moduleDir = new java.io.File("/data/adb/modules/rezygisk");
            if (moduleDir.exists()) {
                item.addDetectionDetail("📁 模块目录",
                    "ReZygisk 模块",
                    "/data/adb/modules/rezygisk",
                    DetectionLayer.NATIVE,
                    "📦");

                // 检测模块文件列表
                java.io.File[] files = moduleDir.listFiles();
                if (files != null && files.length > 0) {
                    StringBuilder fileList = new StringBuilder();
                    int count = 0;
                    for (java.io.File file : files) {
                        if (count < 5) { // 只列出前5个
                            fileList.append("• ").append(file.getName()).append("\n");
                        }
                        count++;
                    }
                    if (count > 5) {
                        fileList.append("... 共 ").append(count).append(" 个文件");
                    }
                    item.addDetectionDetail("📄 模块文件",
                        "文件列表",
                        fileList.toString().trim(),
                        DetectionLayer.NATIVE,
                        "📋");
                }
            }

            // 检测 module.prop 内容
            java.io.File moduleProp = new java.io.File("/data/adb/modules/rezygisk/module.prop");
            if (moduleProp.exists()) {
                try {
                    java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.FileReader(moduleProp));
                    String line;
                    StringBuilder propContent = new StringBuilder();
                    while ((line = reader.readLine()) != null) {
                        if (line.startsWith("id=") || line.startsWith("name=") ||
                            line.startsWith("version=") || line.startsWith("description=")) {
                            propContent.append(line).append("\n");
                        }
                    }
                    reader.close();

                    if (propContent.length() > 0) {
                        item.addDetectionDetail("⚙️ 模块配置",
                            "module.prop",
                            propContent.toString().trim(),
                            DetectionLayer.NATIVE,
                            "📝");
                    }
                } catch (Exception e) {
                    android.util.Log.e("HookDetector", "Error reading module.prop", e);
                }
            }

            // 检测 rezygiskd/zygiskd/ptracer 进程
            try {
                java.io.File procDir = new java.io.File("/proc");
                java.io.File[] procs = procDir.listFiles();
                if (procs != null) {
                    for (java.io.File proc : procs) {
                        if (!proc.getName().matches("\\d+")) continue;

                        try {
                            java.io.File cmdlineFile = new java.io.File(proc, "cmdline");
                            if (cmdlineFile.exists()) {
                                java.io.BufferedReader reader = new java.io.BufferedReader(
                                    new java.io.FileReader(cmdlineFile));
                                String cmdline = reader.readLine();
                                reader.close();

                                if (cmdline != null) {
                                    if (cmdline.contains("rezygiskd")) {
                                        item.addDetectionDetail("🔄 守护进程",
                                            "rezygiskd (ReZygisk守护进程)",
                                            "PID: " + proc.getName() + "\nCMD: " + cmdline,
                                            DetectionLayer.NATIVE,
                                            "⚙️");
                                    } else if (cmdline.contains("zygiskd")) {
                                        item.addDetectionDetail("🔄 守护进程",
                                            "zygiskd (Zygisk守护进程)",
                                            "PID: " + proc.getName() + "\nCMD: " + cmdline,
                                            DetectionLayer.NATIVE,
                                            "⚙️");
                                    } else if (cmdline.contains("ptracer")) {
                                        item.addDetectionDetail("🔍 追踪进程",
                                            "ptracer (进程追踪)",
                                            "PID: " + proc.getName() + "\nCMD: " + cmdline +
                                            "\n说明: ReZygisk使用ptracer进行沙箱控制",
                                            DetectionLayer.NATIVE,
                                            "👁️");
                                    }
                                }
                            }
                        } catch (Exception ignored) {}
                    }
                }
            } catch (Exception e) {
                android.util.Log.e("HookDetector", "Error checking processes", e);
            }

            // 检测内存映射
            try {
                java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/self/maps"));
                String line;
                int rezygiskMaps = 0;
                boolean foundLibzygisk = false;
                while ((line = reader.readLine()) != null) {
                    String lowerLine = line.toLowerCase();

                    // 优先检测核心库 libzygisk.so
                    if (lowerLine.contains("libzygisk.so") && !foundLibzygisk) {
                        foundLibzygisk = true;
                        String[] parts = line.split("\\s+");
                        String addrRange = parts.length > 0 ? parts[0] : "";
                        String path = parts.length > 5 ? parts[parts.length - 1] : "";
                        String perms = parts.length > 1 ? parts[1] : "";
                        item.addDetectionDetail("💾 核心库",
                            "libzygisk.so (ReZygisk核心)",
                            "地址: " + addrRange + "\n权限: " + perms + "\n路径: " + path +
                            "\n说明: ReZygisk主注入库",
                            DetectionLayer.NATIVE,
                            "🎯");
                        rezygiskMaps++;
                    }

                    // 检测其他 ReZygisk 相关库
                    if (lowerLine.contains("rezygisk") ||
                        lowerLine.contains("lsplt") ||
                        lowerLine.contains("csoloader")) {
                        rezygiskMaps++;
                        if (rezygiskMaps <= 5) {  // 显示更多条目
                            String[] parts = line.split("\\s+");
                            String addrRange = parts.length > 0 ? parts[0] : "";
                            String path = parts.length > 5 ? parts[parts.length - 1] : "";
                            String type = "";
                            if (lowerLine.contains("lsplt")) {
                                type = "LSPLt (PLT Hook库)";
                            } else if (lowerLine.contains("csoloader")) {
                                type = "CSOLoader (自定义链接器)";
                            } else {
                                type = "ReZygisk 模块";
                            }
                            item.addDetectionDetail("💾 内存映射",
                                type,
                                "地址: " + addrRange + "\n路径: " + path,
                                DetectionLayer.NATIVE,
                                "🔍");
                        }
                    }
                }
                reader.close();
                if (rezygiskMaps > 5) {
                    item.addDetectionDetail("📊 内存统计",
                        "ReZygisk 映射总数",
                        rezygiskMaps + " 个内存区域",
                        DetectionLayer.NATIVE,
                        "📈");
                }
            } catch (Exception e) {
                android.util.Log.e("HookDetector", "Error reading maps", e);
            }

            // 检测 TracerPid (ReZygisk 使用 ptrace)
            try {
                java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/self/status"));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("TracerPid:")) {
                        String pidStr = line.substring(10).trim();
                        int pid = Integer.parseInt(pidStr);
                        if (pid > 0) {
                            try {
                                java.io.File tracerCmdline = new java.io.File("/proc/" + pid + "/cmdline");
                                if (tracerCmdline.exists()) {
                                    java.io.BufferedReader tracerReader = new java.io.BufferedReader(
                                        new java.io.FileReader(tracerCmdline));
                                    String cmdline = tracerReader.readLine();
                                    tracerReader.close();
                                    if (cmdline != null && (cmdline.contains("rezygisk") ||
                                        cmdline.contains("zygisk") || cmdline.contains("ptracer"))) {
                                        item.addDetectionDetail("🔒 Ptrace检测",
                                            "进程追踪器",
                                            "TracerPid: " + pid + "\n追踪器: " + cmdline +
                                            "\n说明: ReZygisk通过ptrace实现进程监控",
                                            DetectionLayer.NATIVE,
                                            "🛡️");
                                    }
                                }
                            } catch (Exception ignored2) {}
                        }
                        break;
                    }
                }
                reader.close();
            } catch (Exception e) {
                android.util.Log.e("HookDetector", "Error reading status", e);
            }

            // 检测特征库
            String[] libraries = {"lsplt", "csoloader"};
            for (String lib : libraries) {
                try {
                    java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.FileReader("/proc/self/maps"));
                    String line;
                    boolean found = false;
                    while ((line = reader.readLine()) != null && !found) {
                        if (line.toLowerCase().contains(lib)) {
                            String[] parts = line.split("\\s+");
                            String path = parts.length > 5 ? parts[parts.length - 1] : "";
                            item.addDetectionDetail("📚 依赖库",
                                lib.toUpperCase(),
                                "路径: " + path + "\n说明: " +
                                (lib.equals("lsplt") ? "PLT Hook库" : "自定义链接器"),
                                DetectionLayer.NATIVE,
                                "🔗");
                            found = true;
                        }
                    }
                    reader.close();
                } catch (Exception ignored) {
                }
            }

        } catch (Exception e) {
            android.util.Log.e("HookDetector", "Error collecting ReZygisk details", e);
        }

        android.util.Log.d("HookDetector", "=== collectReZygiskDetails() END - Total details: " +
            (item.hasDetails() ? item.getDetectionDetails().size() : 0) + " ===");
    }

    /**
     * Collect detailed Frida detection information
     */
    private void collectFridaDetails(DetectionItem item) {
        // 检测 Frida 端口
        int[] fridaPorts = {27042, 27043, 27044, 27045};
        for (int port : fridaPorts) {
            try {
                java.net.Socket socket = new java.net.Socket();
                socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), 100);
                socket.close();
                item.addDetectionDetail("🌐 Frida 端口", "端口 " + port,
                    "127.0.0.1:" + port + " 正在监听", DetectionLayer.JAVA, "🔌");
            } catch (Exception ignored) {
            }
        }

        // 检测 Frida 进程
        try {
            java.io.File procDir = new java.io.File("/proc");
            java.io.File[] procs = procDir.listFiles();
            if (procs != null) {
                for (java.io.File proc : procs) {
                    if (!proc.getName().matches("\\d+")) continue;

                    try {
                        java.io.File cmdlineFile = new java.io.File(proc, "cmdline");
                        if (cmdlineFile.exists()) {
                            java.io.BufferedReader reader = new java.io.BufferedReader(
                                new java.io.FileReader(cmdlineFile));
                            String cmdline = reader.readLine();
                            reader.close();

                            if (cmdline != null &&
                                (cmdline.contains("frida-server") ||
                                 cmdline.contains("frida-helper") ||
                                 cmdline.contains("re.frida.server"))) {
                                item.addDetectionDetail("🔄 Frida 进程", "frida-server",
                                    "PID: " + proc.getName() + "\nCMD: " + cmdline,
                                    DetectionLayer.NATIVE, "⚙️");
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {
        }

        // 检测 Frida 文件
        String[] fridaFiles = {
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida-agent"
        };

        for (String path : fridaFiles) {
            java.io.File file = new java.io.File(path);
            if (file.exists()) {
                String detail = "路径: " + path +
                    "\n大小: " + (file.length() / 1024) + " KB";
                if (file.canExecute()) {
                    detail += "\n权限: 可执行";
                }
                item.addDetectionDetail("📁 Frida 文件", path,
                    detail, DetectionLayer.NATIVE, "📄");
            }
        }

        // 检测内存中的 Frida
        try {
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.FileReader("/proc/self/maps"));
            String line;
            int fridaMaps = 0;
            while ((line = reader.readLine()) != null) {
                String lowerLine = line.toLowerCase();
                if (lowerLine.contains("frida") ||
                    lowerLine.contains("gum-js-loop") ||
                    lowerLine.contains("frida-agent")) {
                    fridaMaps++;
                    if (fridaMaps <= 3) {
                        String[] parts = line.split("\\s+");
                        String addrRange = parts.length > 0 ? parts[0] : "";
                        String path = parts.length > 5 ? parts[parts.length - 1] : "";
                        item.addDetectionDetail("💾 内存特征", "Frida 内存映射",
                            "地址: " + addrRange + "\n路径: " + path,
                            DetectionLayer.NATIVE, "🔍");
                    }
                }
            }
            reader.close();
            if (fridaMaps > 3) {
                item.addDetectionDetail("📊 内存统计", "Frida 映射数量",
                    fridaMaps + " 个", DetectionLayer.NATIVE, "📈");
            }
        } catch (Exception ignored) {
        }

        // 检测 Frida 线程
        try {
            java.io.File taskDir = new java.io.File("/proc/self/task");
            java.io.File[] tasks = taskDir.listFiles();
            if (tasks != null) {
                for (java.io.File task : tasks) {
                    try {
                        java.io.File commFile = new java.io.File(task, "comm");
                        if (commFile.exists()) {
                            java.io.BufferedReader reader = new java.io.BufferedReader(
                                new java.io.FileReader(commFile));
                            String threadName = reader.readLine();
                            reader.close();

                            if (threadName != null &&
                                (threadName.contains("gmain") ||
                                 threadName.contains("gdbus") ||
                                 threadName.contains("gum-js-loop") ||
                                 threadName.contains("pool-frida"))) {
                                item.addDetectionDetail("🧵 Frida 线程", threadName,
                                    "TID: " + task.getName() + "\n线程名: " + threadName,
                                    DetectionLayer.NATIVE, "🔗");
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {
        }
    }
}
