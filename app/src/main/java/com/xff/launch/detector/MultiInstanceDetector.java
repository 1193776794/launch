package com.xff.launch.detector;

import android.content.Context;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 多开容器 / 沙箱劫持检测。
 *
 * <p>对照京东 JDGuard field 1（多开/沙箱/UID 一致性自检）：
 * <ul>
 *   <li>多开容器：遍历 ActivityThread.mPackages，发现非本包且 /data/data 可写的宿主
 *       → 命中 VirtualXposed / 分身大师 / 双开助手 等多开框架。</li>
 *   <li>沙箱路径劫持：在 filesDir 建临时文件取 fd，readlink /proc/self/fd/N 拿内核视角真实路径，
 *       basename/路径与申报不符 → 文件系统被虚拟化劫持（多开容器特征）。/proc/self/fd 是内核视角，
 *       多开器很难 hook。</li>
 * </ul>
 *
 * <p>注：UID 四源一致性校验放在指纹板块（uid_consistency，多路投票天然标红），此处不重复。
 */
public class MultiInstanceDetector {

    private final Context context;
    private final NativeDetector nativeDetector;

    public MultiInstanceDetector(Context context) {
        this.context = context.getApplicationContext();
        this.nativeDetector = NativeDetector.getInstance();
    }

    public List<DetectionItem> getAllDetections() {
        List<DetectionItem> items = new ArrayList<>();
        items.add(detectMultiOpenContainer());
        items.add(detectSandboxHijack());
        items.add(detectFakeLibs());
        return items;
    }

    // ===================== 3. fake-libs 多开特征 (JD field 16-1) =====================

    /**
     * 检测 fake-libs 特征（VirtualXposed/分身大师等多开容器把伪造 so 放进 fake-libs/
     * 并加入 LD_LIBRARY_PATH 来 hook 目标 App）。三处取证：
     * 自身 nativeLibraryDir / /proc/self/maps / 已知容器 fake-libs 路径。
     */
    private DetectionItem detectFakeLibs() {
        DetectionItem item = new DetectionItem("fake-libs 多开特征",
                "nativeLibraryDir / maps / 容器目录是否含 fake-libs");
        boolean detected = false;
        try {
            // 1) 自身 native 库目录
            String nld = context.getApplicationInfo().nativeLibraryDir;
            if (nld != null && nld.contains("fake-libs")) {
                detected = true;
                item.addDetectionDetail("⚠️ nativeLibraryDir", nld,
                        "本进程 native 库目录含 fake-libs — 多开容器特征", DetectionLayer.JAVA, "🔴");
            } else {
                item.addDetectionDetail("✅ nativeLibraryDir", nld != null ? nld : "(空)",
                        "无 fake-libs 痕迹", DetectionLayer.JAVA, "🟢");
            }

            // 2) /proc/self/maps（syscall 读，绕 libc hook）
            String maps = nativeDetector.readFileSyscall("/proc/self/maps");
            if (maps != null && maps.contains("fake-libs")) {
                detected = true;
                item.addDetectionDetail("⚠️ /proc/self/maps", "含 fake-libs 映射",
                        "已加载伪造 so — 多开/注入特征", DetectionLayer.SYSCALL, "🔴");
            }

            // 3) 已知多开容器 fake-libs 路径存在性
            String[] containerPaths = {
                    "/data/data/io.va.exposed/fake-libs",
                    "/data/data/io.va.exposed64/fake-libs",
                    "/data/data/io.va.exposed/fake-libs64",
            };
            for (String p : containerPaths) {
                try {
                    if (new File(p).exists()) {
                        detected = true;
                        item.addDetectionDetail("⚠️ 容器路径", p,
                                "VirtualXposed/多开容器 fake-libs 目录存在", DetectionLayer.JAVA, "🔴");
                    }
                } catch (Exception ignored) {}
            }

            item.setLayerResult(DetectionLayer.JAVA, detected);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, detected);
            if (detected) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到 fake-libs 多开/注入特征");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未检测到 fake-libs 特征");
            }
        } catch (Exception e) {
            unknown(item, e);
        }
        return item;
    }

    // ===================== 1. 多开容器检测 (JD field 1-2) =====================

    @SuppressWarnings("unchecked")
    private DetectionItem detectMultiOpenContainer() {
        DetectionItem item = new DetectionItem("多开容器检测",
                "遍历已加载包，发现非本包且 /data/data 可写宿主 → 多开框架");
        String self = context.getPackageName();
        boolean detected = false;
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Method currentAT = atClass.getMethod("currentActivityThread");
            Object at = currentAT.invoke(null);
            Field mPackagesField = atClass.getDeclaredField("mPackages");
            mPackagesField.setAccessible(true);
            Map<String, ?> mPackages = (Map<String, ?>) mPackagesField.get(at);

            int foreign = 0;
            if (mPackages != null) {
                for (String pkg : mPackages.keySet()) {
                    if (pkg == null || pkg.equals(self)) continue;
                    if (pkg.endsWith("android.webview") || pkg.endsWith("webview")) continue;
                    boolean writable = false;
                    try {
                        writable = new File("/data/data/" + pkg).canWrite();
                    } catch (Exception ignored) {}
                    if (writable) {
                        foreign++;
                        detected = true;
                        item.addDetectionDetail("⚠️ 多开宿主", pkg,
                                "/data/data/" + pkg + " 可写 — 多开容器特征",
                                DetectionLayer.JAVA, "🔴");
                    }
                }
            }
            if (!detected) {
                item.addDetectionDetail("✅ 已加载包", "仅本包 (" + self + ")",
                        "未发现可写的外部包目录", DetectionLayer.JAVA, "🟢");
            }

            item.setLayerResult(DetectionLayer.JAVA, detected);
            item.setLayerResult(DetectionLayer.NATIVE, false);
            item.setLayerResult(DetectionLayer.SYSCALL, false);
            if (detected) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("检测到 " + foreign + " 个多开容器宿主包");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("未检测到多开容器");
            }
        } catch (Exception e) {
            unknown(item, e);
        }
        return item;
    }

    // ===================== 2. 沙箱路径劫持 (JD field 1-3/1-4) =====================

    private DetectionItem detectSandboxHijack() {
        DetectionItem item = new DetectionItem("沙箱路径劫持",
                "fd readlink 内核视角真实路径 vs 申报路径 (多开器难 hook)");
        File tmp = null;
        FileOutputStream fos = null;
        try {
            File dir = context.getFilesDir();
            tmp = new File(dir, "jdg_fdprobe_" + android.os.Process.myPid());
            fos = new FileOutputStream(tmp);
            FileDescriptor jfd = fos.getFD();

            int fdNum = extractFdNumber(jfd);
            if (fdNum < 0) {
                item.addDetectionDetail("❓ fd 解析", "失败", "无法反射取 FileDescriptor 整数",
                        DetectionLayer.JAVA, "⚪");
                unknown(item, null);
                return item;
            }

            String linkPath = "/proc/self/fd/" + fdNum;
            // 内核视角真实路径（syscall readlink，绕过 libc/Java hook）
            String realPath = nativeDetector.readlinkSyscall(linkPath);
            if (realPath == null || realPath.isEmpty()) {
                realPath = nativeDetector.readlinkNative(linkPath);
            }

            String declaredPath = tmp.getAbsolutePath();
            String declaredName = tmp.getName();

            item.addDetectionDetail("📄 申报路径", declaredPath,
                    "Java 视角 getFilesDir()", DetectionLayer.JAVA, "📊");
            item.addDetectionDetail("🛡 内核真实路径",
                    realPath == null || realPath.isEmpty() ? "(读不到)" : realPath,
                    "readlink /proc/self/fd/" + fdNum + " — 内核视角", DetectionLayer.SYSCALL, "📊");

            boolean hijacked = false;
            if (realPath != null && !realPath.isEmpty()) {
                String realName = new File(realPath).getName();
                // basename 不符，或真实路径不包含申报目录 → 被虚拟化劫持
                if (!realName.equals(declaredName)) {
                    hijacked = true;
                    item.addDetectionDetail("⚠️ 路径不一致", "basename: " + realName + " ≠ " + declaredName,
                            "fd 真实路径与申报不符 — 沙箱被劫持/多开", DetectionLayer.SYSCALL, "🔴");
                }
            }

            item.setLayerResult(DetectionLayer.JAVA, false);
            item.setLayerResult(DetectionLayer.NATIVE, hijacked);
            item.setLayerResult(DetectionLayer.SYSCALL, hijacked);
            if (hijacked) {
                item.setStatus(DetectionStatus.RISK);
                item.setDetail("fd 真实路径与申报不一致 — 疑似多开/沙箱劫持");
            } else {
                item.setStatus(DetectionStatus.SAFE);
                item.setDetail("fd 路径与申报一致 — 沙箱未被劫持");
            }
        } catch (Exception e) {
            unknown(item, e);
        } finally {
            try { if (fos != null) fos.close(); } catch (Exception ignored) {}
            try { if (tmp != null) tmp.delete(); } catch (Exception ignored) {}
        }
        return item;
    }

    /** 反射 FileDescriptor 的整数值（字段名 "descriptor" 或方法 getInt$）。 */
    private static int extractFdNumber(FileDescriptor fd) {
        try {
            Field f = FileDescriptor.class.getDeclaredField("descriptor");
            f.setAccessible(true);
            return f.getInt(fd);
        } catch (Exception ignored) {}
        try {
            Method m = FileDescriptor.class.getDeclaredMethod("getInt$");
            m.setAccessible(true);
            return (int) m.invoke(fd);
        } catch (Exception ignored) {}
        return -1;
    }

    private void unknown(DetectionItem item, Exception e) {
        item.setLayerResult(DetectionLayer.JAVA, false);
        item.setLayerResult(DetectionLayer.NATIVE, false);
        item.setLayerResult(DetectionLayer.SYSCALL, false);
        item.setStatus(DetectionStatus.UNKNOWN);
        item.setDetail("无法采集" + (e != null && e.getMessage() != null ? ": " + e.getMessage() : ""));
    }
}
