package com.xff.launch.detector;

import android.content.Context;
import android.os.Debug;
import android.provider.Settings;

import com.xff.launch.model.DetectionItem;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.DetectionStatus;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Debug detection with multi-layer support
 */
public class DebugDetector {

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
        return items;
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
                // IDA Pro android_server 默认端口 23946 = 0x5D8A
                if (line.contains(":5D8A")) {
                    item.addDetectionDetail("🌐 IDA 端口", "/proc/net/tcp",
                        "检测到 IDA Pro 端口 23946 (0x5D8A): " + line.trim(),
                        DetectionLayer.JAVA, "🔌");
                }
                // Frida 默认端口 27042 = 0x69A2, 27043 = 0x69A3
                if (line.contains(":69A2") || line.contains(":69A3")) {
                    item.addDetectionDetail("🌐 Frida 端口", "/proc/net/tcp",
                        "检测到 Frida 端口: " + line.trim(),
                        DetectionLayer.JAVA, "🔌");
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
}
