package com.xff.launch.util;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraManager;
import android.media.AudioManager;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.opengl.GLES20;
import android.util.SizeF;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.zip.GZIPInputStream;

/**
 * 扩展硬件指纹采集源——传感器/GPU/相机/编解码器等需要 SDK API 的维度。
 *
 * <p>所有方法都做了异常隔离，失败返回空串（引擎据此标 EMPTY）。这里只负责"怎么取"，
 * "取什么"在 {@code FingerprintDefinitions} 声明。
 */
public final class HwProbe {

    private HwProbe() {}

    private static String hash(String s) {
        if (s == null || s.isEmpty()) return "";
        return ReflectionUtils.djb2Hash(s);
    }

    // ==================== 传感器列表指纹（机型级·铁稳·无权限）====================

    /**
     * 枚举全部传感器的硬件描述（名/厂/版本/量程/分辨率/功耗/采样），排序后取 hash。
     * 不依赖运动状态，跨会话稳定，熵很高。
     */
    public static String sensorListFingerprint(Context ctx) {
        try {
            SensorManager sm = (SensorManager) ctx.getSystemService(Context.SENSOR_SERVICE);
            if (sm == null) return "";
            List<Sensor> list = sm.getSensorList(Sensor.TYPE_ALL);
            if (list == null || list.isEmpty()) return "";
            List<String> rows = new ArrayList<>();
            for (Sensor s : list) {
                rows.add(s.getName() + "|" + s.getVendor() + "|" + s.getVersion() + "|" + s.getType()
                        + "|" + s.getMaximumRange() + "|" + s.getResolution() + "|" + s.getPower()
                        + "|" + s.getMinDelay());
            }
            Collections.sort(rows);
            return hash(joinLines(rows));
        } catch (Throwable t) {
            return "";
        }
    }

    // ==================== GPU 渲染指纹（离屏 EGL）====================

    /** GL_VENDOR | GL_RENDERER | GL_VERSION，机型级高熵。 */
    public static String gpuFingerprint() {
        EGLDisplay dpy = EGL14.EGL_NO_DISPLAY;
        EGLContext context = EGL14.EGL_NO_CONTEXT;
        EGLSurface surface = EGL14.EGL_NO_SURFACE;
        try {
            dpy = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY);
            if (dpy == EGL14.EGL_NO_DISPLAY) return "";
            int[] ver = new int[2];
            if (!EGL14.eglInitialize(dpy, ver, 0, ver, 1)) return "";

            int[] cfgAttr = {
                    EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                    EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT,
                    EGL14.EGL_NONE
            };
            EGLConfig[] cfgs = new EGLConfig[1];
            int[] num = new int[1];
            if (!EGL14.eglChooseConfig(dpy, cfgAttr, 0, cfgs, 0, 1, num, 0) || num[0] == 0) return "";

            int[] ctxAttr = {EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE};
            context = EGL14.eglCreateContext(dpy, cfgs[0], EGL14.EGL_NO_CONTEXT, ctxAttr, 0);
            int[] surfAttr = {EGL14.EGL_WIDTH, 1, EGL14.EGL_HEIGHT, 1, EGL14.EGL_NONE};
            surface = EGL14.eglCreatePbufferSurface(dpy, cfgs[0], surfAttr, 0);
            if (!EGL14.eglMakeCurrent(dpy, surface, surface, context)) return "";

            String vendor = GLES20.glGetString(GLES20.GL_VENDOR);
            String renderer = GLES20.glGetString(GLES20.GL_RENDERER);
            String version = GLES20.glGetString(GLES20.GL_VERSION);
            return safe(vendor) + "|" + safe(renderer) + "|" + safe(version);
        } catch (Throwable t) {
            return "";
        } finally {
            try {
                if (dpy != EGL14.EGL_NO_DISPLAY) {
                    EGL14.eglMakeCurrent(dpy, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
                    if (surface != EGL14.EGL_NO_SURFACE) EGL14.eglDestroySurface(dpy, surface);
                    if (context != EGL14.EGL_NO_CONTEXT) EGL14.eglDestroyContext(dpy, context);
                    EGL14.eglTerminate(dpy);
                }
            } catch (Throwable ignored) {}
        }
    }

    // ==================== 相机特性指纹（机型级）====================

    public static String cameraFingerprint(Context ctx) {
        try {
            CameraManager cm = (CameraManager) ctx.getSystemService(Context.CAMERA_SERVICE);
            if (cm == null) return "";
            String[] ids = cm.getCameraIdList();
            List<String> rows = new ArrayList<>();
            for (String id : ids) {
                CameraCharacteristics cc = cm.getCameraCharacteristics(id);
                Integer facing = cc.get(CameraCharacteristics.LENS_FACING);
                SizeF physical = cc.get(CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE);
                android.util.Size pixels = cc.get(CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE);
                float[] focal = cc.get(CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS);
                Integer level = cc.get(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL);
                rows.add(id + "|" + facing + "|" + physical + "|" + pixels
                        + "|" + Arrays.toString(focal) + "|" + level);
            }
            Collections.sort(rows);
            return hash(joinLines(rows));
        } catch (Throwable t) {
            return "";
        }
    }

    // ==================== 编解码器指纹（机型级·无权限）====================

    public static String mediaCodecFingerprint() {
        try {
            MediaCodecList mcl = new MediaCodecList(MediaCodecList.REGULAR_CODECS);
            MediaCodecInfo[] infos = mcl.getCodecInfos();
            List<String> rows = new ArrayList<>();
            for (MediaCodecInfo ci : infos) {
                String[] types = ci.getSupportedTypes();
                Arrays.sort(types);
                rows.add(ci.getName() + "|" + ci.isEncoder() + "|" + Arrays.toString(types));
            }
            Collections.sort(rows);
            return hash(joinLines(rows));
        } catch (Throwable t) {
            return "";
        }
    }

    // ==================== 文件型大块 hash（机型级）====================

    /** 整文件读取后 djb2，失败空串。供 /proc/cpuinfo、/proc/iomem 等使用。 */
    public static String fileHash(String path) {
        String content = ReflectionUtils.readFile(path);
        return hash(content);
    }

    /** 多路径取第一份非空内容做 hash（用于内存布局：iomem/zoneinfo 任一）。 */
    public static String fileHashAny(String... paths) {
        for (String p : paths) {
            String c = ReflectionUtils.readFile(p);
            if (c != null && !c.isEmpty()) return hash(c);
        }
        return "";
    }

    /** eMMC CID / UFS 序列（存储芯片序列）多路径首个命中。UFS 设备无 mmcblk，走 sda。 */
    public static String storageCid() {
        String[] paths = {
                // eMMC
                "/sys/block/mmcblk0/device/cid",
                "/sys/class/mmc_host/mmc0/mmc0:0001/cid",
                "/sys/class/mmc_host/mmc0/mmc0:0001/serial",
                // UFS（MEIZU 21 等旗舰）
                "/sys/block/sda/device/serial",
                "/sys/block/sda/device/unique_id",
                "/sys/devices/platform/soc/1d84000.ufshc/string_descriptors/serial_number"
        };
        for (String p : paths) {
            String v = ReflectionUtils.readFileFirstLine(p);
            if (v != null && !v.isEmpty()) return v.trim();
        }
        return "";
    }

    /** Device-Tree compatible（机型/板型）。 */
    public static String deviceTreeCompat() {
        String[] paths = {
                "/proc/device-tree/compatible",
                "/sys/firmware/devicetree/base/compatible"
        };
        for (String p : paths) {
            String c = ReflectionUtils.readFile(p);
            if (c != null && !c.isEmpty()) {
                return c.replace('\0', ';').trim();
            }
        }
        return "";
    }

    // ==================== 电池特征（机型级·设计容量稳定）====================

    /** 设计容量(mAh) | 电池技术。容量经 PowerProfile 反射，技术读 sysfs。 */
    public static String batteryFingerprint(Context ctx) {
        String cap = "";
        try {
            Class<?> cls = Class.forName("com.android.internal.os.PowerProfile");
            Object pp = cls.getConstructor(Context.class).newInstance(ctx);
            double mAh = (double) cls.getMethod("getBatteryCapacity").invoke(pp);
            cap = String.valueOf(Math.round(mAh));
        } catch (Throwable ignored) {
        }
        if (cap.isEmpty()) {
            // sysfs 设计容量(µAh)兜底
            String design = ReflectionUtils.readFileFirstLine("/sys/class/power_supply/battery/charge_full_design");
            if (design != null && !design.isEmpty()) {
                try { cap = String.valueOf(Long.parseLong(design.trim()) / 1000); } catch (Exception e) { cap = design.trim(); }
            }
        }
        String tech = ReflectionUtils.readFileFirstLine("/sys/class/power_supply/battery/technology");
        String s = cap + "|" + (tech == null ? "" : tech.trim());
        return s.equals("|") ? "" : s;
    }

    // ==================== 热区列表（机型级）====================

    /** 枚举各 thermal_zoneN 的 type 文件，类型清单 hash。 */
    public static String thermalZonesFingerprint() {
        List<String> types = new ArrayList<>();
        for (int i = 0; i < 64; i++) {
            String type = ReflectionUtils.readFileFirstLine("/sys/class/thermal/thermal_zone" + i + "/type");
            if (type == null || type.isEmpty()) {
                if (i > 0) break; // zone0 必有；连续缺失即结束
                else continue;
            }
            types.add(type.trim());
        }
        if (types.isEmpty()) return "";
        return hash(joinLines(types));
    }

    // ==================== CPU 拓扑（大小核分簇布局）====================

    public static String cpuTopologyFingerprint() {
        StringBuilder sb = new StringBuilder();
        String present = ReflectionUtils.readFileFirstLine("/sys/devices/system/cpu/present");
        sb.append("present=").append(present == null ? "" : present.trim()).append('\n');
        for (int i = 0; i < 32; i++) {
            String base = "/sys/devices/system/cpu/cpu" + i;
            String pkg = ReflectionUtils.readFileFirstLine(base + "/topology/physical_package_id");
            String sib = ReflectionUtils.readFileFirstLine(base + "/topology/core_siblings_list");
            String maxFreq = ReflectionUtils.readFileFirstLine(base + "/cpufreq/cpuinfo_max_freq");
            if ((pkg == null || pkg.isEmpty()) && (sib == null || sib.isEmpty()) && (maxFreq == null || maxFreq.isEmpty())) {
                if (i > 0) break; else continue;
            }
            sb.append("cpu").append(i).append(':').append(trimOf(pkg)).append('/')
                    .append(trimOf(sib)).append('/').append(trimOf(maxFreq)).append('\n');
        }
        return hash(sb.toString());
    }

    private static String trimOf(String s) {
        return s == null ? "" : s.trim();
    }

    // ==================== GPU 能力/扩展全集（比 renderer 串熵更高）====================

    /** GL_EXTENSIONS + SLVERSION + MAX_TEXTURE_SIZE + EGL 扩展，取 hash。 */
    public static String gpuCapsFingerprint() {
        EGLDisplay dpy = EGL14.EGL_NO_DISPLAY;
        EGLContext context = EGL14.EGL_NO_CONTEXT;
        EGLSurface surface = EGL14.EGL_NO_SURFACE;
        try {
            dpy = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY);
            if (dpy == EGL14.EGL_NO_DISPLAY) return "";
            int[] ver = new int[2];
            if (!EGL14.eglInitialize(dpy, ver, 0, ver, 1)) return "";
            int[] cfgAttr = {EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                    EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT, EGL14.EGL_NONE};
            EGLConfig[] cfgs = new EGLConfig[1];
            int[] num = new int[1];
            if (!EGL14.eglChooseConfig(dpy, cfgAttr, 0, cfgs, 0, 1, num, 0) || num[0] == 0) return "";
            int[] ctxAttr = {EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE};
            context = EGL14.eglCreateContext(dpy, cfgs[0], EGL14.EGL_NO_CONTEXT, ctxAttr, 0);
            int[] surfAttr = {EGL14.EGL_WIDTH, 1, EGL14.EGL_HEIGHT, 1, EGL14.EGL_NONE};
            surface = EGL14.eglCreatePbufferSurface(dpy, cfgs[0], surfAttr, 0);
            if (!EGL14.eglMakeCurrent(dpy, surface, surface, context)) return "";

            StringBuilder sb = new StringBuilder();
            sb.append(safe(GLES20.glGetString(GLES20.GL_EXTENSIONS))).append('\n');
            sb.append(safe(GLES20.glGetString(GLES20.GL_SHADING_LANGUAGE_VERSION))).append('\n');
            int[] maxTex = new int[1];
            GLES20.glGetIntegerv(GLES20.GL_MAX_TEXTURE_SIZE, maxTex, 0);
            sb.append("maxTex=").append(maxTex[0]).append('\n');
            sb.append(safe(EGL14.eglQueryString(dpy, EGL14.EGL_EXTENSIONS))).append('\n');
            sb.append(safe(EGL14.eglQueryString(dpy, EGL14.EGL_VENDOR)));
            return hash(sb.toString());
        } catch (Throwable t) {
            return "";
        } finally {
            try {
                if (dpy != EGL14.EGL_NO_DISPLAY) {
                    EGL14.eglMakeCurrent(dpy, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
                    if (surface != EGL14.EGL_NO_SURFACE) EGL14.eglDestroySurface(dpy, surface);
                    if (context != EGL14.EGL_NO_CONTEXT) EGL14.eglDestroyContext(dpy, context);
                    EGL14.eglTerminate(dpy);
                }
            } catch (Throwable ignored) {}
        }
    }

    // ==================== GPU 像素渲染指纹（WebGL canvas 的安卓移植）====================

    /**
     * 离屏渲染一个确定性场景（含 sin/pow/tan/fract 等放大 GPU 浮点精度差异的着色器），
     * glReadPixels 读回像素做 SHA-256。熵定位「GPU 型号 + 驱动」级——同型号同 ROM 相同，
     * 但难伪造、抗恢复出厂、可揪模拟器/云机。
     */
    public static String glPixelFingerprint() {
        final int W = 256, H = 256;
        EGLDisplay dpy = EGL14.EGL_NO_DISPLAY;
        EGLContext context = EGL14.EGL_NO_CONTEXT;
        EGLSurface surface = EGL14.EGL_NO_SURFACE;
        try {
            dpy = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY);
            if (dpy == EGL14.EGL_NO_DISPLAY) return "";
            int[] ver = new int[2];
            if (!EGL14.eglInitialize(dpy, ver, 0, ver, 1)) return "";
            int[] cfgAttr = {
                    EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                    EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT,
                    EGL14.EGL_RED_SIZE, 8, EGL14.EGL_GREEN_SIZE, 8,
                    EGL14.EGL_BLUE_SIZE, 8, EGL14.EGL_ALPHA_SIZE, 8,
                    EGL14.EGL_NONE
            };
            EGLConfig[] cfgs = new EGLConfig[1];
            int[] num = new int[1];
            if (!EGL14.eglChooseConfig(dpy, cfgAttr, 0, cfgs, 0, 1, num, 0) || num[0] == 0) return "";
            int[] ctxAttr = {EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE};
            context = EGL14.eglCreateContext(dpy, cfgs[0], EGL14.EGL_NO_CONTEXT, ctxAttr, 0);
            int[] surfAttr = {EGL14.EGL_WIDTH, W, EGL14.EGL_HEIGHT, H, EGL14.EGL_NONE};
            surface = EGL14.eglCreatePbufferSurface(dpy, cfgs[0], surfAttr, 0);
            if (!EGL14.eglMakeCurrent(dpy, surface, surface, context)) return "";

            final String VS =
                    "attribute vec2 aPos;\n" +
                    "void main(){ gl_Position = vec4(aPos, 0.0, 1.0); }\n";
            final String FS =
                    "precision highp float;\n" +
                    "void main(){\n" +
                    "  vec2 p = gl_FragCoord.xy / 256.0;\n" +
                    "  float a = fract(sin(dot(p, vec2(12.9898,78.233))) * 43758.5453);\n" +
                    "  float b = pow(p.x, 2.2) * cos(p.y * 50.0);\n" +
                    "  float c = tan(p.x * 3.14159 + 0.0007);\n" +
                    "  float d = exp(p.y) * sin(p.x * 91.7);\n" +
                    "  gl_FragColor = vec4(fract(a+d), fract(abs(b)), fract(abs(c)), 1.0);\n" +
                    "}\n";

            int prog = buildProgram(VS, FS);
            if (prog == 0) return "";

            GLES20.glDisable(GLES20.GL_DITHER);
            GLES20.glViewport(0, 0, W, H);
            GLES20.glClearColor(0f, 0f, 0f, 1f);
            GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT);
            GLES20.glUseProgram(prog);

            float[] quad = {-1f, -1f, 1f, -1f, -1f, 1f, 1f, 1f};
            FloatBuffer vb = ByteBuffer.allocateDirect(quad.length * 4)
                    .order(ByteOrder.nativeOrder()).asFloatBuffer();
            vb.put(quad).position(0);
            int loc = GLES20.glGetAttribLocation(prog, "aPos");
            GLES20.glEnableVertexAttribArray(loc);
            GLES20.glVertexAttribPointer(loc, 2, GLES20.GL_FLOAT, false, 0, vb);
            GLES20.glDrawArrays(GLES20.GL_TRIANGLE_STRIP, 0, 4);
            GLES20.glFinish();

            ByteBuffer pixels = ByteBuffer.allocateDirect(W * H * 4).order(ByteOrder.nativeOrder());
            GLES20.glReadPixels(0, 0, W, H, GLES20.GL_RGBA, GLES20.GL_UNSIGNED_BYTE, pixels);
            pixels.position(0);
            byte[] buf = new byte[W * H * 4];
            pixels.get(buf);
            return sha256Hex(buf);
        } catch (Throwable t) {
            return "";
        } finally {
            try {
                if (dpy != EGL14.EGL_NO_DISPLAY) {
                    EGL14.eglMakeCurrent(dpy, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
                    if (surface != EGL14.EGL_NO_SURFACE) EGL14.eglDestroySurface(dpy, surface);
                    if (context != EGL14.EGL_NO_CONTEXT) EGL14.eglDestroyContext(dpy, context);
                    EGL14.eglTerminate(dpy);
                }
            } catch (Throwable ignored) {}
        }
    }

    private static int buildProgram(String vs, String fs) {
        int v = compileShader(GLES20.GL_VERTEX_SHADER, vs);
        int f = compileShader(GLES20.GL_FRAGMENT_SHADER, fs);
        if (v == 0 || f == 0) return 0;
        int prog = GLES20.glCreateProgram();
        if (prog == 0) return 0;
        GLES20.glAttachShader(prog, v);
        GLES20.glAttachShader(prog, f);
        GLES20.glLinkProgram(prog);
        int[] status = new int[1];
        GLES20.glGetProgramiv(prog, GLES20.GL_LINK_STATUS, status, 0);
        GLES20.glDeleteShader(v);
        GLES20.glDeleteShader(f);
        if (status[0] == 0) {
            GLES20.glDeleteProgram(prog);
            return 0;
        }
        return prog;
    }

    private static int compileShader(int type, String src) {
        int s = GLES20.glCreateShader(type);
        if (s == 0) return 0;
        GLES20.glShaderSource(s, src);
        GLES20.glCompileShader(s);
        int[] status = new int[1];
        GLES20.glGetShaderiv(s, GLES20.GL_COMPILE_STATUS, status, 0);
        if (status[0] == 0) {
            GLES20.glDeleteShader(s);
            return 0;
        }
        return s;
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : h) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) sb.append('0');
                sb.append(hex);
            }
            return sb.substring(0, 16); // 取前 16 hex 足够
        } catch (Throwable t) {
            return "";
        }
    }

    // ==================== 音频 HAL 参数（机型级·无权限）====================

    public static String audioFingerprint(Context ctx) {
        try {
            AudioManager am = (AudioManager) ctx.getSystemService(Context.AUDIO_SERVICE);
            if (am == null) return "";
            String sr = am.getProperty(AudioManager.PROPERTY_OUTPUT_SAMPLE_RATE);
            String fpb = am.getProperty(AudioManager.PROPERTY_OUTPUT_FRAMES_PER_BUFFER);
            String s = safe(sr) + "|" + safe(fpb);
            return s.equals("|") ? "" : s;
        } catch (Throwable t) {
            return "";
        }
    }

    // ==================== 系统属性全量 Hash（构建级软件指纹）====================

    private static final String[] PROP_KEYS = {
            "ro.product.model", "ro.product.brand", "ro.product.device", "ro.product.name",
            "ro.product.manufacturer", "ro.board.platform", "ro.hardware", "ro.bootloader",
            "ro.build.fingerprint", "ro.build.id", "ro.build.display.id", "ro.build.version.release",
            "ro.build.version.sdk", "ro.build.version.security_patch", "ro.build.version.incremental",
            "ro.build.date.utc", "ro.build.type", "ro.build.tags", "ro.build.flavor",
            "ro.build.description", "ro.vendor.build.fingerprint", "ro.system.build.fingerprint",
            "ro.boot.hardware", "ro.boot.bootloader", "ro.chipname", "ro.soc.model", "ro.soc.manufacturer"
    };

    /** 遍历固定 ro.* 属性集，拼接后 hash——比单条属性更稳更高熵。 */
    public static String propSetHash() {
        StringBuilder sb = new StringBuilder();
        for (String k : PROP_KEYS) {
            sb.append(k).append('=').append(ReflectionUtils.getSystemProperty(k)).append('\n');
        }
        return hash(sb.toString());
    }

    // ==================== 内核配置 hash ====================

    /** /proc/config.gz 解压后 djb2（构建级，高版本可能不可读）。 */
    public static String kernelConfigHash() {
        InputStream in = null;
        try {
            in = new GZIPInputStream(new FileInputStream("/proc/config.gz"));
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            return hash(bos.toString("UTF-8"));
        } catch (Throwable t) {
            return "";
        } finally {
            try { if (in != null) in.close(); } catch (Throwable ignored) {}
        }
    }

    // ==================== 工具 ====================

    private static String joinLines(List<String> rows) {
        StringBuilder sb = new StringBuilder();
        for (String r : rows) sb.append(r).append('\n');
        return sb.toString();
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }
}
