package com.xff.launch.util;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraManager;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.opengl.GLES20;
import android.util.SizeF;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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
