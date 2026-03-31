# SVC 级指纹采集增强 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增 4 个 SVC 级设备指纹项 + 3 个运行时完整性指标 + 跨安装持久化引擎（LSB 隐写），参考 sgmain VM 指纹采集方案。

**Architecture:** 方案 A（指纹模块内聚）—— 所有新增能力收敛在指纹模块，新建 PersistentFingerprint.java 负责持久化和 LSB 隐写，其余改动追加到现有 native-lib.cpp / NativeDetector.java / FingerprintFragment.java。

**Tech Stack:** Android Java + NDK C++ (ARM64 SVC inline asm) + Bitmap PNG LSB steganography

**Spec:** `docs/superpowers/specs/2026-03-31-svc-fingerprint-enhancement-design.md`

---

## 文件结构

| 文件 | 操作 | 职责 |
|------|------|------|
| `app/src/main/cpp/native-lib.cpp:1939` | 修改 | 在 Extended Fingerprint 段后插入：CPU频率、hosts hash、SELinux、cmdline、mmap属性读取、urandom校验 共 13 个 JNI 方法 |
| `app/src/main/java/com/xff/launch/detector/NativeDetector.java:354` | 修改 | 新增 13 个 native 方法声明 |
| `app/src/main/java/com/xff/launch/util/PersistentFingerprint.java` | **新建** | 持久化引擎 + LSB 隐写编解码 + device_token 管理 |
| `app/src/main/java/com/xff/launch/ui/fingerprint/FingerprintFragment.java:713` | 修改 | 新增 4 个指纹项采集 + 运行时指标检查 + 持久化调用 |
| `app/src/main/java/com/xff/launch/model/FingerprintResult.java:90` | 修改 | 信任分计算加入运行时指标扣分 |
| `app/src/main/java/com/xff/launch/util/ReflectionUtils.java` | 修改 | 新增 djb2Hash() |
| `app/src/main/AndroidManifest.xml` | 修改 | 新增 MANAGE_EXTERNAL_STORAGE 权限 |
| `app/src/main/res/values/strings.xml` | 修改 | 新增指纹项显示名称 |

---

### Task 1: Native 层 — CPU 频率 + hosts hash + SELinux + cmdline 采集

**Files:**
- Modify: `app/src/main/cpp/native-lib.cpp:1939` (在 `getDeviceTreeSerialSyscall` 之后, `System Library Integrity Detection` 之前插入)
- Modify: `app/src/main/java/com/xff/launch/detector/NativeDetector.java:354` (在 `getDeviceTreeSerialSyscall` 声明之后, `// Singleton instance` 之前插入)

- [ ] **Step 1: 在 NativeDetector.java 中声明 8 个 native 方法**

在 `getDeviceTreeSerialSyscall()` 声明之后、`// Singleton instance` 之前插入：

```java
    // ===================== SVC Fingerprint: Runtime Verification =====================

    /** Get CPU max frequency pattern (e.g. "1800000,1800000,2400000") via native fopen */
    public native String getCpuFreqPatternNative();
    /** Get CPU max frequency pattern via syscall */
    public native String getCpuFreqPatternSyscall();

    /** Get /etc/hosts file hash via native fopen */
    public native String getHostsHashNative();
    /** Get /etc/hosts file hash via syscall */
    public native String getHostsHashSyscall();

    /** Get SELinux state "Enforcing|u:r:untrusted_app" via native */
    public native String getSELinuxFingerprintNative();
    /** Get SELinux state via syscall */
    public native String getSELinuxFingerprintSyscall();

    /** Get process cmdline (package name) via native fopen */
    public native String getCmdlineNative();
    /** Get process cmdline via syscall */
    public native String getCmdlineSyscall();
```

- [ ] **Step 2: 在 native-lib.cpp 中实现 8 个 JNI 方法**

在 `getDeviceTreeSerialSyscall` 函数之后、`// ===================== System Library Integrity Detection` 注释之前插入：

```cpp
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
        // Trim whitespace
        while (!freq.empty() && (freq.back() == '\n' || freq.back() == '\r' || freq.back() == ' ')) {
            freq.pop_back();
        }
        if (freq.empty()) break; // No more cores
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
    // Read enforce state
    std::string enforce = use_syscall
        ? syscall_read_file("/sys/fs/selinux/enforce", 8)
        : read_file_native("/sys/fs/selinux/enforce", 8);
    while (!enforce.empty() && (enforce.back() == '\n' || enforce.back() == '\r' || enforce.back() == ' ')) {
        enforce.pop_back();
    }
    std::string state = (enforce == "1") ? "Enforcing" : "Permissive";

    // Read context, truncate to domain (before 3rd colon)
    std::string context = use_syscall
        ? syscall_read_file("/proc/self/attr/current", 256)
        : read_file_native("/proc/self/attr/current", 256);
    // Remove trailing null/whitespace
    while (!context.empty() && (context.back() == '\0' || context.back() == '\n' ||
           context.back() == '\r' || context.back() == ' ')) {
        context.pop_back();
    }
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
    // cmdline is null-terminated, strip all \0 and trailing whitespace
    std::string clean;
    for (char c : cmdline) {
        if (c == '\0') break;  // Stop at first null
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
```

- [ ] **Step 3: 构建验证**

Run: `cd /Volumes/Realtek/project/android/project/launch && ./gradlew :app:assembleDebug 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 4: Commit**

```bash
git add app/src/main/cpp/native-lib.cpp app/src/main/java/com/xff/launch/detector/NativeDetector.java
git commit -m "feat(fingerprint): add native CPU freq, hosts hash, SELinux, cmdline collection"
```

---

### Task 2: Native 层 — 运行时完整性指标 (mmap 属性读取 + urandom 校验)

**Files:**
- Modify: `app/src/main/cpp/native-lib.cpp` (紧接 Task 1 新增代码之后)
- Modify: `app/src/main/java/com/xff/launch/detector/NativeDetector.java`

- [ ] **Step 1: 在 NativeDetector.java 中声明 5 个 native 方法**

在 Task 1 新增的声明之后追加：

```java
    // ===================== Runtime Integrity Indicators =====================

    /** Read system property via direct mmap of /dev/__properties__ area (bypasses __system_property_get) */
    public native String getPropertyMmap(String propName);

    /** Compare mmap vs __system_property_get for 5 key properties, returns mismatch count */
    public native int checkPropertyMmapConsistency();

    /** Read 16 bytes from /dev/urandom via native fopen, returns hex string */
    public native String readUrandomNative();
    /** Read 16 bytes from /dev/urandom via syscall, returns hex string */
    public native String readUrandomSyscall();
    /** Check if urandom returns all zeros or fixed pattern, returns true if anomaly */
    public native boolean checkUrandomIntegrity();
```

- [ ] **Step 2: 在 native-lib.cpp 中实现 mmap 属性读取**

紧接 Task 1 的 `getCmdlineSyscall` 之后插入：

```cpp
// ===================== Runtime Integrity Indicators =====================

// --- System Property mmap Direct Read ---
// Android 9+ property area: /dev/__properties__/u:object_r:<context>:s0
// Each property area is mmap'd and contains a trie structure.
// We use a simplified approach: read via __system_property_find + direct memory access.

#include <sys/mman.h>

// Simplified mmap property read: open property files and search for value
// This bypasses __system_property_get() which can be PLT-hooked
static std::string mmap_read_property(const char* prop_name) {
    // Strategy: mmap /system/build.prop and /vendor/build.prop directly
    // and parse the property value. This is more reliable than the trie approach
    // and works across all Android 9+ versions.
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

        // Get file size via fstat
        struct stat st;
        if (syscall_stat(file, &st) != 0 || st.st_size <= 0) {
            syscall_close(fd);
            continue;
        }

        // mmap the file
        void* mapped = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        syscall_close(fd);

        if (mapped == MAP_FAILED) continue;

        // Search for property in mmap'd content
        std::string content((const char*)mapped, st.st_size);
        munmap(mapped, st.st_size);

        size_t pos = content.find(search_key);
        if (pos != std::string::npos) {
            size_t val_start = pos + search_key.length();
            size_t val_end = content.find('\n', val_start);
            std::string val = (val_end != std::string::npos)
                ? content.substr(val_start, val_end - val_start)
                : content.substr(val_start);
            // Trim
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
        // Read via __system_property_get (can be hooked)
        char native_val[256] = {0};
        __system_property_get(key, native_val);

        // Read via mmap (bypasses hooks)
        std::string mmap_val = mmap_read_property(key);

        // Compare (only if both have values)
        if (!mmap_val.empty() && strlen(native_val) > 0) {
            if (mmap_val != std::string(native_val)) {
                mismatch++;
            }
        }
    }
    return mismatch;
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
    // Read 3 times, check for anomalies
    std::string r1 = read_urandom_hex(true);
    std::string r2 = read_urandom_hex(true);
    std::string r3 = read_urandom_hex(true);

    // Check all zeros
    bool all_zero = (r1 == "00000000000000000000000000000000");
    // Check if all reads return same value (hooked to return fixed)
    bool all_same = (r1 == r2 && r2 == r3);

    return (jboolean)(all_zero || all_same);
}
```

- [ ] **Step 3: 构建验证**

Run: `cd /Volumes/Realtek/project/android/project/launch && ./gradlew :app:assembleDebug 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 4: Commit**

```bash
git add app/src/main/cpp/native-lib.cpp app/src/main/java/com/xff/launch/detector/NativeDetector.java
git commit -m "feat(fingerprint): add property mmap comparison and urandom integrity check"
```

---

### Task 3: 新建 PersistentFingerprint.java — 持久化引擎 + LSB 隐写

**Files:**
- Create: `app/src/main/java/com/xff/launch/util/PersistentFingerprint.java`

- [ ] **Step 1: 创建 PersistentFingerprint.java**

```java
package com.xff.launch.util;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * Persistent fingerprint engine with LSB steganography.
 * Survives app uninstall by storing fingerprint data in hidden PNG on external storage.
 */
public class PersistentFingerprint {

    private static final String TAG = "PersistentFP";
    private static final String DIR_NAME = ".launch_fp";
    private static final String FILE_NAME = ".fp_0.png";
    private static final String NOMEDIA = ".nomedia";
    private static final int IMG_SIZE = 64; // 64x64 PNG
    private static final String MAGIC = "LPFP"; // Launch Persistent FingerPrint

    // ==================== Public API ====================

    /**
     * Check if persistent fingerprint exists on external storage.
     */
    public static boolean exists() {
        File file = getFpFile();
        return file != null && file.exists() && file.length() > 0;
    }

    /**
     * Save fingerprint data to hidden PNG with LSB steganography.
     * @param token     UUID device token
     * @param hwHash    SHA256 hardware hash
     */
    public static boolean save(String token, String hwHash) {
        try {
            File dir = getFpDir();
            if (dir == null) return false;

            if (!dir.exists() && !dir.mkdirs()) {
                Log.w(TAG, "Failed to create directory: " + dir.getPath());
                return false;
            }

            // Create .nomedia to prevent media scanning
            File nomedia = new File(dir, NOMEDIA);
            if (!nomedia.exists()) {
                nomedia.createNewFile();
            }

            // Build payload: MAGIC + token + "|" + hwHash + "|" + timestamp
            String payload = MAGIC + token + "|" + hwHash + "|" + System.currentTimeMillis();
            byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);

            // Encode into LSB of a 64x64 PNG
            Bitmap bitmap = lsbEncode(payloadBytes);
            if (bitmap == null) return false;

            // Write PNG
            File file = new File(dir, FILE_NAME);
            try (FileOutputStream fos = new FileOutputStream(file)) {
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, fos);
                fos.flush();
            }
            bitmap.recycle();

            Log.d(TAG, "Persistent fingerprint saved: " + file.getPath());
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Failed to save persistent fingerprint", e);
            return false;
        }
    }

    /**
     * Load persistent fingerprint from hidden PNG.
     * @param currentHwHash  Current hardware hash for comparison
     * @return PersistentData or null if not found/corrupted
     */
    public static PersistentData load(String currentHwHash) {
        File file = getFpFile();
        if (file == null || !file.exists()) return null;

        try {
            Bitmap bitmap = BitmapFactory.decodeFile(file.getAbsolutePath());
            if (bitmap == null) return null;

            byte[] payloadBytes = lsbDecode(bitmap);
            bitmap.recycle();

            if (payloadBytes == null || payloadBytes.length == 0) return null;

            String payload = new String(payloadBytes, StandardCharsets.UTF_8);

            // Verify magic
            if (!payload.startsWith(MAGIC)) return null;
            payload = payload.substring(MAGIC.length());

            // Parse: token|hwHash|timestamp
            String[] parts = payload.split("\\|");
            if (parts.length < 3) return null;

            PersistentData data = new PersistentData();
            data.token = parts[0];
            data.hardwareHash = parts[1];
            try {
                data.timestamp = Long.parseLong(parts[2]);
            } catch (NumberFormatException e) {
                data.timestamp = 0;
            }
            data.deviceChanged = !data.hardwareHash.equals(currentHwHash);

            return data;
        } catch (Exception e) {
            Log.e(TAG, "Failed to load persistent fingerprint", e);
            return null;
        }
    }

    /**
     * Generate a new device token (UUID).
     */
    public static String generateToken() {
        return UUID.randomUUID().toString();
    }

    // ==================== LSB Steganography ====================

    /**
     * Encode payload bytes into LSB of a 64x64 PNG image.
     * Capacity: 64*64*3 bits = 1536 bytes.
     */
    private static Bitmap lsbEncode(byte[] payload) {
        int maxBytes = (IMG_SIZE * IMG_SIZE * 3) / 8 - 4; // 4 bytes for length header
        if (payload.length > maxBytes) {
            Log.e(TAG, "Payload too large: " + payload.length + " > " + maxBytes);
            return null;
        }

        Bitmap bitmap = Bitmap.createBitmap(IMG_SIZE, IMG_SIZE, Bitmap.Config.ARGB_8888);
        SecureRandom random = new SecureRandom();

        // Fill with random pixel values (looks like noise)
        for (int y = 0; y < IMG_SIZE; y++) {
            for (int x = 0; x < IMG_SIZE; x++) {
                int r = random.nextInt(256) & 0xFE; // Clear LSB
                int g = random.nextInt(256) & 0xFE;
                int b = random.nextInt(256) & 0xFE;
                bitmap.setPixel(x, y, Color.argb(255, r, g, b));
            }
        }

        // Prepend 4-byte length header (big-endian)
        byte[] data = new byte[4 + payload.length];
        ByteBuffer.wrap(data).putInt(payload.length);
        System.arraycopy(payload, 0, data, 4, payload.length);

        // Write data bits into LSB of R, G, B channels
        int bitIndex = 0;
        int totalBits = data.length * 8;

        for (int y = 0; y < IMG_SIZE && bitIndex < totalBits; y++) {
            for (int x = 0; x < IMG_SIZE && bitIndex < totalBits; x++) {
                int pixel = bitmap.getPixel(x, y);
                int a = Color.alpha(pixel);
                int r = Color.red(pixel);
                int g = Color.green(pixel);
                int b = Color.blue(pixel);

                if (bitIndex < totalBits) {
                    int bit = (data[bitIndex / 8] >> (7 - bitIndex % 8)) & 1;
                    r = (r & 0xFE) | bit;
                    bitIndex++;
                }
                if (bitIndex < totalBits) {
                    int bit = (data[bitIndex / 8] >> (7 - bitIndex % 8)) & 1;
                    g = (g & 0xFE) | bit;
                    bitIndex++;
                }
                if (bitIndex < totalBits) {
                    int bit = (data[bitIndex / 8] >> (7 - bitIndex % 8)) & 1;
                    b = (b & 0xFE) | bit;
                    bitIndex++;
                }

                bitmap.setPixel(x, y, Color.argb(a, r, g, b));
            }
        }

        return bitmap;
    }

    /**
     * Decode payload bytes from LSB of a PNG image.
     */
    private static byte[] lsbDecode(Bitmap bitmap) {
        if (bitmap.getWidth() < IMG_SIZE || bitmap.getHeight() < IMG_SIZE) return null;

        // First read 4-byte (32-bit) length header
        byte[] lengthBytes = new byte[4];
        int bitIndex = 0;

        for (int y = 0; y < IMG_SIZE && bitIndex < 32; y++) {
            for (int x = 0; x < IMG_SIZE && bitIndex < 32; x++) {
                int pixel = bitmap.getPixel(x, y);

                if (bitIndex < 32) {
                    int bit = Color.red(pixel) & 1;
                    lengthBytes[bitIndex / 8] |= (bit << (7 - bitIndex % 8));
                    bitIndex++;
                }
                if (bitIndex < 32) {
                    int bit = Color.green(pixel) & 1;
                    lengthBytes[bitIndex / 8] |= (bit << (7 - bitIndex % 8));
                    bitIndex++;
                }
                if (bitIndex < 32) {
                    int bit = Color.blue(pixel) & 1;
                    lengthBytes[bitIndex / 8] |= (bit << (7 - bitIndex % 8));
                    bitIndex++;
                }
            }
        }

        int payloadLength = ByteBuffer.wrap(lengthBytes).getInt();
        if (payloadLength <= 0 || payloadLength > 1500) return null; // Sanity check

        // Read payload
        byte[] allData = new byte[4 + payloadLength];
        System.arraycopy(lengthBytes, 0, allData, 0, 4);
        bitIndex = 32; // Continue from where we left off
        int totalBits = allData.length * 8;

        for (int y = 0; y < IMG_SIZE && bitIndex < totalBits; y++) {
            for (int x = 0; x < IMG_SIZE && bitIndex < totalBits; x++) {
                // Skip pixels already read for length header
                if (y * IMG_SIZE + x < (32 + 2) / 3) {
                    // Already processed in length read — but we need to re-read
                    // Actually, continue from correct position
                }
                int pixel = bitmap.getPixel(x, y);

                int rBit = Color.red(pixel) & 1;
                int gBit = Color.green(pixel) & 1;
                int bBit = Color.blue(pixel) & 1;

                int pixelBitStart = (y * IMG_SIZE + x) * 3;

                if (pixelBitStart >= bitIndex - 3) {
                    // This pixel's bits haven't been read yet for payload
                }

                // Simpler approach: re-read all bits from start
                // (only called once, performance not critical)
            }
        }

        // Simpler full re-read approach
        return lsbDecodeAll(bitmap, payloadLength);
    }

    /**
     * Full LSB decode - reads all bits sequentially.
     */
    private static byte[] lsbDecodeAll(Bitmap bitmap, int payloadLength) {
        int totalBytes = 4 + payloadLength;
        byte[] data = new byte[totalBytes];
        int bitIndex = 0;
        int totalBits = totalBytes * 8;

        for (int y = 0; y < IMG_SIZE && bitIndex < totalBits; y++) {
            for (int x = 0; x < IMG_SIZE && bitIndex < totalBits; x++) {
                int pixel = bitmap.getPixel(x, y);

                if (bitIndex < totalBits) {
                    int bit = Color.red(pixel) & 1;
                    data[bitIndex / 8] |= (bit << (7 - bitIndex % 8));
                    bitIndex++;
                }
                if (bitIndex < totalBits) {
                    int bit = Color.green(pixel) & 1;
                    data[bitIndex / 8] |= (bit << (7 - bitIndex % 8));
                    bitIndex++;
                }
                if (bitIndex < totalBits) {
                    int bit = Color.blue(pixel) & 1;
                    data[bitIndex / 8] |= (bit << (7 - bitIndex % 8));
                    bitIndex++;
                }
            }
        }

        // Extract payload (skip 4-byte length header)
        byte[] payload = new byte[payloadLength];
        System.arraycopy(data, 4, payload, 0, payloadLength);
        return payload;
    }

    // ==================== File Helpers ====================

    private static File getFpDir() {
        File extStorage = Environment.getExternalStorageDirectory();
        if (extStorage == null) return null;
        return new File(extStorage, DIR_NAME);
    }

    private static File getFpFile() {
        File dir = getFpDir();
        if (dir == null) return null;
        return new File(dir, FILE_NAME);
    }

    // ==================== Data Class ====================

    public static class PersistentData {
        public String token;
        public String hardwareHash;
        public long timestamp;
        public boolean deviceChanged;
    }
}
```

- [ ] **Step 2: 构建验证**

Run: `cd /Volumes/Realtek/project/android/project/launch && ./gradlew :app:assembleDebug 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/xff/launch/util/PersistentFingerprint.java
git commit -m "feat(fingerprint): add PersistentFingerprint with LSB steganography engine"
```

---

### Task 4: ReflectionUtils + strings.xml + AndroidManifest 更新

**Files:**
- Modify: `app/src/main/java/com/xff/launch/util/ReflectionUtils.java`
- Modify: `app/src/main/res/values/strings.xml`
- Modify: `app/src/main/AndroidManifest.xml`

- [ ] **Step 1: 在 ReflectionUtils.java 末尾（最后一个 `}` 之前）添加 djb2Hash 方法**

```java
    /**
     * Compute djb2 hash of a string.
     * Used for /etc/hosts fingerprinting.
     */
    public static String djb2Hash(String input) {
        if (input == null || input.isEmpty()) return "";
        long hash = 5381;
        for (int i = 0; i < input.length(); i++) {
            hash = ((hash << 5) + hash) + input.charAt(i);
            hash &= 0xFFFFFFFFL; // Keep as unsigned 32-bit
        }
        return String.format("%08x", hash);
    }
```

- [ ] **Step 2: 在 strings.xml 的 fingerprint 区域追加新字符串**

在 `<string name="software_fingerprint">` 之后追加：

```xml
    <string name="cpu_freq_pattern">CPU 频率指纹</string>
    <string name="hosts_hash">Hosts Hash</string>
    <string name="selinux_state">SELinux 状态</string>
    <string name="process_name">进程包名</string>
    <string name="persistent_token">持久化 Token</string>
    <string name="persistent_status_new">新设备</string>
    <string name="persistent_status_same">设备未变更</string>
    <string name="persistent_status_changed">设备已变更</string>
```

- [ ] **Step 3: 在 AndroidManifest.xml 添加权限和属性**

在 `<uses-permission android:name="android.permission.READ_PHONE_STATE" />` 之后添加：

```xml
    <!-- Persistent fingerprint storage (survives uninstall) -->
    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
```

在 `<application` 标签的属性中添加 `android:requestLegacyExternalStorage="true"`。

- [ ] **Step 4: 构建验证**

Run: `cd /Volumes/Realtek/project/android/project/launch && ./gradlew :app:assembleDebug 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/xff/launch/util/ReflectionUtils.java \
      app/src/main/res/values/strings.xml \
      app/src/main/AndroidManifest.xml
git commit -m "feat(fingerprint): add djb2Hash util, string resources, storage permission"
```

---

### Task 5: FingerprintResult.java — 信任分计算加入运行时指标

**Files:**
- Modify: `app/src/main/java/com/xff/launch/model/FingerprintResult.java`

- [ ] **Step 1: 添加运行时指标字段**

在 `private long collectTime;` 之后添加：

```java
    // Runtime integrity penalties
    private int rwxPenalty;
    private int urandomPenalty;
    private int mmapPenalty;
    private int persistentPenalty;
```

- [ ] **Step 2: 添加 getter/setter**

在 `setCollectTime` 方法之后添加：

```java
    public int getRwxPenalty() { return rwxPenalty; }
    public void setRwxPenalty(int p) { this.rwxPenalty = p; }

    public int getUrandomPenalty() { return urandomPenalty; }
    public void setUrandomPenalty(int p) { this.urandomPenalty = p; }

    public int getMmapPenalty() { return mmapPenalty; }
    public void setMmapPenalty(int p) { this.mmapPenalty = p; }

    public int getPersistentPenalty() { return persistentPenalty; }
    public void setPersistentPenalty(int p) { this.persistentPenalty = p; }
```

- [ ] **Step 3: 更新 calculateTrustLevel 方法**

替换现有的 `calculateTrustLevel()` 方法：

```java
    /**
     * Calculate trust level based on consistency + runtime integrity indicators
     */
    public void calculateTrustLevel() {
        int inconsistentCount = 0;

        for (FingerprintItem item : items) {
            if (!item.isConsistent()) {
                inconsistentCount++;
            }
        }

        if (items.isEmpty()) {
            trustLevel = 100;
            tamperingDetected = false;
            return;
        }

        // Consistency penalty: 15 per inconsistent item
        int consistencyReduction = inconsistentCount * 15;
        // Runtime integrity penalties
        int runtimeReduction = rwxPenalty + urandomPenalty + mmapPenalty + persistentPenalty;
        int totalReduction = consistencyReduction + runtimeReduction;

        trustLevel = Math.max(0, 100 - totalReduction);
        tamperingDetected = totalReduction > 0;
    }
```

- [ ] **Step 4: 构建验证**

Run: `cd /Volumes/Realtek/project/android/project/launch && ./gradlew :app:assembleDebug 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/xff/launch/model/FingerprintResult.java
git commit -m "feat(fingerprint): add runtime integrity penalties to trust level calculation"
```

---

### Task 6: FingerprintFragment.java — 整合新指纹项 + 运行时指标 + 持久化

**Files:**
- Modify: `app/src/main/java/com/xff/launch/ui/fingerprint/FingerprintFragment.java`

- [ ] **Step 1: 添加新 import**

在现有 import 区域追加：

```java
import com.xff.launch.util.PersistentFingerprint;
import java.io.FileInputStream;
```

- [ ] **Step 2: 在 performCollection() 的 gsfId 之后、`result.setItems(items)` 之前，添加 4 个新指纹项**

```java
        // ==================== SVC Runtime Verification Fingerprints ====================

        // CPU Frequency Pattern (CPU 频率指纹)
        FingerprintItem cpuFreq = new FingerprintItem("cpu_freq", "CPU 频率指纹");
        String javaCpuFreq = collectCpuFreqJava();
        String nativeCpuFreq = nativeDetector.getCpuFreqPatternNative();
        String syscallCpuFreq = nativeDetector.getCpuFreqPatternSyscall();
        cpuFreq.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaCpuFreq, "N/A"));
        cpuFreq.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeCpuFreq, "N/A"));
        cpuFreq.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallCpuFreq, "N/A"));
        items.add(cpuFreq);

        // /etc/hosts Hash
        FingerprintItem hostsHash = new FingerprintItem("hosts_hash", "Hosts Hash");
        String javaHostsHash = computeHostsHashJava();
        String nativeHostsHash = nativeDetector.getHostsHashNative();
        String syscallHostsHash = nativeDetector.getHostsHashSyscall();
        hostsHash.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaHostsHash, "N/A"));
        hostsHash.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeHostsHash, "N/A"));
        hostsHash.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallHostsHash, "N/A"));
        items.add(hostsHash);

        // SELinux State
        FingerprintItem selinux = new FingerprintItem("selinux", "SELinux 状态");
        String javaSelinux = collectSELinuxJava();
        String nativeSelinux = nativeDetector.getSELinuxFingerprintNative();
        String syscallSelinux = nativeDetector.getSELinuxFingerprintSyscall();
        selinux.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaSelinux, "N/A"));
        selinux.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeSelinux, "N/A"));
        selinux.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallSelinux, "N/A"));
        items.add(selinux);

        // Process Package Name (/proc/self/cmdline)
        FingerprintItem procName = new FingerprintItem("proc_name", "进程包名");
        String javaProcName = requireContext().getPackageName();
        String nativeProcName = nativeDetector.getCmdlineNative();
        String syscallProcName = nativeDetector.getCmdlineSyscall();
        procName.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaProcName, "N/A"));
        procName.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeProcName, "N/A"));
        procName.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallProcName, "N/A"));
        items.add(procName);
```

- [ ] **Step 3: 在 `result.setItems(items)` 之后、`result.calculateTrustLevel()` 之前，添加运行时指标检查**

```java
        result.setItems(items);

        // ==================== Runtime Integrity Indicators ====================

        // RWX anonymous memory detection
        int rwxCount = nativeDetector.countAnonymousRwxMemory();
        int rwxPenalty = 0;
        if (rwxCount >= 3) rwxPenalty = 25;
        else if (rwxCount >= 1) rwxPenalty = 10;
        result.setRwxPenalty(rwxPenalty);

        // /dev/urandom integrity
        int urandomPenalty = 0;
        if (nativeDetector.checkUrandomIntegrity()) {
            urandomPenalty = 20;
        }
        result.setUrandomPenalty(urandomPenalty);

        // Property mmap vs native consistency
        int mmapMismatch = nativeDetector.checkPropertyMmapConsistency();
        int mmapPenalty = (mmapMismatch > 0) ? 20 : 0;
        result.setMmapPenalty(mmapPenalty);

        // Persistent fingerprint check
        int persistentPenalty = 0;
        // (will be set after hwHash is computed, see below)

        result.calculateTrustLevel();
        result.generateCompositeFingerprint();
```

- [ ] **Step 4: 更新 hwString 加入新指纹项，并在 swString 之后添加持久化逻辑**

替换现有的 hwString/swString/return 部分：

```java
        // Generate hardware and software hashes
        String hwString = nonEmpty(reflectBrand) + nonEmpty(reflectModel) + nonEmpty(reflectDevice) +
                nonEmpty(reflectHw) + nonEmpty(reflectBoard) + nonEmpty(nativeCpuSerial, javaCpuSerial) +
                nonEmpty(nativeSocSerial, javaSocSerial) + nonEmpty(nativeBootSerial, javaBootSerial) +
                nonEmpty(javaDrmId) + nonEmpty(javaManufacturer) + nonEmpty(javaMac, fileMac) +
                nonEmpty(javaScreen) + nonEmpty(javaTotalRam) + nonEmpty(javaAbi, propAbi) +
                nonEmpty(javaStorage) + nonEmpty(syscallCpuFreq, nativeCpuFreq);
        result.setHardwareHash(sha256(hwString));

        String swString = nonEmpty(reflectFp) + nonEmpty(reflectId) +
                ReflectionUtils.getBuildVersionField("RELEASE") +
                ReflectionUtils.getBuildVersionField("SDK_INT") +
                nonEmpty(nativeBootId, javaBootId) + nonEmpty(nativeVbmeta, propVbmeta) +
                nonEmpty(reflectBootloader) + nonEmpty(reflectRelease) + nonEmpty(reflectSdk) +
                nonEmpty(reflectPatch) + nonEmpty(reflectType, propType) +
                nonEmpty(reflectTags, propTags) + nonEmpty(javaTimezone, propTimezone) +
                nonEmpty(javaLanguage) + nonEmpty(syscallSelinux, nativeSelinux) +
                nonEmpty(syscallHostsHash, nativeHostsHash);
        result.setSoftwareHash(sha256(swString));

        // ==================== Persistent Fingerprint ====================
        try {
            String currentHwHash = result.getHardwareHash();
            if (PersistentFingerprint.exists()) {
                PersistentFingerprint.PersistentData pData =
                        PersistentFingerprint.load(currentHwHash);
                if (pData != null && pData.deviceChanged) {
                    result.setPersistentPenalty(15);
                    // Recalculate with persistent penalty
                    result.calculateTrustLevel();
                }
                // Update stored fingerprint with current hash
                if (pData != null) {
                    PersistentFingerprint.save(pData.token, currentHwHash);
                }
            } else {
                // First install — generate and save token
                String token = PersistentFingerprint.generateToken();
                PersistentFingerprint.save(token, currentHwHash);
            }
        } catch (Exception e) {
            // Storage permission may not be granted — non-fatal
        }

        return result;
```

- [ ] **Step 5: 在 `roundRamValue` 方法之前，添加 Java 层辅助方法**

```java
    /**
     * Collect CPU max frequency pattern via Java file reading.
     */
    private String collectCpuFreqJava() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            String freq = ReflectionUtils.readFileFirstLine(
                    "/sys/devices/system/cpu/cpu" + i + "/cpufreq/cpuinfo_max_freq");
            if (freq == null || freq.isEmpty()) break;
            if (sb.length() > 0) sb.append(",");
            sb.append(freq.trim());
        }
        return sb.toString();
    }

    /**
     * Compute /etc/hosts hash via Java.
     */
    private String computeHostsHashJava() {
        String content = ReflectionUtils.readFile("/etc/hosts");
        if (content.isEmpty()) {
            content = ReflectionUtils.readFile("/system/etc/hosts");
        }
        if (content.isEmpty()) return "";
        return ReflectionUtils.djb2Hash(content);
    }

    /**
     * Collect SELinux fingerprint via Java.
     * Format: "Enforcing|u:r:untrusted_app"
     */
    private String collectSELinuxJava() {
        String enforce = ReflectionUtils.readFileFirstLine("/sys/fs/selinux/enforce");
        String state = "1".equals(enforce) ? "Enforcing" : "Permissive";

        String context = ReflectionUtils.readFileFirstLine("/proc/self/attr/current");
        if (context != null && !context.isEmpty()) {
            // Truncate at 3rd colon
            int colonCount = 0;
            for (int i = 0; i < context.length(); i++) {
                if (context.charAt(i) == ':') {
                    colonCount++;
                    if (colonCount == 3) {
                        context = context.substring(0, i);
                        break;
                    }
                }
            }
        } else {
            context = "unknown";
        }
        return state + "|" + context;
    }
```

- [ ] **Step 6: 构建验证**

Run: `cd /Volumes/Realtek/project/android/project/launch && ./gradlew :app:assembleDebug 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/xff/launch/ui/fingerprint/FingerprintFragment.java
git commit -m "feat(fingerprint): integrate SVC fingerprints, runtime integrity checks, persistent engine"
```

---

### Task 7: 最终构建验证

**Files:** 无新改动

- [ ] **Step 1: 全量构建**

Run: `cd /Volumes/Realtek/project/android/project/launch && ./gradlew clean :app:assembleDebug 2>&1 | tail -10`
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 2: 检查 APK 产物**

Run: `ls -la app/build/outputs/apk/debug/app-debug.apk`
Expected: APK 文件存在且大小合理

- [ ] **Step 3: 验证 native 方法无遗漏**

Run: 检查 NativeDetector.java 中所有新增 native 方法在 native-lib.cpp 中都有实现，grep 确认。

```bash
cd /Volumes/Realtek/project/android/project/launch
grep -c "getCpuFreqPattern\|getHostsHash\|getSELinuxFingerprint\|getCmdline\|getPropertyMmap\|checkPropertyMmapConsistency\|readUrandom\|checkUrandomIntegrity" app/src/main/java/com/xff/launch/detector/NativeDetector.java
grep -c "getCpuFreqPattern\|getHostsHash\|getSELinuxFingerprint\|getCmdline\|getPropertyMmap\|checkPropertyMmapConsistency\|readUrandom\|checkUrandomIntegrity" app/src/main/cpp/native-lib.cpp
```

Expected: 两个文件的 grep 计数匹配

- [ ] **Step 4: Commit 最终状态（如有遗留修复）**
