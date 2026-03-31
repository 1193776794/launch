package com.xff.launch.util;

import android.annotation.SuppressLint;
import android.content.ContentResolver;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Reflection utilities for anti-hook fingerprint collection
 * Uses reflection to bypass potential hooks on standard APIs
 */
public class ReflectionUtils {

    private static final String TAG = "ReflectionUtils";

    // ==================== Build Class Reflection ====================

    /**
     * Get Build field value via reflection to bypass hooks
     */
    public static String getBuildField(String fieldName) {
        try {
            Class<?> buildClass = Class.forName("android.os.Build");
            Field field = buildClass.getDeclaredField(fieldName);
            field.setAccessible(true);
            Object value = field.get(null);
            return value != null ? value.toString() : "";
        } catch (Exception e) {
            Log.w(TAG, "Failed to get Build." + fieldName + " via reflection", e);
            return "";
        }
    }

    /**
     * Get Build.VERSION field value via reflection
     */
    public static String getBuildVersionField(String fieldName) {
        try {
            Class<?> versionClass = Class.forName("android.os.Build$VERSION");
            Field field = versionClass.getDeclaredField(fieldName);
            field.setAccessible(true);
            Object value = field.get(null);
            return value != null ? value.toString() : "";
        } catch (Exception e) {
            Log.w(TAG, "Failed to get Build.VERSION." + fieldName + " via reflection", e);
            return "";
        }
    }

    /**
     * Get all Build fields via reflection
     */
    public static String getModel() {
        return getBuildField("MODEL");
    }

    public static String getBrand() {
        return getBuildField("BRAND");
    }

    public static String getDevice() {
        return getBuildField("DEVICE");
    }

    public static String getProduct() {
        return getBuildField("PRODUCT");
    }

    public static String getManufacturer() {
        return getBuildField("MANUFACTURER");
    }

    public static String getHardware() {
        return getBuildField("HARDWARE");
    }

    public static String getBoard() {
        return getBuildField("BOARD");
    }

    public static String getBootloader() {
        return getBuildField("BOOTLOADER");
    }

    public static String getFingerprint() {
        return getBuildField("FINGERPRINT");
    }

    public static String getSerial() {
        // Build.SERIAL is deprecated, try multiple ways
        String serial = getBuildField("SERIAL");
        if (serial.isEmpty() || serial.equals("unknown")) {
            serial = getSystemProperty("ro.serialno");
        }
        if (serial.isEmpty() || serial.equals("unknown")) {
            serial = getSystemProperty("ro.boot.serialno");
        }
        return serial;
    }

    public static String getId() {
        return getBuildField("ID");
    }

    public static String getDisplay() {
        return getBuildField("DISPLAY");
    }

    public static String getRadioVersion() {
        try {
            Class<?> buildClass = Class.forName("android.os.Build");
            Method method = buildClass.getMethod("getRadioVersion");
            Object result = method.invoke(null);
            return result != null ? result.toString() : "";
        } catch (Exception e) {
            return getSystemProperty("gsm.version.baseband");
        }
    }

    // ==================== SystemProperties Reflection ====================

    /**
     * Get system property via reflection (hidden API)
     * This bypasses hooks on Build class
     */
    @SuppressLint("PrivateApi")
    public static String getSystemProperty(String key) {
        try {
            Class<?> systemPropertiesClass = Class.forName("android.os.SystemProperties");
            Method getMethod = systemPropertiesClass.getMethod("get", String.class);
            Object result = getMethod.invoke(null, key);
            return result != null ? result.toString() : "";
        } catch (Exception e) {
            Log.w(TAG, "Failed to get SystemProperty: " + key, e);
            return "";
        }
    }

    /**
     * Get system property with default value
     */
    @SuppressLint("PrivateApi")
    public static String getSystemProperty(String key, String defaultValue) {
        try {
            Class<?> systemPropertiesClass = Class.forName("android.os.SystemProperties");
            Method getMethod = systemPropertiesClass.getMethod("get", String.class, String.class);
            Object result = getMethod.invoke(null, key, defaultValue);
            return result != null ? result.toString() : defaultValue;
        } catch (Exception e) {
            Log.w(TAG, "Failed to get SystemProperty: " + key, e);
            return defaultValue;
        }
    }

    // ==================== Settings Reflection ====================

    /**
     * Get Settings.Secure value via reflection
     */
    public static String getSecureSetting(ContentResolver resolver, String name) {
        try {
            Class<?> settingsSecure = Class.forName("android.provider.Settings$Secure");
            Method getString = settingsSecure.getMethod("getString", ContentResolver.class, String.class);
            Object result = getString.invoke(null, resolver, name);
            return result != null ? result.toString() : "";
        } catch (Exception e) {
            // Fallback to direct call
            try {
                return Settings.Secure.getString(resolver, name);
            } catch (Exception e2) {
                return "";
            }
        }
    }

    /**
     * Get ANDROID_ID via reflection
     */
    public static String getAndroidId(ContentResolver resolver) {
        return getSecureSetting(resolver, "android_id");
    }

    // ==================== File Reading (Java Layer) ====================

    /**
     * Read file content using Java IO
     * This serves as fallback when native methods fail
     */
    public static String readFile(String path) {
        try {
            File file = new File(path);
            if (!file.exists() || !file.canRead()) {
                return "";
            }

            StringBuilder content = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (content.length() > 0) {
                        content.append("\n");
                    }
                    content.append(line);
                }
            }

            String result = content.toString().trim();
            return result;
        } catch (Exception e) {
            Log.w(TAG, "Failed to read file: " + path, e);
            return "";
        }
    }

    /**
     * Read first line of file
     */
    public static String readFileFirstLine(String path) {
        try {
            File file = new File(path);
            if (!file.exists() || !file.canRead()) {
                return "";
            }

            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line = reader.readLine();
                return line != null ? line.trim() : "";
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to read file: " + path, e);
            return "";
        }
    }

    /**
     * Execute shell command and get output (requires shell access)
     */
    public static String executeCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                if (output.length() > 0) {
                    output.append("\n");
                }
                output.append(line);
            }
            reader.close();
            process.waitFor();
            return output.toString().trim();
        } catch (Exception e) {
            Log.w(TAG, "Failed to execute command: " + command, e);
            return "";
        }
    }

    /**
     * Get property using getprop command
     */
    public static String getPropertyViaShell(String key) {
        return executeCommand("getprop " + key);
    }

    // ==================== CPU Info Parsing ====================

    /**
     * Parse CPU serial from /proc/cpuinfo
     */
    public static String getCpuSerial() {
        String cpuinfo = readFile("/proc/cpuinfo");
        return extractValue(cpuinfo, "Serial");
    }

    /**
     * Parse Hardware from /proc/cpuinfo
     */
    public static String getCpuHardware() {
        String cpuinfo = readFile("/proc/cpuinfo");
        return extractValue(cpuinfo, "Hardware");
    }

    /**
     * Parse CPU revision from /proc/cpuinfo
     */
    public static String getCpuRevision() {
        String cpuinfo = readFile("/proc/cpuinfo");
        return extractValue(cpuinfo, "Revision");
    }

    /**
     * Parse boot param from /proc/cmdline
     */
    public static String getBootParam(String paramName) {
        String cmdline = readFile("/proc/cmdline");
        if (cmdline.isEmpty()) return "";

        String searchKey = paramName + "=";
        int start = cmdline.indexOf(searchKey);
        if (start == -1) return "";

        start += searchKey.length();
        int end = cmdline.indexOf(' ', start);
        if (end == -1) {
            return cmdline.substring(start).trim();
        }
        return cmdline.substring(start, end).trim();
    }

    /**
     * Extract value from "key : value" or "key: value" format
     */
    private static String extractValue(String content, String key) {
        if (content == null || content.isEmpty()) return "";

        String[] lines = content.split("\n");
        for (String line : lines) {
            if (line.startsWith(key) || line.contains(key + "\t") || line.contains(key + " ")) {
                int colonPos = line.indexOf(':');
                if (colonPos != -1) {
                    return line.substring(colonPos + 1).trim();
                }
            }
        }
        return "";
    }

    // ==================== Comprehensive Value Getter ====================

    /**
     * Get value using multiple methods, returns first non-empty result
     * Priority: Reflection -> SystemProperty -> Shell -> Native
     */
    public static String getValueMultiMethod(String buildField, String systemProp, String shellProp) {
        // Try reflection on Build class first
        String value = getBuildField(buildField);
        if (!value.isEmpty() && !value.equals("unknown")) {
            return value;
        }

        // Try SystemProperties reflection
        if (systemProp != null && !systemProp.isEmpty()) {
            value = getSystemProperty(systemProp);
            if (!value.isEmpty() && !value.equals("unknown")) {
                return value;
            }
        }

        // Try shell command
        if (shellProp != null && !shellProp.isEmpty()) {
            value = getPropertyViaShell(shellProp);
            if (!value.isEmpty() && !value.equals("unknown")) {
                return value;
            }
        }

        return "";
    }

    /**
     * Check if string is empty or placeholder
     */
    public static boolean isEmptyOrUnknown(String value) {
        return value == null || value.isEmpty() ||
               value.equals("unknown") || value.equals("Unknown") ||
               value.equals("null") || value.equals("N/A");
    }

    /**
     * Get first non-empty value from multiple sources
     */
    public static String firstNonEmpty(String... values) {
        for (String value : values) {
            if (!isEmptyOrUnknown(value)) {
                return value;
            }
        }
        return "";
    }

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
}
