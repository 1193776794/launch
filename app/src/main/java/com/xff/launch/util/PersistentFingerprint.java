package com.xff.launch.util;

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
    private static final int IMG_SIZE = 64;
    private static final String MAGIC = "LPFP";

    public static boolean exists() {
        File file = getFpFile();
        return file != null && file.exists() && file.length() > 0;
    }

    public static boolean save(String token, String hwHash) {
        try {
            File dir = getFpDir();
            if (dir == null) return false;

            if (!dir.exists() && !dir.mkdirs()) {
                Log.w(TAG, "Failed to create directory: " + dir.getPath());
                return false;
            }

            File nomedia = new File(dir, NOMEDIA);
            if (!nomedia.exists()) {
                nomedia.createNewFile();
            }

            String payload = MAGIC + token + "|" + hwHash + "|" + System.currentTimeMillis();
            byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);

            Bitmap bitmap = lsbEncode(payloadBytes);
            if (bitmap == null) return false;

            File file = new File(dir, FILE_NAME);
            try (FileOutputStream fos = new FileOutputStream(file)) {
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, fos);
                fos.flush();
            }
            bitmap.recycle();
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Failed to save persistent fingerprint", e);
            return false;
        }
    }

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

            if (!payload.startsWith(MAGIC)) return null;
            payload = payload.substring(MAGIC.length());

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

    public static String generateToken() {
        return UUID.randomUUID().toString();
    }

    // ==================== LSB Steganography ====================

    private static Bitmap lsbEncode(byte[] payload) {
        int maxBytes = (IMG_SIZE * IMG_SIZE * 3) / 8 - 4;
        if (payload.length > maxBytes) {
            Log.e(TAG, "Payload too large: " + payload.length + " > " + maxBytes);
            return null;
        }

        Bitmap bitmap = Bitmap.createBitmap(IMG_SIZE, IMG_SIZE, Bitmap.Config.ARGB_8888);
        SecureRandom random = new SecureRandom();

        // Fill with random pixel values (looks like noise), clear LSBs
        for (int y = 0; y < IMG_SIZE; y++) {
            for (int x = 0; x < IMG_SIZE; x++) {
                int r = random.nextInt(256) & 0xFE;
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

    private static byte[] lsbDecode(Bitmap bitmap) {
        if (bitmap.getWidth() < IMG_SIZE || bitmap.getHeight() < IMG_SIZE) return null;

        // Read 4-byte length header first (32 bits = ~11 pixels)
        int bitIndex = 0;
        byte[] lengthBytes = new byte[4];

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
        if (payloadLength <= 0 || payloadLength > 1500) return null;

        // Now read ALL data from beginning (length header + payload)
        int totalBytes = 4 + payloadLength;
        byte[] data = new byte[totalBytes];
        bitIndex = 0;
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

    public static class PersistentData {
        public String token;
        public String hardwareHash;
        public long timestamp;
        public boolean deviceChanged;
    }
}
