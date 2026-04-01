package com.xff.launch.util;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * Persistent fingerprint engine with LSB steganography.
 * Survives app uninstall by storing fingerprint data in PNG via MediaStore.
 *
 * Strategy (mirrors sgmain approach):
 *   写入: MediaStore.Images → Pictures/  (无需存储权限)
 *   读回: 查询 MediaStore by DISPLAY_NAME  (Android 10+ 需 READ_MEDIA_IMAGES)
 *   回退: 直接文件写入 /sdcard/ (Android 9)
 */
public class PersistentFingerprint {

    private static final String TAG = "PersistentFP";
    private static final String RELATIVE_DIR = "Pictures";
    private static final String FILE_NAME = "launch_fp0.png";
    private static final int IMG_SIZE = 64;
    private static final String MAGIC = "LPFP";

    // ==================== Public API ====================

    public static boolean exists(Context ctx) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return findMediaStoreUri(ctx) != null;
        } else {
            File file = getLegacyFile();
            return file != null && file.exists() && file.length() > 0;
        }
    }

    /**
     * Save fingerprint data to hidden PNG with LSB steganography.
     * Uses MediaStore on Android 10+, direct file write on Android 9.
     */
    public static boolean save(Context ctx, String token, String hwHash) {
        String payload = MAGIC + token + "|" + hwHash + "|" + System.currentTimeMillis();
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);

        Bitmap bitmap = lsbEncode(payloadBytes);
        if (bitmap == null) return false;

        boolean result;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            result = saveViaMediaStore(ctx, bitmap);
        } else {
            result = saveViaDirectFile(bitmap);
        }
        bitmap.recycle();
        return result;
    }

    /**
     * Load persistent fingerprint data.
     * @param ctx           Application context
     * @param currentHwHash Current hardware hash for comparison
     * @return PersistentData or null
     */
    public static PersistentData load(Context ctx, String currentHwHash) {
        Bitmap bitmap = null;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            bitmap = loadViaMediaStore(ctx);
        } else {
            bitmap = loadViaDirectFile();
        }

        if (bitmap == null) return null;

        try {
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
            Log.d(TAG, "Loaded token=" + data.token.substring(0, 8) + "... deviceChanged=" + !data.hardwareHash.equals(currentHwHash));
            try {
                data.timestamp = Long.parseLong(parts[2]);
            } catch (NumberFormatException e) {
                data.timestamp = 0;
            }
            data.deviceChanged = !data.hardwareHash.equals(currentHwHash);
            return data;
        } catch (Exception e) {
            Log.e(TAG, "Failed to decode persistent fingerprint", e);
            bitmap.recycle();
            return null;
        }
    }

    public static String generateToken() {
        return UUID.randomUUID().toString();
    }

    // ==================== MediaStore (Android 10+) ====================

    private static boolean saveViaMediaStore(Context ctx, Bitmap bitmap) {
        try {
            ContentResolver resolver = ctx.getContentResolver();

            // Try to update existing entry owned by this app (same install session)
            Uri existingUri = findOwnedUri(ctx);
            if (existingUri != null) {
                try (OutputStream os = resolver.openOutputStream(existingUri)) {
                    if (os != null) {
                        bitmap.compress(Bitmap.CompressFormat.PNG, 100, os);
                        os.flush();
                        Log.d(TAG, "Updated via MediaStore: " + existingUri);
                        return true;
                    }
                } catch (SecurityException e) {
                    // Can't write to orphaned entry from previous install — fall through to insert
                    Log.d(TAG, "Can't update orphaned entry, inserting new one");
                }
            }

            // Insert new entry (always succeeds, no permission needed)
            ContentValues values = new ContentValues();
            values.put(MediaStore.Images.Media.DISPLAY_NAME, FILE_NAME);
            values.put(MediaStore.Images.Media.MIME_TYPE, "image/png");
            values.put(MediaStore.Images.Media.RELATIVE_PATH, RELATIVE_DIR);
            values.put(MediaStore.Images.Media.IS_PENDING, 1);

            Uri uri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values);
            if (uri == null) return false;

            try (OutputStream os = resolver.openOutputStream(uri)) {
                if (os == null) return false;
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, os);
                os.flush();
            }

            values.clear();
            values.put(MediaStore.Images.Media.IS_PENDING, 0);
            resolver.update(uri, values, null, null);

            Log.d(TAG, "Saved via MediaStore: " + uri);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to save via MediaStore", e);
            return false;
        }
    }

    /**
     * Find entry owned by current app (can write to it).
     * Different from findMediaStoreUri which finds any entry with matching name.
     */
    private static Uri findOwnedUri(Context ctx) {
        ContentResolver resolver = ctx.getContentResolver();
        String[] projection = {MediaStore.Images.Media._ID};
        // OWNER_PACKAGE_NAME only available on API 29+, and only returns own entries
        String selection = MediaStore.Images.Media.DISPLAY_NAME + "=?";
        String[] selectionArgs = {FILE_NAME};

        // Query without read permission — only returns entries owned by this app
        try (Cursor cursor = resolver.query(
                MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
                projection, selection, selectionArgs,
                MediaStore.Images.Media.DATE_MODIFIED + " DESC")) {
            if (cursor != null && cursor.moveToFirst()) {
                long id = cursor.getLong(cursor.getColumnIndexOrThrow(MediaStore.Images.Media._ID));
                return Uri.withAppendedPath(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, String.valueOf(id));
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    private static Bitmap loadViaMediaStore(Context ctx) {
        try {
            Uri uri = findMediaStoreUri(ctx);
            if (uri == null) return null;

            ContentResolver resolver = ctx.getContentResolver();
            try (InputStream is = resolver.openInputStream(uri)) {
                if (is == null) return null;
                return BitmapFactory.decodeStream(is);
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to load via MediaStore", e);
            return null;
        }
    }

    /**
     * Find our fingerprint image in MediaStore by filename.
     */
    private static Uri findMediaStoreUri(Context ctx) {
        ContentResolver resolver = ctx.getContentResolver();
        String[] projection = {MediaStore.Images.Media._ID};
        String selection = MediaStore.Images.Media.DISPLAY_NAME + "=?";
        String[] selectionArgs = {FILE_NAME};

        try (Cursor cursor = resolver.query(
                MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
                projection, selection, selectionArgs,
                MediaStore.Images.Media.DATE_MODIFIED + " DESC")) {
            if (cursor != null && cursor.moveToFirst()) {
                long id = cursor.getLong(cursor.getColumnIndexOrThrow(MediaStore.Images.Media._ID));
                return Uri.withAppendedPath(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, String.valueOf(id));
            }
        } catch (Exception e) {
            Log.w(TAG, "MediaStore query failed", e);
        }
        return null;
    }

    // ==================== Direct File (Android 9) ====================

    private static boolean saveViaDirectFile(Bitmap bitmap) {
        try {
            File dir = getLegacyDir();
            if (dir == null) return false;

            if (!dir.exists() && !dir.mkdirs()) return false;

            // .nomedia prevents media scanner
            File nomedia = new File(dir, ".nomedia");
            if (!nomedia.exists()) nomedia.createNewFile();

            File file = new File(dir, FILE_NAME);
            try (FileOutputStream fos = new FileOutputStream(file)) {
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, fos);
                fos.flush();
            }
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Failed to save via direct file", e);
            return false;
        }
    }

    private static Bitmap loadViaDirectFile() {
        File file = getLegacyFile();
        if (file == null || !file.exists()) return null;
        return BitmapFactory.decodeFile(file.getAbsolutePath());
    }

    private static File getLegacyDir() {
        File pictures = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES);
        if (pictures == null) return null;
        return pictures;
    }

    private static File getLegacyFile() {
        File dir = getLegacyDir();
        if (dir == null) return null;
        return new File(dir, FILE_NAME);
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

        for (int y = 0; y < IMG_SIZE; y++) {
            for (int x = 0; x < IMG_SIZE; x++) {
                int r = random.nextInt(256) & 0xFE;
                int g = random.nextInt(256) & 0xFE;
                int b = random.nextInt(256) & 0xFE;
                bitmap.setPixel(x, y, Color.argb(255, r, g, b));
            }
        }

        byte[] data = new byte[4 + payload.length];
        ByteBuffer.wrap(data).putInt(payload.length);
        System.arraycopy(payload, 0, data, 4, payload.length);

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

        // Read 4-byte length header
        byte[] lengthBytes = new byte[4];
        int bitIndex = 0;

        for (int y = 0; y < IMG_SIZE && bitIndex < 32; y++) {
            for (int x = 0; x < IMG_SIZE && bitIndex < 32; x++) {
                int pixel = bitmap.getPixel(x, y);
                if (bitIndex < 32) {
                    lengthBytes[bitIndex / 8] |= ((Color.red(pixel) & 1) << (7 - bitIndex % 8));
                    bitIndex++;
                }
                if (bitIndex < 32) {
                    lengthBytes[bitIndex / 8] |= ((Color.green(pixel) & 1) << (7 - bitIndex % 8));
                    bitIndex++;
                }
                if (bitIndex < 32) {
                    lengthBytes[bitIndex / 8] |= ((Color.blue(pixel) & 1) << (7 - bitIndex % 8));
                    bitIndex++;
                }
            }
        }

        int payloadLength = ByteBuffer.wrap(lengthBytes).getInt();
        if (payloadLength <= 0 || payloadLength > 1500) return null;

        // Full re-read
        int totalBytes = 4 + payloadLength;
        byte[] data = new byte[totalBytes];
        bitIndex = 0;
        int totalBits = totalBytes * 8;

        for (int y = 0; y < IMG_SIZE && bitIndex < totalBits; y++) {
            for (int x = 0; x < IMG_SIZE && bitIndex < totalBits; x++) {
                int pixel = bitmap.getPixel(x, y);
                if (bitIndex < totalBits) {
                    data[bitIndex / 8] |= ((Color.red(pixel) & 1) << (7 - bitIndex % 8));
                    bitIndex++;
                }
                if (bitIndex < totalBits) {
                    data[bitIndex / 8] |= ((Color.green(pixel) & 1) << (7 - bitIndex % 8));
                    bitIndex++;
                }
                if (bitIndex < totalBits) {
                    data[bitIndex / 8] |= ((Color.blue(pixel) & 1) << (7 - bitIndex % 8));
                    bitIndex++;
                }
            }
        }

        byte[] payload = new byte[payloadLength];
        System.arraycopy(data, 4, payload, 0, payloadLength);
        return payload;
    }

    // ==================== Data Class ====================

    public static class PersistentData {
        public String token;
        public String hardwareHash;
        public long timestamp;
        public boolean deviceChanged;
    }
}
