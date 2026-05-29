package com.xff.launch;

import android.animation.ObjectAnimator;
import android.os.Bundle;
import android.os.Debug;
import android.util.Log;
import android.view.View;
import android.view.animation.LinearInterpolator;
import android.widget.ImageButton;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.WindowCompat;
import androidx.fragment.app.Fragment;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.xff.launch.detector.NativeDetector;
import com.xff.launch.ui.deviceinfo.DeviceInfoFragment;
import com.xff.launch.ui.environment.EnvironmentFragment;
import com.xff.launch.ui.fingerprint.FingerprintFragment;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Main activity with bottom navigation - Material Design 3
 */
public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("launch");
    }

    private BottomNavigationView bottomNavigation;
    private ImageButton btnRefresh;
    private ImageButton btnAbout;

    private EnvironmentFragment environmentFragment;
    private FingerprintFragment fingerprintFragment;
    private DeviceInfoFragment deviceInfoFragment;

    private Fragment activeFragment;
    private ObjectAnimator rotateAnimator;

    // === Attach watcher: 后台轮询 JDWP attach 信号，状态变化时主动触发刷新 ===
    // 解决"detectJdwp 只在 app 启动/手动 refresh 时跑一次"的快照时机问题
    private static final String WATCHER_TAG = "AttachWatcher";
    private static final long WATCHER_INTERVAL_MS = 2000;
    private ScheduledExecutorService attachWatcher;
    private volatile String lastAttachFingerprint = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // Edge-to-edge
        WindowCompat.setDecorFitsSystemWindows(getWindow(), true);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();
        initFragments();
        setupNavigation();
    }

    private void initViews() {
        bottomNavigation = findViewById(R.id.bottom_navigation);
        btnRefresh = findViewById(R.id.btn_refresh);
        btnAbout = findViewById(R.id.btn_about);

        // Setup refresh button animation
        rotateAnimator = ObjectAnimator.ofFloat(btnRefresh, "rotation", 0f, 360f);
        rotateAnimator.setDuration(1000);
        rotateAnimator.setRepeatCount(ObjectAnimator.INFINITE);
        rotateAnimator.setInterpolator(new LinearInterpolator());

        btnRefresh.setOnClickListener(v -> refreshCurrentFragment());
        btnAbout.setOnClickListener(v -> showAboutBottomSheet());
    }

    private void initFragments() {
        environmentFragment = new EnvironmentFragment();
        fingerprintFragment = new FingerprintFragment();
        deviceInfoFragment = new DeviceInfoFragment();

        // Add all fragments but hide all except the first
        getSupportFragmentManager().beginTransaction()
                .add(R.id.fragment_container, deviceInfoFragment, "device").hide(deviceInfoFragment)
                .add(R.id.fragment_container, fingerprintFragment, "fingerprint").hide(fingerprintFragment)
                .add(R.id.fragment_container, environmentFragment, "environment")
                .commit();

        activeFragment = environmentFragment;
    }

    private void setupNavigation() {
        bottomNavigation.setOnItemSelectedListener(item -> {
            Fragment selectedFragment = null;
            int itemId = item.getItemId();

            if (itemId == R.id.navigation_environment) {
                selectedFragment = environmentFragment;
            } else if (itemId == R.id.navigation_fingerprint) {
                selectedFragment = fingerprintFragment;
            } else if (itemId == R.id.navigation_device_info) {
                selectedFragment = deviceInfoFragment;
            }

            if (selectedFragment != null && selectedFragment != activeFragment) {
                getSupportFragmentManager().beginTransaction()
                        .hide(activeFragment)
                        .show(selectedFragment)
                        .commit();
                activeFragment = selectedFragment;
            }

            return true;
        });

        // Select first item by default
        bottomNavigation.setSelectedItemId(R.id.navigation_environment);
    }

    private void refreshCurrentFragment() {
        // Start rotation animation
        rotateAnimator.start();

        if (activeFragment instanceof EnvironmentFragment) {
            ((EnvironmentFragment) activeFragment).startDetection();
        } else if (activeFragment instanceof FingerprintFragment) {
            ((FingerprintFragment) activeFragment).collectFingerprints();
        } else if (activeFragment instanceof DeviceInfoFragment) {
            ((DeviceInfoFragment) activeFragment).loadDeviceInfo();
        }

        // Stop animation after delay
        btnRefresh.postDelayed(() -> {
            rotateAnimator.cancel();
            btnRefresh.setRotation(0f);
        }, 2000);
    }

    private void showAboutBottomSheet() {
        BottomSheetDialog dialog = new BottomSheetDialog(this);
        View view = getLayoutInflater().inflate(R.layout.bottom_sheet_about, null);
        dialog.setContentView(view);
        dialog.show();
    }

    @Override
    protected void onResume() {
        super.onResume();
        startAttachWatcher();
    }

    @Override
    protected void onPause() {
        stopAttachWatcher();
        super.onPause();
    }

    /**
     * 启动后台 watcher。每 2 秒读一次 JDWP/JVMTI 真 attach 信号指纹；
     * 指纹变化即在主线程触发 refresh —— attach jdb/Studio Profiler/Frida JVMTI
     * 时不需要手动点刷新按钮。
     *
     * 后台 thread 复用 NativeDetector 单例 + Java Debug API，无锁。
     */
    private void startAttachWatcher() {
        if (attachWatcher != null) return;
        // 用当前真实状态做基线，避免首次 poll 误触发
        lastAttachFingerprint = computeAttachFingerprint();
        attachWatcher = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "AttachWatcher");
            t.setDaemon(true);
            return t;
        });
        attachWatcher.scheduleWithFixedDelay(this::pollAttachState,
                WATCHER_INTERVAL_MS, WATCHER_INTERVAL_MS, TimeUnit.MILLISECONDS);
        Log.i(WATCHER_TAG, "started, baseline=" + lastAttachFingerprint);
    }

    private void stopAttachWatcher() {
        if (attachWatcher == null) return;
        attachWatcher.shutdownNow();
        attachWatcher = null;
        Log.i(WATCHER_TAG, "stopped");
    }

    private void pollAttachState() {
        try {
            String now = computeAttachFingerprint();
            String prev = lastAttachFingerprint;
            if (now.equals(prev)) return;
            lastAttachFingerprint = now;
            Log.i(WATCHER_TAG, "state changed: " + prev + " → " + now);
            // 只在 EnvironmentFragment 可见时刷新，其他 tab 不影响
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                if (activeFragment instanceof EnvironmentFragment) {
                    refreshCurrentFragment();
                }
            });
        } catch (Throwable t) {
            Log.w(WATCHER_TAG, "poll error", t);
        }
    }

    /**
     * 真 attach 信号指纹：JVMTI + @jdwp-self socket + transport 线程 + Debug API。
     * 任一变化即刷新。capability 信号 (libadbconnection / control thread) 不在指纹里，
     * 因为它们在 debuggable app 上常驻、不指示 attach 状态变化。
     */
    private String computeAttachFingerprint() {
        String jvmti = "0", selfSock = "0", xport = "0";
        try {
            String report = NativeDetector.getInstance().getJdwpDetectionReport();
            if (report != null) {
                jvmti = parseReportField(report, "JVMTI");
                selfSock = parseReportField(report, "JDWP_SOCK_SELF");
                String xportRaw = parseReportField(report, "JDWP_THREADS_XPORT");
                xport = xportRaw.isEmpty() ? "0" : "1";
            }
        } catch (Throwable ignored) {
        }
        boolean debuggerConnected = false;
        boolean waitingForDebugger = false;
        try {
            debuggerConnected = Debug.isDebuggerConnected();
            waitingForDebugger = Debug.waitingForDebugger();
        } catch (Throwable ignored) {
        }
        return "j=" + jvmti + " s=" + selfSock + " x=" + xport
                + " dc=" + (debuggerConnected ? 1 : 0)
                + " dw=" + (waitingForDebugger ? 1 : 0);
    }

    private static String parseReportField(String report, String key) {
        for (String line : report.split("\n")) {
            int eq = line.indexOf('=');
            if (eq > 0 && line.substring(0, eq).equals(key)) {
                return line.substring(eq + 1);
            }
        }
        return "";
    }

    public native String stringFromJNI();
}
