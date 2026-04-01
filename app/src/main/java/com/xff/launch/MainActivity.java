package com.xff.launch;

import android.animation.ObjectAnimator;
import android.os.Bundle;
import android.view.View;
import android.view.animation.LinearInterpolator;
import android.widget.ImageButton;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.WindowCompat;
import androidx.fragment.app.Fragment;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.xff.launch.ui.deviceinfo.DeviceInfoFragment;
import com.xff.launch.ui.environment.EnvironmentFragment;
import com.xff.launch.ui.fingerprint.FingerprintFragment;

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

    public native String stringFromJNI();
}
