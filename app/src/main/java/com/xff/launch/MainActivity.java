package com.xff.launch;

import android.animation.ObjectAnimator;
import android.os.Bundle;
import android.view.animation.LinearInterpolator;
import android.widget.ImageButton;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.xff.launch.ui.about.AboutFragment;
import com.xff.launch.ui.deviceinfo.DeviceInfoFragment;
import com.xff.launch.ui.environment.EnvironmentFragment;
import com.xff.launch.ui.fingerprint.FingerprintFragment;

/**
 * Main activity with bottom navigation
 */
public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("launch");
    }

    private BottomNavigationView bottomNavigation;
    private ImageButton btnRefresh;

    private EnvironmentFragment environmentFragment;
    private FingerprintFragment fingerprintFragment;
    private DeviceInfoFragment deviceInfoFragment;
    private AboutFragment aboutFragment;

    private Fragment activeFragment;
    private ObjectAnimator rotateAnimator;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();
        initFragments();
        setupNavigation();
    }

    private void initViews() {
        bottomNavigation = findViewById(R.id.bottom_navigation);
        btnRefresh = findViewById(R.id.btn_refresh);

        // Setup refresh button animation
        rotateAnimator = ObjectAnimator.ofFloat(btnRefresh, "rotation", 0f, 360f);
        rotateAnimator.setDuration(1000);
        rotateAnimator.setRepeatCount(ObjectAnimator.INFINITE);
        rotateAnimator.setInterpolator(new LinearInterpolator());

        btnRefresh.setOnClickListener(v -> refreshCurrentFragment());
    }

    private void initFragments() {
        environmentFragment = new EnvironmentFragment();
        fingerprintFragment = new FingerprintFragment();
        deviceInfoFragment = new DeviceInfoFragment();
        aboutFragment = new AboutFragment();

        // Add all fragments but hide all except the first
        getSupportFragmentManager().beginTransaction()
                .add(R.id.fragment_container, aboutFragment, "about").hide(aboutFragment)
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
            } else if (itemId == R.id.navigation_about) {
                selectedFragment = aboutFragment;
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
        } else {
            Toast.makeText(this, "此页面无需刷新", Toast.LENGTH_SHORT).show();
        }

        // Stop animation after delay
        btnRefresh.postDelayed(() -> {
            rotateAnimator.cancel();
            btnRefresh.setRotation(0f);
        }, 2000);
    }

    public native String stringFromJNI();
}
