package com.xff.launch.ui.deviceinfo;

import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.StatFs;
import android.telephony.TelephonyManager;
import android.util.DisplayMetrics;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.google.android.material.chip.Chip;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.xff.launch.R;
import com.xff.launch.detector.DeviceLegitimacyDetector;
import com.xff.launch.detector.NativeDetector;
import com.xff.launch.model.DeviceInfo;
import com.xff.launch.model.DeviceLegitimacyResult;
import com.xff.launch.model.VendorProfile;
import com.xff.launch.model.VendorService;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Device information and legitimacy fragment
 */
public class DeviceInfoFragment extends Fragment {

    private SwipeRefreshLayout swipeRefresh;
    private TextView tvLegitimacyScore;
    private TextView tvLegitimacyStatus;
    private LinearProgressIndicator progressLegitimacy;
    private Chip tvCheckBuild, tvCheckRom, tvCheckService, tvCheckHardware, tvCheckFingerprint;

    // Basic info
    private View rowBrand, rowModel, rowManufacturer, rowDevice, rowBoard;
    // System info
    private View rowAndroidVersion, rowApiLevel, rowRomVersion, rowSecurityPatch, rowKernelVersion;
    // Hardware info
    private View rowCpu, rowMemory, rowStorage, rowScreen, rowSensors;

    private RecyclerView recyclerVendorServices;
    private RecyclerView recyclerRomFeatures;

    private ExecutorService executor;
    private NativeDetector nativeDetector;
    private DeviceLegitimacyDetector legitimacyDetector;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_device_info, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        nativeDetector = NativeDetector.getInstance();
        legitimacyDetector = new DeviceLegitimacyDetector(requireContext());
        initViews(view);
        loadDeviceInfo();
    }

    private void initViews(View view) {
        swipeRefresh = view.findViewById(R.id.swipe_refresh);
        tvLegitimacyScore = view.findViewById(R.id.tv_legitimacy_score);
        tvLegitimacyStatus = view.findViewById(R.id.tv_legitimacy_status);
        progressLegitimacy = view.findViewById(R.id.progress_legitimacy);

        tvCheckBuild = view.findViewById(R.id.tv_check_build);
        tvCheckRom = view.findViewById(R.id.tv_check_rom);
        tvCheckService = view.findViewById(R.id.tv_check_service);
        tvCheckHardware = view.findViewById(R.id.tv_check_hardware);
        tvCheckFingerprint = view.findViewById(R.id.tv_check_fingerprint);

        rowBrand = view.findViewById(R.id.row_brand);
        rowModel = view.findViewById(R.id.row_model);
        rowManufacturer = view.findViewById(R.id.row_manufacturer);
        rowDevice = view.findViewById(R.id.row_device);
        rowBoard = view.findViewById(R.id.row_board);

        rowAndroidVersion = view.findViewById(R.id.row_android_version);
        rowApiLevel = view.findViewById(R.id.row_api_level);
        rowRomVersion = view.findViewById(R.id.row_rom_version);
        rowSecurityPatch = view.findViewById(R.id.row_security_patch);
        rowKernelVersion = view.findViewById(R.id.row_kernel_version);

        rowCpu = view.findViewById(R.id.row_cpu);
        rowMemory = view.findViewById(R.id.row_memory);
        rowStorage = view.findViewById(R.id.row_storage);
        rowScreen = view.findViewById(R.id.row_screen);
        rowSensors = view.findViewById(R.id.row_sensors);

        recyclerVendorServices = view.findViewById(R.id.recycler_vendor_services);
        recyclerRomFeatures = view.findViewById(R.id.recycler_rom_features);

        recyclerVendorServices.setLayoutManager(new LinearLayoutManager(requireContext()));
        recyclerRomFeatures.setLayoutManager(new LinearLayoutManager(requireContext()));

        swipeRefresh.setColorSchemeResources(R.color.primary);
        swipeRefresh.setOnRefreshListener(this::loadDeviceInfo);
    }

    public void loadDeviceInfo() {
        if (executor == null) {
            executor = Executors.newSingleThreadExecutor();
        }
        if (!isAdded()) return;

        // Cache context on main thread before background work
        final Context ctx = requireContext().getApplicationContext();

        swipeRefresh.setRefreshing(true);

        executor.execute(() -> {
            DeviceInfo info = collectDeviceInfo(ctx);
            DeviceLegitimacyResult legitimacy = checkLegitimacy(info);

            if (getActivity() != null && isAdded()) {
                getActivity().runOnUiThread(() -> {
                    if (!isAdded()) return;
                    updateUI(info, legitimacy);
                    swipeRefresh.setRefreshing(false);
                });
            }
        });
    }

    private DeviceInfo collectDeviceInfo(Context ctx) {
        DeviceInfo info = new DeviceInfo();

        // Basic info
        info.setBrand(Build.BRAND);
        info.setModel(Build.MODEL);
        info.setManufacturer(Build.MANUFACTURER);
        info.setDevice(Build.DEVICE);
        info.setBoard(Build.BOARD);
        info.setHardware(Build.HARDWARE);
        info.setProduct(Build.PRODUCT);

        // System info
        info.setAndroidVersion(Build.VERSION.RELEASE);
        info.setApiLevel(Build.VERSION.SDK_INT);
        info.setBuildFingerprint(Build.FINGERPRINT);
        info.setSecurityPatch(Build.VERSION.SECURITY_PATCH);
        info.setBuildId(Build.ID);

        // Kernel version
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/version"));
            String version = reader.readLine();
            reader.close();
            info.setKernelVersion(version != null ? version.split(" ")[2] : "Unknown");
        } catch (Exception e) {
            info.setKernelVersion("Unknown");
        }

        // ROM version
        String romVersion = detectRomVersion();
        info.setRomVersion(romVersion);

        // CPU info
        info.setCpuAbi(Build.SUPPORTED_ABIS[0]);
        info.setCpuCores(Runtime.getRuntime().availableProcessors());

        // Memory info
        ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
        ActivityManager.MemoryInfo memInfo = new ActivityManager.MemoryInfo();
        am.getMemoryInfo(memInfo);
        info.setTotalMemory(memInfo.totalMem);
        info.setAvailableMemory(memInfo.availMem);

        // Storage info
        StatFs stat = new StatFs(Environment.getDataDirectory().getPath());
        info.setTotalStorage(stat.getTotalBytes());
        info.setAvailableStorage(stat.getAvailableBytes());

        // Screen info
        DisplayMetrics dm = ctx.getResources().getDisplayMetrics();
        info.setScreenResolution(dm.widthPixels + "x" + dm.heightPixels);
        info.setScreenDpi(dm.densityDpi);

        // Camera count
        try {
            CameraManager cameraManager = (CameraManager) ctx.getSystemService(Context.CAMERA_SERVICE);
            info.setCameraCount(cameraManager.getCameraIdList().length);
        } catch (Exception e) {
            info.setCameraCount(0);
        }

        // Sensor count
        SensorManager sensorManager = (SensorManager) ctx.getSystemService(Context.SENSOR_SERVICE);
        info.setSensorCount(sensorManager.getSensorList(Sensor.TYPE_ALL).size());

        // Network info
        ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo activeNetwork = cm.getActiveNetworkInfo();
        if (activeNetwork != null) {
            info.setNetworkType(activeNetwork.getTypeName());
        }

        // WiFi info
        WifiManager wifiManager = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
        if (wifiManager != null && wifiManager.isWifiEnabled()) {
            WifiInfo wifiInfo = wifiManager.getConnectionInfo();
            info.setWifiSsid(wifiInfo.getSSID());
        }

        // IP address
        info.setIpAddress(getLocalIpAddress());

        // Carrier
        TelephonyManager tm = (TelephonyManager) ctx.getSystemService(Context.TELEPHONY_SERVICE);
        info.setCarrier(tm.getNetworkOperatorName());

        return info;
    }

    private String detectRomVersion() {
        // Check for various ROM versions
        String miuiVersion = nativeDetector.getBuildPropertyNative("ro.miui.ui.version.name");
        if (miuiVersion != null && !miuiVersion.isEmpty()) {
            return "MIUI " + miuiVersion;
        }

        String emuiVersion = nativeDetector.getBuildPropertyNative("ro.build.version.emui");
        if (emuiVersion != null && !emuiVersion.isEmpty()) {
            return "EMUI " + emuiVersion;
        }

        String colorOsVersion = nativeDetector.getBuildPropertyNative("ro.build.version.opporom");
        if (colorOsVersion != null && !colorOsVersion.isEmpty()) {
            return "ColorOS " + colorOsVersion;
        }

        String originOsVersion = nativeDetector.getBuildPropertyNative("ro.vivo.os.version");
        if (originOsVersion != null && !originOsVersion.isEmpty()) {
            return "OriginOS " + originOsVersion;
        }

        String oneuiVersion = nativeDetector.getBuildPropertyNative("ro.build.version.oneui");
        if (oneuiVersion != null && !oneuiVersion.isEmpty()) {
            return "One UI " + oneuiVersion;
        }

        return "Android " + Build.VERSION.RELEASE;
    }

    private DeviceLegitimacyResult checkLegitimacy(DeviceInfo info) {
        // Use the comprehensive DeviceLegitimacyDetector
        return legitimacyDetector.checkLegitimacy(info);
    }

    private String getLocalIpAddress() {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface intf : interfaces) {
                List<InetAddress> addrs = Collections.list(intf.getInetAddresses());
                for (InetAddress addr : addrs) {
                    if (!addr.isLoopbackAddress() && addr.getHostAddress().indexOf(':') < 0) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return "Unknown";
    }

    private void updateUI(DeviceInfo info, DeviceLegitimacyResult legitimacy) {
        // Update legitimacy score
        int score = legitimacy.getLegitimacyScore();
        tvLegitimacyScore.setText(score + "/100");
        progressLegitimacy.setProgress(score);

        int statusColor;
        if (score >= 90) {
            tvLegitimacyStatus.setText("正常");
            statusColor = R.color.status_safe;
        } else if (score >= 70) {
            tvLegitimacyStatus.setText("存在异常");
            statusColor = R.color.status_warning;
        } else {
            tvLegitimacyStatus.setText("可能被篡改");
            statusColor = R.color.status_risk;
        }
        progressLegitimacy.setIndicatorColor(ContextCompat.getColor(requireContext(), statusColor));

        // Update check items
        updateCheckItem(tvCheckBuild, legitimacy.isBuildConsistent(), "Build一致性");
        updateCheckItem(tvCheckRom, legitimacy.isRomMatched(), "ROM匹配");
        updateCheckItem(tvCheckService, legitimacy.isServiceMatched(), "服务匹配");
        updateCheckItem(tvCheckHardware, legitimacy.isHardwareConsistent(), "硬件一致");
        updateCheckItem(tvCheckFingerprint, legitimacy.isFingerprintFormatValid(), "指纹格式");

        // Update basic info
        setInfoRow(rowBrand, getString(R.string.brand), info.getBrand());
        setInfoRow(rowModel, getString(R.string.model), info.getModel());
        setInfoRow(rowManufacturer, getString(R.string.manufacturer), info.getManufacturer());
        setInfoRow(rowDevice, getString(R.string.device_code), info.getDevice());
        setInfoRow(rowBoard, getString(R.string.board), info.getBoard());

        // Update system info
        setInfoRow(rowAndroidVersion, getString(R.string.android_version), info.getAndroidVersion());
        setInfoRow(rowApiLevel, getString(R.string.api_level), String.valueOf(info.getApiLevel()));
        setInfoRow(rowRomVersion, getString(R.string.rom_version), info.getRomVersion());
        setInfoRow(rowSecurityPatch, getString(R.string.security_patch), info.getSecurityPatch());
        setInfoRow(rowKernelVersion, getString(R.string.kernel_version), info.getKernelVersion());

        // Update hardware info
        setInfoRow(rowCpu, getString(R.string.cpu), info.getCpuAbi() + " (" + info.getCpuCores() + " cores)");
        setInfoRow(rowMemory, getString(R.string.memory), info.getFormattedTotalMemory());
        setInfoRow(rowStorage, getString(R.string.storage), info.getFormattedTotalStorage() + " (Available: " + info.getFormattedAvailableStorage() + ")");
        setInfoRow(rowScreen, getString(R.string.screen), info.getScreenResolution() + " @ " + info.getScreenDpi() + " dpi");
        setInfoRow(rowSensors, getString(R.string.sensors), info.getSensorCount() + " sensors");

        // Update vendor services
        VendorServiceAdapter serviceAdapter = new VendorServiceAdapter(requireContext());
        serviceAdapter.setServices(legitimacy.getVendorServices());
        recyclerVendorServices.setAdapter(serviceAdapter);

        // Update ROM features
        VendorProfile detectedVendor = legitimacyDetector.getDetectedVendor();
        if (detectedVendor != null) {
            List<DeviceLegitimacyDetector.RomFeature> romFeatures = legitimacyDetector.getRomFeatures();
            RomFeatureAdapter featureAdapter = new RomFeatureAdapter(requireContext());
            featureAdapter.setFeatures(romFeatures);
            recyclerRomFeatures.setAdapter(featureAdapter);
        }
    }

    private void updateCheckItem(Chip chip, boolean passed, String label) {
        chip.setText(label + (passed ? " ✓" : " ✗"));
        chip.setTextColor(passed
                ? ContextCompat.getColor(requireContext(), R.color.status_safe)
                : ContextCompat.getColor(requireContext(), R.color.status_risk));
        chip.setChipStrokeColorResource(passed ? R.color.status_safe : R.color.status_risk);
    }

    private void setInfoRow(View row, String label, String value) {
        if (row != null) {
            TextView tvLabel = row.findViewById(R.id.tv_label);
            TextView tvValue = row.findViewById(R.id.tv_value);
            if (tvLabel != null) tvLabel.setText(label);
            if (tvValue != null) tvValue.setText(value != null ? value : "Unknown");
        }
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        if (executor != null) {
            executor.shutdown();
            executor = null;
        }
    }

    // Vendor Service Adapter
    private static class VendorServiceAdapter extends RecyclerView.Adapter<VendorServiceAdapter.ViewHolder> {
        private List<VendorService> services = new ArrayList<>();
        private final Context context;

        VendorServiceAdapter(Context context) {
            this.context = context;
        }

        void setServices(List<VendorService> services) {
            this.services = services;
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_vendor_service, parent, false);
            return new ViewHolder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            VendorService service = services.get(position);
            holder.tvServiceName.setText(service.getName());
            holder.tvStatus.setText(service.getStatusDescription());

            int color = service.isStatusValid() ? R.color.status_safe : R.color.status_risk;
            holder.tvStatus.setTextColor(ContextCompat.getColor(context, color));
            holder.ivStatus.setBackgroundTintList(android.content.res.ColorStateList.valueOf(
                    ContextCompat.getColor(context, color)));
        }

        @Override
        public int getItemCount() {
            return services.size();
        }

        static class ViewHolder extends RecyclerView.ViewHolder {
            TextView tvServiceName, tvStatus;
            View ivStatus;

            ViewHolder(@NonNull View itemView) {
                super(itemView);
                tvServiceName = itemView.findViewById(R.id.tv_service_name);
                tvStatus = itemView.findViewById(R.id.tv_status);
                ivStatus = itemView.findViewById(R.id.iv_status);
            }
        }
    }

    // ROM Feature Adapter
    private static class RomFeatureAdapter extends RecyclerView.Adapter<RomFeatureAdapter.ViewHolder> {
        private List<DeviceLegitimacyDetector.RomFeature> features = new ArrayList<>();
        private final Context context;

        RomFeatureAdapter(Context context) {
            this.context = context;
        }

        void setFeatures(List<DeviceLegitimacyDetector.RomFeature> features) {
            this.features = features;
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_rom_feature, parent, false);
            return new ViewHolder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            DeviceLegitimacyDetector.RomFeature feature = features.get(position);
            holder.tvProperty.setText(feature.getProperty());
            holder.tvValue.setText(feature.exists() ? feature.getValue() : "未检测到");

            int color = feature.exists() ? R.color.status_safe : R.color.status_warning;
            holder.tvValue.setTextColor(ContextCompat.getColor(context, color));
            holder.ivStatus.setBackgroundTintList(android.content.res.ColorStateList.valueOf(
                    ContextCompat.getColor(context, color)));
        }

        @Override
        public int getItemCount() {
            return features.size();
        }

        static class ViewHolder extends RecyclerView.ViewHolder {
            TextView tvProperty, tvValue;
            View ivStatus;

            ViewHolder(@NonNull View itemView) {
                super(itemView);
                tvProperty = itemView.findViewById(R.id.tv_property);
                tvValue = itemView.findViewById(R.id.tv_value);
                ivStatus = itemView.findViewById(R.id.iv_status);
            }
        }
    }
}
