package com.xff.launch.ui.fingerprint;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.media.MediaDrm;
import android.media.UnsupportedSchemeException;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import android.content.res.ColorStateList;

import com.google.android.material.progressindicator.LinearProgressIndicator;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.xff.launch.R;
import com.xff.launch.detector.NativeDetector;
import com.xff.launch.model.DetectionLayer;
import com.xff.launch.model.FingerprintItem;
import com.xff.launch.model.FingerprintResult;
import com.xff.launch.util.PersistentFingerprint;
import com.xff.launch.util.ReflectionUtils;

import android.app.ActivityManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.StatFs;
import android.text.TextUtils;
import android.util.DisplayMetrics;

import java.net.NetworkInterface;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Fingerprint information fragment
 */
public class FingerprintFragment extends Fragment {

    private SwipeRefreshLayout swipeRefresh;
    private TextView tvDeviceFingerprint;
    private TextView tvTrustLevel;
    private TextView tvTamperingStatus;
    private View ivStatusIcon;
    private LinearProgressIndicator progressTrust;
    private TextView tvHardwareHash;
    private TextView tvSoftwareHash;
    private TextView tvBuildFingerprint;
    private RecyclerView recyclerIdentifiers;
    private RecyclerView recyclerComparison;

    private View btnCopyFingerprint;
    private View btnCopyHwHash;
    private View btnCopySwHash;
    private View btnCopyBuildFp;

    private ExecutorService executor;
    private FingerprintResult currentResult;
    private NativeDetector nativeDetector;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_fingerprint, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        nativeDetector = NativeDetector.getInstance();
        initViews(view);
        setupCopyButtons();

        // Request read permission first; collect after permission resolved
        if (hasReadPermission()) {
            collectFingerprints();
        } else {
            requestStoragePermissionIfNeeded();
            // Also collect immediately (write works without permission, read will show "新设备" until granted)
            collectFingerprints();
        }
    }

    private void initViews(View view) {
        swipeRefresh = view.findViewById(R.id.swipe_refresh);
        tvDeviceFingerprint = view.findViewById(R.id.tv_device_fingerprint);
        tvTrustLevel = view.findViewById(R.id.tv_trust_level);
        tvTamperingStatus = view.findViewById(R.id.tv_tampering_status);
        ivStatusIcon = view.findViewById(R.id.iv_status_icon);
        progressTrust = view.findViewById(R.id.progress_trust);
        // Hash rows use include layout - find views inside included layouts
        View layoutHwHash = view.findViewById(R.id.layout_hw_hash);
        View layoutSwHash = view.findViewById(R.id.layout_sw_hash);
        View layoutBuildFp = view.findViewById(R.id.layout_build_fp);

        tvHardwareHash = layoutHwHash.findViewById(R.id.tv_hash_value);
        tvSoftwareHash = layoutSwHash.findViewById(R.id.tv_hash_value);
        tvBuildFingerprint = layoutBuildFp.findViewById(R.id.tv_hash_value);

        // Set labels for hash rows
        ((TextView) layoutHwHash.findViewById(R.id.tv_hash_label)).setText(R.string.hardware_fingerprint);
        ((TextView) layoutSwHash.findViewById(R.id.tv_hash_label)).setText(R.string.software_fingerprint);
        ((TextView) layoutBuildFp.findViewById(R.id.tv_hash_label)).setText(R.string.build_fingerprint);

        recyclerIdentifiers = view.findViewById(R.id.recycler_identifiers);
        recyclerComparison = view.findViewById(R.id.recycler_comparison);

        btnCopyFingerprint = view.findViewById(R.id.btn_copy_fingerprint);
        btnCopyHwHash = layoutHwHash.findViewById(R.id.btn_copy);
        btnCopySwHash = layoutSwHash.findViewById(R.id.btn_copy);
        btnCopyBuildFp = layoutBuildFp.findViewById(R.id.btn_copy);

        swipeRefresh.setColorSchemeResources(R.color.primary);
        swipeRefresh.setOnRefreshListener(this::collectFingerprints);

        recyclerIdentifiers.setLayoutManager(new LinearLayoutManager(requireContext()));
        recyclerComparison.setLayoutManager(new LinearLayoutManager(requireContext()));
    }

    private void setupCopyButtons() {
        btnCopyFingerprint.setOnClickListener(v -> copyToClipboard("Device Fingerprint", tvDeviceFingerprint.getText().toString()));
        btnCopyHwHash.setOnClickListener(v -> copyToClipboard("Hardware Hash", tvHardwareHash.getText().toString()));
        btnCopySwHash.setOnClickListener(v -> copyToClipboard("Software Hash", tvSoftwareHash.getText().toString()));
        btnCopyBuildFp.setOnClickListener(v -> copyToClipboard("Build Fingerprint", tvBuildFingerprint.getText().toString()));
    }

    public void collectFingerprints() {
        if (executor == null) {
            executor = Executors.newSingleThreadExecutor();
        }

        swipeRefresh.setRefreshing(true);

        executor.execute(() -> {
            FingerprintResult result = performCollection();

            if (getActivity() != null && isAdded()) {
                getActivity().runOnUiThread(() -> {
                    if (!isAdded()) return;
                    currentResult = result;
                    updateUI(result);
                    swipeRefresh.setRefreshing(false);
                });
            }
        });
    }

    private FingerprintResult performCollection() {
        FingerprintResult result = new FingerprintResult();
        List<FingerprintItem> items = new ArrayList<>();

        // ==================== Basic Identifiers ====================

        // ANDROID_ID - Use reflection to bypass hooks
        FingerprintItem androidId = new FingerprintItem("android_id", "ANDROID_ID");
        String reflectAndroidId = ReflectionUtils.getAndroidId(requireContext().getContentResolver());
        String directAndroidId = Settings.Secure.getString(requireContext().getContentResolver(), Settings.Secure.ANDROID_ID);
        androidId.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectAndroidId, directAndroidId));
        androidId.setLayerValue(DetectionLayer.NATIVE, directAndroidId);
        androidId.setLayerValue(DetectionLayer.SYSCALL, reflectAndroidId);
        items.add(androidId);

        // Serial - Multiple sources with reflection and direct access
        FingerprintItem serial = new FingerprintItem("serial", "设备序列号");
        String reflectSerial = ReflectionUtils.getSerial();
        String directSerial = Build.SERIAL; // Direct access as fallback
        String propSerial = ReflectionUtils.getSystemProperty("ro.serialno");
        String serialBootProp = ReflectionUtils.getSystemProperty("ro.boot.serialno");
        String gsmSerial = ReflectionUtils.getSystemProperty("gsm.serial");
        String nativeSerial = nativeDetector.getBuildPropertyNative("ro.serialno");
        String syscallSerial = nonEmpty(nativeDetector.getBuildPropertySyscall("ro.serialno"),
                nativeDetector.getBuildPropertySyscall("ro.boot.serialno"),
                nativeDetector.readFileSyscall("/sys/class/android_usb/android0/iSerial"));
        String javaSerial = nonEmpty(reflectSerial, directSerial, propSerial, serialBootProp, gsmSerial);
        serial.setLayerValue(DetectionLayer.JAVA, javaSerial.isEmpty() ? "N/A" : javaSerial);
        serial.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeSerial, propSerial).isEmpty() ? "N/A" : nonEmpty(nativeSerial, propSerial));
        serial.setLayerValue(DetectionLayer.SYSCALL, syscallSerial.isEmpty() ? "N/A" : syscallSerial);
        items.add(serial);

        // Build.MODEL - Direct access + Reflection + SystemProperties
        FingerprintItem model = new FingerprintItem("model", "设备型号");
        String reflectModel = ReflectionUtils.getModel();
        String directModel = Build.MODEL; // Direct access as primary fallback
        String propModel = ReflectionUtils.getSystemProperty("ro.product.model");
        String vendorModel = ReflectionUtils.getSystemProperty("ro.product.vendor.model");
        String odmModel = ReflectionUtils.getSystemProperty("ro.product.odm.model");
        String nativeModel = nativeDetector.getBuildPropertyNative("ro.product.model");
        String syscallModel = nonEmpty(nativeDetector.getBuildPropertySyscall("ro.product.model"),
                nativeDetector.getBuildPropertySyscall("ro.product.vendor.model"));
        String javaModel = nonEmpty(reflectModel, directModel, propModel, vendorModel, odmModel);
        model.setLayerValue(DetectionLayer.JAVA, javaModel.isEmpty() ? "N/A" : javaModel);
        model.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeModel, propModel).isEmpty() ? "N/A" : nonEmpty(nativeModel, propModel));
        model.setLayerValue(DetectionLayer.SYSCALL, syscallModel.isEmpty() ? "N/A" : syscallModel);
        items.add(model);

        // Build.BRAND - Direct access + Reflection + SystemProperties
        FingerprintItem brand = new FingerprintItem("brand", "品牌");
        String reflectBrand = ReflectionUtils.getBrand();
        String directBrand = Build.BRAND; // Direct access as primary fallback
        String propBrand = ReflectionUtils.getSystemProperty("ro.product.brand");
        String vendorBrand = ReflectionUtils.getSystemProperty("ro.product.vendor.brand");
        String odmBrand = ReflectionUtils.getSystemProperty("ro.product.odm.brand");
        String nativeBrand = nativeDetector.getBuildPropertyNative("ro.product.brand");
        String syscallBrand = nonEmpty(nativeDetector.getBuildPropertySyscall("ro.product.brand"),
                nativeDetector.getBuildPropertySyscall("ro.product.vendor.brand"));
        String javaBrand = nonEmpty(reflectBrand, directBrand, propBrand, vendorBrand, odmBrand);
        brand.setLayerValue(DetectionLayer.JAVA, javaBrand.isEmpty() ? "N/A" : javaBrand);
        brand.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeBrand, propBrand).isEmpty() ? "N/A" : nonEmpty(nativeBrand, propBrand));
        brand.setLayerValue(DetectionLayer.SYSCALL, syscallBrand.isEmpty() ? "N/A" : syscallBrand);
        items.add(brand);

        // Build.FINGERPRINT - Direct access + Reflection + SystemProperties
        FingerprintItem fingerprint = new FingerprintItem("fingerprint", "Build 指纹");
        String reflectFp = ReflectionUtils.getFingerprint();
        String directFp = Build.FINGERPRINT; // Direct access as primary fallback
        String propFp = ReflectionUtils.getSystemProperty("ro.build.fingerprint");
        String vendorFp = ReflectionUtils.getSystemProperty("ro.vendor.build.fingerprint");
        String bootFp = ReflectionUtils.getSystemProperty("ro.bootimage.build.fingerprint");
        String nativeFp = nativeDetector.getBuildPropertyNative("ro.build.fingerprint");
        String syscallFp = nonEmpty(nativeDetector.getBuildPropertySyscall("ro.build.fingerprint"),
                nativeDetector.getBuildPropertySyscall("ro.vendor.build.fingerprint"));
        String javaFp = nonEmpty(reflectFp, directFp, propFp, vendorFp, bootFp);
        fingerprint.setLayerValue(DetectionLayer.JAVA, javaFp.isEmpty() ? "N/A" : javaFp);
        fingerprint.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeFp, propFp).isEmpty() ? "N/A" : nonEmpty(nativeFp, propFp));
        fingerprint.setLayerValue(DetectionLayer.SYSCALL, syscallFp.isEmpty() ? "N/A" : syscallFp);
        items.add(fingerprint);

        // ==================== Kernel Identifiers ====================

        // Boot ID - unique per boot
        FingerprintItem bootId = new FingerprintItem("boot_id", "Boot ID");
        String javaBootId = ReflectionUtils.readFileFirstLine("/proc/sys/kernel/random/boot_id");
        String nativeBootId = nativeDetector.readKernelFile("/proc/sys/kernel/random/boot_id");
        String syscallBootId = nativeDetector.readFileSyscall("/proc/sys/kernel/random/boot_id");
        bootId.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaBootId, nativeBootId));
        bootId.setLayerValue(DetectionLayer.NATIVE, nativeBootId);
        bootId.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallBootId, javaBootId));
        items.add(bootId);

        // Note: /proc/sys/kernel/random/uuid generates a NEW UUID on each read
        // It's NOT suitable for fingerprinting or multi-layer comparison
        // Use boot_id instead which is stable within a boot session

        // Kernel Version - Multiple sources
        FingerprintItem kernelVersion = new FingerprintItem("kernel_version", "内核版本");
        String javaKernel = System.getProperty("os.version");
        String fileKernel = ReflectionUtils.readFileFirstLine("/proc/version");
        String nativeKernel = nativeDetector.readKernelFile("/proc/version");
        String syscallKernel = nativeDetector.readFileSyscall("/proc/version");
        // Also try /proc/sys/kernel/osrelease
        String osRelease = ReflectionUtils.readFileFirstLine("/proc/sys/kernel/osrelease");
        kernelVersion.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaKernel, osRelease, fileKernel));
        kernelVersion.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeKernel, osRelease, fileKernel));
        kernelVersion.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallKernel, osRelease, javaKernel));
        items.add(kernelVersion);

        // Hostname - Multiple sources
        FingerprintItem hostname = new FingerprintItem("hostname", "主机名");
        String javaHostname = ReflectionUtils.readFileFirstLine("/proc/sys/kernel/hostname");
        String nativeHostname = nativeDetector.readKernelFile("/proc/sys/kernel/hostname");
        String syscallHostname = nativeDetector.readFileSyscall("/proc/sys/kernel/hostname");
        // Also try Build.HOST via reflection and net.hostname property
        String buildHost = ReflectionUtils.getBuildField("HOST");
        String propHostname = ReflectionUtils.getSystemProperty("net.hostname");
        hostname.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaHostname, buildHost, propHostname));
        hostname.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeHostname, buildHost));
        hostname.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallHostname, javaHostname, buildHost));
        items.add(hostname);

        // ==================== Hardware Identifiers ====================

        // CPU Serial from /proc/cpuinfo - Not available on all devices
        FingerprintItem cpuSerial = new FingerprintItem("cpu_serial", "CPU 序列号");
        String javaCpuSerial = ReflectionUtils.getCpuSerial();
        String nativeCpuSerial = nativeDetector.getCpuSerial();
        String syscallCpuSerial = nativeDetector.getCpuSerialSyscall();
        // CPU Revision as fallback (more commonly available)
        String cpuRevision = ReflectionUtils.getCpuRevision();
        // Also try ro.boot.cpuid property
        String cpuIdProp = ReflectionUtils.getSystemProperty("ro.boot.cpuid");
        cpuSerial.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaCpuSerial, cpuRevision, cpuIdProp, "N/A"));
        cpuSerial.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeCpuSerial, cpuRevision, "N/A"));
        cpuSerial.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallCpuSerial, cpuRevision, "N/A"));
        items.add(cpuSerial);

        // CPU Hardware from /proc/cpuinfo
        FingerprintItem cpuHardware = new FingerprintItem("cpu_hardware", "CPU 硬件");
        String reflectHw = ReflectionUtils.getHardware();
        String javaCpuHw = ReflectionUtils.getCpuHardware();
        String nativeCpuHw = nativeDetector.getCpuHardware();
        String syscallCpuHw = nativeDetector.getCpuHardwareSyscall();
        // Also try ro.hardware and ro.boot.hardware properties
        String propHw = ReflectionUtils.getSystemProperty("ro.hardware");
        String propBootHwFallback = ReflectionUtils.getSystemProperty("ro.boot.hardware");
        cpuHardware.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectHw, javaCpuHw, propHw, propBootHwFallback));
        cpuHardware.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeCpuHw, propHw, javaCpuHw));
        cpuHardware.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallCpuHw, propHw, javaCpuHw));
        items.add(cpuHardware);

        // SoC Serial - Try multiple paths
        FingerprintItem socSerial = new FingerprintItem("soc_serial", "SoC 序列号");
        String javaSocSerial = nonEmpty(
                ReflectionUtils.readFileFirstLine("/sys/devices/soc0/serial_number"),
                ReflectionUtils.readFileFirstLine("/sys/devices/system/soc/soc0/serial_number"));
        String nativeSocSerial = nativeDetector.readKernelFile("/sys/devices/soc0/serial_number");
        String syscallSocSerial = nativeDetector.readFileSyscall("/sys/devices/soc0/serial_number");
        socSerial.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaSocSerial, nativeSocSerial, "N/A"));
        socSerial.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeSocSerial, javaSocSerial, "N/A"));
        socSerial.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallSocSerial, javaSocSerial, "N/A"));
        items.add(socSerial);

        // SoC ID
        FingerprintItem socId = new FingerprintItem("soc_id", "SoC ID");
        String javaSocId = nonEmpty(
                ReflectionUtils.readFileFirstLine("/sys/devices/soc0/soc_id"),
                ReflectionUtils.getSystemProperty("ro.board.platform"));
        String nativeSocId = nativeDetector.readKernelFile("/sys/devices/soc0/soc_id");
        String syscallSocId = nativeDetector.readFileSyscall("/sys/devices/soc0/soc_id");
        socId.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaSocId, nativeSocId, "N/A"));
        socId.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeSocId, javaSocId, "N/A"));
        socId.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallSocId, javaSocId, "N/A"));
        items.add(socId);

        // ==================== Boot Parameters ====================

        // androidboot.serialno from /proc/cmdline - Multiple sources
        FingerprintItem bootSerial = new FingerprintItem("boot_serial", "Boot 序列号");
        String javaBootSerial = ReflectionUtils.getBootParam("androidboot.serialno");
        String propBootSerial = ReflectionUtils.getSystemProperty("ro.boot.serialno");
        String nativeBootSerial = nativeDetector.getBootParam("androidboot.serialno");
        String syscallBootSerial = nativeDetector.getBootParamSyscall("androidboot.serialno");
        // Additional fallbacks
        String roSerial = ReflectionUtils.getSystemProperty("ro.serialno");
        String gsSerial = ReflectionUtils.getSystemProperty("gsm.serial");
        bootSerial.setLayerValue(DetectionLayer.JAVA, nonEmpty(propBootSerial, javaBootSerial, roSerial, gsSerial, "N/A"));
        bootSerial.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeBootSerial, propBootSerial, roSerial, "N/A"));
        bootSerial.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallBootSerial, propBootSerial, roSerial, "N/A"));
        items.add(bootSerial);

        // androidboot.hardware - Multiple sources
        FingerprintItem bootHardware = new FingerprintItem("boot_hardware", "Boot 硬件");
        String javaBootHw = ReflectionUtils.getBootParam("androidboot.hardware");
        String propBootHw = ReflectionUtils.getSystemProperty("ro.boot.hardware");
        String nativeBootHw = nativeDetector.getBootParam("androidboot.hardware");
        String syscallBootHw = nativeDetector.getBootParamSyscall("androidboot.hardware");
        // Additional fallbacks
        String propHardware = ReflectionUtils.getSystemProperty("ro.hardware");
        String buildHardware = ReflectionUtils.getHardware();
        bootHardware.setLayerValue(DetectionLayer.JAVA, nonEmpty(propBootHw, javaBootHw, propHardware, buildHardware));
        bootHardware.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeBootHw, propBootHw, propHardware));
        bootHardware.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallBootHw, propBootHw, propHardware));
        items.add(bootHardware);

        // androidboot.bootdevice - Multiple sources
        FingerprintItem bootDevice = new FingerprintItem("boot_device", "Boot Device");
        String javaBootDev = ReflectionUtils.getBootParam("androidboot.bootdevice");
        String nativeBootDev = nativeDetector.getBootParam("androidboot.bootdevice");
        String syscallBootDev = nativeDetector.getBootParamSyscall("androidboot.bootdevice");
        // Additional fallbacks - try slot suffix and other boot params
        String slotSuffix = ReflectionUtils.getSystemProperty("ro.boot.slot_suffix");
        String bootSlot = ReflectionUtils.getBootParam("androidboot.slot_suffix");
        String verifiedBoot = ReflectionUtils.getSystemProperty("ro.boot.verifiedbootstate");
        bootDevice.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaBootDev, slotSuffix, bootSlot, verifiedBoot, "N/A"));
        bootDevice.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeBootDev, slotSuffix, "N/A"));
        bootDevice.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallBootDev, slotSuffix, "N/A"));
        items.add(bootDevice);

        // ==================== Additional System IDs ====================

        // DRM ID (Widevine) - Hardware-bound, difficult to tamper
        FingerprintItem drmId = new FingerprintItem("drm_id", "DRM ID (Widevine)");
        String javaDrmId = getWidevineDeviceId();
        drmId.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaDrmId, "N/A"));
        drmId.setLayerValue(DetectionLayer.NATIVE, nonEmpty(javaDrmId, "N/A")); // DRM只能通过Java API获取
        drmId.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(javaDrmId, "N/A"));
        items.add(drmId);

        // ro.boot.vbmeta.digest - Verified Boot metadata
        FingerprintItem vbmetaDigest = new FingerprintItem("vbmeta_digest", "VBMeta 摘要");
        String propVbmeta = ReflectionUtils.getSystemProperty("ro.boot.vbmeta.digest");
        String nativeVbmeta = nativeDetector.getBuildPropertyNative("ro.boot.vbmeta.digest");
        String syscallVbmeta = nativeDetector.getBuildPropertySyscall("ro.boot.vbmeta.digest");
        vbmetaDigest.setLayerValue(DetectionLayer.JAVA, nonEmpty(propVbmeta, nativeVbmeta, "N/A"));
        vbmetaDigest.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeVbmeta, propVbmeta, "N/A"));
        vbmetaDigest.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallVbmeta, propVbmeta, "N/A"));
        items.add(vbmetaDigest);

        // ro.build.id
        FingerprintItem buildId = new FingerprintItem("build_id", "Build ID");
        String reflectId = ReflectionUtils.getId();
        String propId = ReflectionUtils.getSystemProperty("ro.build.id");
        String nativeBuildId = nativeDetector.getBuildPropertyNative("ro.build.id");
        String syscallBuildId = nativeDetector.getBuildPropertySyscall("ro.build.id");
        buildId.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectId, propId));
        buildId.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeBuildId, propId));
        buildId.setLayerValue(DetectionLayer.SYSCALL, syscallBuildId);
        items.add(buildId);

        // ro.build.display.id
        FingerprintItem displayId = new FingerprintItem("display_id", "Display ID");
        String reflectDisplay = ReflectionUtils.getDisplay();
        String propDisplay = ReflectionUtils.getSystemProperty("ro.build.display.id");
        String nativeDisplayId = nativeDetector.getBuildPropertyNative("ro.build.display.id");
        String syscallDisplayId = nativeDetector.getBuildPropertySyscall("ro.build.display.id");
        displayId.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectDisplay, propDisplay));
        displayId.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeDisplayId, propDisplay));
        displayId.setLayerValue(DetectionLayer.SYSCALL, syscallDisplayId);
        items.add(displayId);

        // Bootloader version
        FingerprintItem bootloader = new FingerprintItem("bootloader", "Bootloader");
        String reflectBootloader = ReflectionUtils.getBootloader();
        String propBootloader = ReflectionUtils.getSystemProperty("ro.bootloader");
        String nativeBootloader = nativeDetector.getBuildPropertyNative("ro.bootloader");
        String syscallBootloader = nativeDetector.getBuildPropertySyscall("ro.bootloader");
        bootloader.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectBootloader, propBootloader));
        bootloader.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeBootloader, propBootloader));
        bootloader.setLayerValue(DetectionLayer.SYSCALL, syscallBootloader);
        items.add(bootloader);

        // Radio/Baseband version
        FingerprintItem radio = new FingerprintItem("radio", "基带版本");
        String reflectRadio = ReflectionUtils.getRadioVersion();
        String propRadio = ReflectionUtils.getSystemProperty("gsm.version.baseband");
        String nativeRadio = nativeDetector.getBuildPropertyNative("gsm.version.baseband");
        String syscallRadio = nativeDetector.getBuildPropertySyscall("gsm.version.baseband");
        radio.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectRadio, propRadio, "N/A"));
        radio.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeRadio, propRadio, "N/A"));
        radio.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallRadio, propRadio, "N/A"));
        items.add(radio);

        // ==================== Additional Identifiers ====================

        // Device code name
        FingerprintItem device = new FingerprintItem("device", "设备代号");
        String reflectDevice = ReflectionUtils.getDevice();
        String propDevice = ReflectionUtils.getSystemProperty("ro.product.device");
        String nativeDevice = nativeDetector.getBuildPropertyNative("ro.product.device");
        String syscallDevice = nativeDetector.getBuildPropertySyscall("ro.product.device");
        device.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectDevice, propDevice));
        device.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeDevice, propDevice));
        device.setLayerValue(DetectionLayer.SYSCALL, syscallDevice);
        items.add(device);

        // Board
        FingerprintItem board = new FingerprintItem("board", "主板");
        String reflectBoard = ReflectionUtils.getBoard();
        String propBoard = ReflectionUtils.getSystemProperty("ro.product.board");
        String nativeBoard = nativeDetector.getBuildPropertyNative("ro.product.board");
        String syscallBoard = nativeDetector.getBuildPropertySyscall("ro.product.board");
        board.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectBoard, propBoard));
        board.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeBoard, propBoard));
        board.setLayerValue(DetectionLayer.SYSCALL, syscallBoard);
        items.add(board);

        // ==================== Extended Identifiers ====================

        // Manufacturer (制造商)
        FingerprintItem manufacturer = new FingerprintItem("manufacturer", "制造商");
        String reflectManufacturer = ReflectionUtils.getManufacturer();
        String directManufacturer = Build.MANUFACTURER;
        String propManufacturer = ReflectionUtils.getSystemProperty("ro.product.manufacturer");
        String vendorManufacturer = ReflectionUtils.getSystemProperty("ro.product.vendor.manufacturer");
        String odmManufacturer = ReflectionUtils.getSystemProperty("ro.product.odm.manufacturer");
        String nativeManufacturer = nativeDetector.getBuildPropertyNative("ro.product.manufacturer");
        String syscallManufacturer = nonEmpty(nativeDetector.getBuildPropertySyscall("ro.product.manufacturer"),
                nativeDetector.getBuildPropertySyscall("ro.product.vendor.manufacturer"));
        String javaManufacturer = nonEmpty(reflectManufacturer, directManufacturer, propManufacturer, vendorManufacturer, odmManufacturer);
        manufacturer.setLayerValue(DetectionLayer.JAVA, javaManufacturer.isEmpty() ? "N/A" : javaManufacturer);
        manufacturer.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeManufacturer, propManufacturer).isEmpty() ? "N/A" : nonEmpty(nativeManufacturer, propManufacturer));
        manufacturer.setLayerValue(DetectionLayer.SYSCALL, syscallManufacturer.isEmpty() ? "N/A" : syscallManufacturer);
        items.add(manufacturer);

        // Product (产品名)
        FingerprintItem product = new FingerprintItem("product", "产品名");
        String reflectProduct = ReflectionUtils.getProduct();
        String directProduct = Build.PRODUCT;
        String propProduct = ReflectionUtils.getSystemProperty("ro.product.name");
        String vendorProduct = ReflectionUtils.getSystemProperty("ro.product.vendor.name");
        String odmProduct = ReflectionUtils.getSystemProperty("ro.product.odm.name");
        String nativeProduct = nativeDetector.getBuildPropertyNative("ro.product.name");
        String syscallProduct = nonEmpty(nativeDetector.getBuildPropertySyscall("ro.product.name"),
                nativeDetector.getBuildPropertySyscall("ro.product.vendor.name"));
        String javaProduct = nonEmpty(reflectProduct, directProduct, propProduct, vendorProduct, odmProduct);
        product.setLayerValue(DetectionLayer.JAVA, javaProduct.isEmpty() ? "N/A" : javaProduct);
        product.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeProduct, propProduct).isEmpty() ? "N/A" : nonEmpty(nativeProduct, propProduct));
        product.setLayerValue(DetectionLayer.SYSCALL, syscallProduct.isEmpty() ? "N/A" : syscallProduct);
        items.add(product);

        // Build Type (构建类型)
        FingerprintItem buildType = new FingerprintItem("build_type", "构建类型");
        String reflectType = ReflectionUtils.getBuildField("TYPE");
        String propType = ReflectionUtils.getSystemProperty("ro.build.type");
        String nativeType = nativeDetector.getBuildPropertyNative("ro.build.type");
        String syscallType = nativeDetector.getBuildPropertySyscall("ro.build.type");
        buildType.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectType, propType));
        buildType.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeType, propType));
        buildType.setLayerValue(DetectionLayer.SYSCALL, syscallType);
        items.add(buildType);

        // Build Tags (构建标签)
        FingerprintItem buildTags = new FingerprintItem("build_tags", "构建标签");
        String reflectTags = ReflectionUtils.getBuildField("TAGS");
        String propTags = ReflectionUtils.getSystemProperty("ro.build.tags");
        String nativeTags = nativeDetector.getBuildPropertyNative("ro.build.tags");
        String syscallTags = nativeDetector.getBuildPropertySyscall("ro.build.tags");
        buildTags.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectTags, propTags));
        buildTags.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeTags, propTags));
        buildTags.setLayerValue(DetectionLayer.SYSCALL, syscallTags);
        items.add(buildTags);

        // Android Version (Android 版本)
        FingerprintItem androidVersion = new FingerprintItem("android_version", "Android 版本");
        String reflectRelease = ReflectionUtils.getBuildVersionField("RELEASE");
        String propRelease = ReflectionUtils.getSystemProperty("ro.build.version.release");
        String nativeRelease = nativeDetector.getBuildPropertyNative("ro.build.version.release");
        String syscallRelease = nativeDetector.getBuildPropertySyscall("ro.build.version.release");
        androidVersion.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectRelease, propRelease));
        androidVersion.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeRelease, propRelease));
        androidVersion.setLayerValue(DetectionLayer.SYSCALL, syscallRelease);
        items.add(androidVersion);

        // SDK Level (API 级别)
        FingerprintItem sdkLevel = new FingerprintItem("sdk_level", "API 级别");
        String reflectSdk = ReflectionUtils.getBuildVersionField("SDK_INT");
        String propSdk = ReflectionUtils.getSystemProperty("ro.build.version.sdk");
        String nativeSdk = nativeDetector.getBuildPropertyNative("ro.build.version.sdk");
        String syscallSdk = nativeDetector.getBuildPropertySyscall("ro.build.version.sdk");
        sdkLevel.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectSdk, propSdk));
        sdkLevel.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeSdk, propSdk));
        sdkLevel.setLayerValue(DetectionLayer.SYSCALL, syscallSdk);
        items.add(sdkLevel);

        // Security Patch (安全补丁)
        FingerprintItem securityPatch = new FingerprintItem("security_patch", "安全补丁");
        String reflectPatch = ReflectionUtils.getBuildVersionField("SECURITY_PATCH");
        String propPatch = ReflectionUtils.getSystemProperty("ro.build.version.security_patch");
        String nativePatch = nativeDetector.getBuildPropertyNative("ro.build.version.security_patch");
        String syscallPatch = nativeDetector.getBuildPropertySyscall("ro.build.version.security_patch");
        securityPatch.setLayerValue(DetectionLayer.JAVA, nonEmpty(reflectPatch, propPatch));
        securityPatch.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativePatch, propPatch));
        securityPatch.setLayerValue(DetectionLayer.SYSCALL, syscallPatch);
        items.add(securityPatch);

        // MAC Address (MAC 地址)
        FingerprintItem macAddress = new FingerprintItem("mac_address", "MAC 地址");
        String javaMac = "";
        try {
            NetworkInterface wlan0 = NetworkInterface.getByName("wlan0");
            if (wlan0 != null) {
                byte[] macBytes = wlan0.getHardwareAddress();
                if (macBytes != null && macBytes.length > 0) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < macBytes.length; i++) {
                        sb.append(String.format("%02X", macBytes[i]));
                        if (i < macBytes.length - 1) sb.append(":");
                    }
                    javaMac = sb.toString();
                }
            }
        } catch (Exception e) {
            // NetworkInterface access may fail
        }
        String fileMac = ReflectionUtils.readFileFirstLine("/sys/class/net/wlan0/address");
        String nativeMac = nativeDetector.getMacAddressNative();
        String syscallMac = nativeDetector.getMacAddressSyscall();
        macAddress.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaMac, fileMac, "N/A"));
        macAddress.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeMac, fileMac, "N/A"));
        macAddress.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallMac, fileMac, "N/A"));
        items.add(macAddress);

        // Total RAM (总内存) - 统一为MB单位，各层数值可能有微小差异，四舍五入到最近的128MB
        FingerprintItem totalRam = new FingerprintItem("total_ram", "总内存");
        String javaTotalRam = "";
        try {
            ActivityManager am = (ActivityManager) requireContext().getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) {
                ActivityManager.MemoryInfo memInfo = new ActivityManager.MemoryInfo();
                am.getMemoryInfo(memInfo);
                long mb = memInfo.totalMem / (1024L * 1024L);
                // 四舍五入到128MB边界，消除各层微小差异
                mb = ((mb + 64) / 128) * 128;
                javaTotalRam = mb + " MB";
            }
        } catch (Exception e) {
            // ActivityManager access may fail
        }
        String nativeRam = nativeDetector.getTotalRamNative();
        String syscallRam = nativeDetector.getTotalRamSyscall();
        // Native/Syscall返回的也需要对齐到128MB
        nativeRam = roundRamValue(nativeRam);
        syscallRam = roundRamValue(syscallRam);
        totalRam.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaTotalRam, "N/A"));
        totalRam.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeRam, "N/A"));
        totalRam.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallRam, "N/A"));
        items.add(totalRam);

        // Screen Resolution (屏幕分辨率)
        FingerprintItem screenInfo = new FingerprintItem("screen_info", "屏幕分辨率");
        String javaScreen = "";
        try {
            DisplayMetrics dm = requireContext().getResources().getDisplayMetrics();
            javaScreen = dm.widthPixels + "x" + dm.heightPixels + "@" + dm.densityDpi;
        } catch (Exception e) {
            // DisplayMetrics access may fail
        }
        String nativeScreen = nativeDetector.getScreenInfoNative();
        String syscallScreen = nativeDetector.getScreenInfoSyscall();
        screenInfo.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaScreen, "N/A"));
        screenInfo.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeScreen, "N/A"));
        screenInfo.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallScreen, "N/A"));
        items.add(screenInfo);

        // CPU ABI (处理器架构) - 统一使用主ABI进行比对
        FingerprintItem cpuAbi = new FingerprintItem("cpu_abi", "处理器架构");
        String javaAbi = "";
        try {
            if (Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0) {
                javaAbi = Build.SUPPORTED_ABIS[0]; // 只取主ABI，与Native/Syscall一致
            }
        } catch (Exception e) {
            // SUPPORTED_ABIS access may fail
        }
        String propAbi = ReflectionUtils.getSystemProperty("ro.product.cpu.abi");
        String nativeAbi = nativeDetector.getCpuAbiNative();
        String syscallAbi = nativeDetector.getCpuAbiSyscall();
        cpuAbi.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaAbi, propAbi, "N/A"));
        cpuAbi.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeAbi, propAbi, "N/A"));
        cpuAbi.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallAbi, propAbi, "N/A"));
        items.add(cpuAbi);

        // Timezone (时区)
        FingerprintItem timezone = new FingerprintItem("timezone", "时区");
        String javaTimezone = TimeZone.getDefault().getID();
        String propTimezone = ReflectionUtils.getSystemProperty("persist.sys.timezone");
        String nativeTimezone = nativeDetector.getBuildPropertyNative("persist.sys.timezone");
        String syscallTimezone = nativeDetector.getBuildPropertySyscall("persist.sys.timezone");
        timezone.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaTimezone, propTimezone));
        timezone.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeTimezone, propTimezone));
        timezone.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallTimezone, propTimezone));
        items.add(timezone);

        // Language (系统语言)
        FingerprintItem language = new FingerprintItem("language", "系统语言");
        String javaLanguage = Locale.getDefault().toString();
        String propLang = ReflectionUtils.getSystemProperty("persist.sys.language");
        String propCountry = ReflectionUtils.getSystemProperty("persist.sys.country");
        String propLangFull = nonEmpty(propLang).isEmpty() ? "" : propLang + "_" + nonEmpty(propCountry);
        String nativeLanguage = nativeDetector.getBuildPropertyNative("persist.sys.language");
        String syscallLanguage = nativeDetector.getBuildPropertySyscall("persist.sys.language");
        language.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaLanguage, propLangFull));
        language.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeLanguage, propLang));
        language.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallLanguage, propLang));
        items.add(language);

        // Total Storage (存储容量)
        FingerprintItem totalStorage = new FingerprintItem("total_storage", "存储容量");
        String javaStorage = "";
        try {
            StatFs statFs = new StatFs(android.os.Environment.getDataDirectory().getPath());
            long totalBytes = statFs.getTotalBytes();
            javaStorage = (totalBytes / (1024L * 1024L * 1024L)) + " GB";
        } catch (Exception e) {
            // StatFs access may fail
        }
        String nativeStorage = nativeDetector.getTotalStorageNative();
        String syscallStorage = nativeDetector.getTotalStorageSyscall();
        totalStorage.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaStorage, "N/A"));
        totalStorage.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeStorage, "N/A"));
        totalStorage.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallStorage, "N/A"));
        items.add(totalStorage);

        // Uname Info (内核架构信息)
        FingerprintItem unameInfo = new FingerprintItem("uname_info", "内核架构信息");
        String javaUname = nonEmpty(System.getProperty("os.arch")) + " " + nonEmpty(System.getProperty("os.name"));
        String nativeUname = nativeDetector.getUnameInfoNative();
        String syscallUname = nativeDetector.getUnameInfoSyscall();
        unameInfo.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaUname.trim()));
        unameInfo.setLayerValue(DetectionLayer.NATIVE, nonEmpty(nativeUname, javaUname.trim()));
        unameInfo.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallUname, javaUname.trim()));
        items.add(unameInfo);

        // GSF ID (Google Services Framework ID)
        FingerprintItem gsfId = new FingerprintItem("gsf_id", "GSF ID");
        String javaGsfId = "";
        try {
            Uri gsfUri = Uri.parse("content://com.google.android.gsf.gservices");
            Cursor cursor = requireContext().getContentResolver().query(gsfUri, null, null, new String[]{"android_id"}, null);
            if (cursor != null) {
                if (cursor.moveToFirst() && cursor.getColumnCount() >= 2) {
                    javaGsfId = cursor.getString(1);
                }
                cursor.close();
            }
        } catch (Exception e) {
            // GMS may not be installed
        }
        gsfId.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaGsfId, "N/A"));
        gsfId.setLayerValue(DetectionLayer.NATIVE, nonEmpty(javaGsfId, "N/A"));
        gsfId.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(javaGsfId, "N/A"));
        items.add(gsfId);

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

        result.calculateTrustLevel();
        result.generateCompositeFingerprint();

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
        // Only run persistent logic when we have read permission.
        // Without it, we can't distinguish "new device" from "reinstall but can't read yet".
        String persistentToken = "";
        String persistentStatus = "等待权限";
        try {
            Context ctx = requireContext();
            boolean canRead = hasReadPermission();
            String currentHwHash = result.getHardwareHash();

            if (canRead && PersistentFingerprint.exists(ctx)) {
                // Found old fingerprint — load and compare
                PersistentFingerprint.PersistentData pData =
                        PersistentFingerprint.load(ctx, currentHwHash);
                if (pData != null) {
                    persistentToken = pData.token;
                    if (pData.deviceChanged) {
                        persistentStatus = "设备已变更";
                        result.setPersistentPenalty(15);
                        result.calculateTrustLevel();
                    } else {
                        persistentStatus = "设备未变更";
                    }
                    // Update with current hash
                    PersistentFingerprint.save(ctx, pData.token, currentHwHash);
                }
            } else if (canRead) {
                // Have permission but no file — truly new device
                persistentToken = PersistentFingerprint.generateToken();
                PersistentFingerprint.save(ctx, persistentToken, currentHwHash);
                persistentStatus = "新设备 (首次记录)";
            }
            // else: no permission yet — show "等待权限", don't write anything
        } catch (Exception e) {
            persistentToken = "N/A";
            persistentStatus = "无存储权限";
        }

        // Add persistent token as a fingerprint item for display
        FingerprintItem persistItem = new FingerprintItem("persistent_token", "持久化 Token");
        persistItem.setLayerValue(DetectionLayer.JAVA, nonEmpty(persistentToken, "N/A"));
        persistItem.setLayerValue(DetectionLayer.NATIVE, nonEmpty(persistentStatus));
        persistItem.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(persistentToken, "N/A"));
        // Token is same across layers by definition — mark consistent
        items.add(persistItem);

        // Re-set items to include persistent token
        result.setItems(items);

        return result;
    }

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
            // Truncate at 3rd colon: "u:r:untrusted_app:s0:c512" -> "u:r:untrusted_app"
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

    /**
     * Request MANAGE_EXTERNAL_STORAGE permission for persistent fingerprint.
     * On Android 11+, this opens the system settings page for the user to grant.
     */
    private static final int PERM_REQUEST_CODE = 1001;

    /**
     * Check if we have read permission for MediaStore (needed to recover fingerprint after reinstall).
     */
    private boolean hasReadPermission() {
        if (Build.VERSION.SDK_INT >= 33) {
            return requireContext().checkSelfPermission("android.permission.READ_MEDIA_IMAGES")
                    == android.content.pm.PackageManager.PERMISSION_GRANTED;
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return requireContext().checkSelfPermission("android.permission.READ_EXTERNAL_STORAGE")
                    == android.content.pm.PackageManager.PERMISSION_GRANTED;
        }
        return true; // Android 9: requestLegacyExternalStorage handles it
    }

    /**
     * Request read permission for persistent fingerprint recovery after reinstall.
     * MediaStore write needs NO permission. Read after reinstall needs:
     *   Android 13+: READ_MEDIA_IMAGES (runtime dialog)
     *   Android 10-12: READ_EXTERNAL_STORAGE (runtime dialog)
     *   Android 9: requestLegacyExternalStorage=true (manifest, no dialog)
     */
    private void requestStoragePermissionIfNeeded() {
        String permission;
        if (Build.VERSION.SDK_INT >= 33) {
            permission = "android.permission.READ_MEDIA_IMAGES";
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            permission = "android.permission.READ_EXTERNAL_STORAGE";
        } else {
            return;
        }
        requestPermissions(new String[]{permission}, PERM_REQUEST_CODE);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERM_REQUEST_CODE && grantResults.length > 0
                && grantResults[0] == android.content.pm.PackageManager.PERMISSION_GRANTED) {
            // Permission granted — re-collect to recover persistent fingerprint
            collectFingerprints();
        }
    }

    /**
     * Round RAM value string (e.g. "7890 MB") to nearest 128MB boundary for cross-layer consistency.
     * sysconf, /proc/meminfo and ActivityManager report slightly different totals.
     */
    private String roundRamValue(String raw) {
        if (raw == null || raw.isEmpty()) return "";
        try {
            // Extract numeric part - Native returns "XXXX MB"
            String num = raw.replaceAll("[^0-9]", "");
            if (num.isEmpty()) return raw;
            long mb = Long.parseLong(num);
            mb = ((mb + 64) / 128) * 128;
            return mb + " MB";
        } catch (NumberFormatException e) {
            return raw;
        }
    }

    /**
     * Helper method to get first non-empty value
     */
    private String nonEmpty(String... values) {
        for (String value : values) {
            if (value != null && !value.isEmpty() && !value.equals("unknown") && !value.equals("Unknown")) {
                return value;
            }
        }
        return "";
    }

    /**
     * Get Widevine DRM Device ID
     * DRM ID is hardware-bound and very difficult to tamper with
     *
     * @return Base64-encoded device unique ID, or empty string if unavailable
     */
    private String getWidevineDeviceId() {
        // Widevine UUID - standard identifier for Widevine DRM
        final UUID WIDEVINE_UUID = new UUID(0xEDEF8BA979D64ACEL, 0xA3C827DCD51D21EDL);

        MediaDrm mediaDrm = null;
        try {
            mediaDrm = new MediaDrm(WIDEVINE_UUID);
            byte[] deviceId = mediaDrm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID);
            if (deviceId != null && deviceId.length > 0) {
                return Base64.encodeToString(deviceId, Base64.NO_WRAP);
            }
        } catch (UnsupportedSchemeException e) {
            // Widevine not supported on this device
        } catch (Exception e) {
            // Other errors (security exception, etc.)
        } finally {
            if (mediaDrm != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    mediaDrm.close();
                } else {
                    mediaDrm.release();
                }
            }
        }
        return "";
    }

    private void updateUI(FingerprintResult result) {
        // Update composite fingerprint
        String compositeFp = result.getCompositeFingerprint();
        tvDeviceFingerprint.setText(compositeFp != null ? compositeFp.substring(0, Math.min(32, compositeFp.length())) : "");

        // Update trust level
        int trustLevel = result.getTrustLevel();
        tvTrustLevel.setText(trustLevel + "%");
        progressTrust.setProgress(trustLevel);

        // Update tampering status (M3 dot + progress indicator)
        if (result.isTamperingDetected()) {
            tvTamperingStatus.setText(R.string.tampering_detected);
            tvTamperingStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_risk));
            ivStatusIcon.setBackgroundTintList(ColorStateList.valueOf(ContextCompat.getColor(requireContext(), R.color.status_risk)));
            tvTrustLevel.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_risk));
            progressTrust.setIndicatorColor(ContextCompat.getColor(requireContext(), R.color.status_risk));
        } else {
            tvTamperingStatus.setText(R.string.no_tampering);
            tvTamperingStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_safe));
            ivStatusIcon.setBackgroundTintList(ColorStateList.valueOf(ContextCompat.getColor(requireContext(), R.color.status_safe)));
            tvTrustLevel.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_safe));
            progressTrust.setIndicatorColor(ContextCompat.getColor(requireContext(), R.color.status_safe));
        }

        // Update hashes
        tvHardwareHash.setText("SHA256: " + abbreviate(result.getHardwareHash(), 24));
        tvSoftwareHash.setText("SHA256: " + abbreviate(result.getSoftwareHash(), 24));
        tvBuildFingerprint.setText(Build.FINGERPRINT);

        // Update recycler views with adapters
        FingerprintItemAdapter identifierAdapter = new FingerprintItemAdapter(requireContext());
        identifierAdapter.setItems(result.getItems());
        recyclerIdentifiers.setAdapter(identifierAdapter);

        ComparisonAdapter comparisonAdapter = new ComparisonAdapter();
        comparisonAdapter.setItems(result.getItems());
        recyclerComparison.setAdapter(comparisonAdapter);
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private String abbreviate(String text, int maxLength) {
        if (text == null) return "";
        if (text.length() <= maxLength) return text;
        return text.substring(0, maxLength) + "...";
    }

    private void copyToClipboard(String label, String text) {
        ClipboardManager clipboard = (ClipboardManager) requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText(label, text);
        clipboard.setPrimaryClip(clip);
        Toast.makeText(requireContext(), R.string.copied, Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        if (executor != null) {
            executor.shutdown();
            executor = null;
        }
    }

    // Inner adapter classes
    private static class FingerprintItemAdapter extends RecyclerView.Adapter<FingerprintItemAdapter.ViewHolder> {
        private List<FingerprintItem> items = new ArrayList<>();
        private final Context context;

        FingerprintItemAdapter(Context context) {
            this.context = context;
        }

        void setItems(List<FingerprintItem> items) {
            this.items = items;
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_fingerprint, parent, false);
            return new ViewHolder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            FingerprintItem item = items.get(position);
            holder.tvName.setText(item.getDisplayName());
            holder.tvValue.setText(item.getPrimaryValue());

            String javaVal = item.getAbbreviatedValue(DetectionLayer.JAVA, 8);
            String nativeVal = item.getAbbreviatedValue(DetectionLayer.NATIVE, 8);
            holder.tvJavaValue.setText("Java: " + javaVal);
            holder.tvNativeValue.setText("Native: " + nativeVal);

            if (item.isConsistent()) {
                holder.ivConsistency.setBackgroundTintList(ColorStateList.valueOf(
                        ContextCompat.getColor(context, R.color.status_safe)));
                holder.tvConsistency.setText("一致");
                holder.tvConsistency.setTextColor(ContextCompat.getColor(context, R.color.status_safe));
            } else {
                holder.ivConsistency.setBackgroundTintList(ColorStateList.valueOf(
                        ContextCompat.getColor(context, R.color.status_risk)));
                holder.tvConsistency.setText("不一致");
                holder.tvConsistency.setTextColor(ContextCompat.getColor(context, R.color.status_risk));
            }

            holder.btnCopy.setOnClickListener(v -> {
                ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = ClipData.newPlainText(item.getDisplayName(), item.getPrimaryValue());
                clipboard.setPrimaryClip(clip);
                Toast.makeText(context, R.string.copied, Toast.LENGTH_SHORT).show();
            });
        }

        @Override
        public int getItemCount() {
            return items.size();
        }

        static class ViewHolder extends RecyclerView.ViewHolder {
            TextView tvName, tvValue, tvJavaValue, tvNativeValue, tvConsistency;
            View ivConsistency;
            View btnCopy;

            ViewHolder(@NonNull View itemView) {
                super(itemView);
                tvName = itemView.findViewById(R.id.tv_name);
                tvValue = itemView.findViewById(R.id.tv_value);
                tvJavaValue = itemView.findViewById(R.id.tv_java_value);
                tvNativeValue = itemView.findViewById(R.id.tv_native_value);
                tvConsistency = itemView.findViewById(R.id.tv_consistency);
                ivConsistency = itemView.findViewById(R.id.iv_consistency);
                btnCopy = itemView.findViewById(R.id.btn_copy);
            }
        }
    }

    private static class ComparisonAdapter extends RecyclerView.Adapter<ComparisonAdapter.ViewHolder> {
        private List<FingerprintItem> items = new ArrayList<>();

        void setItems(List<FingerprintItem> items) {
            this.items = items;
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_comparison, parent, false);
            return new ViewHolder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            FingerprintItem item = items.get(position);
            holder.tvName.setText(item.getDisplayName());
            holder.tvJava.setText(item.getAbbreviatedValue(DetectionLayer.JAVA, 6));
            holder.tvNative.setText(item.getAbbreviatedValue(DetectionLayer.NATIVE, 6));
            holder.tvSyscall.setText(item.getAbbreviatedValue(DetectionLayer.SYSCALL, 6));

            if (item.isConsistent()) {
                holder.ivStatus.setBackgroundTintList(ColorStateList.valueOf(
                        ContextCompat.getColor(holder.itemView.getContext(), R.color.status_safe)));
            } else {
                holder.ivStatus.setBackgroundTintList(ColorStateList.valueOf(
                        ContextCompat.getColor(holder.itemView.getContext(), R.color.status_risk)));
            }
        }

        @Override
        public int getItemCount() {
            return items.size();
        }

        static class ViewHolder extends RecyclerView.ViewHolder {
            TextView tvName, tvJava, tvNative, tvSyscall;
            View ivStatus;

            ViewHolder(@NonNull View itemView) {
                super(itemView);
                tvName = itemView.findViewById(R.id.tv_name);
                tvJava = itemView.findViewById(R.id.tv_java);
                tvNative = itemView.findViewById(R.id.tv_native);
                tvSyscall = itemView.findViewById(R.id.tv_syscall);
                ivStatus = itemView.findViewById(R.id.iv_status);
            }
        }
    }
}
