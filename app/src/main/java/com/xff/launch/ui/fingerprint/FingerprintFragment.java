package com.xff.launch.ui.fingerprint;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.ProgressBar;
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
import com.xff.launch.util.ReflectionUtils;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
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
    private ImageView ivStatusIcon;
    private ProgressBar progressTrust;
    private TextView tvHardwareHash;
    private TextView tvSoftwareHash;
    private TextView tvBuildFingerprint;
    private RecyclerView recyclerIdentifiers;
    private RecyclerView recyclerComparison;

    private ImageButton btnCopyFingerprint;
    private ImageButton btnCopyHwHash;
    private ImageButton btnCopySwHash;
    private ImageButton btnCopyBuildFp;

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
        collectFingerprints();
    }

    private void initViews(View view) {
        swipeRefresh = view.findViewById(R.id.swipe_refresh);
        tvDeviceFingerprint = view.findViewById(R.id.tv_device_fingerprint);
        tvTrustLevel = view.findViewById(R.id.tv_trust_level);
        tvTamperingStatus = view.findViewById(R.id.tv_tampering_status);
        ivStatusIcon = view.findViewById(R.id.iv_status_icon);
        progressTrust = view.findViewById(R.id.progress_trust);
        tvHardwareHash = view.findViewById(R.id.tv_hardware_hash);
        tvSoftwareHash = view.findViewById(R.id.tv_software_hash);
        tvBuildFingerprint = view.findViewById(R.id.tv_build_fingerprint);
        recyclerIdentifiers = view.findViewById(R.id.recycler_identifiers);
        recyclerComparison = view.findViewById(R.id.recycler_comparison);

        btnCopyFingerprint = view.findViewById(R.id.btn_copy_fingerprint);
        btnCopyHwHash = view.findViewById(R.id.btn_copy_hw_hash);
        btnCopySwHash = view.findViewById(R.id.btn_copy_sw_hash);
        btnCopyBuildFp = view.findViewById(R.id.btn_copy_build_fp);

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

            if (getActivity() != null) {
                getActivity().runOnUiThread(() -> {
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

        // Random UUID (changes each read)
        FingerprintItem randomUuid = new FingerprintItem("random_uuid", "Random UUID");
        String javaUuid = ReflectionUtils.readFileFirstLine("/proc/sys/kernel/random/uuid");
        String nativeUuid = nativeDetector.readKernelFile("/proc/sys/kernel/random/uuid");
        String syscallUuid = nativeDetector.readFileSyscall("/proc/sys/kernel/random/uuid");
        randomUuid.setLayerValue(DetectionLayer.JAVA, nonEmpty(javaUuid, nativeUuid));
        randomUuid.setLayerValue(DetectionLayer.NATIVE, nativeUuid);
        randomUuid.setLayerValue(DetectionLayer.SYSCALL, nonEmpty(syscallUuid, javaUuid));
        items.add(randomUuid);

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

        result.setItems(items);
        result.calculateTrustLevel();
        result.generateCompositeFingerprint();

        // Generate hardware and software hashes using reflection values
        String hwString = nonEmpty(reflectBrand) + nonEmpty(reflectModel) + nonEmpty(reflectDevice) +
                nonEmpty(reflectHw) + nonEmpty(reflectBoard) + nonEmpty(nativeCpuSerial, javaCpuSerial) +
                nonEmpty(nativeSocSerial, javaSocSerial) + nonEmpty(nativeBootSerial, javaBootSerial);
        result.setHardwareHash(sha256(hwString));

        String swString = nonEmpty(reflectFp) + nonEmpty(reflectId) +
                ReflectionUtils.getBuildVersionField("RELEASE") +
                ReflectionUtils.getBuildVersionField("SDK_INT") +
                nonEmpty(nativeBootId, javaBootId) + nonEmpty(nativeVbmeta, propVbmeta) +
                nonEmpty(reflectBootloader);
        result.setSoftwareHash(sha256(swString));

        return result;
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

    private void updateUI(FingerprintResult result) {
        // Update composite fingerprint
        String compositeFp = result.getCompositeFingerprint();
        tvDeviceFingerprint.setText(compositeFp != null ? compositeFp.substring(0, Math.min(32, compositeFp.length())) : "");

        // Update trust level
        int trustLevel = result.getTrustLevel();
        tvTrustLevel.setText(trustLevel + "%");
        progressTrust.setProgress(trustLevel);

        // Update tampering status
        if (result.isTamperingDetected()) {
            tvTamperingStatus.setText(R.string.tampering_detected);
            tvTamperingStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_risk));
            ivStatusIcon.setImageResource(R.drawable.ic_status_risk);
            tvTrustLevel.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_risk));
            progressTrust.setProgressTintList(ContextCompat.getColorStateList(requireContext(), R.color.status_risk));
        } else {
            tvTamperingStatus.setText(R.string.no_tampering);
            tvTamperingStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_safe));
            ivStatusIcon.setImageResource(R.drawable.ic_status_safe);
            tvTrustLevel.setTextColor(ContextCompat.getColor(requireContext(), R.color.status_safe));
            progressTrust.setProgressTintList(ContextCompat.getColorStateList(requireContext(), R.color.status_safe));
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
                holder.ivConsistency.setImageResource(R.drawable.ic_status_safe);
                holder.tvConsistency.setText("一致");
                holder.tvConsistency.setTextColor(ContextCompat.getColor(context, R.color.status_safe));
            } else {
                holder.ivConsistency.setImageResource(R.drawable.ic_status_risk);
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
            ImageView ivConsistency;
            ImageButton btnCopy;

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
                holder.ivStatus.setImageResource(R.drawable.ic_status_safe);
            } else {
                holder.ivStatus.setImageResource(R.drawable.ic_status_risk);
            }
        }

        @Override
        public int getItemCount() {
            return items.size();
        }

        static class ViewHolder extends RecyclerView.ViewHolder {
            TextView tvName, tvJava, tvNative, tvSyscall;
            ImageView ivStatus;

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
