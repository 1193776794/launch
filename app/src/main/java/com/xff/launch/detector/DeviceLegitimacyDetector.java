package com.xff.launch.detector;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

import com.xff.launch.model.DeviceInfo;
import com.xff.launch.model.DeviceLegitimacyResult;
import com.xff.launch.model.VendorDatabase;
import com.xff.launch.model.VendorProfile;
import com.xff.launch.model.VendorService;
import com.xff.launch.util.ReflectionUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Device legitimacy detector that verifies device authenticity
 * by checking vendor services, ROM features, and system consistency
 */
public class DeviceLegitimacyDetector {
    private final Context context;
    private final NativeDetector nativeDetector;
    private final VendorDatabase vendorDatabase;
    private VendorProfile detectedVendor;

    public DeviceLegitimacyDetector(Context context) {
        this.context = context;
        this.nativeDetector = NativeDetector.getInstance();
        this.vendorDatabase = VendorDatabase.getInstance();
    }

    /**
     * Detect the device vendor based on Build properties
     */
    public VendorProfile detectVendor() {
        String brand = Build.BRAND;
        String manufacturer = Build.MANUFACTURER;
        detectedVendor = vendorDatabase.findVendor(brand, manufacturer);
        return detectedVendor;
    }

    /**
     * Perform comprehensive legitimacy check
     */
    public DeviceLegitimacyResult checkLegitimacy(DeviceInfo info) {
        DeviceLegitimacyResult result = new DeviceLegitimacyResult();
        result.setDeviceInfo(info);

        // Detect vendor first
        detectedVendor = vendorDatabase.findVendor(info.getBrand(), info.getManufacturer());

        // Perform all checks
        result.setBuildConsistent(checkBuildConsistency(info));
        result.setRomMatched(checkRomMatch(info));
        result.setHardwareConsistent(checkHardwareConsistency(info));
        result.setFingerprintFormatValid(checkFingerprintFormat(info));

        // Check vendor services
        List<VendorService> services = checkVendorServices(info);
        result.setVendorServices(services);

        // Calculate service match status
        int totalExpected = 0;
        int matchedExpected = 0;
        for (VendorService service : services) {
            if (service.isExpected()) {
                totalExpected++;
                if (service.isInstalled()) {
                    matchedExpected++;
                }
            }
        }
        // Service is matched if at least 50% of expected services are present
        result.setServiceMatched(totalExpected == 0 || matchedExpected >= totalExpected / 2);

        result.calculateScore();
        return result;
    }

    /**
     * Check Build property consistency between Java and Native layers
     */
    private boolean checkBuildConsistency(DeviceInfo info) {
        boolean consistent = true;
        List<String> inconsistencies = new ArrayList<>();

        // Check MODEL consistency
        String javaModel = Build.MODEL;
        String nativeModel = nativeDetector.getBuildPropertyNative("ro.product.model");
        String syscallModel = nativeDetector.getBuildPropertySyscall("ro.product.model");
        if (!isEmpty(nativeModel) && !javaModel.equals(nativeModel)) {
            consistent = false;
            inconsistencies.add("MODEL: Java=" + javaModel + " vs Native=" + nativeModel);
        }

        // Check BRAND consistency
        String javaBrand = Build.BRAND;
        String nativeBrand = nativeDetector.getBuildPropertyNative("ro.product.brand");
        if (!isEmpty(nativeBrand) && !javaBrand.equalsIgnoreCase(nativeBrand)) {
            consistent = false;
            inconsistencies.add("BRAND: Java=" + javaBrand + " vs Native=" + nativeBrand);
        }

        // Check DEVICE consistency
        String javaDevice = Build.DEVICE;
        String nativeDevice = nativeDetector.getBuildPropertyNative("ro.product.device");
        if (!isEmpty(nativeDevice) && !javaDevice.equals(nativeDevice)) {
            consistent = false;
            inconsistencies.add("DEVICE: Java=" + javaDevice + " vs Native=" + nativeDevice);
        }

        // Check FINGERPRINT consistency
        String javaFp = Build.FINGERPRINT;
        String nativeFp = nativeDetector.getBuildPropertyNative("ro.build.fingerprint");
        if (!isEmpty(nativeFp) && !javaFp.equals(nativeFp)) {
            consistent = false;
            inconsistencies.add("FINGERPRINT mismatch");
        }

        // Check via reflection
        String reflectModel = ReflectionUtils.getModel();
        if (!isEmpty(reflectModel) && !javaModel.equals(reflectModel)) {
            consistent = false;
            inconsistencies.add("Reflection MODEL mismatch");
        }

        return consistent;
    }

    /**
     * Check if ROM matches the detected vendor
     */
    private boolean checkRomMatch(DeviceInfo info) {
        if (detectedVendor == null) {
            // Unknown vendor, can't verify ROM
            return true;
        }

        String romVersion = info.getRomVersion();
        if (romVersion == null || romVersion.isEmpty()) {
            return false;
        }

        // Check if ROM version properties exist for this vendor
        for (String property : detectedVendor.getRomVersionProperties()) {
            String value = nativeDetector.getBuildPropertyNative(property);
            if (!isEmpty(value)) {
                return true;
            }
        }

        // Check ROM name match
        String romName = detectedVendor.getRomName();
        if (romName != null && !romName.isEmpty()) {
            String lowerRom = romVersion.toLowerCase();
            String[] romParts = romName.toLowerCase().split("/");
            for (String part : romParts) {
                if (lowerRom.contains(part.trim())) {
                    return true;
                }
            }
        }

        // For generic Android, always pass
        if (romVersion.toLowerCase().startsWith("android")) {
            return true;
        }

        return false;
    }

    /**
     * Check vendor-specific services
     */
    private List<VendorService> checkVendorServices(DeviceInfo info) {
        List<VendorService> services = new ArrayList<>();
        PackageManager pm = context.getPackageManager();
        String brand = info.getBrand().toLowerCase();

        // Add vendor-specific required packages
        if (detectedVendor != null) {
            for (String pkg : detectedVendor.getRequiredPackages()) {
                String serviceName = getServiceDisplayName(pkg);
                VendorService service = new VendorService(serviceName, pkg, detectedVendor.getVendorId());
                service.setExpected(true);
                service.setInstalled(isPackageInstalled(pm, pkg));
                services.add(service);
            }

            // Add vendor-specific optional packages (sample a few)
            List<String> optionalPkgs = detectedVendor.getOptionalPackages();
            int maxOptional = Math.min(5, optionalPkgs.size());
            for (int i = 0; i < maxOptional; i++) {
                String pkg = optionalPkgs.get(i);
                String serviceName = getServiceDisplayName(pkg);
                VendorService service = new VendorService(serviceName, pkg, detectedVendor.getVendorId());
                service.setExpected(true);
                service.setInstalled(isPackageInstalled(pm, pkg));
                services.add(service);
            }
        }

        // Common vendor services check
        addCommonVendorServices(services, pm, brand);

        return services;
    }

    private void addCommonVendorServices(List<VendorService> services, PackageManager pm, String brand) {
        // Google Play Services (expected on most devices except Huawei)
        boolean expectGms = detectedVendor == null || detectedVendor.hasGms();
        VendorService gmsService = new VendorService("GMS 服务", "com.google.android.gms", "google");
        gmsService.setExpected(expectGms);
        gmsService.setInstalled(isPackageInstalled(pm, "com.google.android.gms"));
        services.add(gmsService);

        // Google Play Store
        VendorService playStore = new VendorService("Play 商店", "com.android.vending", "google");
        playStore.setExpected(expectGms);
        playStore.setInstalled(isPackageInstalled(pm, "com.android.vending"));
        services.add(playStore);

        // Xiaomi specific
        if (brand.contains("xiaomi") || brand.contains("redmi") || brand.contains("poco")) {
            addServiceIfNotExists(services, pm, "小米服务框架", "com.xiaomi.xmsf", "xiaomi", true);
            addServiceIfNotExists(services, pm, "小米账户", "com.xiaomi.account", "xiaomi", true);
        }

        // Huawei specific
        if (brand.contains("huawei")) {
            addServiceIfNotExists(services, pm, "HMS Core", "com.huawei.hms.core", "huawei", true);
            addServiceIfNotExists(services, pm, "华为应用市场", "com.huawei.appmarket", "huawei", true);
        }

        // Honor specific
        if (brand.contains("honor")) {
            addServiceIfNotExists(services, pm, "荣耀账号", "com.hihonor.id", "honor", true);
        }

        // OPPO specific
        if (brand.contains("oppo")) {
            addServiceIfNotExists(services, pm, "OPPO 推送", "com.heytap.msp", "oppo", true);
            addServiceIfNotExists(services, pm, "ColorOS 安全", "com.coloros.safecenter", "oppo", true);
        }

        // vivo specific
        if (brand.contains("vivo") || brand.contains("iqoo")) {
            addServiceIfNotExists(services, pm, "vivo 推送", "com.vivo.pushservice", "vivo", true);
            addServiceIfNotExists(services, pm, "vivo 应用商店", "com.vivo.appstore", "vivo", true);
        }

        // Samsung specific
        if (brand.contains("samsung")) {
            addServiceIfNotExists(services, pm, "三星账户", "com.samsung.android.mobileservice", "samsung", true);
            addServiceIfNotExists(services, pm, "三星 Knox", "com.samsung.android.knox.containercore", "samsung", false);
        }
    }

    private void addServiceIfNotExists(List<VendorService> services, PackageManager pm,
                                       String name, String packageName, String vendor, boolean expected) {
        // Check if already exists
        for (VendorService s : services) {
            if (s.getPackageName().equals(packageName)) {
                return;
            }
        }
        VendorService service = new VendorService(name, packageName, vendor);
        service.setExpected(expected);
        service.setInstalled(isPackageInstalled(pm, packageName));
        services.add(service);
    }

    /**
     * Check hardware consistency
     */
    private boolean checkHardwareConsistency(DeviceInfo info) {
        boolean consistent = true;

        // Basic sanity checks
        if (info.getCpuCores() < 1 || info.getCpuCores() > 32) {
            consistent = false;
        }

        if (info.getTotalMemory() < 512 * 1024 * 1024L) { // Less than 512MB
            consistent = false;
        }

        if (info.getSensorCount() < 3) { // Most real devices have at least 3 sensors
            consistent = false;
        }

        // Check if hardware matches Build.HARDWARE
        String nativeHw = nativeDetector.getBuildPropertyNative("ro.hardware");
        if (!isEmpty(nativeHw) && !isEmpty(info.getHardware())) {
            if (!info.getHardware().equalsIgnoreCase(nativeHw)) {
                consistent = false;
            }
        }

        return consistent;
    }

    /**
     * Check fingerprint format validity
     */
    private boolean checkFingerprintFormat(DeviceInfo info) {
        String fp = info.getBuildFingerprint();
        if (fp == null || fp.isEmpty()) {
            return false;
        }

        // Standard format: brand/product/device:version/id/incremental:type/tags
        // Should contain at least: brand/product/device:version
        if (!fp.contains("/") || !fp.contains(":")) {
            return false;
        }

        String[] parts = fp.split("/");
        if (parts.length < 3) {
            return false;
        }

        // Check if brand in fingerprint matches Build.BRAND
        String fpBrand = parts[0];
        String buildBrand = Build.BRAND;
        if (!fpBrand.equalsIgnoreCase(buildBrand)) {
            // Might be modified
            return false;
        }

        // Check if fingerprint contains expected vendor patterns
        if (detectedVendor != null) {
            return detectedVendor.matchesFingerprint(fp);
        }

        return true;
    }

    /**
     * Get display name for a package
     */
    private String getServiceDisplayName(String packageName) {
        // Extract a readable name from package name
        String[] parts = packageName.split("\\.");
        if (parts.length >= 2) {
            String last = parts[parts.length - 1];
            // Capitalize first letter
            return last.substring(0, 1).toUpperCase() + last.substring(1);
        }
        return packageName;
    }

    /**
     * Check if a package is installed
     */
    private boolean isPackageInstalled(PackageManager pm, String packageName) {
        try {
            pm.getPackageInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private boolean isEmpty(String str) {
        return str == null || str.isEmpty() || str.equals("unknown");
    }

    /**
     * Get the detected vendor profile
     */
    public VendorProfile getDetectedVendor() {
        return detectedVendor;
    }

    /**
     * Get ROM features for the detected vendor
     */
    public List<RomFeature> getRomFeatures() {
        List<RomFeature> features = new ArrayList<>();

        if (detectedVendor == null) {
            return features;
        }

        // Check ROM version properties
        for (String property : detectedVendor.getRomVersionProperties()) {
            String value = nativeDetector.getBuildPropertyNative(property);
            boolean hasValue = !isEmpty(value);
            features.add(new RomFeature(property, value, hasValue));
        }

        // Check system properties
        for (String property : detectedVendor.getSystemProperties()) {
            String value = nativeDetector.getBuildPropertyNative(property);
            boolean hasValue = !isEmpty(value);
            features.add(new RomFeature(property, value, hasValue));
        }

        return features;
    }

    /**
     * ROM feature check result
     */
    public static class RomFeature {
        private final String property;
        private final String value;
        private final boolean exists;

        public RomFeature(String property, String value, boolean exists) {
            this.property = property;
            this.value = value;
            this.exists = exists;
        }

        public String getProperty() {
            return property;
        }

        public String getValue() {
            return value;
        }

        public boolean exists() {
            return exists;
        }

        public String getDisplayName() {
            // Convert property name to readable format
            String name = property.replace("ro.", "").replace(".", " ");
            return name.substring(0, 1).toUpperCase() + name.substring(1);
        }
    }
}
