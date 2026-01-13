package com.xff.launch.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Vendor profile containing brand-specific features for device legitimacy verification
 */
public class VendorProfile {
    private String vendorId;
    private String displayName;
    private List<String> brandIdentifiers;
    private List<String> manufacturerIdentifiers;
    private String romName;
    private List<String> romVersionProperties;
    private List<String> requiredPackages;
    private List<String> optionalPackages;
    private List<String> systemProperties;
    private List<String> fingerprintPatterns;
    private boolean hasGms;

    public VendorProfile(String vendorId, String displayName) {
        this.vendorId = vendorId;
        this.displayName = displayName;
        this.brandIdentifiers = new ArrayList<>();
        this.manufacturerIdentifiers = new ArrayList<>();
        this.romVersionProperties = new ArrayList<>();
        this.requiredPackages = new ArrayList<>();
        this.optionalPackages = new ArrayList<>();
        this.systemProperties = new ArrayList<>();
        this.fingerprintPatterns = new ArrayList<>();
        this.hasGms = true;
    }

    // Builder methods
    public VendorProfile setBrands(String... brands) {
        this.brandIdentifiers = Arrays.asList(brands);
        return this;
    }

    public VendorProfile setManufacturers(String... manufacturers) {
        this.manufacturerIdentifiers = Arrays.asList(manufacturers);
        return this;
    }

    public VendorProfile setRomName(String romName) {
        this.romName = romName;
        return this;
    }

    public VendorProfile setRomVersionProperties(String... properties) {
        this.romVersionProperties = Arrays.asList(properties);
        return this;
    }

    public VendorProfile setRequiredPackages(String... packages) {
        this.requiredPackages = Arrays.asList(packages);
        return this;
    }

    public VendorProfile setOptionalPackages(String... packages) {
        this.optionalPackages = Arrays.asList(packages);
        return this;
    }

    public VendorProfile setSystemProperties(String... properties) {
        this.systemProperties = Arrays.asList(properties);
        return this;
    }

    public VendorProfile setFingerprintPatterns(String... patterns) {
        this.fingerprintPatterns = Arrays.asList(patterns);
        return this;
    }

    public VendorProfile setHasGms(boolean hasGms) {
        this.hasGms = hasGms;
        return this;
    }

    // Getters
    public String getVendorId() {
        return vendorId;
    }

    public String getDisplayName() {
        return displayName;
    }

    public List<String> getBrandIdentifiers() {
        return brandIdentifiers;
    }

    public List<String> getManufacturerIdentifiers() {
        return manufacturerIdentifiers;
    }

    public String getRomName() {
        return romName;
    }

    public List<String> getRomVersionProperties() {
        return romVersionProperties;
    }

    public List<String> getRequiredPackages() {
        return requiredPackages;
    }

    public List<String> getOptionalPackages() {
        return optionalPackages;
    }

    public List<String> getSystemProperties() {
        return systemProperties;
    }

    public List<String> getFingerprintPatterns() {
        return fingerprintPatterns;
    }

    public boolean hasGms() {
        return hasGms;
    }

    /**
     * Check if this profile matches the given brand/manufacturer
     */
    public boolean matchesBrand(String brand) {
        if (brand == null) return false;
        String lowerBrand = brand.toLowerCase();
        for (String identifier : brandIdentifiers) {
            if (lowerBrand.contains(identifier.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    public boolean matchesManufacturer(String manufacturer) {
        if (manufacturer == null) return false;
        String lowerMfr = manufacturer.toLowerCase();
        for (String identifier : manufacturerIdentifiers) {
            if (lowerMfr.contains(identifier.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if fingerprint matches expected patterns
     */
    public boolean matchesFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprintPatterns.isEmpty()) return true;
        String lowerFp = fingerprint.toLowerCase();
        for (String pattern : fingerprintPatterns) {
            if (lowerFp.contains(pattern.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
}
