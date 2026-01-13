package com.xff.launch.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Device legitimacy verification result
 */
public class DeviceLegitimacyResult {
    private DeviceInfo deviceInfo;
    private List<VendorService> vendorServices;
    private int legitimacyScore;
    private boolean buildConsistent;
    private boolean romMatched;
    private boolean serviceMatched;
    private boolean hardwareConsistent;
    private boolean fingerprintFormatValid;
    private List<String> issues;
    private long checkTime;

    public DeviceLegitimacyResult() {
        this.vendorServices = new ArrayList<>();
        this.issues = new ArrayList<>();
        this.legitimacyScore = 100;
        this.buildConsistent = true;
        this.romMatched = true;
        this.serviceMatched = true;
        this.hardwareConsistent = true;
        this.fingerprintFormatValid = true;
        this.checkTime = System.currentTimeMillis();
    }

    public DeviceInfo getDeviceInfo() {
        return deviceInfo;
    }

    public void setDeviceInfo(DeviceInfo deviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    public List<VendorService> getVendorServices() {
        return vendorServices;
    }

    public void addVendorService(VendorService service) {
        vendorServices.add(service);
    }

    public void setVendorServices(List<VendorService> vendorServices) {
        this.vendorServices = vendorServices;
    }

    public int getLegitimacyScore() {
        return legitimacyScore;
    }

    public void setLegitimacyScore(int legitimacyScore) {
        this.legitimacyScore = legitimacyScore;
    }

    public boolean isBuildConsistent() {
        return buildConsistent;
    }

    public void setBuildConsistent(boolean buildConsistent) {
        this.buildConsistent = buildConsistent;
    }

    public boolean isRomMatched() {
        return romMatched;
    }

    public void setRomMatched(boolean romMatched) {
        this.romMatched = romMatched;
    }

    public boolean isServiceMatched() {
        return serviceMatched;
    }

    public void setServiceMatched(boolean serviceMatched) {
        this.serviceMatched = serviceMatched;
    }

    public boolean isHardwareConsistent() {
        return hardwareConsistent;
    }

    public void setHardwareConsistent(boolean hardwareConsistent) {
        this.hardwareConsistent = hardwareConsistent;
    }

    public boolean isFingerprintFormatValid() {
        return fingerprintFormatValid;
    }

    public void setFingerprintFormatValid(boolean fingerprintFormatValid) {
        this.fingerprintFormatValid = fingerprintFormatValid;
    }

    public List<String> getIssues() {
        return issues;
    }

    public void addIssue(String issue) {
        issues.add(issue);
    }

    public void setIssues(List<String> issues) {
        this.issues = issues;
    }

    public long getCheckTime() {
        return checkTime;
    }

    public void setCheckTime(long checkTime) {
        this.checkTime = checkTime;
    }

    /**
     * Calculate legitimacy score based on verification results
     */
    public void calculateScore() {
        int score = 100;

        if (!buildConsistent) {
            score -= 20;
        }
        if (!romMatched) {
            score -= 20;
        }
        if (!serviceMatched) {
            score -= 15;
        }
        if (!hardwareConsistent) {
            score -= 15;
        }
        if (!fingerprintFormatValid) {
            score -= 10;
        }

        // Check vendor services
        for (VendorService service : vendorServices) {
            if (!service.isStatusValid()) {
                score -= 10;
            }
        }

        legitimacyScore = Math.max(0, score);
    }

    /**
     * Get overall status
     */
    public DetectionStatus getOverallStatus() {
        if (legitimacyScore >= 90) return DetectionStatus.SAFE;
        if (legitimacyScore >= 70) return DetectionStatus.WARNING;
        return DetectionStatus.RISK;
    }

    /**
     * Get status description
     */
    public String getStatusDescription() {
        if (legitimacyScore >= 90) return "正常";
        if (legitimacyScore >= 70) return "存在异常";
        return "可能被篡改";
    }

    /**
     * Get count of passed checks
     */
    public int getPassedCheckCount() {
        int count = 0;
        if (buildConsistent) count++;
        if (romMatched) count++;
        if (serviceMatched) count++;
        if (hardwareConsistent) count++;
        if (fingerprintFormatValid) count++;
        return count;
    }

    /**
     * Get total check count
     */
    public int getTotalCheckCount() {
        return 5;
    }
}
