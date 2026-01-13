package com.xff.launch.model;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Overall fingerprint collection result
 */
public class FingerprintResult {
    private List<FingerprintItem> items;
    private String compositeFingerprint;
    private String hardwareHash;
    private String softwareHash;
    private int trustLevel;
    private boolean tamperingDetected;
    private long collectTime;

    public FingerprintResult() {
        this.items = new ArrayList<>();
        this.trustLevel = 100;
        this.tamperingDetected = false;
        this.collectTime = System.currentTimeMillis();
    }

    public List<FingerprintItem> getItems() {
        return items;
    }

    public void addItem(FingerprintItem item) {
        items.add(item);
    }

    public void setItems(List<FingerprintItem> items) {
        this.items = items;
    }

    public String getCompositeFingerprint() {
        return compositeFingerprint;
    }

    public void setCompositeFingerprint(String compositeFingerprint) {
        this.compositeFingerprint = compositeFingerprint;
    }

    public String getHardwareHash() {
        return hardwareHash;
    }

    public void setHardwareHash(String hardwareHash) {
        this.hardwareHash = hardwareHash;
    }

    public String getSoftwareHash() {
        return softwareHash;
    }

    public void setSoftwareHash(String softwareHash) {
        this.softwareHash = softwareHash;
    }

    public int getTrustLevel() {
        return trustLevel;
    }

    public void setTrustLevel(int trustLevel) {
        this.trustLevel = trustLevel;
    }

    public boolean isTamperingDetected() {
        return tamperingDetected;
    }

    public void setTamperingDetected(boolean tamperingDetected) {
        this.tamperingDetected = tamperingDetected;
    }

    public long getCollectTime() {
        return collectTime;
    }

    public void setCollectTime(long collectTime) {
        this.collectTime = collectTime;
    }

    /**
     * Calculate trust level based on consistency of fingerprint items
     */
    public void calculateTrustLevel() {
        int inconsistentCount = 0;
        int totalItems = items.size();

        for (FingerprintItem item : items) {
            if (!item.isConsistent()) {
                inconsistentCount++;
            }
        }

        if (totalItems == 0) {
            trustLevel = 100;
            tamperingDetected = false;
            return;
        }

        // Each inconsistent item reduces trust by 15%
        int reduction = (inconsistentCount * 15);
        trustLevel = Math.max(0, 100 - reduction);
        tamperingDetected = inconsistentCount > 0;
    }

    /**
     * Generate composite fingerprint from all items
     */
    public void generateCompositeFingerprint() {
        StringBuilder sb = new StringBuilder();
        for (FingerprintItem item : items) {
            String value = item.getPrimaryValue();
            if (value != null && !value.isEmpty()) {
                sb.append(value);
            }
        }
        compositeFingerprint = sha256(sb.toString());
    }

    /**
     * Get count of consistent items
     */
    public int getConsistentCount() {
        int count = 0;
        for (FingerprintItem item : items) {
            if (item.isConsistent()) count++;
        }
        return count;
    }

    /**
     * Get count of inconsistent items
     */
    public int getInconsistentCount() {
        int count = 0;
        for (FingerprintItem item : items) {
            if (!item.isConsistent()) count++;
        }
        return count;
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
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }
}
