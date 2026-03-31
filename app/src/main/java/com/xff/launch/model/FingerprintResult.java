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

    // Runtime integrity penalties
    private int rwxPenalty;
    private int urandomPenalty;
    private int mmapPenalty;
    private int persistentPenalty;

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

    public int getRwxPenalty() { return rwxPenalty; }
    public void setRwxPenalty(int p) { this.rwxPenalty = p; }

    public int getUrandomPenalty() { return urandomPenalty; }
    public void setUrandomPenalty(int p) { this.urandomPenalty = p; }

    public int getMmapPenalty() { return mmapPenalty; }
    public void setMmapPenalty(int p) { this.mmapPenalty = p; }

    public int getPersistentPenalty() { return persistentPenalty; }
    public void setPersistentPenalty(int p) { this.persistentPenalty = p; }

    /**
     * Calculate trust level based on consistency + runtime integrity indicators
     */
    public void calculateTrustLevel() {
        int inconsistentCount = 0;

        for (FingerprintItem item : items) {
            if (!item.isConsistent()) {
                inconsistentCount++;
            }
        }

        if (items.isEmpty()) {
            trustLevel = 100;
            tamperingDetected = false;
            return;
        }

        // Consistency penalty: 15 per inconsistent item
        int consistencyReduction = inconsistentCount * 15;
        // Runtime integrity penalties
        int runtimeReduction = rwxPenalty + urandomPenalty + mmapPenalty + persistentPenalty;
        int totalReduction = consistencyReduction + runtimeReduction;

        trustLevel = Math.max(0, 100 - totalReduction);
        tamperingDetected = totalReduction > 0;
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
