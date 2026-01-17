package com.xff.launch.model;

import java.util.HashMap;
import java.util.Map;

/**
 * Device fingerprint item with multi-layer values
 */
public class FingerprintItem {
    private String name;
    private String displayName;
    private Map<DetectionLayer, String> layerValues;
    private boolean consistent;
    private boolean requiresPermission;
    private boolean hasPermission;

    public FingerprintItem(String name, String displayName) {
        this.name = name;
        this.displayName = displayName;
        this.layerValues = new HashMap<>();
        this.consistent = true;
        this.requiresPermission = false;
        this.hasPermission = true;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public Map<DetectionLayer, String> getLayerValues() {
        return layerValues;
    }

    public void setLayerValue(DetectionLayer layer, String value) {
        layerValues.put(layer, value);
        checkConsistency();
    }

    public String getLayerValue(DetectionLayer layer) {
        return layerValues.get(layer);
    }

    /**
     * Get the primary value to display
     * Prefers valid values over N/A, in order: SYSCALL > NATIVE > JAVA
     */
    public String getPrimaryValue() {
        // Prefer syscall value if available and not N/A
        String syscallValue = layerValues.get(DetectionLayer.SYSCALL);
        if (isValidValue(syscallValue)) {
            return syscallValue;
        }

        String nativeValue = layerValues.get(DetectionLayer.NATIVE);
        if (isValidValue(nativeValue)) {
            return nativeValue;
        }

        String javaValue = layerValues.get(DetectionLayer.JAVA);
        if (isValidValue(javaValue)) {
            return javaValue;
        }

        // If all values are N/A or empty, return N/A
        return "N/A";
    }

    /**
     * Check if a value is valid (not null, not empty, not N/A)
     */
    private boolean isValidValue(String value) {
        return value != null && !value.isEmpty() && !value.equals("N/A");
    }

    public boolean isConsistent() {
        return consistent;
    }

    private void checkConsistency() {
        if (layerValues.size() < 2) {
            consistent = true;
            return;
        }

        String firstValue = null;
        int validValueCount = 0;
        for (String value : layerValues.values()) {
            // Skip null, empty, and "N/A" values - don't compare them
            if (value == null || value.isEmpty() || value.equals("N/A")) continue;

            // Trim whitespace and newlines for comparison
            String trimmedValue = value.trim();
            if (trimmedValue.isEmpty()) continue;

            validValueCount++;
            if (firstValue == null) {
                firstValue = trimmedValue;
            } else if (!firstValue.equals(trimmedValue)) {
                consistent = false;
                return;
            }
        }
        // If we have less than 2 valid values to compare, consider it consistent
        // (can't determine inconsistency with only 0 or 1 valid values)
        consistent = validValueCount < 2 || firstValue != null;
    }

    public boolean isRequiresPermission() {
        return requiresPermission;
    }

    public void setRequiresPermission(boolean requiresPermission) {
        this.requiresPermission = requiresPermission;
    }

    public boolean isHasPermission() {
        return hasPermission;
    }

    public void setHasPermission(boolean hasPermission) {
        this.hasPermission = hasPermission;
    }

    /**
     * Get abbreviated value for display in comparison table
     */
    public String getAbbreviatedValue(DetectionLayer layer, int maxLength) {
        String value = layerValues.get(layer);
        if (value == null) return "N/A";
        if (value.length() <= maxLength) return value;
        return value.substring(0, maxLength - 2) + "..";
    }
}
