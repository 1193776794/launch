package com.xff.launch.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Detection group containing multiple detection items
 */
public class DetectionGroup {
    private String name;
    private DetectionCategory category;
    private int iconResId;
    private List<DetectionItem> items;
    private boolean expanded;

    public DetectionGroup(String name, DetectionCategory category, int iconResId) {
        this.name = name;
        this.category = category;
        this.iconResId = iconResId;
        this.items = new ArrayList<>();
        this.expanded = false;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public DetectionCategory getCategory() {
        return category;
    }

    public void setCategory(DetectionCategory category) {
        this.category = category;
    }

    public int getIconResId() {
        return iconResId;
    }

    public void setIconResId(int iconResId) {
        this.iconResId = iconResId;
    }

    public List<DetectionItem> getItems() {
        return items;
    }

    public void addItem(DetectionItem item) {
        items.add(item);
    }

    public void setItems(List<DetectionItem> items) {
        this.items = items;
    }

    public boolean isExpanded() {
        return expanded;
    }

    public void setExpanded(boolean expanded) {
        this.expanded = expanded;
    }

    public void toggleExpanded() {
        this.expanded = !this.expanded;
    }

    /**
     * Get the overall status of this group
     */
    public DetectionStatus getOverallStatus() {
        boolean hasRisk = false;
        boolean hasWarning = false;
        boolean hasUnknown = false;

        for (DetectionItem item : items) {
            switch (item.getStatus()) {
                case RISK:
                    hasRisk = true;
                    break;
                case WARNING:
                    hasWarning = true;
                    break;
                case UNKNOWN:
                    hasUnknown = true;
                    break;
            }
        }

        if (hasRisk) return DetectionStatus.RISK;
        if (hasWarning) return DetectionStatus.WARNING;
        if (hasUnknown) return DetectionStatus.UNKNOWN;
        return DetectionStatus.SAFE;
    }

    /**
     * Get count of items with specific status
     */
    public int getStatusCount(DetectionStatus status) {
        int count = 0;
        for (DetectionItem item : items) {
            if (item.getStatus() == status) {
                count++;
            }
        }
        return count;
    }

    /**
     * Get count of risk items
     */
    public int getRiskCount() {
        return getStatusCount(DetectionStatus.RISK);
    }

    /**
     * Get count of safe items
     */
    public int getSafeCount() {
        return getStatusCount(DetectionStatus.SAFE);
    }
}
