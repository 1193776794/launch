package com.xff.launch.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Overall detection result containing all detection groups
 */
public class DetectionResult {
    private List<DetectionGroup> groups;
    private long detectTime;
    private int overallScore;

    public DetectionResult() {
        this.groups = new ArrayList<>();
        this.detectTime = System.currentTimeMillis();
        this.overallScore = 100;
    }

    public List<DetectionGroup> getGroups() {
        return groups;
    }

    public void addGroup(DetectionGroup group) {
        groups.add(group);
    }

    public void setGroups(List<DetectionGroup> groups) {
        this.groups = groups;
    }

    public long getDetectTime() {
        return detectTime;
    }

    public void setDetectTime(long detectTime) {
        this.detectTime = detectTime;
    }

    public int getOverallScore() {
        return overallScore;
    }

    public void setOverallScore(int overallScore) {
        this.overallScore = overallScore;
    }

    /**
     * Calculate overall score based on detection results
     */
    public void calculateScore() {
        int totalItems = 0;
        int riskItems = 0;
        int warningItems = 0;

        for (DetectionGroup group : groups) {
            for (DetectionItem item : group.getItems()) {
                totalItems++;
                if (item.getStatus() == DetectionStatus.RISK) {
                    riskItems++;
                } else if (item.getStatus() == DetectionStatus.WARNING) {
                    warningItems++;
                }
            }
        }

        if (totalItems == 0) {
            overallScore = 100;
            return;
        }

        // Each risk item deducts 15 points, warning deducts 5 points
        int deduction = (riskItems * 15) + (warningItems * 5);
        overallScore = Math.max(0, 100 - deduction);
    }

    /**
     * Get total count of items with specific status
     */
    public int getTotalStatusCount(DetectionStatus status) {
        int count = 0;
        for (DetectionGroup group : groups) {
            count += group.getStatusCount(status);
        }
        return count;
    }

    /**
     * Get total safe count
     */
    public int getSafeCount() {
        return getTotalStatusCount(DetectionStatus.SAFE);
    }

    /**
     * Get total risk count
     */
    public int getRiskCount() {
        return getTotalStatusCount(DetectionStatus.RISK);
    }

    /**
     * Get total warning count
     */
    public int getWarningCount() {
        return getTotalStatusCount(DetectionStatus.WARNING);
    }

    /**
     * Get total unknown count
     */
    public int getUnknownCount() {
        return getTotalStatusCount(DetectionStatus.UNKNOWN);
    }

    /**
     * Get overall status level
     */
    public DetectionStatus getOverallStatus() {
        if (getRiskCount() > 0) return DetectionStatus.RISK;
        if (getWarningCount() > 0) return DetectionStatus.WARNING;
        if (getUnknownCount() > 0) return DetectionStatus.UNKNOWN;
        return DetectionStatus.SAFE;
    }
}
