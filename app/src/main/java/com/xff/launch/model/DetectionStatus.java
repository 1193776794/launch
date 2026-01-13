package com.xff.launch.model;

/**
 * Detection status enum representing different security states
 */
public enum DetectionStatus {
    SAFE,       // No risk detected
    RISK,       // Risk detected
    WARNING,    // Potential risk
    UNKNOWN     // Unable to determine
}
