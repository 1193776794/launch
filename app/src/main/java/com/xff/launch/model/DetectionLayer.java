package com.xff.launch.model;

/**
 * Detection layer enum for multi-layer detection architecture
 */
public enum DetectionLayer {
    JAVA,       // Java API layer
    NATIVE,     // Native libc layer
    SYSCALL     // Direct syscall layer
}
