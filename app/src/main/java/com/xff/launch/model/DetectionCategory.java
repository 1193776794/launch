package com.xff.launch.model;

/**
 * Detection category enum
 */
public enum DetectionCategory {
    ROOT,           // Root detection
    HOOK,           // Hook framework detection
    EMULATOR,       // Emulator/VM detection
    DEBUG,          // Debug detection
    INTEGRITY,      // Integrity verification
    NETWORK,        // Network security detection
    SIDE_CHANNEL,   // Side-channel attack detection (Spectre/Meltdown/Cache timing)
    READLINK,       // Readlink/symlink detection (proc, fd, mount namespace)
    ZYGOTE,         // Zygote injection detection (Zygisk/Riru/LSPosed)
    TAMPER,         // Tamper/device modification tool detection
    BOOTLOADER,     // Bootloader unlock detection
    AUTHENTICITY,   // Device authenticity / risk-control signals (lockscreen, battery, accessibility, TEE)
    MULTI_INSTANCE  // Multi-open container / sandbox hijack detection
}
