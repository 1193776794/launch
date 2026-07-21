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
    TAMPER,         // Tamper/device modification tool detection
    BOOTLOADER,     // Bootloader unlock detection
    AUTHENTICITY,   // Device authenticity / risk-control signals (lockscreen, battery, accessibility, TEE)
    MULTI_INSTANCE, // Multi-open container / sandbox hijack detection
    DEVICE_CONSISTENCY, // 机型一致性 (Build/property multi-source & cross-partition, SoC, display, sensors)
    SYSTEM_SERVICE, // 系统服务/框架/HAL/特征文件 一致性 (servicemanager, OEM framework, VINTF, ROM leak)
    DEVICE_SPOOF    // 改机/新机检测 (一键新机工具留痕/包/磁盘build.prop vs运行期/boot dex/伪装.so/标识符漂移)
}
