package com.xff.launch.model;

/**
 * 采集方式（探针通道）。
 *
 * <p>每个枚举值代表一种获取同一指纹值的"取证手段"，按抗 Hook 难度分为三层：
 * 上层（Java）易被 Hook，底层（系统调用 / 内存直读）难被篡改。多路对比即可暴露
 * 某一路被 Hook 的情况。
 *
 * <p>新增一种采集方式 = 在这里加一个枚举值，声明层 {@code .probe(新方式, ...)} 引用即可，
 * UI 会按 {@link #icon} / {@link #tier} 自动渲染。
 */
public enum ProbeMethod {
    JAVA_REFLECT("Java 反射", "🔍", Tier.HIGH),   // 🔍
    JAVA_API("Java API", "☕", Tier.HIGH),              // ☕
    JAVA_FILE("Java 文件", "📄", Tier.HIGH),       // 📄 Java 读 /proc·/sys
    NATIVE_PROP("属性 native", "⚙", Tier.MID),          // ⚙
    NATIVE_FILE("JNI 文件", "🔧", Tier.MID),       // 🔧
    SYSCALL("系统调用", "🛡", Tier.LOW),           // 🛡
    MMAP("内存 mmap", "🧠", Tier.LOW);            // 🧠

    /** 抗 Hook 层级，决定 UI 图标着色（越靠底层越可信）。 */
    public enum Tier { HIGH, MID, LOW }

    private final String displayName;
    private final String icon;
    private final Tier tier;

    ProbeMethod(String displayName, String icon, Tier tier) {
        this.displayName = displayName;
        this.icon = icon;
        this.tier = tier;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getIcon() {
        return icon;
    }

    public Tier getTier() {
        return tier;
    }
}
