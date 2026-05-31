package com.xff.launch.model;

/**
 * 一条探针的采集结果：用哪种方式、什么手段、从哪取、取到什么、状态如何。
 *
 * <p>这是 UI 展开后逐行展示的数据单元。
 */
public class CollectProbe {
    private final ProbeMethod method;
    private final String api;       // 具体手段，如 "Build.getSerial()"
    private final String source;    // 来源路径，可空，如 "/proc/version"
    private final String value;     // 采集到的原始值（已是字符串）
    private final ProbeStatus status;
    private boolean outlier;        // 投票后：与众数不同则标红

    public CollectProbe(ProbeMethod method, String api, String source, String value, ProbeStatus status) {
        this.method = method;
        this.api = api;
        this.source = source;
        this.value = value == null ? "" : value;
        this.status = status;
        this.outlier = false;
    }

    public ProbeMethod getMethod() {
        return method;
    }

    public String getApi() {
        return api;
    }

    public String getSource() {
        return source;
    }

    public String getValue() {
        return value;
    }

    public ProbeStatus getStatus() {
        return status;
    }

    public boolean isOutlier() {
        return outlier;
    }

    public void setOutlier(boolean outlier) {
        this.outlier = outlier;
    }

    /** 展示用：值为空时回退 "N/A"。 */
    public String getDisplayValue() {
        return value.isEmpty() ? "N/A" : value;
    }
}
