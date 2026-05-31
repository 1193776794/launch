package com.xff.launch.model;

import java.util.ArrayList;
import java.util.List;

/**
 * 整体指纹采集结果。
 *
 * <p>已取消信任分体系——一致/不一致改由每个 {@link FingerprintItem} 自身的颜色标识，
 * 整体只提供"一致项计数"供概览展示。
 */
public class FingerprintResult {
    private List<FingerprintItem> items = new ArrayList<>();
    private String compositeFingerprint;
    private String hardwareHash;
    private String softwareHash;
    private long collectTime = System.currentTimeMillis();

    public List<FingerprintItem> getItems() {
        return items;
    }

    public void setItems(List<FingerprintItem> items) {
        this.items = items;
    }

    public void addItem(FingerprintItem item) {
        items.add(item);
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

    public long getCollectTime() {
        return collectTime;
    }

    public void setCollectTime(long collectTime) {
        this.collectTime = collectTime;
    }

    public int getConsistentCount() {
        int count = 0;
        for (FingerprintItem item : items) {
            if (item.isConsistent()) count++;
        }
        return count;
    }

    public int getInconsistentCount() {
        return items.size() - getConsistentCount();
    }

    public boolean hasInconsistency() {
        return getInconsistentCount() > 0;
    }
}
