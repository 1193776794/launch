package com.xff.launch.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Single detection item result
 */
public class DetectionItem {
    private String name;
    private String description;
    private DetectionStatus status;
    private String detail;
    private Map<DetectionLayer, Boolean> layerResults;
    private List<DetectionDetail> detectionDetails;  // 详细检测信息

    /**
     * Detection detail item
     */
    public static class DetectionDetail {
        private String category;     // 类别 (如 "文件特征", "内存特征", "进程特征")
        private String item;         // 项目名称
        private String value;        // 检测到的值
        private DetectionLayer layer; // 检测层级
        private String icon;         // 图标 emoji

        public DetectionDetail(String category, String item, String value, DetectionLayer layer, String icon) {
            this.category = category;
            this.item = item;
            this.value = value;
            this.layer = layer;
            this.icon = icon;
        }

        public String getCategory() { return category; }
        public String getItem() { return item; }
        public String getValue() { return value; }
        public DetectionLayer getLayer() { return layer; }
        public String getIcon() { return icon; }
    }

    public DetectionItem(String name, String description) {
        this.name = name;
        this.description = description;
        this.status = DetectionStatus.UNKNOWN;
        this.detail = "";
        this.layerResults = new HashMap<>();
        this.detectionDetails = new ArrayList<>();
    }

    public DetectionItem(String name, String description, DetectionStatus status, String detail) {
        this.name = name;
        this.description = description;
        this.status = status;
        this.detail = detail;
        this.layerResults = new HashMap<>();
        this.detectionDetails = new ArrayList<>();
    }

    public List<DetectionDetail> getDetectionDetails() {
        return detectionDetails;
    }

    public void addDetectionDetail(String category, String item, String value, DetectionLayer layer, String icon) {
        detectionDetails.add(new DetectionDetail(category, item, value, layer, icon));
    }

    public void addDetectionDetail(DetectionDetail detail) {
        detectionDetails.add(detail);
    }

    public boolean hasDetails() {
        return detectionDetails != null && !detectionDetails.isEmpty();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public DetectionStatus getStatus() {
        return status;
    }

    public void setStatus(DetectionStatus status) {
        this.status = status;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public Map<DetectionLayer, Boolean> getLayerResults() {
        return layerResults;
    }

    public void setLayerResult(DetectionLayer layer, boolean detected) {
        layerResults.put(layer, detected);
    }

    public Boolean getLayerResult(DetectionLayer layer) {
        return layerResults.get(layer);
    }

    /**
     * Check if any layer detected risk
     */
    public boolean isDetected() {
        return layerResults.values().stream().anyMatch(Boolean::booleanValue);
    }

    /**
     * Check if layers have inconsistent results (potential hook detected)
     */
    public boolean hasInconsistentResults() {
        if (layerResults.size() < 2) return false;
        Boolean first = null;
        for (Boolean result : layerResults.values()) {
            if (first == null) {
                first = result;
            } else if (!first.equals(result)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get the most trustworthy result (syscall > native > java)
     */
    public boolean getMostTrustworthyResult() {
        // Modified logic: If ANY layer detects the threat, consider it detected
        // This prevents false negatives when one layer is bypassed but others detect it

        // Priority order for positive detection:
        // 1. If Syscall layer detects, definitely detected (highest trust for positive)
        if (layerResults.containsKey(DetectionLayer.SYSCALL) &&
            layerResults.get(DetectionLayer.SYSCALL)) {
            return true;
        }

        // 2. If Native layer detects, likely detected (high trust)
        if (layerResults.containsKey(DetectionLayer.NATIVE) &&
            layerResults.get(DetectionLayer.NATIVE)) {
            return true;
        }

        // 3. If Java layer detects, possibly detected (can be hooked, but still valid)
        if (layerResults.containsKey(DetectionLayer.JAVA) &&
            layerResults.get(DetectionLayer.JAVA)) {
            return true;
        }

        // Only if ALL layers report false (or no layers), then it's safe
        return false;
    }
}
