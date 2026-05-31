package com.xff.launch.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 一个指纹项的<b>结果</b>：包含通过多种采集方式得到的探针列表，以及对它们投票后的
 * 一致性判定与命中值。
 *
 * <p>一致性 = 所有 {@link ProbeStatus#OK} 探针的值（规整化后）是否全等。任何一路不同
 * 即为"不一致"，并把离群探针标红。
 */
public class FingerprintItem {
    private final String id;
    private final String displayName;
    private final List<CollectProbe> probes = new ArrayList<>();

    private boolean consistent = true;
    private String hitValue = "N/A";

    public FingerprintItem(String id, String displayName) {
        this.id = id;
        this.displayName = displayName;
    }

    public void addProbe(CollectProbe probe) {
        probes.add(probe);
    }

    /**
     * 对所有 OK 探针做众数投票：计算命中值、标记离群、判定一致性。
     * 引擎在一项所有探针采集完后调用一次。
     */
    public void vote() {
        Map<String, Integer> counts = new HashMap<>();
        int validCount = 0;
        for (CollectProbe p : probes) {
            if (p.getStatus() != ProbeStatus.OK) continue;
            String norm = p.getValue().trim();
            if (norm.isEmpty()) continue;
            validCount++;
            counts.merge(norm, 1, Integer::sum);
        }

        if (counts.isEmpty()) {
            hitValue = "N/A";
            consistent = true; // 无有效值，无从判定不一致
            return;
        }

        // 众数 = 命中值
        String mode = null;
        int best = -1;
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            if (e.getValue() > best) {
                best = e.getValue();
                mode = e.getKey();
            }
        }
        hitValue = mode;
        // 单一取值 → 一致；出现 ≥2 种不同取值 → 不一致
        consistent = counts.size() <= 1 || validCount < 2;

        // 标记离群（OK 且非空且 != 命中值）
        for (CollectProbe p : probes) {
            if (p.getStatus() != ProbeStatus.OK) continue;
            String norm = p.getValue().trim();
            if (norm.isEmpty()) continue;
            p.setOutlier(!norm.equals(mode));
        }
    }

    public String getId() {
        return id;
    }

    public String getDisplayName() {
        return displayName;
    }

    public List<CollectProbe> getProbes() {
        return probes;
    }

    public boolean isConsistent() {
        return consistent;
    }

    /** 命中值（多数票）；用于概览、hash、复制。 */
    public String getHitValue() {
        return hitValue;
    }

    /** 参与投票的有效探针数。 */
    public int getOkCount() {
        int c = 0;
        for (CollectProbe p : probes) {
            if (p.getStatus() == ProbeStatus.OK && !p.getValue().trim().isEmpty()) c++;
        }
        return c;
    }

    /** 离群（异常）探针数。 */
    public int getOutlierCount() {
        int c = 0;
        for (CollectProbe p : probes) {
            if (p.isOutlier()) c++;
        }
        return c;
    }
}
