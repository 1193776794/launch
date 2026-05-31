package com.xff.launch.ui.fingerprint;

import com.xff.launch.model.CollectProbe;
import com.xff.launch.model.FingerprintItem;
import com.xff.launch.model.FingerprintResult;
import com.xff.launch.model.FingerprintSpec;
import com.xff.launch.model.ProbeStatus;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * 指纹采集引擎：消费声明（{@link FingerprintSpec}），执行每条探针，产出
 * {@link FingerprintResult}。
 *
 * <p>这里不含任何具体取证逻辑——取证写在声明层的 lambda 里。引擎只负责：
 * 执行 → 分类状态 → 投票 → 按 Hash 标签归集。新增指纹/方式都不需要改动本文件。
 */
public class FingerprintEngine {

    /** 跑完所有声明，返回结果。应在后台线程调用。 */
    public FingerprintResult collect(List<FingerprintSpec> specs) {
        FingerprintResult result = new FingerprintResult();
        List<FingerprintItem> items = new ArrayList<>();

        StringBuilder composite = new StringBuilder();
        StringBuilder hw = new StringBuilder();
        StringBuilder sw = new StringBuilder();

        for (FingerprintSpec spec : specs) {
            FingerprintItem item = new FingerprintItem(spec.getId(), spec.getDisplayName());

            for (FingerprintSpec.ProbeDef def : spec.getProbeDefs()) {
                String value;
                ProbeStatus status;
                try {
                    value = def.collector.collect();
                    status = isValid(value) ? ProbeStatus.OK : ProbeStatus.EMPTY;
                } catch (Throwable t) {
                    value = "";
                    status = ProbeStatus.ERROR;
                }
                item.addProbe(new CollectProbe(def.method, def.api, def.source, value, status));
            }

            item.vote();
            items.add(item);

            String hit = item.getHitValue();
            if (isValid(hit)) {
                composite.append(hit);
                switch (spec.getHashTag()) {
                    case HARDWARE: hw.append(hit); break;
                    case SOFTWARE: sw.append(hit); break;
                    default: break;
                }
            }
        }

        result.setItems(items);
        result.setCompositeFingerprint(sha256(composite.toString()));
        result.setHardwareHash(sha256(hw.toString()));
        result.setSoftwareHash(sha256(sw.toString()));
        return result;
    }

    private static boolean isValid(String v) {
        return v != null && !v.isEmpty() && !v.equals("N/A");
    }

    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) sb.append('0');
                sb.append(hex);
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
