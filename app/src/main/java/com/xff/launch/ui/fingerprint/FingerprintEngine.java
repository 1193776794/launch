package com.xff.launch.ui.fingerprint;

import android.util.Log;

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

    private static final String TAG = "FpEngine";

    /** 跑完所有声明，返回结果。应在后台线程调用。 */
    public FingerprintResult collect(List<FingerprintSpec> specs) {
        FingerprintResult result = new FingerprintResult();
        List<FingerprintItem> items = new ArrayList<>();

        StringBuilder composite = new StringBuilder();
        StringBuilder hw = new StringBuilder();
        StringBuilder sw = new StringBuilder();

        Log.i(TAG, "==== 指纹采集开始, 共 " + specs.size() + " 项 ====");

        for (FingerprintSpec spec : specs) {
            FingerprintItem item = new FingerprintItem(spec.getId(), spec.getDisplayName());

            for (FingerprintSpec.ProbeDef def : spec.getProbeDefs()) {
                String value;
                ProbeStatus status;
                String err = null;
                try {
                    value = def.collector.collect();
                    status = isValid(value) ? ProbeStatus.OK : ProbeStatus.EMPTY;
                } catch (Throwable t) {
                    value = "";
                    status = ProbeStatus.ERROR;
                    err = t.getClass().getSimpleName() + ":" + t.getMessage();
                }
                item.addProbe(new CollectProbe(def.method, def.api, def.source, value, status));
                Log.d(TAG, String.format("  [%s] %-12s %-7s api=%s val=%s%s",
                        spec.getId(), def.method, status, def.api, truncate(value),
                        err != null ? " ERR=" + err : ""));
            }

            item.vote();
            items.add(item);

            String hit = item.getHitValue();
            Log.i(TAG, String.format("ITEM %-16s %s hit=%s (%d路/%d异常)",
                    spec.getId(), item.isConsistent() ? "一致 " : "不一致", truncate(hit),
                    item.getOkCount(), item.getOutlierCount()));

            if (isValid(hit)) {
                // composite 按权重重复计入；weight=0 的项（如 boot_id 每次开机变）不纳入
                for (int i = 0; i < spec.getWeight(); i++) composite.append(hit).append('|');
                switch (spec.getHashTag()) {
                    case HARDWARE: hw.append(hit); break;
                    case SOFTWARE: sw.append(hit); break;
                    default: break;
                }
            }
        }

        Log.i(TAG, String.format("==== 采集结束: %d 项, %d 项不一致 ====",
                items.size(), countInconsistent(items)));

        result.setItems(items);
        result.setCompositeFingerprint(sha256(composite.toString()));
        result.setHardwareHash(sha256(hw.toString()));
        result.setSoftwareHash(sha256(sw.toString()));
        Log.i(TAG, "COMPOSITE=" + result.getCompositeFingerprint());
        return result;
    }

    private static boolean isValid(String v) {
        return v != null && !v.isEmpty()
                && !v.equals("N/A")
                && !v.equalsIgnoreCase("unknown");
    }

    private static String truncate(String v) {
        if (v == null) return "<null>";
        if (v.isEmpty()) return "<empty>";
        return v.length() <= 48 ? v : v.substring(0, 48) + "..";
    }

    private static int countInconsistent(List<FingerprintItem> items) {
        int c = 0;
        for (FingerprintItem i : items) if (!i.isConsistent()) c++;
        return c;
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
