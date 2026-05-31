package com.xff.launch.model;

import java.util.ArrayList;
import java.util.List;

/**
 * 一个指纹项的<b>声明</b>：它叫什么、属于哪组、是否进 hash、用哪些方式采集。
 *
 * <p>声明层（{@code FingerprintDefinitions}）用流式 API 描述每一项；引擎
 * （{@code FingerprintEngine}）消费这些声明、执行 collector、产出 {@link FingerprintItem}。
 *
 * <pre>
 * FingerprintSpec.define("serial", "设备序列号", Group.IDENTITY, HashTag.HARDWARE)
 *     .probe(ProbeMethod.JAVA_REFLECT, "Build.getSerial()", () -> ReflectionUtils.getSerial())
 *     .probe(ProbeMethod.SYSCALL, "openat /sys/.../iSerial", "/sys/.../iSerial",
 *            () -> nd.readFileSyscall("/sys/.../iSerial"));
 * </pre>
 */
public class FingerprintSpec {

    /** 展示分组（用于分区/排序，可扩展）。 */
    public enum Group { IDENTITY, KERNEL, HARDWARE, BOOT, SYSTEM, RUNTIME }

    /** Hash 归集标签：引擎据此自动把命中值拼进硬件/软件 hash。 */
    public enum HashTag { HARDWARE, SOFTWARE, NONE }

    /** 一条探针的声明（方式 + 手段 + 来源 + 采集动作）。 */
    public static class ProbeDef {
        public final ProbeMethod method;
        public final String api;
        public final String source;
        public final Collector collector;

        ProbeDef(ProbeMethod method, String api, String source, Collector collector) {
            this.method = method;
            this.api = api;
            this.source = source;
            this.collector = collector;
        }
    }

    private final String id;
    private final String displayName;
    private final Group group;
    private final HashTag hashTag;
    private final List<ProbeDef> probeDefs = new ArrayList<>();

    private FingerprintSpec(String id, String displayName, Group group, HashTag hashTag) {
        this.id = id;
        this.displayName = displayName;
        this.group = group;
        this.hashTag = hashTag;
    }

    /** 声明一个指纹项。 */
    public static FingerprintSpec define(String id, String displayName, Group group, HashTag hashTag) {
        return new FingerprintSpec(id, displayName, group, hashTag);
    }

    /** 追加一条采集方式（无来源路径）。 */
    public FingerprintSpec probe(ProbeMethod method, String api, Collector collector) {
        return probe(method, api, null, collector);
    }

    /** 追加一条采集方式（带来源路径）。 */
    public FingerprintSpec probe(ProbeMethod method, String api, String source, Collector collector) {
        probeDefs.add(new ProbeDef(method, api, source, collector));
        return this;
    }

    public String getId() {
        return id;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Group getGroup() {
        return group;
    }

    public HashTag getHashTag() {
        return hashTag;
    }

    public List<ProbeDef> getProbeDefs() {
        return probeDefs;
    }
}
