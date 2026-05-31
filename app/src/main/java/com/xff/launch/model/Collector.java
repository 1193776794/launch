package com.xff.launch.model;

/**
 * 一条探针的采集动作。允许抛异常——引擎会捕获并标记为 {@link ProbeStatus#ERROR}，
 * 不影响同项其它探针。
 *
 * <p>声明层用 lambda 实现，例如 {@code () -> ReflectionUtils.getSerial()}。
 */
@FunctionalInterface
public interface Collector {
    String collect() throws Exception;
}
