package com.xff.launch.model;

/**
 * 单条探针的采集状态。
 */
public enum ProbeStatus {
    /** 采集到有效值，参与投票。 */
    OK,
    /** 空值或 N/A，不参与投票。 */
    EMPTY,
    /** 采集过程中抛出异常。 */
    ERROR
}
