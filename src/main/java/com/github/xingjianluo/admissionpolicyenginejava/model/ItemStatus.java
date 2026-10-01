package com.github.xingjianluo.admissionpolicyenginejava.model;

/** 批量/预演中单个条目的处理状态。 */
public enum ItemStatus {
    /** 输入合法并已完成评估/预演。 */
    EVALUATED,
    /** 该条目输入不合法（只影响本项，不影响同批其他条目）。 */
    INPUT_ERROR,
    /**
     * 该条目输入合法，但当前生效策略含历史坏规则，评估无法进行
     * （errorCode=POLICY_RULESET_INVALID，只标记本项，不影响同批其他条目）。
     */
    POLICY_ERROR
}
