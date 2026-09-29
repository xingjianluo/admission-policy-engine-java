package com.github.xingjianluo.admissionpolicyenginejava.model;

/** 预演中单个镜像在“现网策略 → 候选规则”之间的结论变化方向。 */
public enum ChangeDirection {
    /** 现网放行，候选拒绝。 */
    ALLOW_TO_DENY,
    /** 现网拒绝，候选放行。 */
    DENY_TO_ALLOW,
    /** 两侧结论一致。 */
    UNCHANGED
}
