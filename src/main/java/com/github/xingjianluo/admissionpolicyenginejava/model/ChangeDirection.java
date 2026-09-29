package com.github.xingjianluo.admissionpolicyenginejava.model;

/**
 * 预演中单个镜像“当前策略结论 → 候选规则结论”的变化方向。
 */
public enum ChangeDirection {
    /** 结论未变化（ALLOW→ALLOW 或 DENY→DENY）。 */
    UNCHANGED,
    /** 当前放行，候选规则下变为拒绝。 */
    ALLOW_TO_DENY,
    /** 当前拒绝，候选规则下变为放行。 */
    DENY_TO_ALLOW
}
