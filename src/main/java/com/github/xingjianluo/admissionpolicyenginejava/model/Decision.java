package com.github.xingjianluo.admissionpolicyenginejava.model;

/**
 * 准入判定结论。
 */
public enum Decision {
    /** 允许：至少一条 ALLOW 命中且未被更高优先级的 DENY 覆盖。 */
    ALLOW,
    /** 显式拒绝：命中 DENY 规则。 */
    DENY,
    /** 输入不合法（字段缺失、指纹不一致、格式不完整）导致无法评估。 */
    REJECT_INVALID_INPUT,
    /** 未找到任何适用的 ALLOW 规则（默认拒绝）。 */
    DENY_NO_MATCH
}
