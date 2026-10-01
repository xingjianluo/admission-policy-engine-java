package com.github.xingjianluo.admissionpolicyenginejava.policy;

import java.util.List;

/**
 * 策略规则集合法性校验：正式发布与预演共用同一套规则，
 * 保证“候选规则不合法”与“正式发布不合法”得到完全一致的处理。
 */
public interface PolicyRuleSetValidator {

    /**
     * 校验并冻结规则集（null、空集、重复 id、缺 effect、schemaVersion 越界、
     * 条件参数非法等均抛 AdmissionException；其中条件参数非法为
     * POLICY_RULESET_INVALID，schemaVersion 越界为 POLICY_SCHEMA_UNSUPPORTED，
     * 其余结构问题为 INVALID_REQUEST）。
     *
     * @return 不可变的规则列表
     */
    List<PolicyRule> validateAndFreeze(List<PolicyRule> rules);
}
