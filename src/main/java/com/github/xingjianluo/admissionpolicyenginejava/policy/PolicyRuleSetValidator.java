package com.github.xingjianluo.admissionpolicyenginejava.policy;

import java.util.List;

/**
 * 策略规则集合法性校验：正式发布与预演共用同一套规则，
 * 保证“候选规则不合法”与“正式发布不合法”得到完全一致的处理。
 */
public interface PolicyRuleSetValidator {

    /**
     * 校验并冻结规则集（null、空集、重复 id、缺 effect、schemaVersion 越界、
     * 条件缺参数/参数格式错误/严重级别档位不允许等均抛 AdmissionException）。
     * 通过后条件参数按规约归一化（trim；SEVERITY_AT_LEAST 转大写）。
     *
     * @return 不可变的规则列表
     */
    List<PolicyRule> validateAndFreeze(List<PolicyRule> rules);
}
