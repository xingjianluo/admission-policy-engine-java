package com.github.xingjianluo.admissionpolicyenginejava.model;

/**
 * 一条命中的策略规则及其命中依据。
 *
 * @param ruleId     命中规则 ID
 * @param priority   规则优先级（数值越大优先级越高）
 * @param effect     命中效果
 * @param reason     命中依据的人类可读说明
 */
public record MatchedRule(
        String ruleId,
        int priority,
        PolicyEffect effect,
        String reason
) {
}
