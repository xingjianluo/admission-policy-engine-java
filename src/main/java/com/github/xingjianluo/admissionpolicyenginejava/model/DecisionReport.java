package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;

/**
 * 一次准入判定的完整、可解释结论。
 *
 * @param decision          最终判定
 * @param policyVersion     判定所基于的策略集合版本（快照号）
 * @param matchedRules      所有命中的规则（按优先级排序）
 * @param decisiveRule      起决定作用的规则（优先级最高的命中规则）
 * @param rationale         最终判定依据说明（含冲突如何被解决）
 */
public record DecisionReport(
        Decision decision,
        long policyVersion,
        List<MatchedRule> matchedRules,
        MatchedRule decisiveRule,
        String rationale
) {
}
