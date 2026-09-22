package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;

/**
 * 一次准入评估的完整结论。
 *
 * @param requestId     对应请求编号
 * @param decision      最终判定
 * @param policyVersion 评估时生效的策略版本（保证快照一致）
 * @param hits          所有命中的规则（按优先级排序）
 * @param decisiveRuleId 最终起决定作用的规则编号；无规则命中时为 null
 * @param rationale     人类可读的最终判定依据
 * @param evaluatedAtEpochMs 评估时间
 */
public record EvaluationResult(String requestId,
                               Decision decision,
                               long policyVersion,
                               List<RuleHit> hits,
                               String decisiveRuleId,
                               String rationale,
                               long evaluatedAtEpochMs) {

    public EvaluationResult {
        hits = hits == null ? List.of() : List.copyOf(hits);
    }
}
