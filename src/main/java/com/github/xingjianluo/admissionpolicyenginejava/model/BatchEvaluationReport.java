package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;

/**
 * 一次批量评估的汇总结果。
 * <p>
 * 整批共享同一份当前策略快照（{@link #policyVersion()}），从而：
 * 批内每个镜像都基于同一份现网策略给出结论，且预演对比的“现网一侧”与之一致。
 *
 * @param policyVersion    整批固定的当前策略版本
 * @param totalCount       提交条目总数
 * @param allowedCount     结论为 ALLOW 的条目数
 * @param deniedCount      结论为 DENY 的条目数
 * @param errorCount       输入非法条目数（status=INPUT_ERROR）
 * @param policyErrorCount 因现网历史坏规则无法评估的条目数（status=POLICY_ERROR）
 * @param items            逐项结果（与输入下标一一对应）
 */
public record BatchEvaluationReport(
        long policyVersion,
        int totalCount,
        int allowedCount,
        int deniedCount,
        int errorCount,
        int policyErrorCount,
        List<BatchItemResult> items
) {
}
