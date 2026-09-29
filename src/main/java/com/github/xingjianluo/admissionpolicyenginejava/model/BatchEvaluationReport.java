package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;

/**
 * 一批镜像的批量评估汇总结果（各项相互独立，坏输入不拖累其他项）。
 *
 * @param total       提交项总数
 * @param succeeded   成功评估的项数
 * @param failed      输入有问题被标出的项数
 * @param allowed     成功项中判定 ALLOW 的数量
 * @param denied      成功项中判定 DENY 的数量
 * @param policyVersion 整批共用的当前策略快照版本（评估前固定）
 * @param items       按下标顺序排列的各项结论
 */
public record BatchEvaluationReport(
        int total,
        int succeeded,
        int failed,
        int allowed,
        int denied,
        long policyVersion,
        List<BatchItemResult> items
) {
}
