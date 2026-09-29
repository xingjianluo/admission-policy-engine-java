package com.github.xingjianluo.admissionpolicyenginejava.model;

/**
 * 单个镜像在一次预演中的双侧对照结果。
 *
 * @param index         对应批量输入项下标
 * @param reference     镜像引用
 * @param status        该项状态
 * @param currentReport 现网策略下结论
 * @param candidateReport 候选规则下结论（预演专用，policyVersion 标记为候选）
 * @param change        结论变化方向
 * @param errorCode     输入错误码（INPUT_ERROR 时非 null）
 * @param errorMessage  输入错误说明（INPUT_ERROR 时非 null）
 */
public record RehearsalItemResult(
        int index,
        String reference,
        ItemStatus status,
        DecisionReport currentReport,
        DecisionReport candidateReport,
        ChangeDirection change,
        String errorCode,
        String errorMessage
) {
}
