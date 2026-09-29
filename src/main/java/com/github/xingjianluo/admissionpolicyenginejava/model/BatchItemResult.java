package com.github.xingjianluo.admissionpolicyenginejava.model;

/**
 * 批量评估中单个镜像的结果：要么是评估结论，要么是该项输入错误说明。
 *
 * @param index        对应批量输入项下标
 * @param reference    镜像引用（能取到时回填，便于人工对位）
 * @param status       该项状态
 * @param report       评估结论（status=EVALUATED 时非 null）
 * @param errorCode    输入错误码（status=INPUT_ERROR 时非 null）
 * @param errorMessage 输入错误说明（status=INPUT_ERROR 时非 null）
 */
public record BatchItemResult(
        int index,
        String reference,
        ItemStatus status,
        DecisionReport report,
        String errorCode,
        String errorMessage
) {
}
