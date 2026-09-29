package com.github.xingjianluo.admissionpolicyenginejava.model;

/**
 * 批量评估中单个镜像项的结论。
 *
 * @param index     该项在提交批次中的下标（从 0 开始）
 * @param reference 请求中给出的镜像引用（输入畸形时也尽量回填）
 * @param ok        该项是否成功完成评估；false 表示该项输入有问题，不影响其他项
 * @param errorCode 输入有问题时的错误码（{@link com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode} 名称），成功为 null
 * @param errorMessage 输入有问题时的可读原因，成功为 null
 * @param report    评估成功时的完整结论；失败为 null
 */
public record BatchItemResult(
        int index,
        String reference,
        boolean ok,
        String errorCode,
        String errorMessage,
        DecisionReport report
) {
}
