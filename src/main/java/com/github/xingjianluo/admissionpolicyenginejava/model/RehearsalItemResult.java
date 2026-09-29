package com.github.xingjianluo.admissionpolicyenginejava.model;

/**
 * 预演中单个镜像在“当前策略 / 候选规则”下的对照结果。
 *
 * @param index        批次下标（从 0 开始）
 * @param reference    镜像引用
 * @param ok           该项输入是否合法；false 时两份结论均为 null 并标出原因，不参与变化统计
 * @param errorCode    输入错误码名称，成功为 null
 * @param errorMessage 输入错误原因，成功为 null
 * @param baseline     当前生效策略下的结论
 * @param candidate    候选规则集下的结论
 * @param changed      结论是否发生变化（输入不合法时为 false）
 * @param direction    变化方向
 */
public record RehearsalItemResult(
        int index,
        String reference,
        boolean ok,
        String errorCode,
        String errorMessage,
        DecisionReport baseline,
        DecisionReport candidate,
        boolean changed,
        ChangeDirection direction
) {
}
