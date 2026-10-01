package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;

/**
 * 一次策略预演的汇总结果。
 * <p>
 * 同一份当前策略快照（{@link #currentPolicyVersion()}）用于全批“现网一侧”，
 * 候选规则仅存在于本次请求内存中（{@link #candidateFingerprint()} 标识其内容），
 * 不会发布、不产生正式版本。
 *
 * @param currentPolicyVersion 预演开始时固定的现网策略版本
 * @param candidateFingerprint 候选规则集内容指纹（幂等/留痕用）
 * @param totalCount           条目总数
 * @param changedCount         结论发生变化的条目数
 * @param allowToDenyCount     放行变拒绝的条目数
 * @param denyToAllowCount     拒绝变放行的条目数
 * @param unchangedCount       结论不变的条目数
 * @param errorCount           输入非法条目数
 * @param policyErrorCount     因现网历史坏规则无法完成对照的条目数
 *                             （status=POLICY_ERROR；候选规则在预演开始前已整批校验，
 *                             不会以逐项错误形式出现）
 * @param items                逐项双侧对照结果
 */
public record RehearsalReport(
        long currentPolicyVersion,
        String candidateFingerprint,
        int totalCount,
        int changedCount,
        int allowToDenyCount,
        int denyToAllowCount,
        int unchangedCount,
        int errorCount,
        int policyErrorCount,
        List<RehearsalItemResult> items
) {
}
