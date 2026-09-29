package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;

/**
 * 一次策略预演（dry-run）的完整对照报告。
 * <p>
 * 当前策略快照在整次预演开始前固定一次，因此对照的两侧必然来自同一份当前策略，
 * 预演期间任何发布/回滚都不会造成“一半旧一半新”。候选规则只在内存中评估，
 * 绝不写入版本链、不产生正式新版本。
 *
 * @param total            提交项总数
 * @param invalid          输入有问题的项数
 * @param baselineVersion  当前生效策略快照版本
 * @param candidateRuleCount 候选规则条数
 * @param changedCount     结论发生变化的项数
 * @param allowToDenyCount ALLOW→DENY 项数
 * @param denyToAllowCount DENY→ALLOW 项数
 * @param items            逐项对照结果
 */
public record RehearsalReport(
        int total,
        int invalid,
        long baselineVersion,
        int candidateRuleCount,
        int changedCount,
        int allowToDenyCount,
        int denyToAllowCount,
        List<RehearsalItemResult> items
) {
}
