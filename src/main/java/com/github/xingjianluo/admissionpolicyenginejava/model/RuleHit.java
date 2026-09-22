package com.github.xingjianluo.admissionpolicyenginejava.model;

/**
 * 一条规则的命中记录，用于可解释结论。
 *
 * @param ruleId   命中的规则编号
 * @param effect   规则效果
 * @param priority 规则优先级
 * @param reason   命中依据的文字说明
 */
public record RuleHit(String ruleId,
                      PolicyEffect effect,
                      int priority,
                      String reason) {
}
