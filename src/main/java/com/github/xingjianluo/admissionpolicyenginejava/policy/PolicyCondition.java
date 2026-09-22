package com.github.xingjianluo.admissionpolicyenginejava.policy;

/**
 * 单个匹配条件。
 *
 * @param type  条件类型
 * @param value 条件参数（无参条件可为 null；SEVERITY_AT_LEAST 取 Severity 枚举名）
 */
public record PolicyCondition(ConditionType type, String value) {

    public PolicyCondition {
        if (type == null) {
            throw new IllegalArgumentException("条件类型不能为 null");
        }
    }
}
