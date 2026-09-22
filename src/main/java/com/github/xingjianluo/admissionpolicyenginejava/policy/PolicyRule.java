package com.github.xingjianluo.admissionpolicyenginejava.policy;

import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;

import java.util.List;

/**
 * 单条准入策略规则。
 * <p>
 * 规则语义：{@code conditions} 中全部条件（AND）匹配镜像时，规则命中并产生
 * {@code effect}（显式 ALLOW 或显式 DENY）。无条件的规则匹配任意镜像。
 * 优先级 {@code priority} 数值越大越优先；同一版本内规则 id 必须唯一。
 *
 * @param schemaVersion 规则 schema 版本，须在引擎兼容范围
 *                      [{@link PolicyStore#SUPPORTED_SCHEMA_MIN},
 *                      {@link PolicyStore#SUPPORTED_SCHEMA_MAX}] 内
 * @param conditions    匹配条件列表（AND）
 */
public record PolicyRule(
        String id,
        int priority,
        PolicyEffect effect,
        int schemaVersion,
        List<PolicyCondition> conditions,
        String description
) {
    public PolicyRule {
        conditions = conditions == null ? List.of() : List.copyOf(conditions);
    }
}
