package com.github.xingjianluo.admissionpolicyenginejava.policy;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * 规则集校验器默认实现。
 * <p>
 * 规则与正式发布走完全相同的检查：null 条目、缺 id、同版本内 id 重复、缺 effect、
 * schemaVersion 越界（{@link PolicyStore#SUPPORTED_SCHEMA_MIN}~
 * {@link PolicyStore#SUPPORTED_SCHEMA_MAX}）都会拒绝整批并返回与发布一致的错误码。
 * 此外还逐条校验<strong>条件参数</strong>：需要参数的条件缺参数、参数格式不对、
 * {@code SEVERITY_AT_LEAST} 档位不在 LOW/MEDIUM/HIGH/CRITICAL 内，整份规则集都按
 * “规则集不合法”（{@link ErrorCode#POLICY_RULESET_INVALID}）拒绝。
 * 通过校验后，条件参数按规约归一化（trim；严重级别转大写）并冻结为不可变列表。
 */
@Component
public class DefaultPolicyRuleSetValidator implements PolicyRuleSetValidator {

    @Override
    public List<PolicyRule> validateAndFreeze(List<PolicyRule> rules) {
        if (rules == null) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "规则列表不能为 null");
        }
        if (rules.isEmpty()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "规则列表不能为空");
        }
        List<PolicyRule> frozen = new ArrayList<>(rules.size());
        HashSet<String> ids = new HashSet<>();
        for (PolicyRule rule : rules) {
            if (rule == null) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST, "规则列表中不允许 null 条目");
            }
            if (rule.id() == null || rule.id().isBlank()) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST, "规则缺少 id");
            }
            if (!ids.add(rule.id())) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                        "规则 id 在同一版本内重复: " + rule.id());
            }
            if (rule.effect() == null) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                        "规则 " + rule.id() + " 缺少 effect(ALLOW/DENY)");
            }
            if (rule.schemaVersion() < PolicyStore.SUPPORTED_SCHEMA_MIN
                    || rule.schemaVersion() > PolicyStore.SUPPORTED_SCHEMA_MAX) {
                throw new AdmissionException(ErrorCode.POLICY_SCHEMA_UNSUPPORTED,
                        "规则 " + rule.id() + " 的 schemaVersion=" + rule.schemaVersion()
                                + " 不在兼容范围 [" + PolicyStore.SUPPORTED_SCHEMA_MIN + ", "
                                + PolicyStore.SUPPORTED_SCHEMA_MAX + "] 内");
            }
            frozen.add(normalizeConditions(rule));
        }
        return List.copyOf(frozen);
    }

    /**
     * 校验单条规则的全部条件参数，并用归一化后的参数重建不可变规则。
     * 任何一个条件参数不合法都抛 POLICY_RULESET_INVALID，拒绝整份规则集。
     */
    private PolicyRule normalizeConditions(PolicyRule rule) {
        List<PolicyCondition> source = rule.conditions();
        List<PolicyCondition> normalized = new ArrayList<>(source.size());
        for (PolicyCondition c : source) {
            if (c == null) {
                throw new AdmissionException(ErrorCode.POLICY_RULESET_INVALID,
                        "规则 " + rule.id() + " 的条件列表中不允许 null 条目");
            }
            String value = ConditionParameters.normalize(c.type(), c.value(), rule.id());
            normalized.add(new PolicyCondition(c.type(), value));
        }
        return new PolicyRule(rule.id(), rule.priority(), rule.effect(), rule.schemaVersion(),
                List.copyOf(normalized), rule.description());
    }
}
