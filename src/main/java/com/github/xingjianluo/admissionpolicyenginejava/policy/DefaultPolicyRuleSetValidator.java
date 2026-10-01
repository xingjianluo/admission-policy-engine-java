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
 * {@link PolicyStore#SUPPORTED_SCHEMA_MAX}）、以及每条规则内条件参数不合法
 * （严重级别阈值不在 LOW/MEDIUM/HIGH/CRITICAL 内、需要参数的条件缺参数、
 * 无参条件携带参数、参数格式不对、null 条件条目等）都会拒绝整批并返回
 * 与发布一致的错误码。参数规约见 {@link ConditionParameters}。
 * 通过校验后返回不可变列表。
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
        List<String> parameterViolations = new ArrayList<>();
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
            for (int i = 0; i < rule.conditions().size(); i++) {
                PolicyCondition condition = rule.conditions().get(i);
                if (condition == null) {
                    parameterViolations.add(
                            "规则 " + rule.id() + " 的第 " + i + " 个条件为 null");
                    continue;
                }
                try {
                    ConditionParameters.validate(condition.type(), condition.value());
                } catch (IllegalArgumentException e) {
                    parameterViolations.add("规则 " + rule.id() + " 的第 " + i
                            + " 个条件参数非法（type=" + condition.type()
                            + ", value=" + condition.value() + "）: " + e.getMessage());
                }
            }
            frozen.add(rule);
        }
        if (!parameterViolations.isEmpty()) {
            throw new AdmissionException(ErrorCode.POLICY_RULESET_INVALID,
                    "规则集不合法：共发现 " + parameterViolations.size()
                            + " 处条件参数违规；" + String.join("；", parameterViolations));
        }
        return List.copyOf(frozen);
    }
}
