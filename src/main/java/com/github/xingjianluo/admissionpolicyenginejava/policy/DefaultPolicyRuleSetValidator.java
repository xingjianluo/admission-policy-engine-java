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
            frozen.add(rule);
        }
        return List.copyOf(frozen);
    }
}
