package com.github.xingjianluo.admissionpolicyenginejava.policy;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.Severity;

import java.util.EnumSet;
import java.util.Set;

/**
 * 条件参数规约：集中声明每种 {@link ConditionType} 对 value 的取值要求，
 * 供规则集校验（发布/预演共用）与评估期历史坏规则识别使用。
 * <p>
 * 取值归一化规则：所有字符串参数都会先 {@code trim()}；{@code SEVERITY_AT_LEAST}
 * 的阈值还会转大写后再判断，因此 {@code "high"}、{@code " High "} 与 {@code HIGH}
 * 等价。归一化只在校验通过后生效，非法输入永远不会被静默改写后放行。
 */
public final class ConditionParameters {

    /**
     * 允许作为 SEVERITY_AT_LEAST 阈值的严重级别。
     * 明确排除 {@link Severity#UNKNOWN}：UNKNOWN 表示扫描器未能定级，不允许作为策略档位。
     */
    public static final Set<Severity> ALLOWED_SEVERITY_THRESHOLDS =
            EnumSet.of(Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL);

    private ConditionParameters() {
    }

    /** 该条件是否需要非空参数。 */
    public static boolean requiresValue(ConditionType type) {
        return switch (type) {
            case SEVERITY_AT_LEAST,
                 REGISTRY_EQUALS, REGISTRY_NOT_EQUALS,
                 REPOSITORY_PREFIX,
                 BUILDER_ID_EQUALS, SOURCE_URI_PREFIX -> true;
            case PROVENANCE_PRESENT, PROVENANCE_MISSING,
                 SIGNATURE_VERIFIED, SIGNATURE_NOT_VERIFIED -> false;
        };
    }

    /**
     * 校验并归一化单个条件的参数；不合法时抛出 {@link ErrorCode#POLICY_RULESET_INVALID}。
     * <p>
     * 发布与预演共用本方法，保证“候选规则不合法”和“正式发布不合法”得到完全一致的判定。
     *
     * @param type   条件类型（非 null）
     * @param value  原始参数值
     * @param ruleId 所属规则 id（仅用于错误定位）
     * @return 归一化后的参数值；无参条件统一返回 null
     */
    public static String normalize(ConditionType type, String value, String ruleId) {
        if (type == ConditionType.SEVERITY_AT_LEAST) {
            return normalizeSeverity(value, ruleId).name();
        }
        if (!requiresValue(type)) {
            // 布尔型条件不需要参数；即使误填也不参与匹配，统一归一化为 null。
            return null;
        }
        if (value == null || value.isBlank()) {
            throw new AdmissionException(ErrorCode.POLICY_RULESET_INVALID,
                    "规则 " + ruleId + " 的条件 " + type + " 缺少必填参数 value");
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new AdmissionException(ErrorCode.POLICY_RULESET_INVALID,
                    "规则 " + ruleId + " 的条件 " + type + " 参数 value 不能为空白");
        }
        return trimmed;
    }

    /**
     * 解析严重级别阈值（大小写与首尾空格不敏感）；不合法（null/空白/非允许档位）时
     * 抛 {@link ErrorCode#POLICY_RULESET_INVALID}。评估期遇到历史坏规则也走同一判定，
     * 从而以可区分的 4xx 失败边界代替 500。
     */
    public static Severity normalizeSeverity(String value, String ruleId) {
        if (value == null || value.isBlank()) {
            throw new AdmissionException(ErrorCode.POLICY_RULESET_INVALID,
                    "规则 " + ruleId + " 的条件 SEVERITY_AT_LEAST 缺少必填参数 value"
                            + "（允许取值: LOW/MEDIUM/HIGH/CRITICAL）");
        }
        String normalized = value.trim().toUpperCase();
        final Severity threshold;
        try {
            threshold = Severity.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            throw new AdmissionException(ErrorCode.POLICY_RULESET_INVALID,
                    "规则 " + ruleId + " 的条件 SEVERITY_AT_LEAST 严重级别档位不合法: '"
                            + value + "'（允许取值: LOW/MEDIUM/HIGH/CRITICAL，"
                            + "大小写与首尾空格不敏感）");
        }
        if (!ALLOWED_SEVERITY_THRESHOLDS.contains(threshold)) {
            throw new AdmissionException(ErrorCode.POLICY_RULESET_INVALID,
                    "规则 " + ruleId + " 的条件 SEVERITY_AT_LEAST 严重级别档位不合法: '"
                            + value + "'（允许取值: LOW/MEDIUM/HIGH/CRITICAL，"
                            + "UNKNOWN 不能作为策略阈值）");
        }
        return threshold;
    }
}
