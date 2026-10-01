package com.github.xingjianluo.admissionpolicyenginejava.policy;

import com.github.xingjianluo.admissionpolicyenginejava.model.Severity;

/**
 * 各 {@link ConditionType} 对条件参数 {@code value} 的取值规约。
 * <p>
 * 发布/预演入口的规则集校验与评估期对历史坏规则的识别共用本规约，保证
 * “什么叫参数合法”只有一处定义、两处口径完全一致。
 */
public final class ConditionParameters {

    private ConditionParameters() {
    }

    /**
     * 该条件类型是否需要 value 参数（非 null 且非空白）。
     * 无参条件（PROVENANCE_* / SIGNATURE_*）返回 false，携带参数即视为非法。
     */
    public static boolean requiresValue(ConditionType type) {
        return switch (type) {
            case PROVENANCE_PRESENT, PROVENANCE_MISSING,
                 SIGNATURE_VERIFIED, SIGNATURE_NOT_VERIFIED -> false;
            case SEVERITY_AT_LEAST, REGISTRY_EQUALS, REGISTRY_NOT_EQUALS,
                 REPOSITORY_PREFIX, BUILDER_ID_EQUALS, SOURCE_URI_PREFIX -> true;
        };
    }

    /**
     * 校验单个条件的参数是否合法；不合法抛出 {@link IllegalArgumentException}，
     * 消息中携带条件类型与具体原因，便于定位到规则与条件。
     *
     * @param type  条件类型
     * @param value 条件参数（允许 null）
     */
    public static void validate(ConditionType type, String value) {
        boolean required = requiresValue(type);
        boolean blank = value == null || value.isBlank();
        if (required && blank) {
            throw new IllegalArgumentException(
                    "条件 " + type + " 需要非空参数 value，但实际缺失");
        }
        if (!required && !blank) {
            throw new IllegalArgumentException(
                    "条件 " + type + " 不接受参数 value（无参条件），但实际传入: " + value);
        }
        if (required) {
            switch (type) {
                case SEVERITY_AT_LEAST -> parseSeverity(type, value);
                case REGISTRY_EQUALS, REGISTRY_NOT_EQUALS, REPOSITORY_PREFIX,
                     BUILDER_ID_EQUALS, SOURCE_URI_PREFIX -> {
                    // 任意非空白字符串均为合法取值（比较时做精确/前缀匹配）。
                }
                default -> throw new IllegalStateException("未覆盖的参数条件类型: " + type);
            }
        }
    }

    /**
     * 解析 SEVERITY_AT_LEAST 的阈值。
     * 允许大小写差异与首尾空格差异（如 " high "、"CrItIcAl" 归一化为 HIGH/CRITICAL）；
     * 其他词（含 UNKNOWN）一律拒绝。
     */
    public static Severity parseSeverity(ConditionType type, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    "条件 " + type + " 需要非空参数 value，但实际缺失");
        }
        String normalized = value.trim().toUpperCase();
        if ("UNKNOWN".equals(normalized)) {
            throw new IllegalArgumentException(
                    "条件 " + type + " 的严重级别阈值不允许为 UNKNOWN，"
                            + "允许取值: LOW/MEDIUM/HIGH/CRITICAL（不区分大小写、可带首尾空格）");
        }
        try {
            return Severity.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "条件 " + type + " 的严重级别阈值无法识别: " + value
                            + "，允许取值: LOW/MEDIUM/HIGH/CRITICAL"
                            + "（不区分大小写、可带首尾空格）");
        }
    }
}
