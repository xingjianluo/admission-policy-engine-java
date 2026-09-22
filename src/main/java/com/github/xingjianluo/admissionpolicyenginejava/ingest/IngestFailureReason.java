package com.github.xingjianluo.admissionpolicyenginejava.ingest;

/**
 * 本地输入装配阶段的失败原因细分，与策略拒绝、未授权明确区分。
 */
public enum IngestFailureReason {
    /** 文件不存在或无法读取。 */
    UNREADABLE_FILE,
    /** JSON 语法错误。 */
    MALFORMED_JSON,
    /** 清单格式未知 / mediaType 不支持。 */
    UNSUPPORTED_MANIFEST_FORMAT,
    /** 必填字段缺失（digest、reference、sourceUri 等）。 */
    MISSING_REQUIRED_FIELD,
    /** 漏洞/证明条目自身字段不完整（绝不静默跳过）。 */
    INCOMPLETE_ENTRY,
    /** 清单、扫描、证明三处镜像指纹不一致。 */
    FINGERPRINT_MISMATCH,
    /** 指纹格式非法（非 sha256: 前缀）。 */
    ILLEGAL_DIGEST_FORMAT,
    /** SLSA 等级等枚举值无法解析。 */
    ILLEGAL_ENUM_VALUE,
    /** 缺少三类输入中的某一类。 */
    MISSING_SOURCE
}
