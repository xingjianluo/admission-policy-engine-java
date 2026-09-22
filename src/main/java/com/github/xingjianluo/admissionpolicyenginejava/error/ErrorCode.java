package com.github.xingjianluo.admissionpolicyenginejava.error;

/**
 * 可区分的拒绝/失败原因分类。
 * 输入类错误（4xx 数据问题）、鉴权类错误、策略版本类错误各自独立，
 * 便于调用方与审计记录区分“策略拒绝”和“请求本身非法/未授权”。
 */
public enum ErrorCode {
    /** 工件内容无法按声明格式解析。 */
    MALFORMED_ARTIFACT,
    /** 已解析工件缺少必填字段。 */
    MISSING_REQUIRED_FIELD,
    /** 缺少必需的工件类别（例如只有清单没有任何来源工件）。 */
    INCOMPLETE_ARTIFACT_SET,
    /** 不同工件对同一镜像声明的指纹（digest）不一致。 */
    FINGERPRINT_MISMATCH,
    /** 调用方无权限执行该操作——与策略拒绝严格区分。 */
    UNAUTHORIZED,
    /** 提交更新时基于的策略版本已过期（并发冲突）。 */
    POLICY_VERSION_CONFLICT,
    /** 策略规则的 schemaVersion 不在本引擎兼容范围内。 */
    POLICY_SCHEMA_UNSUPPORTED,
    /** 回dump目标版本不存在。 */
    POLICY_VERSION_NOT_FOUND,
    /** 请求参数本身不合法。 */
    INVALID_REQUEST
}
