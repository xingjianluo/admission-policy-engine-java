package com.github.xingjianluo.admissionpolicyenginejava.exception;

/**
 * 错误大类。保证“输入非法”“策略拒绝”“未授权”这三类原因可被明确区分。
 */
public enum ErrorCategory {
    /** 输入数据畸形：字段缺失、指纹不一致、格式不完整、版本不兼容。 */
    INVALID_INPUT,
    /** 策略判定结果为拒绝（属于正常业务结论，不是错误，仅在需要以异常表达时使用）。 */
    POLICY_DENIED,
    /** 调用方无权限执行该操作。 */
    UNAUTHORIZED,
    /** 策略版本冲突或快照过期（并发更新）。 */
    VERSION_CONFLICT
}
