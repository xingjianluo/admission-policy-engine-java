package com.github.xingjianluo.admissionpolicyenginejava.exception;

/**
 * 策略版本冲突：乐观并发条件不满足，或 schema 版本超出兼容范围。
 */
public class PolicyVersionException extends AdmissionException {

    private final long expectedVersion;
    private final long actualVersion;

    public PolicyVersionException(String message, long expectedVersion, long actualVersion) {
        super(ErrorCategory.VERSION_CONFLICT,
                message + " (expectedVersion=" + expectedVersion
                        + ", actualVersion=" + actualVersion + ")");
        this.expectedVersion = expectedVersion;
        this.actualVersion = actualVersion;
    }

    public long expectedVersion() { return expectedVersion; }
    public long actualVersion() { return actualVersion; }
}
