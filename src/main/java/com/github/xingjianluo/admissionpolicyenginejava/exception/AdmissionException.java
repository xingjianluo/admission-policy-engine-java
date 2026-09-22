package com.github.xingjianluo.admissionpolicyenginejava.exception;

/**
 * 本服务所有受检业务错误的基类（运行时异常），携带可区分的错误大类与细节原因。
 */
public class AdmissionException extends RuntimeException {

    private final ErrorCategory category;

    public AdmissionException(ErrorCategory category, String message) {
        super(message);
        this.category = category;
    }

    public AdmissionException(ErrorCategory category, String message, Throwable cause) {
        super(message, cause);
        this.category = category;
    }

    public ErrorCategory category() {
        return category;
    }
}
