package com.github.xingjianluo.admissionpolicyenginejava.error;

/** 领域内所有可归类错误的统一异常，携带可区分的 {@link ErrorCode}。 */
public class AdmissionException extends RuntimeException {

    private final ErrorCode code;

    public AdmissionException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public AdmissionException(ErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public ErrorCode getCode() {
        return code;
    }
}
