package com.github.xingjianluo.admissionpolicyenginejava.exception;

import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestFailureReason;

/**
 * 本地输入装配失败异常：错误大类固定为 INVALID_INPUT，并携带细分原因。
 */
public class IngestException extends AdmissionException {

    private final IngestFailureReason reason;
    private final String source;

    public IngestException(IngestFailureReason reason, String source, String detail) {
        super(ErrorCategory.INVALID_INPUT,
                "[" + reason + "] " + (source == null ? "" : source + ": ") + detail);
        this.reason = reason;
        this.source = source;
    }

    public IngestFailureReason reason() {
        return reason;
    }

    public String source() {
        return source;
    }
}
