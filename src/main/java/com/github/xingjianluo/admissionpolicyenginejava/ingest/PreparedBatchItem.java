package com.github.xingjianluo.admissionpolicyenginejava.ingest;

/**
 * 进入应用服务之前已准备好的单个批量项：
 * 要么是可解析的 {@link BatchItemInput}，要么携带该项自身的结构错误（错误码 + 原因）。
 * 单项结构错误只标记该项，绝不阻断整批其余项。
 */
public record PreparedBatchItem(BatchItemInput input, String errorCode, String errorMessage) {

    public static PreparedBatchItem of(BatchItemInput input) {
        return new PreparedBatchItem(input, null, null);
    }

    public static PreparedBatchItem invalid(String errorCode, String errorMessage) {
        return new PreparedBatchItem(null, errorCode, errorMessage);
    }

    public boolean valid() {
        return input != null;
    }
}
