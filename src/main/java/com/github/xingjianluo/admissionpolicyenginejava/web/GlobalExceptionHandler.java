package com.github.xingjianluo.admissionpolicyenginejava.web;

import com.github.xingjianluo.admissionpolicyenginejava.exception.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.exception.ErrorCategory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * 统一错误响应：HTTP 状态码 + errorCategory，调用方可区分
 * INVALID_INPUT / UNAUTHORIZED / VERSION_CONFLICT / POLICY_DENIED。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AdmissionException.class)
    public ResponseEntity<Map<String, Object>> handleAdmission(AdmissionException e) {
        ErrorCategory category = e.category();
        int httpStatus = switch (category) {
            case UNAUTHORIZED, POLICY_DENIED -> 403;
            case VERSION_CONFLICT -> 409;
            case INVALID_INPUT -> 422;
        };
        return ResponseEntity.status(httpStatus).body(Map.of(
                "errorCategory", category.name(),
                "message", e.getMessage() == null ? "" : e.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleOther(Exception e) {
        return ResponseEntity.status(500).body(Map.of(
                "errorCategory", "INTERNAL_ERROR",
                "message", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
    }
}
