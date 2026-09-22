package com.github.xingjianluo.admissionpolicyenginejava.web;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.ApiError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;

/**
 * 全局异常映射。
 * <p>
 * 状态码约定：
 * <ul>
 *   <li>401：{@link ErrorCode#UNAUTHORIZED}（鉴权拒绝，与策略 DENY 区分）；</li>
 *   <li>409：{@link ErrorCode#POLICY_VERSION_CONFLICT}（并发更新冲突）；</li>
 *   <li>404：{@link ErrorCode#POLICY_VERSION_NOT_FOUND}；</li>
 *   <li>422：输入/格式/指纹/schema 类可归类错误（注意：这不是策略 DENY）；</li>
 *   <li>400：请求本身不合法。</li>
 * </ul>
 * 注意：策略判定为 DENY 是正常 200 响应体内的 decision 字段，不会走异常通道。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AdmissionException.class)
    public ResponseEntity<ApiError> handle(AdmissionException ex) {
        HttpStatus status = switch (ex.getCode()) {
            case UNAUTHORIZED -> HttpStatus.UNAUTHORIZED;
            case POLICY_VERSION_CONFLICT -> HttpStatus.CONFLICT;
            case POLICY_VERSION_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case INVALID_REQUEST -> HttpStatus.BAD_REQUEST;
            default -> HttpStatus.UNPROCESSABLE_ENTITY;
        };
        log.warn("请求被拒绝 httpStatus={} errorCode={} message={}",
                status.value(), ex.getCode(), ex.getMessage());
        return ResponseEntity.status(status).body(new ApiError(
                ex.getCode().name(), ex.getMessage(), Instant.now().toString()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleUnexpected(Exception ex) {
        log.error("未预期的内部错误", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiError(
                "INTERNAL_ERROR", "内部错误: " + ex.getMessage(), Instant.now().toString()));
    }
}
