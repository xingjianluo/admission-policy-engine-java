package com.github.xingjianluo.admissionpolicyenginejava.web.dto;

/**
 * 策略回滚请求：expectedVersion 为乐观并发条件，targetVersion 为历史版本号。
 */
public record RollbackRequest(long expectedVersion,
                              long targetVersion) {
}
