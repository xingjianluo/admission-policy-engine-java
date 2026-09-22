package com.github.xingjianluo.admissionpolicyenginejava.web.dto;

/**
 * 策略更新请求：expectedVersion 为乐观并发条件，policyJson 为新策略文件内容。
 */
public record PolicyUpdateRequest(long expectedVersion,
                                  String policyJson,
                                  String comment) {
}
