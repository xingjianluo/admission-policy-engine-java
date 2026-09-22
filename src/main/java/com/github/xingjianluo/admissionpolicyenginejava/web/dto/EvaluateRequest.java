package com.github.xingjianluo.admissionpolicyenginejava.web.dto;

/**
 * 评估请求体：给出三类本地输入文件路径。
 */
public record EvaluateRequest(String requestId,
                              String manifestPath,
                              String scanPath,
                              String provenancePath) {
}
