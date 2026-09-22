package com.github.xingjianluo.admissionpolicyenginejava.model;

/**
 * 统一评估输入：由本地镜像清单、扫描结果、供应链证明装配而成。
 * 三个组成部分均已通过读取阶段的格式校验，且 imageDigest 一致。
 *
 * @param requestId  调用方提供的请求编号，用于审计去重（幂等键）
 * @param metadata   镜像清单元数据
 * @param scan       漏洞扫描结果
 * @param provenance 供应链证明
 */
public record AdmissionRequest(String requestId,
                               ImageMetadata metadata,
                               ScanReport scan,
                               Provenance provenance) {
}
