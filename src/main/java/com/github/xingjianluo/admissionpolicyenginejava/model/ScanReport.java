package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;

/**
 * 统一后的镜像漏洞扫描结果。
 *
 * @param imageDigest 扫描所针对的镜像指纹（digest），用于与清单/证明交叉校验
 * @param scanner     扫描器名称与来源格式，便于审计追溯
 * @param vulnerabilities 漏洞列表（不含被静默丢弃的条目，读取阶段对畸形条目直接报错）
 */
public record ScanReport(String imageDigest,
                         String scanner,
                         List<Vulnerability> vulnerabilities) {
}
