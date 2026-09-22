package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;

/**
 * 供应链证明（SLSA 风格）。
 *
 * @param builderId      构建方标识
 * @param sourceUri      源码来源 URI
 * @param sourceRevision 源码修订标识
 * @param attestation    证明载荷原文（便于审计留痕）
 */
public record Provenance(
        String builderId,
        String sourceUri,
        String sourceRevision,
        List<String> materials,
        String attestation
) {
}
