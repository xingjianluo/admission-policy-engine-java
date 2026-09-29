package com.github.xingjianluo.admissionpolicyenginejava.ingest;

import java.util.List;

/**
 * 批量评估/预演中单个镜像项的原始输入（与单镜像评估同构：引用 + 工件列表）。
 */
public record BatchItemInput(
        String reference,
        List<RawArtifact> artifacts
) {
}
