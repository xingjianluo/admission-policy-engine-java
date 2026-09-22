package com.github.xingjianluo.admissionpolicyenginejava.ingest;

import java.util.List;

/** 一次准入请求提交的全部本地工件。 */
public record IngestionRequest(
        String reference,
        List<RawArtifact> artifacts
) {
}
