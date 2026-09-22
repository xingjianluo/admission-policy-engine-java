package com.github.xingjianluo.admissionpolicyenginejava.ingest;

/**
 * 调用方提交的单个原始工件。
 *
 * @param kind   工件类别
 * @param format 工件格式标识，如 OCI-MANIFEST / SIMPLE-MANIFEST /
 *               CYCLONEDX-JSON / SIMPLE-SCAN / SLSA-V1-JSON / SIGNOTE-JSON / SIMPLE-SIGNATURE
 * @param content 文本内容（JSON 或 properties 风格）
 */
public record RawArtifact(
        ArtifactKind kind,
        String format,
        String content
) {
}
