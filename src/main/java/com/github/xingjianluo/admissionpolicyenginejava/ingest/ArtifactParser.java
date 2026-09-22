package com.github.xingjianluo.admissionpolicyenginejava.ingest;

import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;

/**
 * 工件解析器：把一批异构本地工件归一化为 {@link ImageDescriptor}。
 * 字段缺失、指纹不一致或格式不完整必须抛出可区分的 AdmissionException，
 * 绝不允许静默跳过。
 */
public interface ArtifactParser {

    ImageDescriptor parse(IngestionRequest request);
}
