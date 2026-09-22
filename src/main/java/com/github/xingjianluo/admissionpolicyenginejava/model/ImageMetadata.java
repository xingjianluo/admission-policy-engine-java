package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;

/**
 * 统一后的镜像清单元数据。
 *
 * @param reference    用户请求的镜像引用（name:tag）
 * @param digest       镜像内容指纹（sha256:...），指纹一致性校验的基准
 * @param registry     所属仓库地址
 * @param repository   仓库内路径
 * @param tag          标签
 * @param mediaTypes   本地清单格式（如 v2 manifest、OCI index），用于可解释性
 * @param labels       镜像标签键值
 */
public record ImageMetadata(String reference,
                            String digest,
                            String registry,
                            String repository,
                            String tag,
                            List<String> mediaTypes,
                            java.util.Map<String, String> labels) {
}
