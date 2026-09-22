package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;

/**
 * 镜像供应链证明（SLSA 风格，本地模拟）。
 *
 * @param imageDigest      证明绑定的镜像指纹
 * @param sourceUri        源码来源（如 git 仓库地址）
 * @param sourceRevision   源码版本（commit）
 * @param builderId        构建方标识
 * @param buildSlsaLevel   SLSA 等级（0-3），缺失/非法时由读取方报错
 * @param attestationDigest 证明自身的指纹（用于交叉校验，不能为空）
 * @param materials        构建物料摘要列表
 */
public record Provenance(String imageDigest,
                         String sourceUri,
                         String sourceRevision,
                         String builderId,
                         int buildSlsaLevel,
                         String attestationDigest,
                         List<String> materials) {
}
