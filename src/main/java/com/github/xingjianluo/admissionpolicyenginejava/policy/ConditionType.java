package com.github.xingjianluo.admissionpolicyenginejava.policy;

/**
 * 规则匹配条件类型。一条规则的全部条件之间为 AND；
 * 条件全部匹配时规则命中并产生其 effect。
 * <p>
 * 同时提供正向（EQUALS/PRESENT/VERIFIED）与反向（NOT_EQUALS/MISSING/NOT_VERIFIED）
 * 条件，使 DENY 护栏（“坏镜像命中”）与 ALLOW 豁免（“好镜像命中”）都能直接表达。
 */
public enum ConditionType {
    /** 存在严重级别 &gt;= value(枚举名) 的漏洞时匹配 */
    SEVERITY_AT_LEAST,
    /** registry 等于 value 时匹配 */
    REGISTRY_EQUALS,
    /** registry 不等于 value 时匹配 */
    REGISTRY_NOT_EQUALS,
    /** repository 以 value 为前缀时匹配 */
    REPOSITORY_PREFIX,
    /** 提供了供应链证明时匹配 */
    PROVENANCE_PRESENT,
    /** 缺少供应链证明时匹配 */
    PROVENANCE_MISSING,
    /** 存在签名工件且校验通过时匹配 */
    SIGNATURE_VERIFIED,
    /** 无签名工件或校验未通过时匹配 */
    SIGNATURE_NOT_VERIFIED,
    /** provenance.builderId 等于 value 时匹配 */
    BUILDER_ID_EQUALS,
    /** provenance.sourceUri 以 value 为前缀时匹配 */
    SOURCE_URI_PREFIX
}
