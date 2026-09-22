package com.github.xingjianluo.admissionpolicyenginejava.model;

/**
 * 漏洞严重级别。顺序即严重程度，可用于“最高级别”比较。
 */
public enum Severity {
    UNKNOWN,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
