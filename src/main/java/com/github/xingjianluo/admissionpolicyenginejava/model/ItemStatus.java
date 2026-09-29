package com.github.xingjianluo.admissionpolicyenginejava.model;

/** 批量中单个条目的处理状态。 */
public enum ItemStatus {
    /** 输入合法并已完成评估/预演。 */
    EVALUATED,
    /** 该条目输入不合法（只影响本项，不影响同批其他条目）。 */
    INPUT_ERROR
}
