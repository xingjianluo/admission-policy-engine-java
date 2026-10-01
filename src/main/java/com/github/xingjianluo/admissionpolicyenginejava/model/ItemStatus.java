package com.github.xingjianluo.admissionpolicyenginejava.model;

/** 批量中单个条目的处理状态。 */
public enum ItemStatus {
    /** 输入合法并已完成评估/预演。 */
    EVALUATED,
    /** 该条目输入不合法（只影响本项，不影响同批其他项）。 */
    INPUT_ERROR,
    /** 输入本身合法，但所用现网策略版本含非法条件参数（历史坏规则），无法对该项给出策略结论。 */
    POLICY_ERROR
}
