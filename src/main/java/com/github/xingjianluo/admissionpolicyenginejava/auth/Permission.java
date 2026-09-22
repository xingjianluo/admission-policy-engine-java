package com.github.xingjianluo.admissionpolicyenginejava.auth;

/**
 * 受权限校验保护的操作。
 */
public enum Permission {
    /** 提交镜像进行准入评估。 */
    EVALUATE,
    /** 更新策略集合。 */
    UPDATE_POLICY,
    /** 回滚策略集合。 */
    ROLLBACK_POLICY,
    /** 查询审计记录。 */
    READ_AUDIT
}
