package com.github.xingjianluo.admissionpolicyenginejava.auth;

import java.util.EnumSet;
import java.util.Set;

/**
 * 调用方角色及其持有的权限集合。
 */
public enum Role {
    /** 平台管理员：全部权限。 */
    ADMIN(EnumSet.allOf(Permission.class)),
    /** 安全工程师：评估、策略更新/回滚。 */
    SECURITY_ENGINEER(EnumSet.of(Permission.EVALUATE,
            Permission.UPDATE_POLICY, Permission.ROLLBACK_POLICY)),
    /** 只读审计员：评估与查看审计。 */
    AUDITOR(EnumSet.of(Permission.EVALUATE, Permission.READ_AUDIT)),
    /** 普通服务账号：仅可提交评估。 */
    SERVICE_ACCOUNT(EnumSet.of(Permission.EVALUATE));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public boolean has(Permission permission) {
        return permissions.contains(permission);
    }
}
