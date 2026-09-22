package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.Set;

/**
 * 调用方主体及其角色。
 *
 * @param name  主体名
 * @param roles 角色集合（ADMIN / READER 等）
 */
public record Caller(String name, Set<String> roles) {

    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }
}
