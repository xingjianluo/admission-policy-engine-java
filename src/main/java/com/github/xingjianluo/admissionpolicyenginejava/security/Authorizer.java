package com.github.xingjianluo.admissionpolicyenginejava.security;

import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.Permission;

/** 权限校验：未授权抛出 UNAUTHORIZED，与策略拒绝原因严格区分。 */
public interface Authorizer {

    void check(Caller caller, Permission permission);
}
