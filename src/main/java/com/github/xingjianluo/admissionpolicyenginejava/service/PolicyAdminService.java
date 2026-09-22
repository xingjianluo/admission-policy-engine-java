package com.github.xingjianluo.admissionpolicyenginejava.service;

import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;

import java.util.List;

/** 策略管理应用服务：封装权限校验、版本发布/回滚与审计。 */
public interface PolicyAdminService {

    PolicySnapshot update(Caller caller, long expectedBaseVersion, List<PolicyRule> rules, String comment);

    PolicySnapshot rollback(Caller caller, long targetVersion);

    PolicySnapshot current(Caller caller);

    List<PolicySnapshot> history(Caller caller);
}
