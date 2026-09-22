package com.github.xingjianluo.admissionpolicyenginejava.security;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.Permission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * 基于角色的权限校验。
 * <ul>
 *   <li>READER：评估、读取策略</li>
 *   <li>AUDITOR：额外可读取审计</li>
 *   <li>ADMIN：全部权限（含策略更新与回滚）</li>
 * </ul>
 * 未授权统一抛出 {@link ErrorCode#UNAUTHORIZED}，与“策略判定拒绝(DENY)”
 * 使用完全不同的错误通道，原因可明确区分。
 */
@Component
public class RbacAuthorizer implements Authorizer {

    private static final Logger log = LoggerFactory.getLogger(RbacAuthorizer.class);

    static final String ROLE_READER = "READER";
    static final String ROLE_AUDITOR = "AUDITOR";
    static final String ROLE_ADMIN = "ADMIN";

    private static final Map<String, Set<Permission>> ROLE_PERMISSIONS = Map.of(
            ROLE_READER, EnumSet.of(Permission.EVALUATE, Permission.READ_POLICY),
            ROLE_AUDITOR, EnumSet.of(Permission.EVALUATE, Permission.READ_POLICY,
                    Permission.READ_AUDIT),
            ROLE_ADMIN, EnumSet.allOf(Permission.class)
    );

    @Override
    public void check(Caller caller, Permission permission) {
        if (caller == null || caller.name() == null || caller.name().isBlank()) {
            throw new AdmissionException(ErrorCode.UNAUTHORIZED,
                    "缺少调用方身份，拒绝访问: " + permission);
        }
        boolean granted = caller.roles() != null
                && caller.roles().stream()
                .filter(ROLE_PERMISSIONS::containsKey)
                .map(ROLE_PERMISSIONS::get)
                .anyMatch(perms -> perms.contains(permission));
        if (!granted) {
            log.warn("鉴权拒绝 caller={} permission={} roles={}",
                    caller.name(), permission, caller.roles());
            throw new AdmissionException(ErrorCode.UNAUTHORIZED,
                    "调用方 '" + caller.name() + "' 缺少权限 " + permission
                            + "（这是鉴权拒绝，不是策略判定拒绝）");
        }
        log.debug("鉴权通过 caller={} permission={}", caller.name(), permission);
    }
}
