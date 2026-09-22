package com.github.xingjianluo.admissionpolicyenginejava.auth;

import com.github.xingjianluo.admissionpolicyenginejava.exception.AuthorizationException;
import org.springframework.stereotype.Service;

/**
 * 权限校验：不满足时抛出 AuthorizationException（错误大类 UNAUTHORIZED），
 * 与策略拒绝（DENY）明确区分。
 */
@Service
public class AuthorizationService {

    public void check(ActorContext actor, Permission permission, String action) {
        if (actor == null || !actor.role().has(permission)) {
            String actorId = actor == null ? "<anonymous>" : actor.actorId();
            throw new AuthorizationException(actorId, permission.name(), action);
        }
    }
}
