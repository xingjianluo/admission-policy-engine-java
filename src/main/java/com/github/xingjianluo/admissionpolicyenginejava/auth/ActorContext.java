package com.github.xingjianluo.admissionpolicyenginejava.auth;

/**
 * 一次调用的调用方身份（本地模拟 HTTP 头解析结果）。
 */
public record ActorContext(String actorId, Role role) {

    public ActorContext {
        if (actorId == null || actorId.isBlank()) {
            throw new IllegalArgumentException("actorId must not be blank");
        }
        if (role == null) {
            throw new IllegalArgumentException("role must not be null");
        }
    }
}
