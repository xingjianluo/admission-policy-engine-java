package com.github.xingjianluo.admissionpolicyenginejava.exception;

/**
 * 未授权操作异常，与策略拒绝原因可区分。
 */
public class AuthorizationException extends AdmissionException {

    private final String requiredPermission;

    public AuthorizationException(String actor, String requiredPermission, String action) {
        super(ErrorCategory.UNAUTHORIZED,
                "actor '" + actor + "' is not permitted to " + action
                        + " (requires permission " + requiredPermission + ")");
        this.requiredPermission = requiredPermission;
    }

    public String requiredPermission() {
        return requiredPermission;
    }
}
