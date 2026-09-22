package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditRecord;
import com.github.xingjianluo.admissionpolicyenginejava.auth.ActorContext;
import com.github.xingjianluo.admissionpolicyenginejava.auth.Role;
import com.github.xingjianluo.admissionpolicyenginejava.exception.AuthorizationException;
import com.github.xingjianluo.admissionpolicyenginejava.exception.ErrorCategory;
import com.github.xingjianluo.admissionpolicyenginejava.service.AdmissionService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 权限校验测试：未授权必须拒绝，且错误大类 UNAUTHORIZED 与策略 DENY、
 * INVALID_INPUT 可区分；拒绝事件同样进入审计。
 */
@SpringBootTest
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
class UnauthorizedAccessTest {

    private static final Logger log = LoggerFactory.getLogger(UnauthorizedAccessTest.class);

    @Autowired
    private AdmissionService service;

    private final ActorContext serviceAccount =
            new ActorContext("sa-1", Role.SERVICE_ACCOUNT);
    private final ActorContext auditor = new ActorContext("auditor-1", Role.AUDITOR);
    private final ActorContext admin = new ActorContext("admin-3", Role.ADMIN);

    @Test
    void serviceAccountCannotUpdatePolicy() {
        String policy = "{\"schemaVersion\":1,\"rules\":[]}";
        AuthorizationException e = assertThrows(AuthorizationException.class,
                () -> service.updatePolicy(serviceAccount,
                        service.currentPolicy(admin).version(), policy, "forbidden attempt"));
        log.warn("[CASE] unauthorized update: category={} message={}",
                e.category(), e.getMessage());
        assertEquals(ErrorCategory.UNAUTHORIZED, e.category());
        assertEquals("UPDATE_POLICY", e.requiredPermission());
    }

    @Test
    void serviceAccountCannotRollbackPolicy() {
        AuthorizationException e = assertThrows(AuthorizationException.class,
                () -> service.rollbackPolicy(serviceAccount,
                        service.currentPolicy(admin).version(), 0L));
        assertEquals(ErrorCategory.UNAUTHORIZED, e.category());
        assertEquals("ROLLBACK_POLICY", e.requiredPermission());
        log.warn("[CASE] unauthorized rollback: {}", e.getMessage());
    }

    @Test
    void serviceAccountCannotReadAudit() {
        AuthorizationException e = assertThrows(AuthorizationException.class,
                () -> service.auditTrail(serviceAccount));
        assertEquals(ErrorCategory.UNAUTHORIZED, e.category());
        log.warn("[CASE] unauthorized audit read: {}", e.getMessage());
    }

    @Test
    void serviceAccountCanEvaluate(@TempDir Path dir) throws Exception {
        var bundle = TestFixtures.validBundle(dir, "MEDIUM");
        var result = service.evaluate(serviceAccount, "req-authz-ok",
                bundle.manifest(), bundle.scan(), bundle.provenance());
        log.info("[CASE] authorized evaluate by service account: decision={}",
                result.decision());
        // MEDIUM 镜像：默认策略 DENY-CRITICAL 不命中，ALLOW-LOW-RISK 命中
        assertEquals(com.github.xingjianluo.admissionpolicyenginejava.model.Decision.ALLOW,
                result.decision());
    }

    @Test
    void auditorCanReadAuditButCannotUpdatePolicy() {
        assertDoesNotThrowAuditRead();
        String policy = "{\"schemaVersion\":1,\"rules\":[]}";
        AuthorizationException e = assertThrows(AuthorizationException.class,
                () -> service.updatePolicy(auditor,
                        service.currentPolicy(admin).version(), policy, "auditor attempt"));
        assertEquals(ErrorCategory.UNAUTHORIZED, e.category());
        log.warn("[CASE] auditor update rejected: {}", e.getMessage());
    }

    @Test
    void unauthorizedAttemptsAreAuditedAndDistinguishable() {
        List<AuditRecord> before = service.auditTrail(admin);
        assertThrows(AuthorizationException.class,
                () -> service.auditTrail(serviceAccount));
        List<AuditRecord> after = service.auditTrail(admin);
        assertTrue(after.size() > before.size(), "unauthorized attempt must be audited");
        AuditRecord latest = after.get(after.size() - 1);
        assertEquals("UNAUTHORIZED", latest.operation());
        assertEquals(ErrorCategory.UNAUTHORIZED, latest.errorCategory());
        log.info("[CASE] audit record for denial: op={} actor={} category={}",
                latest.operation(), latest.actorId(), latest.errorCategory());
    }

    private void assertDoesNotThrowAuditRead() {
        List<AuditRecord> records = service.auditTrail(auditor);
        log.info("[CASE] auditor read audit rows={}", records.size());
    }
}
