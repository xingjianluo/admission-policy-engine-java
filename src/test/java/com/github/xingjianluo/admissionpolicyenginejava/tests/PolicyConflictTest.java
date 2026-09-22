package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.auth.ActorContext;
import com.github.xingjianluo.admissionpolicyenginejava.auth.Role;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.EvaluationResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicySet;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 策略冲突与优先级覆盖测试。
 */
@SpringBootTest
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
class PolicyConflictTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyConflictTest.class);

    @Autowired
    private AdmissionService service;

    private final ActorContext admin = new ActorContext("admin-1", Role.ADMIN);

    private long currentVersion() {
        return service.currentPolicy(admin).version();
    }

    /** DENY(p100) 与 ALLOW(p10) 同时命中：DENY 生效。 */
    @Test
    void explicitDenyOverridesLowerPriorityAllow(@TempDir Path dir) throws Exception {
        var bundle = TestFixtures.validBundle(dir, "CRITICAL");
        String policy = """
                {"schemaVersion": 1, "rules": [
                  {"id":"ALLOW-ALL","name":"allow-all","effect":"ALLOW","priority":10,
                   "description":"all allowed"},
                  {"id":"DENY-CRIT","name":"deny-critical","effect":"DENY","priority":100,
                   "denyIfSeverityAtLeast":"CRITICAL",
                   "description":"critical cves are denied"}
                ]}
                """;
        PolicySet v1 = service.updatePolicy(admin, currentVersion(), policy, "conflict setup");

        EvaluationResult result = service.evaluate(admin, "req-conflict-1",
                bundle.manifest(), bundle.scan(), bundle.provenance());

        log.info("[CASE] request=req-conflict-1 policyVersion={} decision={} hits={} rationale={}",
                result.policyVersion(), result.decision(),
                result.hits().stream().map(h -> h.ruleId() + "/" + h.effect()).toList(),
                result.rationale());

        assertEquals(Decision.DENY, result.decision());
        assertEquals("DENY-CRIT", result.decisiveRuleId());
        assertEquals(v1.version(), result.policyVersion());
        assertTrue(result.hits().size() >= 2, "both rules should be reported as hits");
    }

    /** 同优先级 ALLOW 与 DENY 冲突：DENY 优先，且不依赖规则文件中的书写顺序。 */
    @Test
    void samePriorityDenyWinsRegardlessOfOrder(@TempDir Path dir) throws Exception {
        var bundle = TestFixtures.validBundle(dir, "HIGH");
        String policy = """
                {"schemaVersion": 1, "rules": [
                  {"id":"ALLOW-X","name":"allow-x","effect":"ALLOW","priority":50,
                   "maxAllowedSeverity":"HIGH","description":"allow up to high"},
                  {"id":"DENY-X","name":"deny-x","effect":"DENY","priority":50,
                   "denyIfSeverityAtLeast":"HIGH","description":"deny high and above"}
                ]}
                """;
        service.updatePolicy(admin, currentVersion(), policy, "same priority conflict");

        EvaluationResult result = service.evaluate(admin, "req-conflict-2",
                bundle.manifest(), bundle.scan(), bundle.provenance());

        log.info("[CASE] request=req-conflict-2 decision={} decisive={} rationale={}",
                result.decision(), result.decisiveRuleId(), result.rationale());

        assertEquals(Decision.DENY, result.decision());
        assertEquals("DENY-X", result.decisiveRuleId());
    }

    /** 高优先级 ALLOW 覆盖低优先级 DENY。 */
    @Test
    void higherPriorityAllowOverridesLowerDeny(@TempDir Path dir) throws Exception {
        var bundle = TestFixtures.validBundle(dir, "MEDIUM");
        // 低优先级 DENY 实际不会命中（MEDIUM 未达 HIGH），因此加一条命中的低优先级 DENY：
        // 用 registry 无限制的 DENY(p1) + 高危无关，改为“所有镜像 DENY(p1)”
        String policy = """
                {"schemaVersion": 1, "rules": [
                  {"id":"DENY-ALL-LOW","name":"deny-all-low","effect":"DENY","priority":1,
                   "description":"broad low-priority deny"},
                  {"id":"ALLOW-MED-HIGH","name":"allow-medium","effect":"ALLOW","priority":90,
                   "maxAllowedSeverity":"MEDIUM","description":"medium images allowed"}
                ]}
                """;
        service.updatePolicy(admin, currentVersion(), policy, "priority override");

        EvaluationResult result = service.evaluate(admin, "req-conflict-3",
                bundle.manifest(), bundle.scan(), bundle.provenance());

        log.info("[CASE] request=req-conflict-3 decision={} decisive={} hits={}",
                result.decision(), result.decisiveRuleId(),
                result.hits().stream().map(h -> h.ruleId() + "/p" + h.priority()).toList());

        assertEquals(Decision.ALLOW, result.decision());
        assertEquals("ALLOW-MED-HIGH", result.decisiveRuleId());
    }

    /** 无任何规则命中：默认拒绝 DENY_NO_MATCH。 */
    @Test
    void denyByDefaultWhenNothingMatches(@TempDir Path dir) throws Exception {
        var bundle = TestFixtures.validBundle(dir, "LOW");
        String policy = """
                {"schemaVersion": 1, "rules": [
                  {"id":"ALLOW-OTHER-REGISTRY","name":"allow-other","effect":"ALLOW",
                   "priority":10,"registries":["gcr.io"],"description":"only gcr.io"}
                ]}
                """;
        service.updatePolicy(admin, currentVersion(), policy, "no match setup");

        EvaluationResult result = service.evaluate(admin, "req-conflict-4",
                bundle.manifest(), bundle.scan(), bundle.provenance());

        log.info("[CASE] request=req-conflict-4 decision={} rationale={}",
                result.decision(), result.rationale());

        assertEquals(Decision.DENY_NO_MATCH, result.decision());
        assertNotNull(result.rationale());
        assertTrue(result.hits().isEmpty());
    }

    /** 同一输入连续两次评估，结论与命中依据必须完全一致（可复现）。 */
    @Test
    void decisionsAreReproducible(@TempDir Path dir) throws Exception {
        var bundle = TestFixtures.validBundle(dir, "MEDIUM");
        EvaluationResult first = service.evaluate(admin, "req-conflict-5",
                bundle.manifest(), bundle.scan(), bundle.provenance());
        EvaluationResult second = service.evaluate(admin, "req-conflict-5",
                bundle.manifest(), bundle.scan(), bundle.provenance());

        assertEquals(first.decision(), second.decision());
        assertEquals(first.decisiveRuleId(), second.decisiveRuleId());
        assertEquals(first.rationale(), second.rationale());
        assertEquals(List.copyOf(first.hits()), List.copyOf(second.hits()));
    }
}
