package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.DecisionReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;
import com.github.xingjianluo.admissionpolicyenginejava.model.MatchedRule;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.Provenance;
import com.github.xingjianluo.admissionpolicyenginejava.model.Severity;
import com.github.xingjianluo.admissionpolicyenginejava.model.Vulnerability;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.DefaultPolicyEvaluator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 策略评估测试：显式 ALLOW/DENY 冲突、优先级覆盖、同优先级 tie-break、
 * 默认拒绝，以及同一输入多次评估结论可复现。
 */
class PolicyEvaluatorTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyEvaluatorTest.class);

    private final DefaultPolicyEvaluator evaluator = new DefaultPolicyEvaluator();

    private ImageDescriptor image(Severity worst, String registry, boolean provenance,
                                  Boolean signatureValid) {
        List<Vulnerability> vulns = worst == null ? List.of()
                : List.of(new Vulnerability("CVE-1", worst, "pkg"));
        Provenance p = provenance
                ? new Provenance("builder-1", "git+https://git.internal/x", "rev", List.of(), "{}")
                : null;
        return new ImageDescriptor(registry + "/x:1", "sha256:aaa", registry, "x", "1",
                vulns, p, signatureValid);
    }

    private PolicyRule rule(String id, int prio, PolicyEffect effect,
                            PolicyCondition... conditions) {
        return new PolicyRule(id, prio, effect, 1, List.of(conditions), "test rule " + id);
    }

    private PolicyCondition cond(ConditionType type, String value) {
        return new PolicyCondition(type, value);
    }

    private PolicySnapshot snapshot(long v, PolicyRule... rules) {
        return new PolicySnapshot(v, Instant.now(), "tester", "test", List.of(rules));
    }

    private void logReport(String scenario, ImageDescriptor d, DecisionReport r) {
        log.info("[评估-{}] 输入: registry={} severities={} vulnCount={} hasProvenance={} "
                        + "signatureValid={}", scenario, d.registry(),
                d.vulnerabilities().stream().map(x -> x.severity().name()).toList(),
                d.vulnerabilities().size(), d.provenance() != null, d.signatureValid());
        log.info("[评估-{}] 命中策略(v{}): {}", scenario, r.policyVersion(),
                r.matchedRules().stream().map(m -> m.ruleId() + "(prio=" + m.priority()
                        + ",effect=" + m.effect() + ",依据=" + m.reason() + ")").toList());
        log.info("[评估-{}] 最终判定: {} 依据: {}", scenario, r.decision(), r.rationale());
    }

    @Test
    void highPriorityDenyOverridesLowPriorityAllow() {
        // 镜像同时满足低优先级 ALLOW（可信 registry）与高优先级 DENY（critical 漏洞）
        PolicyRule allow = rule("allow-trusted", 10, PolicyEffect.ALLOW,
                cond(ConditionType.REGISTRY_EQUALS, "gcr.internal"));
        PolicyRule deny = rule("deny-critical", 100, PolicyEffect.DENY,
                cond(ConditionType.SEVERITY_AT_LEAST, Severity.CRITICAL.name()));
        ImageDescriptor img = image(Severity.CRITICAL, "gcr.internal", true, Boolean.TRUE);

        DecisionReport r = evaluator.evaluate(img, snapshot(1, allow, deny));
        logReport("高优先级DENY覆盖", img, r);

        assertEquals(Decision.DENY, r.decision());
        assertEquals("deny-critical", r.decisiveRule().ruleId());
        assertEquals(2, r.matchedRules().size());
        assertTrue(r.rationale().contains("冲突") || r.rationale().contains("覆盖"));
    }

    @Test
    void highPriorityAllowOverridesLowPriorityDeny() {
        // 高危漏洞触发低优先级 DENY；可信构建方+可信 registry 触发高优先级 ALLOW 覆盖
        PolicyRule deny = rule("deny-high", 10, PolicyEffect.DENY,
                cond(ConditionType.SEVERITY_AT_LEAST, Severity.HIGH.name()));
        PolicyRule allow = rule("allow-builder", 100, PolicyEffect.ALLOW,
                cond(ConditionType.REGISTRY_EQUALS, "gcr.internal"),
                cond(ConditionType.BUILDER_ID_EQUALS, "builder-1"));
        ImageDescriptor img = image(Severity.HIGH, "gcr.internal", true, Boolean.TRUE);

        DecisionReport r = evaluator.evaluate(img, snapshot(2, deny, allow));
        logReport("高优先级ALLOW覆盖", img, r);

        assertEquals(Decision.ALLOW, r.decision());
        assertEquals("allow-builder", r.decisiveRule().ruleId());
    }

    @Test
    void samePriorityConflictResolvedDeterministicallyByRuleId() {
        // 同优先级 ALLOW/DENY 同时命中：id 升序 tie-break（a-deny 在前 => DENY）
        PolicyRule deny = rule("a-deny", 50, PolicyEffect.DENY,
                cond(ConditionType.SEVERITY_AT_LEAST, Severity.HIGH.name()));
        PolicyRule allow = rule("z-allow", 50, PolicyEffect.ALLOW,
                cond(ConditionType.REGISTRY_EQUALS, "gcr.internal"));
        ImageDescriptor img = image(Severity.HIGH, "gcr.internal", true, Boolean.TRUE);

        DecisionReport r1 = evaluator.evaluate(img, snapshot(3, allow, deny));
        DecisionReport r2 = evaluator.evaluate(img, snapshot(3, deny, allow));
        logReport("同优先级冲突tie-break", img, r1);

        assertEquals(Decision.DENY, r1.decision());
        assertEquals("a-deny", r1.decisiveRule().ruleId());
        assertEquals(r1.decision(), r2.decision(), "规则提交顺序不得影响结论");
        assertEquals(r1.decisiveRule().ruleId(), r2.decisiveRule().ruleId());
    }

    @Test
    void noRuleMatchesFailsClosed() {
        // DENY 条件是“registry != evil.example”；镜像来自 gcr.internal，条件不满足 → 不命中
        PolicyRule denyExternal = rule("deny-external", 10, PolicyEffect.DENY,
                cond(ConditionType.REGISTRY_EQUALS, "evil.example"));
        ImageDescriptor img = image(null, "gcr.internal", true, Boolean.TRUE);

        DecisionReport r = evaluator.evaluate(img, snapshot(4, denyExternal));
        logReport("无命中fail-closed", img, r);

        assertEquals(Decision.DENY, r.decision());
        assertNull(r.decisiveRule());
        assertEquals(0, r.matchedRules().size());
    }

    @Test
    void evaluationIsReproducibleAcrossRepeatedRuns() {
        PolicyRule deny = rule("deny-critical", 100, PolicyEffect.DENY,
                cond(ConditionType.SEVERITY_AT_LEAST, Severity.CRITICAL.name()));
        PolicyRule allow = rule("allow-trusted", 10, PolicyEffect.ALLOW,
                cond(ConditionType.REGISTRY_EQUALS, "gcr.internal"));
        ImageDescriptor img = image(Severity.CRITICAL, "gcr.internal", true, Boolean.TRUE);
        PolicySnapshot snap = snapshot(5, allow, deny);

        DecisionReport first = evaluator.evaluate(img, snap);
        for (int i = 0; i < 20; i++) {
            DecisionReport again = evaluator.evaluate(img, snap);
            assertEquals(first.decision(), again.decision());
            assertEquals(first.decisiveRule().ruleId(), again.decisiveRule().ruleId());
            assertEquals(first.matchedRules().size(), again.matchedRules().size());
        }
        logReport("可复现(重复20次一致)", img, first);
    }

    @Test
    void matchedRuleReasonsExplainTheBasis() {
        PolicyRule rule = rule("deny-attest", 20, PolicyEffect.DENY,
                cond(ConditionType.PROVENANCE_MISSING, null),
                cond(ConditionType.SIGNATURE_NOT_VERIFIED, null));
        ImageDescriptor img = image(null, "gcr.internal", false, null);

        DecisionReport r = evaluator.evaluate(img, snapshot(6, rule));
        logReport("命中依据可读", img, r);

        assertEquals(Decision.DENY, r.decision());
        MatchedRule m = r.decisiveRule();
        assertEquals("deny-attest", m.ruleId());
        assertTrue(m.reason().contains("供应链证明"));
        assertTrue(m.reason().contains("签名"));
    }

    @Test
    void emptyConditionRuleMatchesAnyImageAndConflictWithAnotherDeny() {
        // 无条件 ALLOW 匹配任意镜像（prio=1），高优 DENY 覆盖
        PolicyRule allowAll = rule("allow-all", 1, PolicyEffect.ALLOW);
        PolicyRule denyNoProv = rule("deny-no-prov", 5, PolicyEffect.DENY,
                cond(ConditionType.PROVENANCE_MISSING, null));
        ImageDescriptor img = image(null, "gcr.internal", false, Boolean.TRUE);

        DecisionReport r = evaluator.evaluate(img, snapshot(7, allowAll, denyNoProv));
        logReport("无条件规则+冲突", img, r);

        assertEquals(Decision.DENY, r.decision());
        assertEquals("deny-no-prov", r.decisiveRule().ruleId());
        assertEquals(2, r.matchedRules().size());
    }
}
