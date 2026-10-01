package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.Vulnerability;
import com.github.xingjianluo.admissionpolicyenginejava.model.Severity;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.DefaultPolicyEvaluator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 现网已存在历史坏规则时的评估失败边界：
 * 评估器不得抛出裸 IllegalArgumentException/NPE（那样上层会 500），
 * 而要统一抛出可定位的 POLICY_RULESET_INVALID。
 */
class EvaluatorCorruptPolicyTest {

    private final DefaultPolicyEvaluator evaluator = new DefaultPolicyEvaluator();

    private ImageDescriptor image() {
        return new ImageDescriptor("gcr.internal/x:1", "sha256:corrupt0", "gcr.internal",
                "x", "1",
                List.of(new Vulnerability("CVE-1", Severity.HIGH, "openssl")),
                null, null);
    }

    private PolicySnapshot snapshot(long v, PolicyRule... rules) {
        return new PolicySnapshot(v, Instant.now(), "legacy", "corrupt", List.of(rules));
    }

    private PolicyRule severityRule(String id, String value) {
        return new PolicyRule(id, 10, PolicyEffect.DENY, 1,
                List.of(new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, value)), "坏规则");
    }

    @Test
    void badSeverityInHistoryProducesClassifiedErrorNot500() {
        PolicySnapshot snap = snapshot(7, severityRule("legacy-bad-threshold", "URGENT"));
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> evaluator.evaluate(image(), snap));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        assertTrue(ex.getMessage().contains("v7"));
        assertTrue(ex.getMessage().contains("legacy-bad-threshold"));
    }

    @Test
    void missingSeverityValueInHistoryProducesClassifiedError() {
        PolicySnapshot snap = snapshot(8, severityRule("legacy-empty-threshold", null));
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> evaluator.evaluate(image(), snap));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        assertTrue(ex.getMessage().contains("legacy-empty-threshold"));
    }

    @Test
    void missingRegistryValueInHistoryProducesClassifiedError() {
        PolicyRule rule = new PolicyRule("legacy-null-registry", 10, PolicyEffect.DENY, 1,
                List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS, null)), "缺参规则");
        PolicySnapshot snap = snapshot(9, rule);
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> evaluator.evaluate(image(), snap));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        assertTrue(ex.getMessage().contains("legacy-null-registry"));
    }
}
