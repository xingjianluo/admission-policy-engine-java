package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.Severity;
import com.github.xingjianluo.admissionpolicyenginejava.model.Vulnerability;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.DefaultPolicyEvaluator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.DefaultPolicyRuleSetValidator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 条件参数规约单元测试：
 * 1) 非法严重级别档位（含 UNKNOWN）一律按 POLICY_RULESET_INVALID 拒绝；
 * 2) 需要参数的条件缺参数/空白参数拒绝；
 * 3) 合法取值（大小写、首尾空格差异）归一化后通过；
 * 4) 评估期遇到历史坏规则抛可区分的 POLICY_RULESET_INVALID，而不是 IllegalArgumentException/NPE。
 */
class ConditionParameterValidationTest {

    private static final Logger log = LoggerFactory.getLogger(ConditionParameterValidationTest.class);

    private final DefaultPolicyRuleSetValidator validator = new DefaultPolicyRuleSetValidator();
    private final DefaultPolicyEvaluator evaluator = new DefaultPolicyEvaluator();

    private PolicyRule rule(String id, PolicyCondition... conditions) {
        return new PolicyRule(id, 10, PolicyEffect.DENY, 1, List.of(conditions), "junit " + id);
    }

    private void assertInvalid(PolicyRule badRule) {
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> validator.validateAndFreeze(List.of(badRule)));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        log.info("[条件校验] 按规则集不合法拒绝: {}", ex.getMessage());
    }

    @Test
    void invalidSeverityThresholdRejected() {
        assertInvalid(rule("bad-word",
                new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, "URGENT")));
        assertInvalid(rule("empty-word",
                new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, "")));
        // null / 空白也算缺参数
        assertInvalid(rule("null-word",
                new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, null)));
        assertInvalid(rule("blank-word",
                new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, "   ")));
        // UNKNOWN 是扫描器定级缺失的占位值，明确不允许作为策略阈值
        assertInvalid(rule("unknown-word",
                new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, "UNKNOWN")));
    }

    @Test
    void valueRequiredConditionMissingParameterRejected() {
        assertInvalid(rule("no-registry",
                new PolicyCondition(ConditionType.REGISTRY_EQUALS, null)));
        assertInvalid(rule("blank-registry",
                new PolicyCondition(ConditionType.REGISTRY_NOT_EQUALS, "  ")));
        assertInvalid(rule("no-prefix",
                new PolicyCondition(ConditionType.REPOSITORY_PREFIX, null)));
        assertInvalid(rule("no-builder",
                new PolicyCondition(ConditionType.BUILDER_ID_EQUALS, "")));
        assertInvalid(rule("no-source",
                new PolicyCondition(ConditionType.SOURCE_URI_PREFIX, " ")));
    }

    @Test
    void validValuesIncludingCaseAndWhitespaceNormalizedAndAccepted() {
        PolicyRule mixedCase = rule("mixed-case",
                new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, " high "));
        PolicyRule normalized = validator.validateAndFreeze(List.of(mixedCase)).get(0);
        assertEquals("HIGH", normalized.conditions().get(0).value(),
                "大小写与首尾空格差异归一化为枚举名 HIGH");

        PolicyRule upperCritical = rule("upper",
                new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, "CrItIcAl"));
        assertEquals("CRITICAL",
                validator.validateAndFreeze(List.of(upperCritical)).get(0)
                        .conditions().get(0).value());

        // 字符串型参数 trim 但保留大小写
        PolicyRule registry = rule("registry",
                new PolicyCondition(ConditionType.REGISTRY_EQUALS, "  gcr.internal  "));
        assertEquals("gcr.internal",
                validator.validateAndFreeze(List.of(registry)).get(0)
                        .conditions().get(0).value());

        // 无参条件即使误填 value 也归一化为 null，不报错
        PolicyRule booleanCond = rule("bool",
                new PolicyCondition(ConditionType.PROVENANCE_MISSING, "whatever"));
        assertEquals(null,
                validator.validateAndFreeze(List.of(booleanCond)).get(0)
                        .conditions().get(0).value());
        log.info("[条件校验] 合法大小写/空格取值全部归一化通过");
    }

    private ImageDescriptor imageWith(Severity severity) {
        List<Vulnerability> vulns = severity == null ? List.of()
                : List.of(new Vulnerability("CVE-1", severity, "pkg"));
        return new ImageDescriptor("gcr.internal/x:1", "sha256:aaa", "gcr.internal", "x", "1",
                vulns, null, null);
    }

    private PolicySnapshot snapshotWith(PolicyRule badRule) {
        return new PolicySnapshot(77L, Instant.now(), "legacy", "历史坏规则", List.of(badRule));
    }

    @Test
    void historicalInvalidSeverityRuleFailsWithClassifiedErrorNot500() {
        ImageDescriptor img = imageWith(Severity.LOW);
        // 坏档位：过去绕过校验进入线上的历史版本
        PolicySnapshot snapshot = snapshotWith(rule("legacy-bad-sev",
                new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, "URGENT")));
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> evaluator.evaluate(img, snapshot));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        assertTrue(ex.getMessage().contains("legacy-bad-sev"), "错误必须能定位到具体规则");
        assertTrue(ex.getMessage().contains("v77"), "错误必须能定位到具体策略版本");
        log.info("[历史坏规则-档位] 评估以可区分错误失败而非 500: {}", ex.getMessage());
    }

    @Test
    void historicalMissingParameterRuleFailsWithClassifiedErrorNotNpe() {
        ImageDescriptor img = imageWith(null);
        PolicySnapshot snapshot = snapshotWith(rule("legacy-missing-param",
                new PolicyCondition(ConditionType.REGISTRY_EQUALS, null)));
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> evaluator.evaluate(img, snapshot));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        assertTrue(ex.getMessage().contains("legacy-missing-param"));
        log.info("[历史坏规则-缺参] 评估以可区分错误失败而非 NPE/500: {}", ex.getMessage());
    }
}
