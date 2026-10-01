package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.DefaultPolicyRuleSetValidator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRuleSetValidator;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 规则集参数校验单测（发布与预演共用同一实现）：
 * 1) 非法严重级别阈值（含 UNKNOWN、乱写词、空白）一律 POLICY_RULESET_INVALID；
 * 2) 需要参数的条件缺参数、无参条件携带参数，一律 POLICY_RULESET_INVALID；
 * 3) 合法取值（含大小写、首尾空格差异）正常通过。
 */
class PolicyRuleSetValidatorTest {

    private final PolicyRuleSetValidator validator = new DefaultPolicyRuleSetValidator();

    private PolicyRule severityRule(String id, String value) {
        return new PolicyRule(id, 10, PolicyEffect.DENY, 1,
                List.of(new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, value)),
                "severity rule " + id);
    }

    private PolicyRule ruleWithCondition(String id, ConditionType type, String value) {
        return new PolicyRule(id, 10, PolicyEffect.ALLOW, 1,
                List.of(new PolicyCondition(type, value)), "rule " + id);
    }

    private AdmissionException expectInvalid(List<PolicyRule> rules) {
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> validator.validateAndFreeze(rules));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        return ex;
    }

    @Test
    void invalidSeverityThresholdRejectedAsRuleSetInvalid() {
        for (String bad : List.of("URGENT", "low-ish", "99", "unknown", "UNKNOWN", "  ", "")) {
            AdmissionException ex = expectInvalid(List.of(severityRule("bad-sev-" + bad, bad)));
            assertTrue(ex.getMessage().contains("bad-sev-" + bad)
                            || ex.getMessage().contains("SEVERITY_AT_LEAST"),
                    "错误消息应能定位条件，实际: " + ex.getMessage());
        }
        // null（留空）同样拒绝
        AdmissionException nullEx = expectInvalid(List.of(severityRule("bad-sev-null", null)));
        assertTrue(nullEx.getMessage().contains("bad-sev-null"));
    }

    @Test
    void missingParameterForValueRequiredConditionRejected() {
        AdmissionException registry = expectInvalid(
                List.of(ruleWithCondition("r-reg", ConditionType.REGISTRY_EQUALS, null)));
        assertTrue(registry.getMessage().contains("r-reg"));

        AdmissionException repo = expectInvalid(
                List.of(ruleWithCondition("r-repo", ConditionType.REPOSITORY_PREFIX, "  ")));
        assertTrue(repo.getMessage().contains("r-repo"));

        AdmissionException builder = expectInvalid(
                List.of(ruleWithCondition("r-builder", ConditionType.BUILDER_ID_EQUALS, null)));
        assertTrue(builder.getMessage().contains("r-builder"));
    }

    @Test
    void noArgConditionCarryingValueRejected() {
        AdmissionException ex = expectInvalid(List.of(ruleWithCondition("r-prov",
                ConditionType.PROVENANCE_MISSING, "unexpected")));
        assertTrue(ex.getMessage().contains("r-prov"));
    }

    @Test
    void allViolationsAggregatedInOneMessage() {
        List<PolicyRule> rules = List.of(
                severityRule("bad-a", "URGENT"),
                ruleWithCondition("bad-b", ConditionType.REGISTRY_EQUALS, null));
        AdmissionException ex = expectInvalid(rules);
        assertTrue(ex.getMessage().contains("2 处"), ex.getMessage());
        assertTrue(ex.getMessage().contains("bad-a"));
        assertTrue(ex.getMessage().contains("bad-b"));
    }

    @Test
    void legalSeverityValuesAcceptedIncludingCaseAndWhitespace() {
        for (String ok : List.of("LOW", "low", "Medium", " high ", "\tCRITICAL\n", "CrItIcAl")) {
            assertDoesNotThrow(() -> validator.validateAndFreeze(
                    List.of(severityRule("ok-" + ok.hashCode(), ok))));
        }
    }

    @Test
    void legalParameterizedAndNoArgConditionsAccepted() {
        assertDoesNotThrow(() -> validator.validateAndFreeze(List.of(
                ruleWithCondition("r1", ConditionType.REGISTRY_EQUALS, "gcr.internal"),
                ruleWithCondition("r2", ConditionType.PROVENANCE_PRESENT, null),
                ruleWithCondition("r3", ConditionType.SIGNATURE_NOT_VERIFIED, null))));
    }
}
