package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService;
import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactKind;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.RawArtifact;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchEvaluationReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchItemInput;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchItemResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.ItemStatus;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalItemResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalReport;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.InMemoryPolicyStore;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import com.github.xingjianluo.admissionpolicyenginejava.service.AdmissionService;
import com.github.xingjianluo.admissionpolicyenginejava.service.BatchAdmissionService;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyAdminService;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyRehearsalService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 规则集不合法修复的端到端集成测试：
 * <ol>
 *   <li>非法严重级别档位 / 需要参数的条件缺参数，在<strong>发布</strong>与<strong>预演</strong>
 *       两个入口都按 POLICY_RULESET_INVALID（4xx 规则集不合法）整批拒绝；</li>
 *   <li>被拒绝后当前策略版本与版本历史保持原样，且不记成一次成功发布/不留任何预演结论；</li>
 *   <li>合法取值（含大小写、首尾空格差异）在两个入口都正常通过；</li>
 *   <li>现网已存在历史坏规则版本时，单镜像评估不抛 500、批量逐项给 POLICY_ERROR、
 *       预演逐项给 POLICY_ERROR 且不给对照结论。</li>
 * </ol>
 */
@SpringBootTest
class RuleSetInvalidIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(RuleSetInvalidIntegrationTest.class);

    @Autowired
    private PolicyAdminService adminService;
    @Autowired
    private PolicyRehearsalService rehearsalService;
    @Autowired
    private BatchAdmissionService batchService;
    @Autowired
    private AdmissionService admissionService;
    @Autowired
    private AuditService auditService;
    @Autowired
    private InMemoryPolicyStore policyStore;

    private final Caller admin = new Caller("rsi-admin", Set.of("ADMIN"));
    private final Caller reader = new Caller("rsi-reader", Set.of("READER"));
    private final Caller guest = new Caller("rsi-guest", Set.of("GUEST"));

    @AfterEach
    void restoreDefaultPolicy() throws Exception {
        // 反射注入的历史坏版本也一并丢弃：回滚到 v1 即恢复默认规则集。
        adminService.rollback(admin, 1L);
    }

    // ---------- 构造规则 / 镜像 ----------

    private PolicyRule severityRule(String id, String rawValue) {
        return new PolicyRule(id, 10, PolicyEffect.DENY, 1,
                List.of(new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, rawValue)),
                "junit severity " + id);
    }

    private PolicyRule registryRuleMissingValue(String id) {
        return new PolicyRule(id, 10, PolicyEffect.DENY, 1,
                List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS, null)),
                "junit missing param " + id);
    }

    static final String MANIFEST = """
            {
              "schemaVersion": 2,
              "digest": "sha256:rsi0001",
              "config": { "digest": "sha256:rsi0001" },
              "annotations": {
                "io.xj.registry": "gcr.internal",
                "io.xj.repository": "team-r/app",
                "io.xj.tag": "1.0"
              }
            }
            """;
    static final String SCAN = "{ \"digest\": \"sha256:rsi0001\", \"vulnerabilities\": [] }";

    private IngestionRequest image() {
        return new IngestionRequest("gcr.internal/team-r/app:1.0", List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", MANIFEST),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", SCAN)));
    }

    private List<BatchItemInput> oneItem() {
        return List.of(new BatchItemInput(0, image(), null));
    }

    // ---------- 发布入口 ----------

    @Test
    void publishRejectsIllegalSeverityThresholdAndLeavesVersionAndHistoryUntouched() {
        long base = adminService.current(admin).version();
        int historyBefore = adminService.history(admin).size();
        int auditBefore = auditService.recent(1_000_000).size();

        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> adminService.update(admin, base,
                        List.of(severityRule("bad-severity", "URGENT")), "非法档位"));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        assertTrue(ex.getMessage().contains("bad-severity"));

        assertVersionChainUnchanged(base, historyBefore, auditBefore);
        log.info("[发布-非法档位] 按 {} 整批拒绝: {}", ex.getCode(), ex.getMessage());
    }

    @Test
    void publishRejectsMissingParameterConditionAndLeavesVersionAndHistoryUntouched() {
        long base = adminService.current(admin).version();
        int historyBefore = adminService.history(admin).size();
        int auditBefore = auditService.recent(1_000_000).size();

        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> adminService.update(admin, base,
                        List.of(registryRuleMissingValue("no-registry-value")), "缺参数"));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        assertTrue(ex.getMessage().contains("no-registry-value"));

        assertVersionChainUnchanged(base, historyBefore, auditBefore);
        log.info("[发布-缺参数] 按 {} 整批拒绝: {}", ex.getCode(), ex.getMessage());
    }

    private void assertVersionChainUnchanged(long expectedCurrent, int expectedHistorySize,
                                             int expectedAuditSize) {
        assertEquals(expectedCurrent, adminService.current(admin).version(),
                "被拒绝的发布不得推进当前版本");
        assertEquals(expectedHistorySize, adminService.history(admin).size(),
                "被拒绝的发布不得在版本历史留下新版本");
        assertEquals(expectedAuditSize, auditService.recent(1_000_000).size(),
                "被拒绝的发布不得记成一次成功发布");
    }

    // ---------- 预演入口 ----------

    @Test
    void rehearsalRejectsIllegalCandidateRulesBeforeAnyComparison() {
        long versionAtStart = adminService.current(admin).version();
        int historyBefore = adminService.history(admin).size();
        int auditBefore = auditService.recent(1_000_000).size();

        // 非法严重级别档位
        AdmissionException sevEx = assertThrows(AdmissionException.class,
                () -> rehearsalService.rehearse(reader, oneItem(),
                        List.of(severityRule("cand-bad-sev", "HIGHER")),
                        "rsi-rehe-sev-" + System.nanoTime()));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, sevEx.getCode());

        // 需要参数的条件缺参数
        AdmissionException missEx = assertThrows(AdmissionException.class,
                () -> rehearsalService.rehearse(reader, oneItem(),
                        List.of(registryRuleMissingValue("cand-missing")),
                        "rsi-rehe-miss-" + System.nanoTime()));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, missEx.getCode());

        // 被拒绝的预演：版本/历史不变
        assertEquals(versionAtStart, adminService.current(admin).version());
        assertEquals(historyBefore, adminService.history(admin).size());
        // 被拒绝的预演不留任何审计（无论成功结论还是输入错误都不写）
        assertEquals(auditBefore, auditService.recent(1_000_000).size(),
                "在评估开始前被拒绝的预演不得产出任何对照留痕");
        log.info("[预演-非法候选] 档位/缺参均按 {} 在评估前整批拒绝，现网保持 v{}",
                sevEx.getCode(), versionAtStart);
    }

    @Test
    void rulesetInvalidIsDistinctFromDenyAndUnauthorized() {
        long base = adminService.current(admin).version();

        // 未授权 → UNAUTHORIZED（401 通道）
        AdmissionException unauth = assertThrows(AdmissionException.class,
                () -> rehearsalService.rehearse(guest, oneItem(),
                        List.of(severityRule("x", "LOW")), "k"));
        assertEquals(ErrorCode.UNAUTHORIZED, unauth.getCode());

        // 规则集不合法 → POLICY_RULESET_INVALID（422 通道）
        AdmissionException invalid = assertThrows(AdmissionException.class,
                () -> rehearsalService.rehearse(reader, oneItem(),
                        List.of(severityRule("x", "NOPE")), "k"));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, invalid.getCode());

        // 策略结论 DENY 是正常结果而非异常：一条合法 DENY 规则照常被评估
        RehearsalReport report = rehearsalService.rehearse(reader, oneItem(),
                List.of(new PolicyRule("cand-deny-all", 1, PolicyEffect.DENY, 1,
                        List.of(), "无条件拒绝")), "rsi-deny-channel");
        RehearsalItemResult item = report.items().get(0);
        assertEquals(ItemStatus.EVALUATED, item.status());
        assertEquals(com.github.xingjianluo.admissionpolicyenginejava.model.Decision.DENY,
                item.candidateReport().decision());
        assertEquals(0, report.policyErrorCount());
        log.info("[三通道区分] 未授权={} 规则集不合法={} 策略DENY=200体内decision",
                unauth.getCode(), invalid.getCode());
    }

    // ---------- 合法取值（含大小写、首尾空格）正常通过 ----------

    @Test
    void legalValuesWithCaseAndWhitespaceVariantsPassBothEntries() {
        long base = adminService.current(admin).version();

        // 发布：小写 + 首尾空格档位，以及带空格的 registry 参数，都应成功
        PolicySnapshot published = adminService.update(admin, base, List.of(
                new PolicyRule("sev-trim", 10, PolicyEffect.DENY, 1,
                        List.of(new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, " high ")),
                        "空格+小写档位"),
                new PolicyRule("registry-trim", 5, PolicyEffect.ALLOW, 1,
                        List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS,
                                "  gcr.internal  ")), "空格registry")),
                "合法取值变体");
        assertEquals(base + 1, published.version());
        // 归一化后写入：档位大写、registry 去空格
        assertEquals("HIGH", published.rules().get(0).conditions().get(0).value());
        assertEquals("gcr.internal", published.rules().get(1).conditions().get(0).value());

        // 预演：混合大小写临界值同样通过，且返回正常对照结论（不是拒绝异常）
        RehearsalReport report = rehearsalService.rehearse(reader, oneItem(),
                List.of(new PolicyRule("cand-critical", 10, PolicyEffect.ALLOW, 1,
                        List.of(new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, "CrItIcAl")),
                        "混合大小写")),
                "rsi-legal-" + System.nanoTime());
        assertEquals(0, report.policyErrorCount());
        assertEquals(ItemStatus.EVALUATED, report.items().get(0).status());
        assertNotNull(report.items().get(0).candidateReport());
        log.info("[合法变体] 发布/预演均通过，档位归一化 HIGH，预演对照结论正常返回");
    }

    // ---------- 历史坏规则的失败边界 ----------

    /**
     * 通过反射把一条坏规则快照直接追加为“当前线上版本”，模拟历史操作留下的坏版本
     * （现在的发布/预演校验已能拦住新提交，但存量坏版本仍需可预期失败）。
     */
    @SuppressWarnings("unchecked")
    private long appendCorruptCurrentVersion(PolicyRule badRule) throws Exception {
        Field f = InMemoryPolicyStore.class.getDeclaredField("versions");
        f.setAccessible(true);
        CopyOnWriteArrayList<PolicySnapshot> versions =
                (CopyOnWriteArrayList<PolicySnapshot>) f.get(policyStore);
        long next = versions.size();
        versions.add(new PolicySnapshot(next, Instant.now(), "legacy-ops",
                "历史遗留坏规则版本", List.of(badRule)));
        return next;
    }

    @Test
    void singleEvaluationAgainstHistoricalBadRuleDoesNotReturn500() throws Exception {
        long badVersion = appendCorruptCurrentVersion(severityRule("legacy-bad-sev", "URGENT"));
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> admissionService.evaluate(reader, image(),
                        "rsi-single-bad-" + System.nanoTime()));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        assertTrue(ex.getMessage().contains("v" + badVersion));
        assertTrue(ex.getMessage().contains("legacy-bad-sev"));
        log.info("[历史坏规则-单镜像] 返回可区分错误而非 500: {}", ex.getMessage());
    }

    @Test
    void batchEvaluationAgainstHistoricalBadRuleMarksEveryItemPolicyError() throws Exception {
        long badVersion = appendCorruptCurrentVersion(
                registryRuleMissingValue("legacy-missing-value"));
        List<BatchItemInput> items = List.of(
                new BatchItemInput(0, image(), null),
                new BatchItemInput(1, image(), null));
        BatchEvaluationReport report = batchService.evaluateBatch(reader, items,
                "rsi-batch-bad-" + System.nanoTime());

        assertEquals(badVersion, report.policyVersion());
        assertEquals(2, report.totalCount());
        assertEquals(2, report.errorCount(), "两项都未给出策略结论，计入错误数");
        assertEquals(0, report.allowedCount());
        assertEquals(0, report.deniedCount());
        for (BatchItemResult item : report.items()) {
            assertEquals(ItemStatus.POLICY_ERROR, item.status(),
                    "每个项都要有明确的 POLICY_ERROR，不能让整批 500");
            assertEquals(ErrorCode.POLICY_RULESET_INVALID.name(), item.errorCode());
            assertTrue(item.errorMessage().contains("legacy-missing-value"));
            assertNull(item.report(), "策略错误项不返回任何评估结论");
        }
        log.info("[历史坏规则-批量] v{} 两项均 POLICY_ERROR，整批未以 500 收场", badVersion);
    }

    @Test
    void rehearsalAgainstHistoricalBadRuleGivesPolicyErrorWithoutComparison() throws Exception {
        long badVersion = appendCorruptCurrentVersion(severityRule("legacy-bad-sev", "URGENT"));
        // 候选本身合法（应通过前置校验）；但现网一侧含坏规则
        List<PolicyRule> legalCandidate = List.of(
                new PolicyRule("candidate-fine", 10, PolicyEffect.ALLOW, 1,
                        List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS, "gcr.internal")),
                        "合法候选"));
        RehearsalReport report = rehearsalService.rehearse(reader, oneItem(), legalCandidate,
                "rsi-rehe-badcurrent-" + System.nanoTime());

        assertEquals(badVersion, report.currentPolicyVersion());
        assertEquals(1, report.policyErrorCount());
        RehearsalItemResult item = report.items().get(0);
        assertEquals(ItemStatus.POLICY_ERROR, item.status());
        assertEquals(ErrorCode.POLICY_RULESET_INVALID.name(), item.errorCode());
        assertNull(item.currentReport(), "现网坏规则时不返回现网结论");
        assertNull(item.candidateReport(), "也不返回候选结论，不给任何对照结论");
        assertNull(item.change());
        log.info("[历史坏规则-预演] 现网 v{} 坏规则 → POLICY_ERROR 且无对照结论", badVersion);
    }
}
