package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService;
import com.github.xingjianluo.admissionpolicyenginejava.audit.InMemoryAuditService;
import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactKind;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.DefaultArtifactParser;
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
import com.github.xingjianluo.admissionpolicyenginejava.policy.DefaultPolicyEvaluator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.DefaultPolicyRuleSetValidator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.InMemoryPolicyStore;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import com.github.xingjianluo.admissionpolicyenginejava.security.RbacAuthorizer;
import com.github.xingjianluo.admissionpolicyenginejava.service.DefaultAdmissionService;
import com.github.xingjianluo.admissionpolicyenginejava.service.DefaultBatchAdmissionService;
import com.github.xingjianluo.admissionpolicyenginejava.service.DefaultPolicyAdminService;
import com.github.xingjianluo.admissionpolicyenginejava.service.DefaultPolicyRehearsalService;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 条件参数非法的端到端处理（手工装配，不依赖 Spring 上下文，稳定可复现）：
 * 1) 非法严重级别阈值 / 需要参数的条件缺参数：发布与预演都按“规则集不合法”
 *    （422 POLICY_RULESET_INVALID）拒绝；
 * 2) 被拒后当前版本与版本历史保持原样，被拒绝的发布不记成功留痕；
 *    被拒预演不返回任何对照结论、不产生正式版本；
 * 3) 合法取值（含大小写与首尾空格差异）在发布、预演入口正常通过；
 * 4) 现网因历史操作已存在坏规则版本时，单镜像/批量/预演都不以 500 失败：
 *    单镜像给可判断错误，批量逐项给结果，预演逐项给 POLICY_ERROR 且无对照结论。
 */
class InvalidRuleParameterIntegrationTest {

    private final Caller admin = new Caller("inv-admin", Set.of("ADMIN"));
    private final Caller reader = new Caller("inv-reader", Set.of("READER"));

    private static PolicyRule severityRule(String id, String value) {
        return new PolicyRule(id, 10, PolicyEffect.DENY, 1,
                List.of(new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, value)),
                "severity " + id);
    }

    private static PolicyRule registryEqualsRule(String id, String value) {
        return new PolicyRule(id, 10, PolicyEffect.ALLOW, 1,
                List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS, value)),
                "registry " + id);
    }

    private static IngestionRequest internalImage() {
        String manifest = """
                {
                  "schemaVersion": 2,
                  "digest": "sha256:inv0001",
                  "config": { "digest": "sha256:inv0001" },
                  "annotations": {
                    "io.xj.registry": "gcr.internal",
                    "io.xj.repository": "team-i/app",
                    "io.xj.tag": "1.0"
                  }
                }
                """;
        String scan = "{ \"digest\": \"sha256:inv0001\", \"vulnerabilities\": [] }";
        return new IngestionRequest("gcr.internal/team-i/app:1.0", List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", manifest),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", scan)));
    }

    private static BatchItemInput oneItem() {
        return new BatchItemInput(0, internalImage(), null);
    }

    // ---------- 发布入口：整批拒绝、版本/历史不变 ----------

    @Test
    void publishRejectsInvalidSeverityThresholdWithoutChangingVersionOrHistory() {
        Harness h = new Harness();
        long versionBefore = h.admin.current(admin).version();
        int historyBefore = h.admin.history(admin).size();

        for (String bad : new String[]{"URGENT", "", "  ", "UNKNOWN", null}) {
            AdmissionException ex = assertThrows(AdmissionException.class,
                    () -> h.admin.update(admin, versionBefore,
                            java.util.Arrays.asList(severityRule("bad-threshold", bad)),
                            "非法阈值"));
            assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        }

        assertEquals(versionBefore, h.admin.current(admin).version(),
                "被拒发布不得推进当前版本");
        assertEquals(historyBefore, h.admin.history(admin).size(),
                "被拒发布不得在版本历史留下新版本");
        // 被拒请求不得记成成功发布
        assertTrue(h.audit.recent(1000).stream()
                .noneMatch(a -> "POLICY_UPDATE".equals(a.action())));
    }

    @Test
    void publishRejectsMissingRequiredParameterWithoutChangingVersionOrHistory() {
        Harness h = new Harness();
        long versionBefore = h.admin.current(admin).version();
        int historyBefore = h.admin.history(admin).size();

        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> h.admin.update(admin, versionBefore,
                        List.of(registryEqualsRule("needs-value", null)), "缺参数"));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        assertTrue(ex.getMessage().contains("needs-value"));

        assertEquals(versionBefore, h.admin.current(admin).version());
        assertEquals(historyBefore, h.admin.history(admin).size());
        assertTrue(h.audit.recent(1000).stream()
                .noneMatch(a -> "POLICY_UPDATE".equals(a.action())));
    }

    @Test
    void oneBadRuleRejectsTheWholeRuleSetIncludingOtherGoodRules() {
        Harness h = new Harness();
        long base = h.admin.current(admin).version();
        List<PolicyRule> mixed = List.of(
                registryEqualsRule("good-rule", "gcr.internal"),
                severityRule("bad-rule", "URGENT"));
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> h.admin.update(admin, base, mixed, "混有一条坏规则"));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, ex.getCode());
        assertEquals(base, h.admin.current(admin).version());
    }

    // ---------- 预演入口：开始前整批拒绝、无对照结论、无版本 ----------

    @Test
    void rehearsalRejectsInvalidCandidateRulesAtStartWithoutComparisonOrVersion() {
        Harness h = new Harness();
        long versionBefore = h.admin.current(admin).version();
        int historyBefore = h.admin.history(admin).size();

        AdmissionException badThreshold = assertThrows(AdmissionException.class,
                () -> h.rehearsal.rehearse(reader, List.of(oneItem()),
                        List.of(severityRule("cand-bad", "URGENT")), "k1"));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, badThreshold.getCode());

        AdmissionException missingValue = assertThrows(AdmissionException.class,
                () -> h.rehearsal.rehearse(reader, List.of(oneItem()),
                        List.of(registryEqualsRule("cand-missing", null)), "k2"));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, missingValue.getCode());

        // 被拒预演不改现网、不产生正式版本，且拿不到任何报告/对照结论
        assertEquals(versionBefore, h.admin.current(admin).version());
        assertEquals(historyBefore, h.admin.history(admin).size());
        assertTrue(h.audit.recent(1000).stream()
                .noneMatch(a -> "POLICY_REHEARSE".equals(a.action())
                        && a.decision() != null), "被拒预演不得产生对照留痕");
    }

    @Test
    void ruleSetInvalidIsDistinctFromDenyAndUnauthorized() {
        Harness h = new Harness();
        long base = h.admin.current(admin).version();

        // 未授权：401 通道
        Caller guest = new Caller("inv-guest", Set.of("GUEST"));
        AdmissionException unauth = assertThrows(AdmissionException.class,
                () -> h.admin.update(guest, base,
                        List.of(severityRule("x", "HIGH")), "无权"));
        assertEquals(ErrorCode.UNAUTHORIZED, unauth.getCode());

        // 规则集不合法：422 通道
        AdmissionException invalid = assertThrows(AdmissionException.class,
                () -> h.admin.update(admin, base,
                        List.of(severityRule("x", "NOPE")), "坏参"));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, invalid.getCode());

        // 策略结论 DENY 是 200 响应体里的 decision，而不是异常（合法规则正常发布后评估）
        h.admin.update(admin, base, List.of(
                new PolicyRule("deny-all", 100, PolicyEffect.DENY, 1, List.of(), "全拒")),
                "合法发布");
        var decisionReport = h.admission.evaluate(reader, internalImage(), "dk");
        assertEquals(com.github.xingjianluo.admissionpolicyenginejava.model.Decision.DENY,
                decisionReport.decision());
    }

    // ---------- 合法取值（含大小写/空格）正常通过 ----------

    @Test
    void legalValuesIncludingCaseAndWhitespacePassPublishAndRehearsal() {
        Harness h = new Harness();
        long base = h.admin.current(admin).version();
        int i = 0;
        for (String value : List.of("LOW", "low", "Medium", " high ", "CRITICAL", "CrItIcAl")) {
            String id = "sev-" + i++;
            long currentBase = h.admin.current(admin).version();
            h.admin.update(admin, currentBase, List.of(severityRule(id, value)),
                    "合法阈值 " + value);
        }
        assertTrue(h.admin.current(admin).version() > base, "合法取值发布应成功产生新版本");

        // 预演入口同样接受大小写/空格变体，且正常给出对照结论
        RehearsalReport report = h.rehearsal.rehearse(reader, List.of(oneItem()),
                List.of(severityRule("cand-low", "  low ")),
                "legal-cand-" + System.nanoTime());
        RehearsalItemResult item = report.items().get(0);
        assertEquals(ItemStatus.EVALUATED, item.status());
        assertNotNull(item.candidateReport());
        assertNotNull(item.change());
    }

    // ---------- 现网已存在历史坏规则版本：失败边界 ----------

    @Test
    void corruptHistoryVersionDoesNotCause500OnAnyEvaluationPath() {
        // 直接植入一个绕过发布校验的坏规则版本，模拟“历史操作遗留”。
        CorruptibleStore store = new CorruptibleStore();
        Harness h = new Harness(store);

        PolicyRule bad = severityRule("legacy-bad", "URGENT");
        long corruptVersion = store.appendCorruptVersion(bad);
        assertEquals(corruptVersion, h.admin.current(admin).version(),
                "测试前置：当前版本即坏规则版本");

        // 单镜像评估：可判断、可定位的 POLICY_RULESET_INVALID，而不是裸异常
        AdmissionException single = assertThrows(AdmissionException.class,
                () -> h.admission.evaluate(reader, internalImage(), "single"));
        assertEquals(ErrorCode.POLICY_RULESET_INVALID, single.getCode());
        assertTrue(single.getMessage().contains("legacy-bad"));
        assertTrue(single.getMessage().contains("v" + corruptVersion));

        // 批量评估：HTTP 层不会 500，逐项给明确错误，且同批合法输入项也有明确结果
        List<BatchItemInput> items = List.of(
                oneItem(),
                new BatchItemInput(1, null, "批量第 1 项缺少镜像引用 reference"));
        BatchEvaluationReport batch = h.batch.evaluateBatch(reader, items, "batch-bad-policy");
        assertEquals(corruptVersion, batch.policyVersion());
        assertEquals(2, batch.items().size());
        BatchItemResult policyItem = batch.items().get(0);
        assertEquals(ItemStatus.POLICY_ERROR, policyItem.status());
        assertEquals(ErrorCode.POLICY_RULESET_INVALID.name(), policyItem.errorCode());
        assertNotNull(policyItem.errorMessage());
        assertNull(policyItem.report());
        // 输入错误项依旧按输入错误归类，两种错误互不混淆
        BatchItemResult inputItem = batch.items().get(1);
        assertEquals(ItemStatus.INPUT_ERROR, inputItem.status());
        assertEquals(1, batch.policyErrorCount());
        assertEquals(1, batch.errorCount());

        // 预演：候选合法，但现网是坏版本 → 逐项 POLICY_ERROR、无对照结论，整次不 500
        RehearsalReport rehearsal = h.rehearsal.rehearse(reader, items,
                List.of(registryEqualsRule("cand-ok", "gcr.internal")),
                "rehe-bad-policy");
        RehearsalItemResult reheItem = rehearsal.items().get(0);
        assertEquals(ItemStatus.POLICY_ERROR, reheItem.status());
        assertNull(reheItem.currentReport(), "坏规则项不得返回现网结论");
        assertNull(reheItem.candidateReport(), "坏规则项不得返回候选对照结论");
        assertNull(reheItem.change());
        assertEquals(ErrorCode.POLICY_RULESET_INVALID.name(), reheItem.errorCode());
        assertEquals(1, rehearsal.policyErrorCount());
        assertEquals(1, rehearsal.errorCount());

        // 预演/评估都不产生正式版本
        assertEquals(corruptVersion, h.admin.current(admin).version());
    }

    /** 手工装配一整套应用服务（与生产相同的实现类）。 */
    private static final class Harness {
        final InMemoryPolicyStore store;
        final AuditService audit;
        final DefaultPolicyAdminService admin;
        final DefaultAdmissionService admission;
        final DefaultBatchAdmissionService batch;
        final DefaultPolicyRehearsalService rehearsal;

        Harness() {
            this(new InMemoryPolicyStore());
        }

        Harness(InMemoryPolicyStore store) {
            this.store = store;
            this.audit = new InMemoryAuditService();
            DefaultArtifactParser parser = new DefaultArtifactParser();
            DefaultPolicyEvaluator evaluator = new DefaultPolicyEvaluator();
            RbacAuthorizer authorizer = new RbacAuthorizer();
            this.admin = new DefaultPolicyAdminService(store, authorizer, audit);
            this.admission = new DefaultAdmissionService(parser, store, evaluator,
                    authorizer, audit);
            this.batch = new DefaultBatchAdmissionService(parser, store, evaluator,
                    authorizer, audit);
            this.rehearsal = new DefaultPolicyRehearsalService(parser, store, evaluator,
                    authorizer, audit, new DefaultPolicyRuleSetValidator());
        }
    }

    /** 仅测试用：可绕过发布校验植入历史坏规则版本的存储。 */
    private static final class CorruptibleStore extends InMemoryPolicyStore {
        long appendCorruptVersion(PolicyRule badRule) {
            PolicySnapshot head = current();
            PolicySnapshot corrupt = new PolicySnapshot(head.version() + 1, Instant.now(),
                    "legacy-operator", "历史遗留坏规则", List.of(badRule));
            history0().add(corrupt);
            return corrupt.version();
        }

        @SuppressWarnings("unchecked")
        private java.util.concurrent.CopyOnWriteArrayList<PolicySnapshot> history0() {
            try {
                java.lang.reflect.Field f = InMemoryPolicyStore.class.getDeclaredField("versions");
                f.setAccessible(true);
                return (java.util.concurrent.CopyOnWriteArrayList<PolicySnapshot>) f.get(this);
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
