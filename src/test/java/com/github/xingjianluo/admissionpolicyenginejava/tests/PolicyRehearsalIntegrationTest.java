package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService;
import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactKind;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.RawArtifact;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchItemInput;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.ChangeDirection;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.ItemStatus;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalItemResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalReport;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyAdminService;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyRehearsalService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 策略预演集成测试：
 * 1) 双侧结论与变化方向正确（放行↔拒绝），并标出由哪条规则决定；
 * 2) 预演不发布、不产生正式版本、不改动现网策略；
 * 3) 候选规则非法时与正式发布同样按规则集不合法拒绝；
 * 4) 同一批输入 + 同一份策略重复预演结果完全一致；
 * 5) 单项坏输入隔离；未授权被拒绝；重复提交不重复留痕。
 */
@SpringBootTest
class PolicyRehearsalIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyRehearsalIntegrationTest.class);

    @Autowired
    private PolicyRehearsalService rehearsalService;
    @Autowired
    private PolicyAdminService adminService;
    @Autowired
    private AuditService auditService;

    private final Caller reader = new Caller("rehe-reader", Set.of("READER"));
    private final Caller guest = new Caller("rehe-guest", Set.of("GUEST"));
    private final Caller admin = new Caller("rehe-admin", Set.of("ADMIN"));

    @AfterEach
    void restoreDefaultPolicy() {
        adminService.rollback(admin, 1L);
    }

    static final String MANIFEST_INTERNAL = """
            {
              "schemaVersion": 2,
              "digest": "sha256:rehe0001",
              "config": { "digest": "sha256:rehe0001" },
              "annotations": {
                "io.xj.registry": "gcr.internal",
                "io.xj.repository": "team-r/app",
                "io.xj.tag": "1.0"
              }
            }
            """;
    static final String SCAN_INTERNAL =
            "{ \"digest\": \"sha256:rehe0001\", \"vulnerabilities\": [] }";

    private IngestionRequest internalImage() {
        return new IngestionRequest("gcr.internal/team-r/app:1.0", List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", MANIFEST_INTERNAL),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", SCAN_INTERNAL)));
    }

    private BatchItemInput oneItem() {
        return new BatchItemInput(0, internalImage(), null);
    }

    /** 候选：高优先级显式放行来自 gcr.internal 的镜像。 */
    private List<PolicyRule> allowInternalCandidate() {
        return List.of(new PolicyRule("candidate-allow-internal", 100, PolicyEffect.ALLOW, 1,
                List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS, "gcr.internal")),
                "预演候选：内部来源放行"));
    }

    @Test
    void rehearsalComparesCurrentVsCandidateAndMarksChangeAndDecisiveRule() {
        long versionBefore = adminService.current(admin).version();

        RehearsalReport report = rehearsalService.rehearse(reader, List.of(oneItem()),
                allowInternalCandidate(), "rehe-change-" + System.nanoTime());
        RehearsalItemResult item = report.items().get(0);

        log.info("[预演-变化] current={} candidate={} change={} currentRule={} candidateRule={}",
                item.currentReport().decision(), item.candidateReport().decision(),
                item.change(),
                item.currentReport().decisiveRule() == null
                        ? "<fail-closed>" : item.currentReport().decisiveRule().ruleId(),
                item.candidateReport().decisiveRule().ruleId());

        assertEquals(versionBefore, report.currentPolicyVersion());
        assertEquals(Decision.DENY, item.currentReport().decision(),
                "现网默认策略下该镜像（缺证明/签名）为 DENY");
        assertEquals(Decision.ALLOW, item.candidateReport().decision());
        assertEquals(ChangeDirection.DENY_TO_ALLOW, item.change());
        assertEquals("candidate-allow-internal",
                item.candidateReport().decisiveRule().ruleId());
        assertEquals(1, report.changedCount());
        assertEquals(1, report.denyToAllowCount());
        assertEquals(0, report.allowToDenyCount());

        // 预演绝不能改动现网或留下正式版本
        assertEquals(versionBefore, adminService.current(admin).version(),
                "预演不得产生新的正式策略版本");
        assertEquals(versionBefore, report.currentPolicyVersion());
    }

    @Test
    void rehearsalDoesNotPublishAndLeavesNoFormalVersion() {
        long before = adminService.current(admin).version();
        rehearsalService.rehearse(reader, List.of(oneItem()), allowInternalCandidate(),
                "rehe-nopub-" + System.nanoTime());
        long after = adminService.current(admin).version();
        assertEquals(before, after, "预演后现网版本必须保持不变");
        // 版本链长度不变
        assertEquals(before + 1, adminService.history(admin).size());
    }

    @Test
    void invalidCandidateRulesRejectedSameAsPublish() {
        long versionAtStart = adminService.current(admin).version();
        // schemaVersion 越界：与正式发布一致的错误码
        List<PolicyRule> badSchema = List.of(new PolicyRule("future-rule", 1, PolicyEffect.ALLOW,
                99, List.of(), "未来 schema"));
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> rehearsalService.rehearse(reader, List.of(oneItem()), badSchema, "k"));
        assertEquals(ErrorCode.POLICY_SCHEMA_UNSUPPORTED, ex.getCode());

        // 空候选规则集：拒绝
        AdmissionException empty = assertThrows(AdmissionException.class,
                () -> rehearsalService.rehearse(reader, List.of(oneItem()), List.of(), "k"));
        assertEquals(ErrorCode.INVALID_REQUEST, empty.getCode());

        // 重复 id：拒绝
        List<PolicyRule> dup = List.of(
                new PolicyRule("dup", 1, PolicyEffect.ALLOW, 1, List.of(), "a"),
                new PolicyRule("dup", 2, PolicyEffect.DENY, 1, List.of(), "b"));
        AdmissionException dupEx = assertThrows(AdmissionException.class,
                () -> rehearsalService.rehearse(reader, List.of(oneItem()), dup, "k"));
        assertEquals(ErrorCode.INVALID_REQUEST, dupEx.getCode());

        // 候选非法时现网版本不因这些被拒绝的预演而变化
        long versionAfterRejected = adminService.current(admin).version();
        assertEquals(versionAtStart, versionAfterRejected,
                "非法候选被拒绝不得改变现网版本");
        log.info("[预演-非法候选] 非法候选与正式发布同规拒绝: {}/{}/{}，现网保持 v{}",
                ex.getCode(), empty.getCode(), dupEx.getCode(), versionAfterRejected);
    }

    @Test
    void sameInputsAndPoliciesProduceIdenticalRehearsalRepeatedly() {
        List<BatchItemInput> items = List.of(oneItem());
        List<PolicyRule> candidate = allowInternalCandidate();
        RehearsalReport first = rehearsalService.rehearse(reader, items, candidate,
                "rehe-deterministic");
        for (int i = 0; i < 5; i++) {
            RehearsalReport again = rehearsalService.rehearse(reader, items, candidate,
                    "rehe-deterministic");
            RehearsalItemResult a = first.items().get(0);
            RehearsalItemResult b = again.items().get(0);
            assertEquals(a.currentReport().decision(), b.currentReport().decision());
            assertEquals(a.candidateReport().decision(), b.candidateReport().decision());
            assertEquals(a.change(), b.change());
            assertEquals(first.candidateFingerprint(), again.candidateFingerprint());
            assertEquals(first.changedCount(), again.changedCount());
        }
        log.info("[预演-可复现] 同批输入+同策略重复 6 次，结论与指纹 {} 完全一致",
                first.candidateFingerprint());
    }

    @Test
    void badInputItemIsFlaggedAndOthersStillCompared() {
        List<BatchItemInput> items = List.of(
                oneItem(),
                new BatchItemInput(1, null, "批量第 1 项缺少镜像引用 reference"));
        RehearsalReport report = rehearsalService.rehearse(reader, items,
                allowInternalCandidate(), "rehe-baditem-" + System.nanoTime());

        assertEquals(ItemStatus.EVALUATED, report.items().get(0).status());
        assertEquals(ItemStatus.INPUT_ERROR, report.items().get(1).status());
        assertEquals("INVALID_REQUEST", report.items().get(1).errorCode());
        assertEquals(ChangeDirection.DENY_TO_ALLOW, report.items().get(0).change());
        assertEquals(1, report.errorCount());
        log.info("[预演-坏输入隔离] 第0项 {}，第1项 INPUT_ERROR 不影响第0项对照",
                report.items().get(0).change());
    }

    @Test
    void unauthorizedRehearsalRejected() {
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> rehearsalService.rehearse(guest, List.of(oneItem()),
                        allowInternalCandidate(), "k"));
        assertEquals(ErrorCode.UNAUTHORIZED, ex.getCode());
        log.info("[预演-未授权] errorCode={}（区别于策略结论）", ex.getCode());
    }

    @Test
    void duplicateRehearsalDoesNotDuplicateAudit() {
        String key = "rehe-dedupe-" + System.nanoTime();
        List<BatchItemInput> items = List.of(oneItem());
        List<PolicyRule> candidate = allowInternalCandidate();
        rehearsalService.rehearse(reader, items, candidate, key);
        int before = auditService.recent(1_000_000).size();
        rehearsalService.rehearse(reader, items, candidate, key);
        int after = auditService.recent(1_000_000).size();
        assertEquals(before, after, "重复预演不得新增审计记录");
        log.info("[预演-幂等] 重复预演审计 {} -> {}（无新增）", before, after);
    }

    @Test
    void allowToDenyDirectionIsReported() {
        // 候选：无条件 DENY，会把原本放行的镜像打成拒绝。
        // 先让现网处于“内部放行”版本，再用无条件 DENY 候选预演。
        long base = adminService.current(admin).version();
        adminService.update(admin, base, allowInternalCandidate(), "现网改为内部放行");
        assertNotEquals(1L, adminService.current(admin).version());

        List<PolicyRule> denyAll = List.of(new PolicyRule("candidate-deny-all", 100,
                PolicyEffect.DENY, 1, List.of(), "预演候选：无条件拒绝"));
        RehearsalReport report = rehearsalService.rehearse(reader, List.of(oneItem()), denyAll,
                "rehe-a2d-" + System.nanoTime());
        RehearsalItemResult item = report.items().get(0);

        log.info("[预演-放行变拒绝] current={} candidate={} change={} rule={}",
                item.currentReport().decision(), item.candidateReport().decision(),
                item.change(), item.candidateReport().decisiveRule().ruleId());
        assertEquals(Decision.ALLOW, item.currentReport().decision());
        assertEquals(Decision.DENY, item.candidateReport().decision());
        assertEquals(ChangeDirection.ALLOW_TO_DENY, item.change());
        assertEquals(1, report.allowToDenyCount());
        assertTrue(item.candidateReport().rationale().contains("candidate-deny-all"));
    }
}
