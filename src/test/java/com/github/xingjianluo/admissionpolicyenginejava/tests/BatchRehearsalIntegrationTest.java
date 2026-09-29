package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService;
import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactKind;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.BatchItemInput;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.PreparedBatchItem;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.RawArtifact;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchEvaluationReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchItemResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.ChangeDirection;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalItemResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalReport;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.service.BatchAdmissionService;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyAdminService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 批量评估 + 策略预演集成测试：
 * 批量各自结论、坏输入单项隔离、批量上限、预演对照正确性（变化方向/决定性规则）、
 * 候选规则非法按规则集不合法处理、预演不发布不留版本、可复现、未授权拒绝。
 */
@SpringBootTest
class BatchRehearsalIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(BatchRehearsalIntegrationTest.class);

    @Autowired
    private BatchAdmissionService batchService;
    @Autowired
    private PolicyAdminService adminService;
    @Autowired
    private AuditService auditService;

    private final Caller reader = new Caller("reader-batch", Set.of("READER"));
    private final Caller admin = new Caller("admin-batch", Set.of("ADMIN"));
    private final Caller guest = new Caller("guest-batch", Set.of("GUEST"));

    @AfterEach
    void restoreDefaultPolicy() {
        adminService.rollback(admin, 1L);
    }

    // --------------------------------------------------------------- 测试夹具

    private static String manifest(String digest, String registry, String repository) {
        return """
                {
                  "schemaVersion": 2,
                  "digest": "%s",
                  "config": { "digest": "%s" },
                  "annotations": {
                    "io.xj.registry": "%s",
                    "io.xj.repository": "%s",
                    "io.xj.tag": "1.0"
                  }
                }
                """.formatted(digest, digest, registry, repository);
    }

    private static String scan(String digest, String... vulns) {
        StringBuilder sb = new StringBuilder("{ \"digest\": \"").append(digest)
                .append("\", \"vulnerabilities\": [");
        for (int i = 0; i < vulns.length; i += 2) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{ \"id\": \"").append(vulns[i]).append("\", ")
                    .append("\"ratings\": [{ \"severity\": \"").append(vulns[i + 1]).append("\" }] }");
        }
        return sb.append("] }").toString();
    }

    /** 合规内部镜像（无漏洞 + 无证明 + 无签名）：默认 v1 下多规则命中 → DENY。 */
    private PreparedBatchItem internalGood(int n) {
        String digest = "sha256:batch-good-" + n;
        return item("gcr.internal/team-a/app%d:1.0".formatted(n),
                manifest(digest, "gcr.internal", "team-a/app" + n),
                scan(digest));
    }

    /** 外部 registry 镜像：默认命中 deny-untrusted-registry。 */
    private PreparedBatchItem externalImage(int n) {
        String digest = "sha256:batch-ext-" + n;
        return item("docker.example.com/team-a/web%d:1.0".formatted(n),
                manifest(digest, "docker.example.com", "team-a/web" + n),
                scan(digest));
    }

    /** 携带 CRITICAL 漏洞的内部镜像：命中 deny-critical-vulns。 */
    private PreparedBatchItem internalCritical(int n) {
        String digest = "sha256:batch-crit-" + n;
        return item("gcr.internal/team-a/vuln%d:1.0".formatted(n),
                manifest(digest, "gcr.internal", "team-a/vuln" + n),
                scan(digest, "CVE-BAD-" + n, "CRITICAL"));
    }

    private PreparedBatchItem item(String reference, String manifest, String scan) {
        return PreparedBatchItem.of(new BatchItemInput(reference, List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", manifest),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", scan))));
    }

    private PreparedBatchItem malformedItem() {
        // 工件格式不支持：解析阶段应被标出，不影响其他项
        return PreparedBatchItem.of(new BatchItemInput("gcr.internal/bad/item:1", List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "NOT-A-FORMAT", "{}"))));
    }

    private PreparedBatchItem structurallyInvalidItem() {
        // DTO 转换阶段就不合法（未知 kind 由 Web 层标记；这里直接构造结构错误项）
        return PreparedBatchItem.invalid("INVALID_REQUEST", "镜像项(x) 未知工件类别 kind=WAT");
    }

    /** 候选规则：内部 registry 放行（priority=100）；CRITICAL 以更高优先级护栏拒绝（priority=200）。 */
    private List<PolicyRule> candidateAllowInternal() {
        return List.of(
                new PolicyRule("cand-allow-internal", 100, PolicyEffect.ALLOW, 1,
                        List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS, "gcr.internal")),
                        "候选：内部来源放行"),
                new PolicyRule("cand-deny-critical", 200, PolicyEffect.DENY, 1,
                        List.of(new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, "CRITICAL")),
                        "候选：严重漏洞高优先级拒绝"));
    }

    private List<PreparedBatchItem> list(PreparedBatchItem... items) {
        return List.of(items);
    }

    // --------------------------------------------------------------- 批量评估

    @Test
    void batchEvaluateGivesIndependentVerdictsAndCounters() {
        BatchEvaluationReport report = batchService.evaluateBatch(reader,
                list(internalGood(1), externalImage(1), internalCritical(1)),
                "batch-ok-" + System.nanoTime());

        assertEquals(3, report.total());
        assertEquals(3, report.succeeded());
        assertEquals(0, report.failed());
        // 默认 v1 是纯 DENY 护栏、无显式 ALLOW 规则：三个镜像都应为 DENY。
        assertEquals(0, report.allowed());
        assertEquals(3, report.denied());
        assertEquals(report.policyVersion(), adminService.current(reader).version());
        for (BatchItemResult r : report.items()) {
            assertTrue(r.ok());
            assertEquals(Decision.DENY, r.report().decision(),
                    "默认纯 DENY 策略下 " + r.reference() + " 必须 DENY");
        }
        log.info("[批量评估] total={} allowed={} denied={} 结果={}", report.total(),
                report.allowed(), report.denied(),
                report.items().stream().map(r -> r.reference() + "="
                        + (r.ok() ? r.report().decision() : "ERR:" + r.errorCode())).toList());
    }

    @Test
    void oneBadInputIsFlaggedAndOthersStillEvaluated() {
        BatchEvaluationReport report = batchService.evaluateBatch(reader,
                list(internalGood(2), malformedItem(), externalImage(2),
                        structurallyInvalidItem()),
                "batch-bad-" + System.nanoTime());

        assertEquals(4, report.total());
        assertEquals(2, report.succeeded(), "两个合法项必须照常出结果");
        assertEquals(2, report.failed(), "两个坏输入项必须各自标出");
        assertTrue(report.items().get(0).ok());
        assertFalse(report.items().get(1).ok());
        assertEquals("MALFORMED_ARTIFACT", report.items().get(1).errorCode());
        assertNotNull(report.items().get(1).errorMessage());
        assertTrue(report.items().get(2).ok());
        assertFalse(report.items().get(3).ok());
        assertEquals("INVALID_REQUEST", report.items().get(3).errorCode());
        assertNull(report.items().get(1).report());
        log.info("[批量-坏输入隔离] 各项 ok={} 错误项={}",
                report.items().stream().map(BatchItemResult::ok).toList(),
                report.items().stream().filter(r -> !r.ok())
                        .map(r -> "#" + r.index() + ":" + r.errorCode()).toList());
    }

    @Test
    void batchOverLimitIsRejectedWhole() {
        List<PreparedBatchItem> tooMany = new ArrayList<>();
        for (int i = 0; i < BatchAdmissionService.MAX_BATCH_ITEMS + 1; i++) {
            tooMany.add(internalGood(1000 + i));
        }
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> batchService.evaluateBatch(reader, tooMany, "batch-too-big"));
        assertEquals(ErrorCode.INVALID_REQUEST, ex.getCode());
        assertTrue(ex.getMessage().contains(String.valueOf(BatchAdmissionService.MAX_BATCH_ITEMS)));
        log.info("[批量-上限] {} 项被整体拒绝: {}", tooMany.size(), ex.getMessage());

        AdmissionException empty = assertThrows(AdmissionException.class,
                () -> batchService.evaluateBatch(reader, List.of(), "batch-empty"));
        assertEquals(ErrorCode.INVALID_REQUEST, empty.getCode());
    }

    @Test
    void unauthorizedBatchCallerRejectedAndDistinctFromDeny() {
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> batchService.evaluateBatch(guest, list(internalGood(3)),
                        "batch-guest"));
        assertEquals(ErrorCode.UNAUTHORIZED, ex.getCode());
        log.info("[批量-未授权] errorCode={}（区别于策略 DENY 与单项坏输入）", ex.getCode());
    }

    // --------------------------------------------------------------- 预演对照

    @Test
    void rehearsalComparesCurrentVsCandidateWithDirectionsAndDecisiveRules() {
        RehearsalReport report = batchService.rehearse(reader,
                list(internalGood(4), externalImage(4), internalCritical(4)),
                candidateAllowInternal(), "rehearse-ok-" + System.nanoTime());

        assertEquals(3, report.total());
        assertEquals(0, report.invalid());
        // 默认 v1 全部 DENY：
        //  internal-good     → 候选 ALLOW（DENY→ALLOW）
        //  external          → 候选仍 DENY（无规则命中 fail-closed）UNCHANGED
        //  internal-critical → 候选命中 cand-deny-critical 仍 DENY，UNCHANGED
        RehearsalItemResult good = report.items().get(0);
        RehearsalItemResult external = report.items().get(1);
        RehearsalItemResult critical = report.items().get(2);

        assertEquals(Decision.DENY, good.baseline().decision());
        assertEquals(Decision.ALLOW, good.candidate().decision());
        assertTrue(good.changed());
        assertEquals(ChangeDirection.DENY_TO_ALLOW, good.direction());
        assertEquals("cand-allow-internal", good.candidate().decisiveRule().ruleId(),
                "变化时必须说清是被哪条候选规则决定的");

        assertEquals(Decision.DENY, external.baseline().decision());
        assertEquals(Decision.DENY, external.candidate().decision());
        assertFalse(external.changed());
        assertEquals(ChangeDirection.UNCHANGED, external.direction());
        assertNull(external.candidate().decisiveRule(), "候选无规则命中应 fail-closed");

        assertEquals(Decision.DENY, critical.baseline().decision());
        assertEquals(Decision.DENY, critical.candidate().decision());
        assertFalse(critical.changed());
        assertEquals("cand-deny-critical", critical.candidate().decisiveRule().ruleId());

        assertEquals(1, report.changedCount());
        assertEquals(0, report.allowToDenyCount());
        assertEquals(1, report.denyToAllowCount());
        log.info("[预演-对照] baseline=v{} changed={} A→D={} D→A={} 逐项={}",
                report.baselineVersion(), report.changedCount(),
                report.allowToDenyCount(), report.denyToAllowCount(),
                report.items().stream().map(r -> r.reference() + ":"
                        + r.baseline().decision() + "→" + r.candidate().decision()
                        + (r.changed() ? "(" + r.direction() + ",by="
                        + r.candidate().decisiveRule().ruleId() + ")" : "")).toList());
    }

    @Test
    void rehearsalAllowToDenyDirectionIsReported() {
        // 先发布一个“内部全放行”的线上策略，使好镜像当前 ALLOW；
        // 候选规则改成空集（无命中 → fail-closed DENY），应报告 ALLOW→DENY。
        long base = adminService.current(admin).version();
        adminService.update(admin, base, List.of(new PolicyRule("live-allow-internal", 100,
                        PolicyEffect.ALLOW, 1,
                        List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS, "gcr.internal")),
                        "线上放行内部")),
                "预演测试：线上放行");

        RehearsalReport report = batchService.rehearse(reader,
                list(internalGood(5)),
                List.of(new PolicyRule("cand-deny-all", 10, PolicyEffect.DENY, 1,
                        List.of(), "候选无条件拒绝")),
                "rehearse-a2d-" + System.nanoTime());

        RehearsalItemResult item = report.items().get(0);
        assertEquals(Decision.ALLOW, item.baseline().decision());
        assertEquals(Decision.DENY, item.candidate().decision());
        assertEquals(ChangeDirection.ALLOW_TO_DENY, item.direction());
        assertEquals("cand-deny-all", item.candidate().decisiveRule().ruleId());
        assertEquals(1, report.allowToDenyCount());
        log.info("[预演-放行变拒绝] {} → {} by={}", item.baseline().decision(),
                item.candidate().decision(), item.candidate().decisiveRule().ruleId());
    }

    @Test
    void invalidCandidateRulesRejectedLikePublishAndNoSideEffects() {
        long versionBefore = adminService.current(admin).version();

        // schemaVersion 越界：与正常发布一致 → POLICY_SCHEMA_UNSUPPORTED
        PolicyRule badSchema = new PolicyRule("bad-schema", 1, PolicyEffect.ALLOW, 99,
                List.of(), "非法 schema");
        AdmissionException ex1 = assertThrows(AdmissionException.class,
                () -> batchService.rehearse(reader, list(internalGood(6)),
                        List.of(badSchema), "rehearse-badschema"));
        assertEquals(ErrorCode.POLICY_SCHEMA_UNSUPPORTED, ex1.getCode());

        // 重复 id：与正常发布一致 → INVALID_REQUEST
        PolicyRule r1 = new PolicyRule("dup", 1, PolicyEffect.ALLOW, 1, List.of(), "a");
        PolicyRule r2 = new PolicyRule("dup", 2, PolicyEffect.DENY, 1, List.of(), "b");
        AdmissionException ex2 = assertThrows(AdmissionException.class,
                () -> batchService.rehearse(reader, list(internalGood(7)),
                        List.of(r1, r2), "rehearse-dupid"));
        assertEquals(ErrorCode.INVALID_REQUEST, ex2.getCode());

        // 严重级别阈值无法识别：规则集不合法，不允许悄悄放过
        PolicyRule badSev = new PolicyRule("bad-sev", 1, PolicyEffect.DENY, 1,
                List.of(new PolicyCondition(ConditionType.SEVERITY_AT_LEAST, "BOGUS")), "x");
        AdmissionException ex3 = assertThrows(AdmissionException.class,
                () -> batchService.rehearse(reader, list(internalGood(8)),
                        List.of(badSev), "rehearse-badsev"));
        assertEquals(ErrorCode.INVALID_REQUEST, ex3.getCode());

        long versionAfter = adminService.current(admin).version();
        assertEquals(versionBefore, versionAfter, "预演绝不能推进线上策略版本");
        log.info("[预演-候选非法] 三次预演分别被 {}/{}/{} 拒绝，线上版本保持 v{}",
                ex1.getCode(), ex2.getCode(), ex3.getCode(), versionAfter);
    }

    @Test
    void rehearsalDoesNotPublishAndLeavesNoNewVersion() {
        long before = adminService.current(admin).version();
        batchService.rehearse(reader, list(internalGood(9), externalImage(9)),
                candidateAllowInternal(), "rehearse-noside-" + System.nanoTime());
        long after = adminService.current(admin).version();
        assertEquals(before, after, "预演前后当前版本必须不变");
        long historySize = adminService.history(admin).size();
        assertEquals(before + 1, historySize, "版本链长度不得因预演增加（v0..vN）");
        log.info("[预演-无副作用] 版本 v{} → v{}，历史版本数 {}（无新增正式版本）",
                before, after, historySize);
    }

    @Test
    void rehearsalIsDeterministicAcrossRepeatedRuns() {
        List<PreparedBatchItem> items = list(internalGood(10), externalImage(10),
                internalCritical(10), malformedItem());
        RehearsalReport first = batchService.rehearse(reader, items,
                candidateAllowInternal(), "rehearse-determ-key");
        for (int i = 0; i < 5; i++) {
            RehearsalReport again = batchService.rehearse(reader, items,
                    candidateAllowInternal(), "rehearse-determ-key");
            assertEquals(first.changedCount(), again.changedCount());
            assertEquals(first.allowToDenyCount(), again.allowToDenyCount());
            assertEquals(first.denyToAllowCount(), again.denyToAllowCount());
            for (int j = 0; j < first.items().size(); j++) {
                RehearsalItemResult a = first.items().get(j);
                RehearsalItemResult b = again.items().get(j);
                assertEquals(a.ok(), b.ok());
                if (a.ok()) {
                    assertEquals(a.baseline().decision(), b.baseline().decision());
                    assertEquals(a.candidate().decision(), b.candidate().decision());
                    assertEquals(a.direction(), b.direction());
                }
            }
        }
        log.info("[预演-可复现] 同批输入+同候选规则重复 6 遍，变化集合一致 changed={}",
                first.changedCount());
    }

    @Test
    void duplicateBatchAndRehearseSubmissionsRecordedOnce() {
        List<PreparedBatchItem> items = list(internalGood(11), externalImage(11));
        String batchKey = "idemp-batch-" + System.nanoTime();
        long beforeBatch = auditService.recent(100_000).stream()
                .filter(r -> "ADMISSION_BATCH_EVALUATE".equals(r.action())).count();
        batchService.evaluateBatch(reader, items, batchKey);
        batchService.evaluateBatch(reader, items, batchKey);
        long afterBatch = auditService.recent(100_000).stream()
                .filter(r -> "ADMISSION_BATCH_EVALUATE".equals(r.action())).count();
        assertEquals(beforeBatch + 1, afterBatch, "同批重复提交只允许一条批量审计");

        String rehearseKey = "idemp-rehearse-" + System.nanoTime();
        long beforeRe = auditService.recent(100_000).stream()
                .filter(r -> "POLICY_REHEARSE".equals(r.action())).count();
        batchService.rehearse(reader, items, candidateAllowInternal(), rehearseKey);
        batchService.rehearse(reader, items, candidateAllowInternal(), rehearseKey);
        long afterRe = auditService.recent(100_000).stream()
                .filter(r -> "POLICY_REHEARSE".equals(r.action())).count();
        assertEquals(beforeRe + 1, afterRe, "同批重复预演只允许一条预演审计");

        // 审计记录要能看出谁、什么时候、基线版本、影响了哪些镜像
        var latest = auditService.recent(100_000).stream()
                .filter(r -> "POLICY_REHEARSE".equals(r.action())).reduce((a, b) -> b).orElseThrow();
        assertEquals("reader-batch", latest.caller());
        assertNotNull(latest.timestamp());
        assertNotNull(latest.policyVersion());
        assertTrue(latest.detail().contains("changedItems="));
        log.info("[批量/预演-幂等留痕] 审计各仅 +1；最近预演记录 caller={} time={} base=v{} detail={}",
                latest.caller(), latest.timestamp(), latest.policyVersion(), latest.detail());
    }

    @Test
    void unauthorizedRehearsalRejected() {
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> batchService.rehearse(guest, list(internalGood(12)),
                        candidateAllowInternal(), "rehearse-guest"));
        assertEquals(ErrorCode.UNAUTHORIZED, ex.getCode());
        log.info("[预演-未授权] errorCode={}", ex.getCode());
    }
}
