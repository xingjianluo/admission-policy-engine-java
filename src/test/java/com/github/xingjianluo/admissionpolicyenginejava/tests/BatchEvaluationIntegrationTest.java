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
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.ItemStatus;
import com.github.xingjianluo.admissionpolicyenginejava.service.BatchAdmissionService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 批量评估集成测试：
 * 1) 批量逐项出结论，可一眼区分过/不过；
 * 2) 单项坏输入只标记该项，其余照常；
 * 3) 空批/超上限明确拒绝；
 * 4) 未授权被拒绝（401 通道，与策略 DENY 不同）；
 * 5) 同批重复提交不重复留痕。
 */
@SpringBootTest
class BatchEvaluationIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(BatchEvaluationIntegrationTest.class);

    @Autowired
    private BatchAdmissionService batchService;
    @Autowired
    private AuditService auditService;

    private final Caller reader = new Caller("batch-reader", Set.of("READER"));
    private final Caller guest = new Caller("batch-guest", Set.of("GUEST"));

    static final String MANIFEST = """
            {
              "schemaVersion": 2,
              "digest": "sha256:batch%04d",
              "config": { "digest": "sha256:batch%04d" },
              "annotations": {
                "io.xj.registry": "gcr.internal",
                "io.xj.repository": "team-b/img",
                "io.xj.tag": "1.0"
              }
            }
            """;
    static final String SCAN = """
            { "digest": "sha256:batch%04d", "vulnerabilities": [] }
            """;

    private IngestionRequest internalImage(int n) {
        String digest = String.format("sha256:batch%04d", n);
        String manifest = MANIFEST.formatted(n, n);
        String scan = SCAN.formatted(n);
        return new IngestionRequest("gcr.internal/team-b/img:1.0-" + n, List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", manifest),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", scan)));
    }

    private IngestionRequest externalImage(int n) {
        // registry 换成外部：默认策略命中 deny-untrusted-registry → DENY
        String digest = String.format("sha256:batch%04d", n);
        String manifest = MANIFEST.formatted(n, n)
                .replace("gcr.internal", "registry.example.com");
        String scan = SCAN.formatted(n);
        return new IngestionRequest("registry.example.com/team-b/img:1.0-" + n, List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", manifest),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", scan)));
    }

    private BatchItemInput item(int index, IngestionRequest req) {
        return new BatchItemInput(index, req, null);
    }

    @Test
    void batchReportsPerItemDecisionsAndTotals() {
        List<BatchItemInput> items = List.of(
                item(0, internalImage(1)),
                item(1, externalImage(2)),
                item(2, internalImage(3)));
        BatchEvaluationReport report = batchService.evaluateBatch(reader, items,
                "batch-mixed-" + System.nanoTime());

        log.info("[批量-混合] total={} allowed={} denied={} errors={} version=v{} 逐项={}",
                report.totalCount(), report.allowedCount(), report.deniedCount(),
                report.errorCount(), report.policyVersion(),
                report.items().stream().map(i -> i.index() + ":" + statusOf(i)).toList());

        assertEquals(3, report.totalCount());
        // 默认纯 DENY 策略下：内部镜像缺证明/签名命中 DENY，外部还命中 untrusted-registry。
        assertEquals(3, report.deniedCount());
        assertEquals(0, report.allowedCount());
        assertEquals(0, report.errorCount());
        for (BatchItemResult r : report.items()) {
            assertEquals(ItemStatus.EVALUATED, r.status());
            assertEquals(Decision.DENY, r.report().decision());
            assertNotNull(r.reference());
        }
        assertTrue(report.items().get(1).report().matchedRules().stream()
                .anyMatch(m -> m.ruleId().equals("deny-untrusted-registry")));
    }

    private String statusOf(BatchItemResult r) {
        return r.status() == ItemStatus.EVALUATED
                ? String.valueOf(r.report().decision()) : "ERROR(" + r.errorCode() + ")";
    }

    @Test
    void oneBadInputIsFlaggedOnlyForThatItemOthersStillEvaluate() {
        List<BatchItemInput> items = List.of(
                item(0, internalImage(10)),
                // 坏输入：工件指纹与清单不一致
                new BatchItemInput(1, new IngestionRequest("gcr.internal/x:bad", List.of(
                        new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", MANIFEST.formatted(11, 11)),
                        new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON",
                                SCAN.formatted(99)))), null),
                item(2, internalImage(12)),
                // 坏输入：空工件集合（缺 MANIFEST）
                new BatchItemInput(3, new IngestionRequest("gcr.internal/y:empty", List.of()),
                        null),
                // 结构性错误：缺 reference
                new BatchItemInput(4, null, "批量第 4 项缺少镜像引用 reference"));

        BatchEvaluationReport report = batchService.evaluateBatch(reader, items,
                "batch-bad-" + System.nanoTime());

        log.info("[批量-坏输入隔离] total={} denied={} errors={} 逐项={}",
                report.totalCount(), report.deniedCount(), report.errorCount(),
                report.items().stream().map(i -> i.index() + ":" + statusOf(i)).toList());

        assertEquals(5, report.totalCount());
        assertEquals(3, report.errorCount(), "坏输入项数应为 3");
        assertEquals(5, report.items().size());
        assertEquals(ItemStatus.EVALUATED, report.items().get(0).status());
        assertEquals(ItemStatus.INPUT_ERROR, report.items().get(1).status());
        assertEquals(ErrorCode.FINGERPRINT_MISMATCH.name(), report.items().get(1).errorCode());
        assertNotNull(report.items().get(1).errorMessage());
        assertEquals(ItemStatus.EVALUATED, report.items().get(2).status(),
                "坏输入不得影响同批其他项");
        assertEquals(ItemStatus.INPUT_ERROR, report.items().get(3).status());
        assertEquals(ErrorCode.INCOMPLETE_ARTIFACT_SET.name(),
                report.items().get(3).errorCode());
        assertEquals(ItemStatus.INPUT_ERROR, report.items().get(4).status());
        assertEquals("INVALID_REQUEST", report.items().get(4).errorCode());
    }

    @Test
    void emptyBatchAndOversizedBatchAreRejected() {
        AdmissionException empty = assertThrows(AdmissionException.class,
                () -> batchService.evaluateBatch(reader, List.of(), "k"));
        assertEquals(ErrorCode.INVALID_REQUEST, empty.getCode());

        List<BatchItemInput> tooMany = new ArrayList<>();
        for (int i = 0; i < 101; i++) {
            tooMany.add(item(i, internalImage(i)));
        }
        AdmissionException tooBig = assertThrows(AdmissionException.class,
                () -> batchService.evaluateBatch(reader, tooMany, "k"));
        assertEquals(ErrorCode.INVALID_REQUEST, tooBig.getCode());
        assertTrue(tooBig.getMessage().contains("100"));
        log.info("[批量-上限] 空批与超 100 条均被明确拒绝: {} / {}",
                empty.getMessage(), tooBig.getMessage());
    }

    @Test
    void unauthorizedCallerRejectedAndNotAPolicyDeny() {
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> batchService.evaluateBatch(guest, List.of(item(0, internalImage(1))), "k"));
        assertEquals(ErrorCode.UNAUTHORIZED, ex.getCode());
        log.info("[批量-未授权] errorCode={}（区别于批量项内的策略 DENY）", ex.getCode());
    }

    @Test
    void duplicateBatchSubmissionDoesNotDuplicateAudit() {
        String key = "batch-dedupe-" + System.nanoTime();
        List<BatchItemInput> items = List.of(
                item(0, internalImage(20)),
                item(1, externalImage(21)));
        BatchEvaluationReport r1 = batchService.evaluateBatch(reader, items, key);
        int before = auditService.recent(1_000_000).size();
        BatchEvaluationReport r2 = batchService.evaluateBatch(reader, items, key);
        int after = auditService.recent(1_000_000).size();

        assertEquals(before, after, "同一批重复提交不得新增审计记录");
        assertEquals(r1.deniedCount(), r2.deniedCount());
        assertEquals(r1.items().get(0).report().decision(),
                r2.items().get(0).report().decision());
        log.info("[批量-幂等] 重复提交 key={} 审计记录 {} -> {}（无新增）", key, before, after);
    }
}
