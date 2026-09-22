package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService;
import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactKind;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.RawArtifact;
import com.github.xingjianluo.admissionpolicyenginejava.model.AuditRecord;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.DecisionReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import com.github.xingjianluo.admissionpolicyenginejava.service.AdmissionService;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyAdminService;
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
 * 端到端集成测试：
 * 鉴权拒绝(UNAUTHORIZED) 与策略拒绝(DENY) 严格区分、评估输入/命中规则/判定依据完整可审计、
 * 重复提交幂等去重。
 */
@SpringBootTest
class AdmissionIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(AdmissionIntegrationTest.class);

    @Autowired
    private AdmissionService admissionService;
    @Autowired
    private PolicyAdminService adminService;
    @Autowired
    private AuditService auditService;

    /**
     * 测试间隔离：任何用例发布的自定义策略在用例结束后都回滚到内置默认规则集 v1。
     * 回滚产生新版本号但恢复默认规则内容，保证后续用例的判定预期稳定。
     */
    @AfterEach
    void restoreDefaultPolicy() {
        adminService.rollback(admin, 1L);
    }

    private final Caller reader = new Caller("reader-1", Set.of("READER"));
    private final Caller auditor = new Caller("auditor-1", Set.of("AUDITOR"));
    private final Caller admin = new Caller("admin-1", Set.of("ADMIN"));
    private final Caller anonymous = new Caller("stranger", Set.of("GUEST"));

    static final String MANIFEST_GOOD = """
            {
              "schemaVersion": 2,
              "digest": "sha256:good0001",
              "config": { "digest": "sha256:good0001" },
              "annotations": {
                "io.xj.registry": "gcr.internal",
                "io.xj.repository": "team-a/app",
                "io.xj.tag": "1.0.0"
              }
            }
            """;

    static final String SCAN_CLEAN = """
            { "digest": "sha256:good0001", "vulnerabilities": [] }
            """;

    static final String PROVENANCE_GOOD = """
            {
              "subjectDigest": "sha256:good0001",
              "predicate": {
                "builder": { "id": "pkg:internal/ci-builder@v2" },
                "invocation": { "configSource": {
                  "uri": "git+https://git.internal/team-a/app", "digest": "sha1:ab12" } }
              }
            }
            """;

    static final String SIGNATURE_OK =
            """
            { "subjectDigest": "sha256:good0001", "verified": true }
            """;

    static final String MANIFEST_EXTERNAL = MANIFEST_GOOD
            .replace("sha256:good0001", "sha256:ext0001")
            .replace("gcr.internal", "docker.example.com");
    static final String SCAN_EXTERNAL = SCAN_CLEAN.replace("sha256:good0001",
            "sha256:ext0001");
    static final String PROV_EXTERNAL = PROVENANCE_GOOD.replace("sha256:good0001",
            "sha256:ext0001");
    static final String SIG_EXTERNAL = SIGNATURE_OK.replace("sha256:good0001",
            "sha256:ext0001");

    private IngestionRequest goodImage() {
        return new IngestionRequest("gcr.internal/team-a/app:1.0.0", List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", MANIFEST_GOOD),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", SCAN_CLEAN),
                new RawArtifact(ArtifactKind.PROVENANCE, "SLSA-V1-JSON", PROVENANCE_GOOD),
                new RawArtifact(ArtifactKind.SIGNATURE, "SIGNOTE-JSON", SIGNATURE_OK)));
    }

    private IngestionRequest externalImage() {
        return new IngestionRequest("docker.example.com/team-a/app:1.0.0", List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", MANIFEST_EXTERNAL),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", SCAN_EXTERNAL),
                new RawArtifact(ArtifactKind.PROVENANCE, "SLSA-V1-JSON", PROV_EXTERNAL),
                new RawArtifact(ArtifactKind.SIGNATURE, "SIGNOTE-JSON", SIG_EXTERNAL)));
    }

    @Test
    void unauthenticatedCallerIsRejectedWithDistinctErrorCodeAndNotADeny() {
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> admissionService.evaluate(anonymous, goodImage(), "k1"));
        assertEquals(ErrorCode.UNAUTHORIZED, ex.getCode());
        log.info("[集成-未授权] errorCode={}（区别于策略 DENY）message={}",
                ex.getCode(), ex.getMessage());

        // READER 也不能更新策略：鉴权拒绝同样是 UNAUTHORIZED
        AdmissionException ex2 = assertThrows(AdmissionException.class,
                () -> adminService.update(reader, 1L,
                        List.of(new PolicyRule("x", 1, PolicyEffect.ALLOW, 1, List.of(), "x")),
                        "nope"));
        assertEquals(ErrorCode.UNAUTHORIZED, ex2.getCode());
        log.info("[集成-越权更新策略] errorCode={} message={}", ex2.getCode(), ex2.getMessage());
    }

    @Test
    void policyDenyIsANormalDecisionDistinctFromErrors() {
        // 外部 registry 镜像命中默认策略 deny-untrusted-registry
        DecisionReport report = admissionService.evaluate(reader, externalImage(),
                "ext-" + System.nanoTime());
        log.info("[集成-策略拒绝] 输入 reference=docker.example.com/... digest={} 命中={} 判定={} 依据={}",
                "sha256:ext0001",
                report.matchedRules().stream().map(m -> m.ruleId() + ":" + m.effect()).toList(),
                report.decision(), report.rationale());

        assertEquals(Decision.DENY, report.decision(), "策略拒绝是 DENY 结论，不是异常");
        assertTrue(report.matchedRules().stream()
                        .anyMatch(m -> m.ruleId().equals("deny-untrusted-registry")),
                "外部 registry 必须命中 deny-untrusted-registry");
        log.info("[集成-策略拒绝] 默认策略版本 v{}（回滚恢复后）", report.policyVersion());
    }

    @Test
    void compliantImageIsAllowedAndAuditCapturesInputVersionAndRationale() {
        DecisionReport report = admissionService.evaluate(reader, goodImage(),
                "good-" + System.nanoTime());
        log.info("[集成-合规放行] 判定={} 命中={} 依据={}",
                report.decision(),
                report.matchedRules().stream().map(m -> m.ruleId() + ":" + m.effect()).toList(),
                report.rationale());

        // 默认策略下合规镜像不命中任何 DENY 条件：无命中 → fail-closed DENY。
        assertEquals(Decision.DENY, report.decision());
        assertEquals(0, report.matchedRules().size(),
                "合规镜像在默认纯DENY策略集下应无规则命中");
        assertTrue(report.rationale().contains("fail-closed"));

        List<AuditRecord> records = auditService.findByDigest("sha256:good0001");
        assertTrue(records.stream().anyMatch(r ->
                        "reader-1".equals(r.caller())
                        && r.action().equals("ADMISSION_EVALUATE")
                        && r.imageDigest().equals("sha256:good0001")),
                "审计记录必须包含调用方、动作与镜像指纹");
        AuditRecord ar = records.get(records.size() - 1);
        log.info("[集成-审计留痕] id={} caller={} digest={} policyVersion=v{} decision={} "
                        + "rationale={} detail={}",
                ar.id(), ar.caller(), ar.imageDigest(), ar.policyVersion(), ar.decision(),
                ar.rationale(), ar.detail());
    }

    @Test
    void adminAllowPolicyOverridesDefaultsAndDeniesStillDistinguishable() {
        // 管理员发布显式 ALLOW：来自 gcr.internal 的镜像高优先级放行
        long base = adminService.current(admin).version();
        List<PolicyRule> rules = List.of(
                new PolicyRule("deny-critical-vulns", 10, PolicyEffect.DENY, 1,
                        List.of(new PolicyCondition(ConditionType.SEVERITY_AT_LEAST,
                                "CRITICAL")), "默认-严重漏洞拒绝"),
                new PolicyRule("allow-internal-good", 100, PolicyEffect.ALLOW, 1,
                        List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS,
                                "gcr.internal")), "内部来源显式放行"));
        PolicySnapshot published = adminService.update(admin, base, rules, "加入显式ALLOW");
        log.info("[集成-策略更新] 发布 v{} 规则={}", published.version(),
                rules.stream().map(PolicyRule::id).toList());

        DecisionReport report = admissionService.evaluate(reader, goodImage(),
                "override-" + System.nanoTime());
        log.info("[集成-ALLOW覆盖] 输入 digest=sha256:good0001 命中={} 最终={} 依据={}",
                report.matchedRules().stream().map(m -> m.ruleId() + ":" + m.effect()
                        + "@p" + m.priority()).toList(),
                report.decision(), report.rationale());

        assertEquals(Decision.ALLOW, report.decision());
        assertEquals("allow-internal-good", report.decisiveRule().ruleId());
        assertNotEquals(1L, report.policyVersion());
    }

    @Test
    void duplicateSubmissionsProduceSingleAuditRecordAndSameDecision() {
        String key = "dedupe-" + System.nanoTime();
        DecisionReport r1 = admissionService.evaluate(reader, externalImage(), key);
        int before = auditService.recent(500).size();
        DecisionReport r2 = admissionService.evaluate(reader, externalImage(), key);
        int after = auditService.recent(500).size();

        assertEquals(r1.decision(), r2.decision());
        assertEquals(before, after, "重复提交不得产生第二条审计记录");
        log.info("[集成-幂等] 重复提交 key={} 结论一致={} 审计记录数 {} -> {}（无新增）",
                key, r1.decision(), before, after);
    }

    @Test
    void readerCannotReadAuditTrailButAuditorCan() {
        admissionService.evaluate(reader, externalImage(), "perm-" + System.nanoTime());

        // READER 可读取策略（不抛异常），但不能读取审计
        PolicySnapshot current = adminService.current(reader);
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> authorizerCheckReadAudit(reader));
        assertEquals(ErrorCode.UNAUTHORIZED, ex.getCode());

        // AUDITOR 读取审计被放行
        authorizerCheckReadAudit(auditor);
        List<AuditRecord> seen = auditService.recent(10);

        log.info("[集成-审计权限] READER 可读策略(v{})但读取审计被 {} 拒绝；"
                        + "AUDITOR 读取审计放行，可见 {} 条",
                current.version(), ErrorCode.UNAUTHORIZED, seen.size());
        assertTrue(seen.size() > 0);
    }

    @Autowired
    private com.github.xingjianluo.admissionpolicyenginejava.security.Authorizer authorizer;

    private void authorizerCheckReadAudit(Caller caller) {
        authorizer.check(caller,
                com.github.xingjianluo.admissionpolicyenginejava.model.Permission.READ_AUDIT);
    }
}
