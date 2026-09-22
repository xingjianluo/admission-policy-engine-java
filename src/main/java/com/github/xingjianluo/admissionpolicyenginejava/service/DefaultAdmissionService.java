package com.github.xingjianluo.admissionpolicyenginejava.service;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactParser;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.model.AuditRecord;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.DecisionReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;
import com.github.xingjianluo.admissionpolicyenginejava.model.Permission;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyEvaluator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyStore;
import com.github.xingjianluo.admissionpolicyenginejava.security.Authorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;

/**
 * 准入评估应用服务默认实现。
 * <p>
 * 关键顺序保证：
 * <ol>
 *   <li>先鉴权：未授权根本不会进入评估，错误类型为 UNAUTHORIZED；</li>
 *   <li>解析工件：畸形/缺失/指纹冲突直接按输入错误抛出，不产生 DENY 判定
 *       （DENY 只代表“输入合法但策略不允许”，原因可区分）；</li>
 *   <li>取不可变策略快照引用后再评估：评估期间任何并发更新都不影响本次判定；</li>
 *   <li>评估前以 (调用方,镜像指纹,策略版本,幂等键) 原子占位审计：
 *       重复/并发提交要么直接读到已完成结论，要么等待首个请求完成后共享同一结论，
 *       保证只评估一次、只留一条审计记录。</li>
 * </ol>
 */
@Service
public class DefaultAdmissionService implements AdmissionService {

    private static final Logger log = LoggerFactory.getLogger(DefaultAdmissionService.class);

    private final ArtifactParser parser;
    private final PolicyStore policyStore;
    private final PolicyEvaluator evaluator;
    private final Authorizer authorizer;
    private final AuditService auditService;

    public DefaultAdmissionService(ArtifactParser parser, PolicyStore policyStore,
                                   PolicyEvaluator evaluator, Authorizer authorizer,
                                   AuditService auditService) {
        this.parser = parser;
        this.policyStore = policyStore;
        this.evaluator = evaluator;
        this.authorizer = authorizer;
        this.auditService = auditService;
    }

    @Override
    public DecisionReport evaluate(Caller caller, IngestionRequest request, String idempotencyKey) {
        authorizer.check(caller, Permission.EVALUATE);

        ImageDescriptor descriptor = parser.parse(request);

        // 先固定快照引用：即使此刻其他线程发布/回滚策略，本次评估看到的集合也不变。
        PolicySnapshot snapshot = policyStore.current();
        String auditId = buildAuditId(caller.name(), descriptor.digest(),
                snapshot.version(), idempotencyKey);

        // 原子占位：决定本次线程是“首个评估者”还是“重复提交跟随者”。
        AuditRecord pending = new AuditRecord(auditId, Instant.now(), caller.name(),
                "ADMISSION_EVALUATE", descriptor.digest(), snapshot.version(),
                null, "评估进行中占位", "reference=" + descriptor.reference());
        AuditRecord existing = auditService.reserveIfAbsent(pending);
        if (existing != null) {
            AuditRecord completed = waitForCompletion(auditId, existing);
            log.info("重复/并发提交共享首次评估结论 auditId={} decision={}",
                    auditId, completed.decision());
            return reportFromAudit(completed);
        }

        try {
            DecisionReport report = evaluator.evaluate(descriptor, snapshot);

            log.info("准入评估输入 caller={} reference={} digest={} registry={} repository={} "
                            + "vulnCount={} severities={} hasProvenance={} signatureValid={}",
                    caller.name(), descriptor.reference(), descriptor.digest(),
                    descriptor.registry(), descriptor.repository(),
                    descriptor.vulnerabilities().size(),
                    descriptor.vulnerabilities().stream()
                            .map(v -> v.id() + ":" + v.severity()).toList(),
                    descriptor.provenance() != null, descriptor.signatureValid());
            log.info("命中策略 policyVersion=v{} matched={} finalDecision={} rationale={}",
                    snapshot.version(),
                    report.matchedRules().stream()
                            .map(m -> m.ruleId() + "(prio=" + m.priority() + ",effect="
                                    + m.effect() + ")").toList(),
                    report.decision(), report.rationale());

            AuditRecord finalized = new AuditRecord(auditId, pending.timestamp(), caller.name(),
                    "ADMISSION_EVALUATE", descriptor.digest(), snapshot.version(),
                    report.decision(), report.rationale(),
                    "reference=" + descriptor.reference()
                            + ", matched=" + report.matchedRules().stream()
                            .map(m -> m.ruleId() + ":" + m.effect()).toList());
            auditService.complete(pending, finalized);
            return report;
        } catch (RuntimeException ex) {
            // 评估失败也要释放占位，避免同一幂等键永远卡在“进行中”。
            auditService.complete(pending, new AuditRecord(auditId, pending.timestamp(),
                    caller.name(), "ADMISSION_EVALUATE_FAILED", descriptor.digest(),
                    snapshot.version(), null, "评估失败: " + ex.getMessage(),
                    "reference=" + descriptor.reference()));
            throw ex;
        }
    }

    /** 跟随线程等待首个请求把占位记录替换为最终记录。 */
    private AuditRecord waitForCompletion(String auditId, AuditRecord current) {
        AuditRecord seen = current;
        for (int i = 0; i < 1000 && seen.decision() == null
                && "ADMISSION_EVALUATE".equals(seen.action()); i++) {
            try {
                Thread.sleep(2);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("等待重复提交结论时被中断", e);
            }
            seen = auditService.findById(auditId);
        }
        return seen;
    }

    /** 跟随者从已完成的审计记录重建结论视图（决策与版本以留痕为准）。 */
    private DecisionReport reportFromAudit(AuditRecord a) {
        return new DecisionReport(a.decision(),
                a.policyVersion() == null ? -1L : a.policyVersion(),
                java.util.List.of(), null, a.rationale());
    }

    private String buildAuditId(String caller, String digest, long policyVersion,
                                String idempotencyKey) {
        String raw = caller + "|" + digest + "|v" + policyVersion + "|"
                + (idempotencyKey == null || idempotencyKey.isBlank()
                        ? "none" : idempotencyKey.trim());
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return "eval:" + HexFormat.of().formatHex(md.digest(
                    raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }
}
