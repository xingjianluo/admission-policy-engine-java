package com.github.xingjianluo.admissionpolicyenginejava.service;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService;
import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactParser;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.BatchItemInput;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.PreparedBatchItem;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.RawArtifact;
import com.github.xingjianluo.admissionpolicyenginejava.model.AuditRecord;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchEvaluationReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchItemResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.ChangeDirection;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.DecisionReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;
import com.github.xingjianluo.admissionpolicyenginejava.model.MatchedRule;
import com.github.xingjianluo.admissionpolicyenginejava.model.Permission;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalItemResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalReport;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyEvaluator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
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
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * 批量评估与策略预演应用服务默认实现。
 * <p>
 * 关键保证：
 * <ol>
 *   <li>先鉴权：未授权 → UNAUTHORIZED，与“策略不允许(DENY)”和“单项坏输入”三条通道完全分离；</li>
 *   <li>批量上限：超过 {@link #MAX_BATCH_ITEMS} 立即 INVALID_REQUEST 拒绝整批，防止拖垮服务；</li>
 *   <li>单项隔离：每个镜像项独立转换/解析/评估，坏输入只把该项标记为 ok=false + 原因，
 *       其余项照常出结论；</li>
 *   <li>快照一致：整次操作只在开始时固定一次当前策略快照引用，期间任何发布/回滚
 *       都不会让一次对照出现“一半旧一半新”；</li>
 *   <li>预演无副作用：候选规则只做与发布相同的合法性校验并在内存快照中评估，
 *       绝不写入版本链、不产生正式新版本；</li>
 *   <li>留痕幂等：每次批量评估/预演写一条审计；同一批请求（调用方+幂等键+策略版本+内容）
 *       重复提交只记一条。</li>
 * </ol>
 */
@Service
public class DefaultBatchAdmissionService implements BatchAdmissionService {

    private static final Logger log = LoggerFactory.getLogger(DefaultBatchAdmissionService.class);

    static final String ACTION_BATCH_EVALUATE = "ADMISSION_BATCH_EVALUATE";
    static final String ACTION_REHEARSE = "POLICY_REHEARSE";

    private final ArtifactParser parser;
    private final PolicyStore policyStore;
    private final PolicyEvaluator evaluator;
    private final Authorizer authorizer;
    private final AuditService auditService;

    public DefaultBatchAdmissionService(ArtifactParser parser, PolicyStore policyStore,
                                        PolicyEvaluator evaluator, Authorizer authorizer,
                                        AuditService auditService) {
        this.parser = parser;
        this.policyStore = policyStore;
        this.evaluator = evaluator;
        this.authorizer = authorizer;
        this.auditService = auditService;
    }

    @Override
    public BatchEvaluationReport evaluateBatch(Caller caller, List<PreparedBatchItem> items,
                                               String idempotencyKey) {
        authorizer.check(caller, Permission.EVALUATE);
        List<PreparedBatchItem> safeItems = validateItems(items);

        // 整批只固定一次当前快照：评估期间发布或回滚都不影响本批。
        PolicySnapshot snapshot = policyStore.current();

        List<BatchItemResult> results = new ArrayList<>(safeItems.size());
        int allowed = 0;
        int denied = 0;
        int failed = 0;
        for (int i = 0; i < safeItems.size(); i++) {
            PreparedBatchItem item = safeItems.get(i);
            BatchItemResult result = evaluateOne(i, item, snapshot);
            results.add(result);
            if (result.ok()) {
                if (result.report().decision() == Decision.ALLOW) {
                    allowed++;
                } else {
                    denied++;
                }
            } else {
                failed++;
            }
        }

        BatchEvaluationReport report = new BatchEvaluationReport(
                safeItems.size(), safeItems.size() - failed, failed,
                allowed, denied, snapshot.version(), List.copyOf(results));

        writeBatchAudit(caller, idempotencyKey, snapshot, safeItems, report);

        log.info("批量评估完成 caller={} total={} ok={} failed={} allowed={} denied={} policyVersion=v{}",
                caller.name(), report.total(), report.succeeded(), report.failed(),
                report.allowed(), report.denied(), snapshot.version());
        return report;
    }

    @Override
    public RehearsalReport rehearse(Caller caller, List<PreparedBatchItem> items,
                                    List<PolicyRule> candidateRules, String idempotencyKey) {
        authorizer.check(caller, Permission.EVALUATE);
        List<PreparedBatchItem> safeItems = validateItems(items);

        // 候选规则必须与正常发布走完全相同的合法性校验；不合法直接按规则集不合法抛出，绝不放过。
        // 校验发生在任何版本读取之前：预演不可能因候选规则非法而影响线上策略。
        List<PolicyRule> validatedCandidates = policyStore.validateRules(
                candidateRules == null ? List.of() : candidateRules);

        // 基线快照在处理任何镜像项之前固定一次，保证两侧对照来自同一份当前策略。
        PolicySnapshot baseline = policyStore.current();
        PolicySnapshot candidate = new PolicySnapshot(-1L, Instant.now(), caller.name(),
                "预演候选规则集（不落盘、不发布）", validatedCandidates, "候选规则集");

        List<RehearsalItemResult> results = new ArrayList<>(safeItems.size());
        int invalid = 0;
        int changed = 0;
        int allowToDeny = 0;
        int denyToAllow = 0;
        for (int i = 0; i < safeItems.size(); i++) {
            PreparedBatchItem item = safeItems.get(i);
            RehearsalItemResult result = rehearseOne(i, item, baseline, candidate);
            results.add(result);
            if (!result.ok()) {
                invalid++;
            } else if (result.changed()) {
                changed++;
                if (result.direction() == ChangeDirection.ALLOW_TO_DENY) {
                    allowToDeny++;
                } else if (result.direction() == ChangeDirection.DENY_TO_ALLOW) {
                    denyToAllow++;
                }
            }
        }

        RehearsalReport report = new RehearsalReport(
                safeItems.size(), invalid, baseline.version(), validatedCandidates.size(),
                changed, allowToDeny, denyToAllow, List.copyOf(results));

        writeRehearseAudit(caller, idempotencyKey, baseline, safeItems,
                validatedCandidates, report);

        log.info("策略预演完成 caller={} total={} invalid={} changed={} (ALLOW→DENY={}, DENY→ALLOW={}) "
                        + "baseline=v{} candidateRules={}（线上策略未改动、无新版本）",
                caller.name(), report.total(), report.invalid(), report.changedCount(),
                report.allowToDenyCount(), report.denyToAllowCount(),
                baseline.version(), validatedCandidates.size());
        return report;
    }

    // ------------------------------------------------------------- 单项处理

    private BatchItemResult evaluateOne(int index, PreparedBatchItem item, PolicySnapshot snapshot) {
        if (!item.valid()) {
            return new BatchItemResult(index, null, false,
                    item.errorCode(), item.errorMessage(), null);
        }
        BatchItemInput input = item.input();
        try {
            ImageDescriptor descriptor = parser.parse(
                    new IngestionRequest(input.reference(), input.artifacts()));
            DecisionReport report = evaluator.evaluate(descriptor, snapshot);
            return new BatchItemResult(index, input.reference(), true, null, null, report);
        } catch (AdmissionException ex) {
            return new BatchItemResult(index, input.reference(), false,
                    ex.getCode().name(), ex.getMessage(), null);
        } catch (RuntimeException ex) {
            // 任何单项意外都不允许拖垮整批：标记该项并继续其余项。
            log.warn("批量评估第 {} 项发生未预期错误: {}", index, ex.toString());
            return new BatchItemResult(index, input.reference(), false,
                    ErrorCode.MALFORMED_ARTIFACT.name(),
                    "该项处理失败: " + ex.getMessage(), null);
        }
    }

    private RehearsalItemResult rehearseOne(int index, PreparedBatchItem item,
                                            PolicySnapshot baseline, PolicySnapshot candidate) {
        if (!item.valid()) {
            return new RehearsalItemResult(index, null, false,
                    item.errorCode(), item.errorMessage(), null, null, false,
                    ChangeDirection.UNCHANGED);
        }
        BatchItemInput input = item.input();
        ImageDescriptor descriptor;
        try {
            descriptor = parser.parse(
                    new IngestionRequest(input.reference(), input.artifacts()));
        } catch (AdmissionException ex) {
            return new RehearsalItemResult(index, input.reference(), false,
                    ex.getCode().name(), ex.getMessage(), null, null, false,
                    ChangeDirection.UNCHANGED);
        } catch (RuntimeException ex) {
            log.warn("策略预演第 {} 项发生未预期错误: {}", index, ex.toString());
            return new RehearsalItemResult(index, input.reference(), false,
                    ErrorCode.MALFORMED_ARTIFACT.name(),
                    "该项处理失败: " + ex.getMessage(), null, null, false,
                    ChangeDirection.UNCHANGED);
        }

        DecisionReport baseReport = evaluator.evaluate(descriptor, baseline);
        DecisionReport candReport = evaluator.evaluate(descriptor, candidate);
        boolean changed = baseReport.decision() != candReport.decision();
        ChangeDirection direction;
        if (!changed) {
            direction = ChangeDirection.UNCHANGED;
        } else if (baseReport.decision() == Decision.ALLOW) {
            direction = ChangeDirection.ALLOW_TO_DENY;
        } else {
            direction = ChangeDirection.DENY_TO_ALLOW;
        }
        return new RehearsalItemResult(index, input.reference(), true, null, null,
                baseReport, candReport, changed, direction);
    }

    // ------------------------------------------------------------- 校验

    private List<PreparedBatchItem> validateItems(List<PreparedBatchItem> items) {
        if (items == null || items.isEmpty()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                    "批量请求 items 不能为空");
        }
        if (items.size() > MAX_BATCH_ITEMS) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                    "批量镜像数 " + items.size() + " 超过上限 " + MAX_BATCH_ITEMS
                            + "，请拆分为多个批次，避免单次请求拖垮服务");
        }
        return List.copyOf(items);
    }

    // ------------------------------------------------------------- 审计

    private void writeBatchAudit(Caller caller, String idempotencyKey, PolicySnapshot snapshot,
                                 List<PreparedBatchItem> items, BatchEvaluationReport report) {
        String fingerprint = batchFingerprint(items);
        String auditId = auditId("batch", caller.name(), idempotencyKey,
                snapshot.version(), fingerprint);
        String detail = "batchFingerprint=" + fingerprint + ", total=" + report.total()
                + ", allowed=" + report.allowed() + ", denied=" + report.denied()
                + ", invalid=" + report.failed()
                + ", invalidItems=" + invalidBatchSummaries(report.items())
                + ", outcomes=" + batchOutcomes(report.items());
        AuditRecord record = new AuditRecord(auditId, Instant.now(), caller.name(),
                ACTION_BATCH_EVALUATE, null, snapshot.version(), null,
                "批量评估：共 " + report.total() + " 项，放行 " + report.allowed()
                        + "，拒绝 " + report.denied() + "，输入无效 " + report.failed(),
                detail);
        AuditRecord existing = auditService.record(record);
        if (existing != record) {
            log.info("批量评估重复提交被幂等去重 auditId={} caller={}", auditId, caller.name());
        }
    }

    private void writeRehearseAudit(Caller caller, String idempotencyKey, PolicySnapshot baseline,
                                    List<PreparedBatchItem> items, List<PolicyRule> candidateRules,
                                    RehearsalReport report) {
        String fingerprint = batchFingerprint(items);
        String rulesHash = rulesHash(candidateRules);
        String auditId = auditId("rehearse", caller.name(), idempotencyKey,
                baseline.version(), fingerprint + "|" + rulesHash);
        String changedItems = report.items().stream()
                .filter(RehearsalItemResult::changed)
                .map(r -> r.reference() + ":" + r.direction()
                        + "(decisive=" + ruleName(r.candidate().decisiveRule()) + ")")
                .toList()
                .toString();
        String detail = "batchFingerprint=" + fingerprint + ", candidateRulesHash=" + rulesHash
                + ", candidateRuleCount=" + report.candidateRuleCount()
                + ", total=" + report.total() + ", invalid=" + report.invalid()
                + ", changed=" + report.changedCount() + ", allowToDeny="
                + report.allowToDenyCount() + ", denyToAllow=" + report.denyToAllowCount()
                + ", changedItems=" + changedItems;
        AuditRecord record = new AuditRecord(auditId, Instant.now(), caller.name(),
                ACTION_REHEARSE, null, baseline.version(), null,
                "策略预演：基于 v" + baseline.version() + " 对照 " + candidateRules.size()
                        + " 条候选规则，结论变化 " + report.changedCount() + " 项"
                        + "（预演不落盘、不产生新版本）",
                detail);
        AuditRecord existing = auditService.record(record);
        if (existing != record) {
            log.info("策略预演重复提交被幂等去重 auditId={} caller={}", auditId, caller.name());
        }
    }

    private String ruleName(MatchedRule rule) {
        return rule == null ? "<none:fail-closed>" : rule.ruleId();
    }

    private String invalidBatchSummaries(List<BatchItemResult> items) {
        return items.stream()
                .filter(r -> !r.ok())
                .map(r -> "#" + r.index() + "(" + r.reference() + "):" + r.errorCode())
                .toList()
                .toString();
    }

    private String batchOutcomes(List<BatchItemResult> items) {
        // 列出成功项的引用与结论，便于审计核对这次批量影响到了哪些镜像。
        return items.stream()
                .filter(BatchItemResult::ok)
                .map(r -> r.reference() + "=" + r.report().decision())
                .toList()
                .toString();
    }

    // ------------------------------------------------------------- 哈希工具

    private String batchFingerprint(List<PreparedBatchItem> items) {
        StringBuilder sb = new StringBuilder();
        for (PreparedBatchItem item : items) {
            if (!item.valid()) {
                sb.append("INVALID:").append(item.errorCode()).append(':')
                        .append(item.errorMessage()).append('\n');
                continue;
            }
            BatchItemInput input = item.input();
            sb.append(input.reference() == null ? "" : input.reference()).append('|');
            if (input.artifacts() != null) {
                for (RawArtifact a : input.artifacts()) {
                    sb.append(a.kind()).append(':').append(a.format()).append(':')
                            .append(a.content() == null ? "" : a.content()).append(';');
                }
            }
            sb.append('\n');
        }
        return sha256(sb.toString());
    }

    private String rulesHash(List<PolicyRule> rules) {
        StringBuilder sb = new StringBuilder();
        for (PolicyRule r : rules) {
            sb.append(r.id()).append(',').append(r.priority()).append(',')
                    .append(r.effect()).append(',').append(r.schemaVersion()).append('[');
            for (var c : r.conditions()) {
                sb.append(c.type()).append('=').append(c.value()).append('&');
            }
            sb.append("]\n");
        }
        return sha256(sb.toString());
    }

    private String auditId(String prefix, String caller, String idempotencyKey,
                           long policyVersion, String contentHash) {
        String key = (idempotencyKey == null || idempotencyKey.isBlank())
                ? contentHash : idempotencyKey.trim() + "|" + contentHash;
        return prefix + ":" + sha256(caller + "|v" + policyVersion + "|" + key);
    }

    private String sha256(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }
}
