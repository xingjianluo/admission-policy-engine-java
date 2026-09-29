package com.github.xingjianluo.admissionpolicyenginejava.service;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService;
import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactParser;
import com.github.xingjianluo.admissionpolicyenginejava.model.AuditRecord;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchItemInput;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.ChangeDirection;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.DecisionReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;
import com.github.xingjianluo.admissionpolicyenginejava.model.ItemStatus;
import com.github.xingjianluo.admissionpolicyenginejava.model.Permission;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalItemResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalReport;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyEvaluator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRuleSetValidator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyStore;
import com.github.xingjianluo.admissionpolicyenginejava.security.Authorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 策略预演服务默认实现。
 * <p>
 * 关键保证：
 * <ol>
 *   <li>先鉴权：未授权 → UNAUTHORIZED，与策略结论/DENY 通道不同；</li>
 *   <li>候选规则先经与“正式发布”完全相同的规则集校验：不合法时按规则集不合法拒绝，
 *       绝不悄悄放过；候选只存在于本次内存快照中，不发布、不产生正式版本、不改现网；</li>
 *   <li>在处理任何一项之前取一次当前策略快照：整次预演的“现网一侧”都基于同一版本，
 *       期间他人发布/回滚不会让对照一半旧一半新；</li>
 *   <li>逐项隔离：单项输入非法只标记该项；双侧评估是对不可变快照的纯函数，
 *       同批输入 + 同一份策略（含相同候选指纹）重复预演任意次结果一致；</li>
 *   <li>逐项幂等留痕：审计键含候选规则指纹，同一批重复提交不重复记录。</li>
 * </ol>
 */
@Service
public class DefaultPolicyRehearsalService implements PolicyRehearsalService {

    private static final Logger log = LoggerFactory.getLogger(DefaultPolicyRehearsalService.class);

    /** 候选规则快照的版本标记：-1 表示“未发布的候选”，区别于任何正式版本号。 */
    public static final long CANDIDATE_VERSION = -1L;

    /** 预演批量条目上限，与批量评估保持一致。 */
    public static final int MAX_REHEARSAL_ITEMS = DefaultBatchAdmissionService.MAX_BATCH_SIZE;

    private final ArtifactParser parser;
    private final PolicyStore policyStore;
    private final PolicyEvaluator evaluator;
    private final Authorizer authorizer;
    private final AuditService auditService;
    private final PolicyRuleSetValidator validator;

    public DefaultPolicyRehearsalService(ArtifactParser parser, PolicyStore policyStore,
                                         PolicyEvaluator evaluator, Authorizer authorizer,
                                         AuditService auditService,
                                         PolicyRuleSetValidator validator) {
        this.parser = parser;
        this.policyStore = policyStore;
        this.evaluator = evaluator;
        this.authorizer = authorizer;
        this.auditService = auditService;
        this.validator = validator;
    }

    @Override
    public RehearsalReport rehearse(Caller caller, List<BatchItemInput> items,
                                    List<PolicyRule> candidateRules, String idempotencyKey) {
        authorizer.check(caller, Permission.EVALUATE);
        if (items == null || items.isEmpty()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "预演 items 不能为空");
        }
        if (items.size() > MAX_REHEARSAL_ITEMS) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                    "预演条目数 " + items.size() + " 超过上限 " + MAX_REHEARSAL_ITEMS
                            + "，请拆分为多个批次");
        }
        // 候选规则合法性与正式发布同规：不合法直接拒绝整个预演，现网与版本链均不变。
        List<PolicyRule> validatedCandidates = validator.validateAndFreeze(candidateRules);
        String candidateFingerprint = fingerprint(validatedCandidates);

        // 固定一份现网快照，整次预演双侧对照都基于它，避免新旧混杂。
        PolicySnapshot current = policyStore.current();
        PolicySnapshot candidateSnapshot = new PolicySnapshot(CANDIDATE_VERSION, Instant.now(),
                caller.name(), "预演候选规则（未发布，指纹 " + candidateFingerprint + "）",
                validatedCandidates);
        String key = IdempotencyIds.normalizeKey(idempotencyKey);

        List<RehearsalItemResult> results = new ArrayList<>(items.size());
        int changed = 0;
        int allowToDeny = 0;
        int denyToAllow = 0;
        int unchanged = 0;
        int errors = 0;

        for (BatchItemInput item : items) {
            RehearsalItemResult result = processOne(caller, item, current, candidateSnapshot,
                    candidateFingerprint, key);
            results.add(result);
            if (result.status() == ItemStatus.INPUT_ERROR) {
                errors++;
                continue;
            }
            switch (result.change()) {
                case ALLOW_TO_DENY -> { changed++; allowToDeny++; }
                case DENY_TO_ALLOW -> { changed++; denyToAllow++; }
                case UNCHANGED -> unchanged++;
            }
        }

        log.info("策略预演完成 caller={} size={} currentVersion=v{} candidateFp={} "
                        + "changed={} allowToDeny={} denyToAllow={} unchanged={} errors={} key={}",
                caller.name(), items.size(), current.version(), candidateFingerprint,
                changed, allowToDeny, denyToAllow, unchanged, errors, key);

        return new RehearsalReport(current.version(), candidateFingerprint, items.size(),
                changed, allowToDeny, denyToAllow, unchanged, errors, List.copyOf(results));
    }

    private RehearsalItemResult processOne(Caller caller, BatchItemInput item,
                                           PolicySnapshot current, PolicySnapshot candidate,
                                           String candidateFingerprint, String key) {
        int index = item.index();
        if (item.requestError() != null) {
            return recordInputError(caller, index, null, "INVALID_REQUEST",
                    item.requestError(), current.version(), candidateFingerprint, key);
        }

        final ImageDescriptor descriptor;
        try {
            descriptor = parser.parse(item.request());
        } catch (AdmissionException e) {
            return recordInputError(caller, index, item.request().reference(),
                    e.getCode().name(), e.getMessage(), current.version(),
                    candidateFingerprint, key);
        }

        // 双侧评估：同一份镜像，分别在现网快照与候选快照上判定。
        DecisionReport currentReport = evaluator.evaluate(descriptor, current);
        DecisionReport candidateReport = evaluator.evaluate(descriptor, candidate);
        ChangeDirection change = directionOf(currentReport.decision(), candidateReport.decision());

        String auditId = "rehe:" + IdempotencyIds.sha256Hex(
                "REHEARSE|" + caller.name() + "|v" + current.version()
                        + "|cand=" + candidateFingerprint + "|" + key
                        + "|#" + index + "|" + descriptor.digest());
        AuditRecord pending = new AuditRecord(auditId, Instant.now(), caller.name(),
                "POLICY_REHEARSE", descriptor.digest(), current.version(), null,
                "预演进行中占位", "index=" + index + ",candidate=" + candidateFingerprint);
        AuditRecord existing = auditService.reserveIfAbsent(pending);
        if (existing == null) {
            auditService.complete(pending, new AuditRecord(auditId, pending.timestamp(),
                    caller.name(), "POLICY_REHEARSE", descriptor.digest(), current.version(),
                    candidateReport.decision(),
                    "预演对照：现网 v" + current.version() + " 结论 " + currentReport.decision()
                            + "（决定性规则 " + ruleName(currentReport) + "）；候选规则结论 "
                            + candidateReport.decision() + "（决定性规则 "
                            + ruleName(candidateReport) + "）；变化 " + change,
                    "index=" + index + ",reference=" + descriptor.reference()
                            + ",candidateFp=" + candidateFingerprint
                            + ",currentDecisive=" + ruleName(currentReport)
                            + ",candidateDecisive=" + ruleName(candidateReport)));
        }
        return new RehearsalItemResult(index, descriptor.reference(), ItemStatus.EVALUATED,
                currentReport, candidateReport, change, null, null);
    }

    private RehearsalItemResult recordInputError(Caller caller, int index, String reference,
                                                 String code, String message,
                                                 long currentVersion, String candidateFingerprint,
                                                 String key) {
        String anchor = reference == null ? "#" + index : reference;
        String auditId = "rehe:" + IdempotencyIds.sha256Hex(
                "REHEARSEERR|" + caller.name() + "|v" + currentVersion
                        + "|cand=" + candidateFingerprint + "|" + key
                        + "|#" + index + "|" + code + "|" + anchor);
        auditService.record(new AuditRecord(auditId, Instant.now(), caller.name(),
                "POLICY_REHEARSE_INPUT_ERROR", null, currentVersion, null,
                "预演第 " + index + " 项输入错误[" + code + "]: " + message,
                "index=" + index + ",reference=" + reference
                        + ",candidateFp=" + candidateFingerprint));
        log.info("预演单项输入错误 index={} reference={} code={} message={}",
                index, reference, code, message);
        return new RehearsalItemResult(index, reference, ItemStatus.INPUT_ERROR, null, null,
                null, code, message);
    }

    private ChangeDirection directionOf(Decision currentDecision, Decision candidateDecision) {
        if (currentDecision == candidateDecision) {
            return ChangeDirection.UNCHANGED;
        }
        return currentDecision == Decision.ALLOW
                ? ChangeDirection.ALLOW_TO_DENY : ChangeDirection.DENY_TO_ALLOW;
    }

    private String ruleName(DecisionReport report) {
        return report.decisiveRule() == null ? "<none:fail-closed>"
                : report.decisiveRule().ruleId();
    }

    /** 候选规则集内容指纹：规则按其字段确定性序列化后哈希，与提交顺序无关。 */
    private String fingerprint(List<PolicyRule> rules) {
        StringBuilder sb = new StringBuilder();
        rules.stream().sorted(java.util.Comparator.comparing(PolicyRule::id)).forEach(r -> {
            sb.append(r.id()).append('@').append(r.priority()).append(':').append(r.effect())
                    .append(":s").append(r.schemaVersion()).append('[');
            r.conditions().forEach(c -> sb.append(c.type()).append('=')
                    .append(c.value() == null ? "" : c.value()).append(';'));
            sb.append("];");
        });
        return IdempotencyIds.sha256Hex(sb.toString()).substring(0, 16);
    }
}
