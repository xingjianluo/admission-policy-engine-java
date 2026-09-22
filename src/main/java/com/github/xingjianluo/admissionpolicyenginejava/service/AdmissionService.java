package com.github.xingjianluo.admissionpolicyenginejava.service;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditLog;
import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditRecord;
import com.github.xingjianluo.admissionpolicyenginejava.auth.ActorContext;
import com.github.xingjianluo.admissionpolicyenginejava.auth.Permission;
import com.github.xingjianluo.admissionpolicyenginejava.auth.AuthorizationService;
import com.github.xingjianluo.admissionpolicyenginejava.exception.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.exception.AuthorizationException;
import com.github.xingjianluo.admissionpolicyenginejava.exception.ErrorCategory;
import com.github.xingjianluo.admissionpolicyenginejava.exception.IngestException;
import com.github.xingjianluo.admissionpolicyenginejava.exception.PolicyVersionException;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.UnifiedInputAssembler;
import com.github.xingjianluo.admissionpolicyenginejava.model.AdmissionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.model.EvaluationResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicySet;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyEvaluator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySetParser;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 准入服务门面：权限校验 → 输入装配 → 快照判定 → 审计留痕。
 *
 * <p>幂等：相同 requestId 的重复/并发评估只执行一次，后续返回首次结论，
 * 审计只有一条记录；首次失败（畸形输入）同样占住幂等键并回放相同错误。
 */
@Service
public class AdmissionService {

    private static final Logger log = LoggerFactory.getLogger(AdmissionService.class);

    private final AuthorizationService authorization;
    private final UnifiedInputAssembler assembler;
    private final PolicyStore policyStore;
    private final PolicySetParser policyParser;
    private final PolicyEvaluator evaluator;
    private final AuditLog auditLog;

    private final ConcurrentMap<String, Object> requestLocks = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, EvaluationResult> resultCache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, AdmissionException> failureCache = new ConcurrentHashMap<>();

    public AdmissionService(AuthorizationService authorization,
                            UnifiedInputAssembler assembler,
                            PolicyStore policyStore,
                            PolicySetParser policyParser,
                            PolicyEvaluator evaluator,
                            AuditLog auditLog) {
        this.authorization = authorization;
        this.assembler = assembler;
        this.policyStore = policyStore;
        this.policyParser = policyParser;
        this.evaluator = evaluator;
        this.auditLog = auditLog;
    }

    /**
     * 评估入口。
     */
    public EvaluationResult evaluate(ActorContext actor,
                                     String requestId,
                                     Path manifestFile,
                                     Path scanFile,
                                     Path provenanceFile) {
        if (actor == null) {
            AuthorizationException e = new AuthorizationException(
                    "<anonymous>", Permission.EVALUATE.name(), "evaluate admission request");
            auditUnauthorized(null, requestId, e);
            throw e;
        }
        try {
            authorization.check(actor, Permission.EVALUATE, "evaluate admission request");
        } catch (AuthorizationException e) {
            auditUnauthorized(actor.actorId(), requestId, e);
            throw e;
        }

        if (requestId == null || requestId.isBlank()) {
            throw new IngestException(
                    com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestFailureReason.MISSING_REQUIRED_FIELD,
                    null, "requestId must not be blank");
        }

        Object lock = requestLocks.computeIfAbsent(requestId, k -> new Object());
        synchronized (lock) {
            EvaluationResult cached = resultCache.get(requestId);
            if (cached != null) {
                log.info("[duplicate request] requestId={} replaying cached decision {}",
                        requestId, cached.decision());
                return cached;
            }
            AdmissionException priorFailure = failureCache.get(requestId);
            if (priorFailure != null) {
                log.info("[duplicate request] requestId={} replaying prior failure: {}",
                        requestId, priorFailure.getMessage());
                throw priorFailure;
            }

            AdmissionRequest input;
            try {
                input = assembler.assemble(requestId, manifestFile, scanFile, provenanceFile);
            } catch (AdmissionException e) {
                failureCache.put(requestId, e);
                auditEvaluationFailure(actor.actorId(), requestId, e);
                throw e;
            }

            // 判定只使用这一份快照：即使此刻其他线程更新策略，本次结论仍基于一致版本
            PolicySet snapshot = policyStore.snapshot();
            EvaluationResult result = evaluator.evaluate(input, snapshot);

            log.info("[evaluate] requestId={} actor={} input={}",
                    requestId, actor.actorId(), summarizeInput(input));
            log.info("[evaluate] requestId={} policyVersion={} matchedRules={}",
                    requestId, result.policyVersion(), AuditLog.summarizeHits(result));
            log.info("[evaluate] requestId={} decision={} decisiveRule={} rationale={}",
                    requestId, result.decision(), result.decisiveRuleId(), result.rationale());

            auditEvaluationSuccess(actor.actorId(), input, result);
            resultCache.put(requestId, result);
            return result;
        }
    }

    /**
     * 策略更新（乐观并发：expectedVersion 必须等于当前版本）。
     */
    public PolicySet updatePolicy(ActorContext actor,
                                  long expectedVersion,
                                  String policyJson,
                                  String comment) {
        requirePermission(actor, Permission.UPDATE_POLICY, "update policy set");
        PolicySetParser.ParsedPolicySet parsed;
        try {
            parsed = policyParser.parse(policyJson);
        } catch (IngestException e) {
            auditPolicyFailure(actor.actorId(), "UPDATE_POLICY",
                    expectedVersion, policyStore.currentVersion(), e);
            throw e;
        }
        long before = policyStore.currentVersion();
        try {
            PolicySet next = policyStore.commitIfMatch(expectedVersion, parsed, comment);
            auditPolicyChange(actor.actorId(), "UPDATE_POLICY", before, next.version(),
                    "policy updated: " + comment);
            log.info("[policy] actor={} updated policy {} -> {}",
                    actor.actorId(), before, next.version());
            return next;
        } catch (PolicyVersionException e) {
            auditPolicyFailure(actor.actorId(), "UPDATE_POLICY",
                    before, policyStore.currentVersion(), e);
            throw e;
        }
    }

    /**
     * 策略回滚（同样向前发布新版本，保证版本号单调）。
     */
    public PolicySet rollbackPolicy(ActorContext actor,
                                    long expectedVersion,
                                    long targetVersion) {
        requirePermission(actor, Permission.ROLLBACK_POLICY, "rollback policy set");
        long before = policyStore.currentVersion();
        try {
            PolicySet next = policyStore.rollbackIfMatch(expectedVersion, targetVersion);
            auditPolicyChange(actor.actorId(), "ROLLBACK_POLICY", before, next.version(),
                    "policy rolled back to version " + targetVersion);
            log.info("[policy] actor={} rolled back policy {} -> {} (target={})",
                    actor.actorId(), before, next.version(), targetVersion);
            return next;
        } catch (PolicyVersionException e) {
            auditPolicyFailure(actor.actorId(), "ROLLBACK_POLICY",
                    before, policyStore.currentVersion(), e);
            throw e;
        }
    }

    public PolicySet currentPolicy(ActorContext actor) {
        requirePermission(actor, Permission.READ_AUDIT, "view current policy");
        return policyStore.snapshot();
    }

    public List<AuditRecord> auditTrail(ActorContext actor) {
        requirePermission(actor, Permission.READ_AUDIT, "read audit trail");
        return auditLog.all();
    }

    // ---- 内部方法 ----

    private void requirePermission(ActorContext actor, Permission permission, String action) {
        if (actor == null) {
            AuthorizationException e = new AuthorizationException(
                    "<anonymous>", permission.name(), action);
            auditUnauthorized(null, null, e);
            throw e;
        }
        try {
            authorization.check(actor, permission, action);
        } catch (AuthorizationException e) {
            auditUnauthorized(actor.actorId(), null, e);
            throw e;
        }
    }

    private static String summarizeInput(AdmissionRequest input) {
        return "image=" + input.metadata().reference()
                + ", digest=" + input.metadata().digest()
                + ", registry=" + input.metadata().registry()
                + ", repository=" + input.metadata().repository()
                + ", scanner=" + input.scan().scanner()
                + ", vulnCount=" + input.scan().vulnerabilities().size()
                + ", source=" + input.provenance().sourceUri()
                + ", builder=" + input.provenance().builderId()
                + ", slsaLevel=" + input.provenance().buildSlsaLevel();
    }

    private void auditEvaluationSuccess(String actorId,
                                        AdmissionRequest input,
                                        EvaluationResult result) {
        AuditRecord draft = new AuditRecord(0L, "EVALUATE", actorId,
                input.requestId(), input.metadata().digest(), summarizeInput(input),
                result.policyVersion(), result.policyVersion(),
                result.decision().name(), result.decisiveRuleId(),
                AuditLog.summarizeHits(result), result.rationale(),
                // DENY 是正常策略结论，不属于错误，errorCategory 为 null
                null,
                result.evaluatedAtEpochMs());
        auditLog.record(draft);
    }

    private void auditEvaluationFailure(String actorId, String requestId, AdmissionException e) {
        log.warn("[evaluate-rejected] requestId={} category={} reason={}",
                requestId, e.category(), e.getMessage());
        AuditRecord draft = new AuditRecord(0L, "EVALUATE", actorId,
                requestId, null, null,
                policyStore.currentVersion(), policyStore.currentVersion(),
                null, null, null, e.getMessage(),
                e.category(), System.currentTimeMillis());
        auditLog.record(draft);
    }

    private void auditPolicyChange(String actorId, String operation,
                                   long before, long after, String rationale) {
        AuditRecord draft = new AuditRecord(0L, operation, actorId, null, null, null,
                before, after, null, null, null, rationale, null,
                System.currentTimeMillis());
        auditLog.record(draft);
    }

    private void auditPolicyFailure(String actorId, String operation,
                                    long expected, long actual, AdmissionException e) {
        log.warn("[policy-rejected] actor={} op={} category={} reason={}",
                actorId, operation, e.category(), e.getMessage());
        AuditRecord draft = new AuditRecord(0L, operation, actorId, null, null, null,
                expected, actual, null, null, null, e.getMessage(),
                e.category(), System.currentTimeMillis());
        auditLog.record(draft);
    }

    private void auditUnauthorized(String actorId, String requestId, AuthorizationException e) {
        log.warn("[unauthorized] actor={} requestId={} reason={}",
                actorId, requestId, e.getMessage());
        // 未授权操作使用独立操作名，不占用 EVALUATE 的 requestId 幂等键
        AuditRecord draft = new AuditRecord(0L, "UNAUTHORIZED",
                actorId == null ? "<anonymous>" : actorId, null, null,
                requestId == null ? null : "requestId=" + requestId,
                policyStore.currentVersion(), policyStore.currentVersion(),
                null, null, null, e.getMessage(), ErrorCategory.UNAUTHORIZED,
                System.currentTimeMillis());
        auditLog.record(draft);
    }
}
