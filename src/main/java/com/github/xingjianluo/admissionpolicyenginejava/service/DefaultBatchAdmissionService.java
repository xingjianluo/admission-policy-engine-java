package com.github.xingjianluo.admissionpolicyenginejava.service;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService;
import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactParser;
import com.github.xingjianluo.admissionpolicyenginejava.model.AuditRecord;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchEvaluationReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchItemInput;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchItemResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.DecisionReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;
import com.github.xingjianluo.admissionpolicyenginejava.model.ItemStatus;
import com.github.xingjianluo.admissionpolicyenginejava.model.Permission;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyEvaluator;
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
 * 批量准入评估服务默认实现。
 * <p>
 * 关键保证：
 * <ol>
 *   <li>先鉴权（未授权 → UNAUTHORIZED，与任何策略结论/DENY 都不同通道）；</li>
 *   <li>批量大小受限：空批或超过 {@link #MAX_BATCH_SIZE} 直接 400 拒绝整批；</li>
 *   <li>处理任何一项之前先固定一份当前策略快照引用，整批共享同一现网版本，
 *       期间他人发布/回滚不影响本批；</li>
 *   <li>逐项隔离：单项输入非法只在该项标 INPUT_ERROR 与原因，其余项照常出结论；</li>
 *   <li>逐项幂等留痕：审计幂等键含 (调用方,策略版本,整批幂等键,下标,镜像指纹)，
 *       同一批重复提交不产生重复记录。</li>
 * </ol>
 */
@Service
public class DefaultBatchAdmissionService implements BatchAdmissionService {

    private static final Logger log = LoggerFactory.getLogger(DefaultBatchAdmissionService.class);

    /** 单次批量评估允许的镜像条目数上限。 */
    public static final int MAX_BATCH_SIZE = 100;

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
    public BatchEvaluationReport evaluateBatch(Caller caller, List<BatchItemInput> items,
                                               String idempotencyKey) {
        authorizer.check(caller, Permission.EVALUATE);
        if (items == null || items.isEmpty()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "批量 items 不能为空");
        }
        if (items.size() > MAX_BATCH_SIZE) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                    "批量条目数 " + items.size() + " 超过上限 " + MAX_BATCH_SIZE
                            + "，请拆分为多个批次");
        }

        // 整批先固定同一份当前策略快照：任何一项看到的现网策略版本都相同。
        PolicySnapshot snapshot = policyStore.current();
        String key = IdempotencyIds.normalizeKey(idempotencyKey);

        List<BatchItemResult> results = new ArrayList<>(items.size());
        int allowed = 0;
        int denied = 0;
        int errors = 0;

        for (BatchItemInput item : items) {
            BatchItemResult result = processOne(caller, item, snapshot, key);
            results.add(result);
            if (result.status() == ItemStatus.INPUT_ERROR) {
                errors++;
            } else if (result.report().decision() == Decision.ALLOW) {
                allowed++;
            } else {
                denied++;
            }
        }

        log.info("批量评估完成 caller={} size={} policyVersion=v{} allowed={} denied={} errors={} key={}",
                caller.name(), items.size(), snapshot.version(), allowed, denied, errors, key);

        return new BatchEvaluationReport(snapshot.version(), items.size(), allowed, denied,
                errors, List.copyOf(results));
    }

    private BatchItemResult processOne(Caller caller, BatchItemInput item,
                                       PolicySnapshot snapshot, String key) {
        int index = item.index();

        // Web 层已判定的结构性错误（缺 reference / 未知 kind / 空条目）。
        if (item.requestError() != null) {
            return recordInputError(caller, index, referenceOf(item), "INVALID_REQUEST",
                    item.requestError(), snapshot.version(), key);
        }

        final ImageDescriptor descriptor;
        try {
            descriptor = parser.parse(item.request());
        } catch (AdmissionException e) {
            // 单项输入有问题：只标记本项，不影响同批其他项。
            return recordInputError(caller, index, item.request().reference(),
                    e.getCode().name(), e.getMessage(), snapshot.version(), key);
        }

        String auditId = "batch:" + IdempotencyIds.sha256Hex(
                "BATCH|" + caller.name() + "|v" + snapshot.version() + "|" + key
                        + "|#" + index + "|" + descriptor.digest());
        AuditRecord pending = new AuditRecord(auditId, Instant.now(), caller.name(),
                "BATCH_EVALUATE", descriptor.digest(), snapshot.version(), null,
                "批量评估进行中占位", "index=" + index + ",reference=" + descriptor.reference());
        AuditRecord existing = auditService.reserveIfAbsent(pending);

        // 评估是对不可变快照的纯函数：跟随者即使重复计算也得到确定一致的结论，
        // 但只有占位者会写最终审计记录，因此同一批重复提交不会重复留痕。
        DecisionReport report = evaluator.evaluate(descriptor, snapshot);
        if (existing == null) {
            auditService.complete(pending, new AuditRecord(auditId, pending.timestamp(),
                    caller.name(), "BATCH_EVALUATE", descriptor.digest(), snapshot.version(),
                    report.decision(), report.rationale(),
                    "index=" + index + ",reference=" + descriptor.reference()
                            + ",matched=" + report.matchedRules().stream()
                            .map(m -> m.ruleId() + ":" + m.effect()).toList()));
        }
        return new BatchItemResult(index, descriptor.reference(), ItemStatus.EVALUATED,
                report, null, null);
    }

    private BatchItemResult recordInputError(Caller caller, int index, String reference,
                                             String code, String message, long policyVersion,
                                             String batchKey) {
        String anchor = reference == null ? "#" + index : reference;
        String auditId = "batch:" + IdempotencyIds.sha256Hex(
                "BATCHERR|" + caller + "|v" + policyVersion + "|" + batchKey
                        + "|#" + index + "|" + code + "|" + anchor);
        auditService.record(new AuditRecord(auditId, Instant.now(), caller.name(),
                "BATCH_EVALUATE_INPUT_ERROR", null, policyVersion, null,
                "批量第 " + index + " 项输入错误[" + code + "]: " + message,
                "index=" + index + ",reference=" + reference));
        log.info("批量单项输入错误 index={} reference={} code={} message={}",
                index, reference, code, message);
        return new BatchItemResult(index, reference, ItemStatus.INPUT_ERROR, null, code, message);
    }

    private String referenceOf(BatchItemInput item) {
        return item.request() == null ? null : item.request().reference();
    }
}
