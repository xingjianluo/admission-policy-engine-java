package com.github.xingjianluo.admissionpolicyenginejava.audit;

import com.github.xingjianluo.admissionpolicyenginejava.model.EvaluationResult;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 审计日志（内存实现，本地模拟）。
 *
 * <p>一致性保证：
 * <ul>
 *   <li>自增序号与落库在同一把锁内完成，并发提交不会重号或丢记录；</li>
 *   <li>以 (operation, requestId) 为幂等键：重复提交直接返回首次记录，
 *       不会产生重复审计，也不会重复评估副作用；</li>
 *   <li>策略变更操作以 (operation, 版本前→后, comment) 之外不做幂等，
 *       正常更新每次都留痕；重复的失败提交（版本冲突）记录 errorCategory。</li>
 * </ul>
 */
@Component
public class AuditLog {

    private final ConcurrentMap<String, AuditRecord> byIdempotencyKey = new ConcurrentHashMap<>();
    private final ConcurrentMap<Long, AuditRecord> byId = new ConcurrentHashMap<>();
    private final AtomicLong sequence = new AtomicLong(0L);

    /**
     * 幂等记录一条审计。返回已存在的同键记录，或写入新记录。
     */
    public AuditRecord record(AuditRecord draft) {
        String key = idempotencyKey(draft.operation(), draft.requestId());
        if (key != null) {
            // computeIfAbsent 原子去重，序号在 mapping 函数内分配
            return byIdempotencyKey.computeIfAbsent(key, k -> assign(draft));
        }
        synchronized (this) {
            return assign(draft);
        }
    }

    public Optional<AuditRecord> findEvaluation(String requestId) {
        return Optional.ofNullable(
                byIdempotencyKey.get(idempotencyKey("EVALUATE", requestId)));
    }

    public List<AuditRecord> all() {
        return byId.values().stream()
                .sorted(java.util.Comparator.comparingLong(AuditRecord::id))
                .toList();
    }

    /** 仅评估操作按 requestId 幂等；失败的评估（畸形输入等）也占住幂等键。 */
    private static String idempotencyKey(String operation, String requestId) {
        if ("EVALUATE".equals(operation) && requestId != null && !requestId.isBlank()) {
            return "EVALUATE:" + requestId;
        }
        return null;
    }

    private AuditRecord assign(AuditRecord draft) {
        long id = sequence.incrementAndGet();
        AuditRecord stored = new AuditRecord(id, draft.operation(), draft.actorId(),
                draft.requestId(), draft.imageDigest(), draft.inputSummary(),
                draft.policyVersionBefore(), draft.policyVersionAfter(),
                draft.decision(), draft.decisiveRuleId(), draft.hitsSummary(),
                draft.rationale(), draft.errorCategory(), draft.createdAtEpochMs());
        byId.put(id, stored);
        return stored;
    }

    /** 便于测试/调试：汇总评估结果的命中规则文本。 */
    public static String summarizeHits(EvaluationResult result) {
        return result.hits().stream()
                .map(h -> h.ruleId() + "(" + h.effect() + ",p" + h.priority() + ")")
                .reduce((a, b) -> a + "," + b)
                .orElse("<none>");
    }
}
