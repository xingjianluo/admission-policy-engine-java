package com.github.xingjianluo.admissionpolicyenginejava.audit;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.AuditRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 内存幂等审计存储。
 * <p>
 * 以 {@code AuditRecord#id()} 为幂等键：并发或重复提交相同 id 时，
 * 只有第一次写入生效，其余返回既有记录，不会产生重复记录，也不会错乱顺序。
 * 记录一经写入不可变。
 */
@Component
public class InMemoryAuditService implements AuditService {

    private static final Logger log = LoggerFactory.getLogger(InMemoryAuditService.class);

    private final ConcurrentHashMap<String, AuditRecord> byId = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<AuditRecord> order = new CopyOnWriteArrayList<>();

    @Override
    public AuditRecord record(AuditRecord record) {
        if (record == null || record.id() == null || record.id().isBlank()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "审计记录缺少幂等 id");
        }
        // putIfAbsent 原子占位：保证并发下只有一个线程拿到 null 并追加顺序列表。
        AuditRecord existing = byId.putIfAbsent(record.id(), record);
        if (existing != null) {
            log.info("重复提交被幂等去重 auditId={} action={} caller={}",
                    record.id(), record.action(), record.caller());
            return existing;
        }
        order.add(record);
        log.info("写入审计记录 auditId={} action={} caller={} decision={} policyVersion={}",
                record.id(), record.action(), record.caller(), record.decision(),
                record.policyVersion());
        return record;
    }

    @Override
    public AuditRecord reserveIfAbsent(AuditRecord pending) {
        if (pending == null || pending.id() == null || pending.id().isBlank()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "审计记录缺少幂等 id");
        }
        AuditRecord existing = byId.putIfAbsent(pending.id(), pending);
        if (existing == null) {
            order.add(pending);
            log.debug("审计占位成功 auditId={}", pending.id());
            return null;
        }
        return existing;
    }

    @Override
    public AuditRecord complete(AuditRecord pending, AuditRecord finalized) {
        if (!pending.id().equals(finalized.id())) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                    "完成审计记录时 id 不一致");
        }
        // CAS：仅当映射中的当前条目正是本次占位对象时才替换为最终记录，
        // 保证并发下只有占位线程自己能完成，且顺序列表中的位置保持不变。
        if (byId.replace(pending.id(), pending, finalized)) {
            order.replaceAll(r -> r == pending ? finalized : r);
            log.info("审计占位完成 auditId={} decision={}", finalized.id(),
                    finalized.decision());
            return finalized;
        }
        return byId.get(pending.id());
    }

    @Override
    public AuditRecord findById(String id) {
        return byId.get(id);
    }

    @Override
    public List<AuditRecord> findByDigest(String digest) {
        if (digest == null || digest.isBlank()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "digest 不能为空");
        }
        return order.stream()
                .filter(r -> digest.equals(r.imageDigest()))
                .toList();
    }

    @Override
    public List<AuditRecord> recent(int limit) {
        int size = order.size();
        int from = Math.max(0, size - Math.max(1, limit));
        return List.copyOf(order.subList(from, size));
    }
}
