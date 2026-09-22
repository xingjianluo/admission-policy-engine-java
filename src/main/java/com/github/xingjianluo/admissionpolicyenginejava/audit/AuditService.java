package com.github.xingjianluo.admissionpolicyenginejava.audit;

import com.github.xingjianluo.admissionpolicyenginejava.model.AuditRecord;

import java.util.List;

/**
 * 审计服务：按幂等键写入，保证并发/重复提交不产生重复记录。
 */
public interface AuditService {

    /** 若相同 id 已存在则返回既有记录，否则原子写入新记录。 */
    AuditRecord record(AuditRecord record);

    /**
     * 仅当 id 尚不存在时原子占位。
     *
     * @return 占位成功返回 null；若已被其他线程占用则返回既有记录
     */
    AuditRecord reserveIfAbsent(AuditRecord pending);

    /** 原子地把占位记录替换为最终记录（仅当占位记录与 pending 为同一 id）。 */
    AuditRecord complete(AuditRecord pending, AuditRecord finalized);

    /** 按 id 查询，不存在返回 null。 */
    AuditRecord findById(String id);

    /** 按镜像指纹查询审计记录（时间升序）。 */
    List<AuditRecord> findByDigest(String digest);

    /** 最近 N 条审计记录。 */
    List<AuditRecord> recent(int limit);
}
