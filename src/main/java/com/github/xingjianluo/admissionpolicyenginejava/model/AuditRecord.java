package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.time.Instant;

/**
 * 审计记录：完整反映输入、策略版本与最终结论。
 *
 * @param id            去重幂等键（由输入指纹 + 策略版本 + 调用方派生）
 * @param timestamp     记录时间
 * @param caller        调用方主体
 * @param action        被审计的操作
 * @param imageDigest   被评估镜像指纹（管理类操作可为空）
 * @param policyVersion 关联的策略版本
 * @param decision      准入判定（管理类操作记录其授权结论）
 * @param rationale     判定/拒绝依据
 * @param detail        操作细节（如更新前后版本）
 */
public record AuditRecord(
        String id,
        Instant timestamp,
        String caller,
        String action,
        String imageDigest,
        Long policyVersion,
        Decision decision,
        String rationale,
        String detail
) {
}
