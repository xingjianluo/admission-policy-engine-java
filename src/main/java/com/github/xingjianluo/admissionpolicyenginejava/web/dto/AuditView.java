package com.github.xingjianluo.admissionpolicyenginejava.web.dto;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditRecord;

/**
 * 审计记录对外视图。
 */
public record AuditView(long id,
                        String operation,
                        String actorId,
                        String requestId,
                        String imageDigest,
                        String inputSummary,
                        long policyVersionBefore,
                        long policyVersionAfter,
                        String decision,
                        String decisiveRuleId,
                        String hitsSummary,
                        String rationale,
                        String errorCategory,
                        long createdAtEpochMs) {

    public static AuditView from(AuditRecord r) {
        return new AuditView(r.id(), r.operation(), r.actorId(), r.requestId(),
                r.imageDigest(), r.inputSummary(),
                r.policyVersionBefore(), r.policyVersionAfter(),
                r.decision(), r.decisiveRuleId(), r.hitsSummary(),
                r.rationale(),
                r.errorCategory() == null ? null : r.errorCategory().name(),
                r.createdAtEpochMs());
    }
}
