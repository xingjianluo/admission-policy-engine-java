package com.github.xingjianluo.admissionpolicyenginejava.audit;

import com.github.xingjianluo.admissionpolicyenginejava.exception.ErrorCategory;

/**
 * 一条不可变审计记录。
 *
 * <p>覆盖两类操作：
 * <ul>
 *   <li>评估（EVALUATE）：记录输入指纹、策略版本、命中规则与最终结论；</li>
 *   <li>策略变更（UPDATE_POLICY / ROLLBACK_POLICY）：记录操作者、旧版本→新版本、说明。</li>
 * </ul>
 * 被拒绝（含未授权、畸形输入）的操作同样留痕，errorCategory 与正常结论可区分。
 *
 * @param id          记录自增序号
 * @param operation   操作类型
 * @param actorId     操作者（匿名拒绝时为 {@code <anonymous>}）
 * @param requestId   评估请求幂等键；策略变更操作可为 null
 * @param imageDigest 被评估镜像指纹；非评估操作为 null
 * @param inputSummary 评估输入摘要（引用/来源/漏洞数/SLSA 等）
 * @param policyVersionBefore 操作前策略版本
 * @param policyVersionAfter  操作后策略版本
 * @param decision    评估结论名称；非评估操作为 null
 * @param decisiveRuleId 决定性规则编号
 * @param hitsSummary 命中规则摘要
 * @param rationale   判定依据 / 操作说明
 * @param errorCategory 错误大类；成功或正常 DENY 为 null
 * @param createdAtEpochMs 记录时间
 */
public record AuditRecord(long id,
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
                          ErrorCategory errorCategory,
                          long createdAtEpochMs) {
}
