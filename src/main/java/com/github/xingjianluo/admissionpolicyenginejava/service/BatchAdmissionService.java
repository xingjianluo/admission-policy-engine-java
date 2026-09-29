package com.github.xingjianluo.admissionpolicyenginejava.service;

import com.github.xingjianluo.admissionpolicyenginejava.ingest.PreparedBatchItem;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchEvaluationReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalReport;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;

import java.util.List;

/**
 * 批量评估与策略预演应用服务。
 * <ul>
 *   <li>批量评估：一批镜像各自独立出结论，单项坏输入只标记该项；</li>
 *   <li>策略预演：同一批镜像在“当前策略 / 候选规则”下做对照，不发布、不留正式版本。</li>
 * </ul>
 */
public interface BatchAdmissionService {

    /** 单次批量请求允许的最大镜像项数。 */
    int MAX_BATCH_ITEMS = 50;

    /** 一批镜像的批量评估（当前生效策略）。 */
    BatchEvaluationReport evaluateBatch(Caller caller, List<PreparedBatchItem> items,
                                        String idempotencyKey);

    /** 使用候选规则集对一批镜像做预演对照（绝不修改线上策略）。 */
    RehearsalReport rehearse(Caller caller, List<PreparedBatchItem> items,
                             List<PolicyRule> candidateRules, String idempotencyKey);
}
