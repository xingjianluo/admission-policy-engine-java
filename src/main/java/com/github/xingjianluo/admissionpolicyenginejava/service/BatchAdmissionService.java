package com.github.xingjianluo.admissionpolicyenginejava.service;

import com.github.xingjianluo.admissionpolicyenginejava.model.BatchEvaluationReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchItemInput;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;

import java.util.List;

/**
 * 批量准入评估应用服务。
 * 整批固定同一份当前策略快照；单项输入非法只标记该项，不影响其余项出结论。
 */
public interface BatchAdmissionService {

    /**
     * 对一批镜像逐个评估。
     *
     * @param caller         调用方（须具备 EVALUATE 权限）
     * @param items          批量输入项（逐项独立）
     * @param idempotencyKey 整批幂等键（可空）
     */
    BatchEvaluationReport evaluateBatch(Caller caller, List<BatchItemInput> items,
                                        String idempotencyKey);
}
