package com.github.xingjianluo.admissionpolicyenginejava.service;

import com.github.xingjianluo.admissionpolicyenginejava.model.BatchItemInput;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalReport;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;

import java.util.List;

/**
 * 策略预演应用服务：不发布候选规则，对同一批镜像同时给出“现网策略”与
 * “候选规则”两侧结论并标注差异。整次预演固定同一份当前策略快照。
 */
public interface PolicyRehearsalService {

    /**
     * 用候选规则集对一批镜像做预演对比。
     *
     * @param caller         调用方（须具备 EVALUATE 权限）
     * @param items          批量输入项
     * @param candidateRules 候选规则（不发布、不产生正式版本；合法性校验与正式发布一致）
     * @param idempotencyKey 整批幂等键（可空）
     */
    RehearsalReport rehearse(Caller caller, List<BatchItemInput> items,
                             List<PolicyRule> candidateRules, String idempotencyKey);
}
