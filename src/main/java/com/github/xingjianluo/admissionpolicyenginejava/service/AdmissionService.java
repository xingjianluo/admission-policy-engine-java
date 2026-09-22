package com.github.xingjianluo.admissionpolicyenginejava.service;

import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.DecisionReport;

/** 准入评估应用服务：摄入 → 快照一致的评估 → 审计留痕。 */
public interface AdmissionService {

    DecisionReport evaluate(Caller caller, IngestionRequest request, String idempotencyKey);
}
