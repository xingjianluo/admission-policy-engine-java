package com.github.xingjianluo.admissionpolicyenginejava.web;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.PreparedBatchItem;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchEvaluationReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalReport;
import com.github.xingjianluo.admissionpolicyenginejava.service.BatchAdmissionService;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.BatchEvaluateRequest;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.BatchItemDto;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.RehearseRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

/**
 * 批量评估与策略预演 HTTP 端点。
 * <p>
 * 与单镜像评估一样：策略 DENY 是正常 200 响应体内的结论；单项坏输入只体现在该项的
 * {@code ok=false/errorCode/errorMessage}；整批级错误（鉴权、超限、候选规则不合法）
 * 走全局异常映射。
 */
@RestController
@RequestMapping("/api/admission")
public class BatchController {

    private final BatchAdmissionService batchService;

    public BatchController(BatchAdmissionService batchService) {
        this.batchService = batchService;
    }

    /**
     * 批量评估：一次提交多批镜像，每项独立给出结论。
     * 单项输入问题只标记该项（{@code ok=false}），其余项照常出结果；
     * 超过 {@link BatchAdmissionService#MAX_BATCH_ITEMS} 时整批以 400 拒绝。
     */
    @PostMapping("/batch-evaluate")
    public BatchEvaluationReport batchEvaluate(@RequestBody BatchEvaluateRequest request) {
        validateEnvelope(request.items() == null ? 0 : request.items().size());
        List<PreparedBatchItem> items = prepareItems(request.items());
        return batchService.evaluateBatch(
                WebMapper.toCaller(request.caller()), items, request.idempotencyKey());
    }

    /**
     * 策略预演：用候选规则集对同一批镜像做“当前策略 vs 候选规则”对照。
     * 候选规则不合法时与正常发布完全一致地按规则集不合法拒绝；不会发布、不产生新版本。
     */
    @PostMapping("/rehearse")
    public RehearsalReport rehearse(@RequestBody RehearseRequest request) {
        validateEnvelope(request.items() == null ? 0 : request.items().size());
        if (request.candidateRules() == null || request.candidateRules().isEmpty()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                    "预演必须提供非空 candidateRules");
        }
        List<PreparedBatchItem> items = prepareItems(request.items());
        return batchService.rehearse(
                WebMapper.toCaller(request.caller()),
                items,
                WebMapper.toRules(request.candidateRules()),
                request.idempotencyKey());
    }

    /** 整批级请求校验：鉴权由服务统一处理，这里只校验批量大小（防止拖垮服务）。 */
    private void validateEnvelope(int size) {
        if (size == 0) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "批量请求 items 不能为空");
        }
        if (size > BatchAdmissionService.MAX_BATCH_ITEMS) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                    "批量镜像数 " + size + " 超过上限 " + BatchAdmissionService.MAX_BATCH_ITEMS
                            + "，请拆分为多个批次");
        }
    }

    /** 逐项转换：单项结构错误转成该项的错误标记，不让一个坏项废掉整批。 */
    private List<PreparedBatchItem> prepareItems(List<BatchItemDto> dtos) {
        List<PreparedBatchItem> items = new ArrayList<>(dtos.size());
        for (BatchItemDto dto : dtos) {
            items.add(WebMapper.prepareBatchItem(dto));
        }
        return List.copyOf(items);
    }
}
