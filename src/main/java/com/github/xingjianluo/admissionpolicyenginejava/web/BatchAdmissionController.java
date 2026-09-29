package com.github.xingjianluo.admissionpolicyenginejava.web;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchEvaluationReport;
import com.github.xingjianluo.admissionpolicyenginejava.service.BatchAdmissionService;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.BatchEvaluateRequest;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.BatchItemDto;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 批量准入评估 HTTP 端点。
 * 整批一个 HTTP 200 响应，逐项给出结论或输入错误；
 * 鉴权失败 / 批量超限 / 空批走全局异常通道。
 */
@RestController
@RequestMapping("/api/admission")
public class BatchAdmissionController {

    private final BatchAdmissionService batchAdmissionService;

    public BatchAdmissionController(BatchAdmissionService batchAdmissionService) {
        this.batchAdmissionService = batchAdmissionService;
    }

    @PostMapping("/batch-evaluate")
    public BatchEvaluationReport evaluateBatch(@RequestBody BatchEvaluateRequest request) {
        if (request == null) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "请求体为空");
        }
        List<BatchItemDto> items = request.items();
        if (items == null || items.isEmpty()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "items 不能为空");
        }
        return batchAdmissionService.evaluateBatch(
                WebMapper.toCaller(request.caller()),
                WebMapper.toBatchItemInputs(items),
                request.idempotencyKey());
    }
}
