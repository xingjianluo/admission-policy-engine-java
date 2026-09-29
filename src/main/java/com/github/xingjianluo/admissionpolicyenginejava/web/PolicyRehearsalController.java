package com.github.xingjianluo.admissionpolicyenginejava.web;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalReport;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyRehearsalService;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.RehearseRequest;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.BatchItemDto;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 策略预演 HTTP 端点：候选规则只用于本次对照，不发布、不产生正式版本。
 */
@RestController
@RequestMapping("/api/admission")
public class PolicyRehearsalController {

    private final PolicyRehearsalService rehearsalService;

    public PolicyRehearsalController(PolicyRehearsalService rehearsalService) {
        this.rehearsalService = rehearsalService;
    }

    @PostMapping("/rehearse")
    public RehearsalReport rehearse(@RequestBody RehearseRequest request) {
        if (request == null) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "请求体为空");
        }
        List<BatchItemDto> items = request.items();
        if (items == null || items.isEmpty()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "items 不能为空");
        }
        if (request.candidateRules() == null || request.candidateRules().isEmpty()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                    "candidateRules 不能为空（预演必须提供候选规则）");
        }
        return rehearsalService.rehearse(
                WebMapper.toCaller(request.caller()),
                WebMapper.toBatchItemInputs(items),
                WebMapper.toRules(request.candidateRules()),
                request.idempotencyKey());
    }
}
