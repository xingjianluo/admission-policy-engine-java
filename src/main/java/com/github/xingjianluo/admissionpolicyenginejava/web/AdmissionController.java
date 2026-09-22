package com.github.xingjianluo.admissionpolicyenginejava.web;

import com.github.xingjianluo.admissionpolicyenginejava.model.DecisionReport;
import com.github.xingjianluo.admissionpolicyenginejava.service.AdmissionService;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.EvaluateRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 准入评估 HTTP 端点。 */
@RestController
@RequestMapping("/api/admission")
public class AdmissionController {

    private final AdmissionService admissionService;

    public AdmissionController(AdmissionService admissionService) {
        this.admissionService = admissionService;
    }

    /**
     * 评估镜像准入。
     * 策略 DENY 仍返回 200 + body.decision=DENY；输入/鉴权错误走全局异常映射。
     */
    @PostMapping("/evaluate")
    public DecisionReport evaluate(@RequestBody EvaluateRequest request) {
        return admissionService.evaluate(
                WebMapper.toCaller(request.caller()),
                WebMapper.toIngestion(request),
                request.idempotencyKey());
    }
}
