package com.github.xingjianluo.admissionpolicyenginejava.web;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditRecord;
import com.github.xingjianluo.admissionpolicyenginejava.auth.ActorContext;
import com.github.xingjianluo.admissionpolicyenginejava.auth.Role;
import com.github.xingjianluo.admissionpolicyenginejava.exception.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.exception.ErrorCategory;
import com.github.xingjianluo.admissionpolicyenginejava.model.EvaluationResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicySet;
import com.github.xingjianluo.admissionpolicyenginejava.service.AdmissionService;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.AuditView;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.EvaluateRequest;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.PolicyUpdateRequest;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.PolicyView;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.RollbackRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Path;
import java.util.List;

/**
 * 准入服务 HTTP 接口。
 * 调用方身份通过请求头模拟：{@code X-Actor-Id} 与 {@code X-Actor-Role}。
 */
@RestController
@RequestMapping("/api/admission")
public class AdmissionController {

    private final AdmissionService admissionService;

    public AdmissionController(AdmissionService admissionService) {
        this.admissionService = admissionService;
    }

    @PostMapping("/evaluate")
    public EvaluationResult evaluate(@RequestHeader(value = "X-Actor-Id", required = false)
                                     String actorId,
                                     @RequestHeader(value = "X-Actor-Role", required = false)
                                     String role,
                                     @RequestBody EvaluateRequest request) {
        ActorContext actor = parseActor(actorId, role);
        return admissionService.evaluate(actor, request.requestId(),
                path(request.manifestPath()), path(request.scanPath()),
                path(request.provenancePath()));
    }

    @PostMapping("/policies")
    public PolicyView updatePolicy(@RequestHeader(value = "X-Actor-Id", required = false)
                                   String actorId,
                                   @RequestHeader(value = "X-Actor-Role", required = false)
                                   String role,
                                   @RequestBody PolicyUpdateRequest request) {
        ActorContext actor = parseActor(actorId, role);
        PolicySet next = admissionService.updatePolicy(actor,
                request.expectedVersion(), request.policyJson(), request.comment());
        return PolicyView.from(next);
    }

    @PostMapping("/policies/rollback")
    public PolicyView rollbackPolicy(@RequestHeader(value = "X-Actor-Id", required = false)
                                     String actorId,
                                     @RequestHeader(value = "X-Actor-Role", required = false)
                                     String role,
                                     @RequestBody RollbackRequest request) {
        ActorContext actor = parseActor(actorId, role);
        PolicySet next = admissionService.rollbackPolicy(actor,
                request.expectedVersion(), request.targetVersion());
        return PolicyView.from(next);
    }

    @GetMapping("/policies/current")
    public PolicyView currentPolicy(@RequestHeader(value = "X-Actor-Id", required = false)
                                    String actorId,
                                    @RequestHeader(value = "X-Actor-Role", required = false)
                                    String role) {
        ActorContext actor = parseActor(actorId, role);
        return PolicyView.from(admissionService.currentPolicy(actor));
    }

    @GetMapping("/audit")
    public List<AuditView> audit(@RequestHeader(value = "X-Actor-Id", required = false)
                                 String actorId,
                                 @RequestHeader(value = "X-Actor-Role", required = false)
                                 String role) {
        ActorContext actor = parseActor(actorId, role);
        return admissionService.auditTrail(actor).stream().map(AuditView::from).toList();
    }

    private ActorContext parseActor(String actorId, String role) {
        // 缺失身份头：返回 null，由服务层按匿名拒绝并审计
        if (actorId == null || actorId.isBlank()) {
            return null;
        }
        if (role == null || role.isBlank()) {
            throw new AdmissionException(ErrorCategory.INVALID_INPUT,
                    "header X-Actor-Role is required when X-Actor-Id is provided");
        }
        try {
            return new ActorContext(actorId, Role.valueOf(role.trim().toUpperCase()));
        } catch (IllegalArgumentException e) {
            throw new AdmissionException(ErrorCategory.INVALID_INPUT,
                    "unknown role '" + role + "'");
        }
    }

    private static Path path(String value) {
        return value == null || value.isBlank() ? null : Path.of(value);
    }
}
