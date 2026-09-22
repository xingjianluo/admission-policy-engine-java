package com.github.xingjianluo.admissionpolicyenginejava.web;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyAdminService;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.CallerDto;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.RollbackRequest;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.UpdatePolicyRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** 策略管理 HTTP 端点：更新（乐观锁）/ 回滚 / 当前版本 / 版本历史。 */
@RestController
@RequestMapping("/api/policies")
public class PolicyAdminController {

    private final PolicyAdminService adminService;

    public PolicyAdminController(PolicyAdminService adminService) {
        this.adminService = adminService;
    }

    /**
     * 发布新策略版本。
     * 请求必须携带 expectedBaseVersion；与服务端当前版本不一致时返回 409
     * POLICY_VERSION_CONFLICT，防止并发更新互相覆盖。
     */
    @PostMapping("/update")
    public PolicySnapshot update(@RequestBody UpdatePolicyRequest request) {
        if (request.expectedBaseVersion() == null) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                    "必须提供 expectedBaseVersion（乐观并发控制）");
        }
        return adminService.update(
                WebMapper.toCaller(request.caller()),
                request.expectedBaseVersion(),
                WebMapper.toRules(request.rules()),
                request.comment());
    }

    @PostMapping("/rollback")
    public PolicySnapshot rollback(@RequestBody RollbackRequest request) {
        if (request.targetVersion() == null) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "必须提供 targetVersion");
        }
        return adminService.rollback(
                WebMapper.toCaller(request.caller()), request.targetVersion());
    }

    @GetMapping("/current")
    public PolicySnapshot current(@RequestHeader("X-Caller") String callerHeader) {
        return adminService.current(WebMapper.toCaller(parseHeaderCaller(callerHeader)));
    }

    @GetMapping("/history")
    public List<PolicySnapshot> history(@RequestHeader("X-Caller") String callerHeader) {
        return adminService.history(WebMapper.toCaller(parseHeaderCaller(callerHeader)));
    }

    /** 只读端点用简单请求头表示调用方：name|ROLE1,ROLE2。 */
    private CallerDto parseHeaderCaller(String header) {
        if (header == null || header.isBlank()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                    "缺少 X-Caller 请求头（格式: name|ROLE1,ROLE2）");
        }
        String[] parts = header.split("\\|", 2);
        String name = parts[0].trim();
        List<String> roles = parts.length > 1
                ? java.util.Arrays.stream(parts[1].split(",")).map(String::trim)
                        .filter(s -> !s.isEmpty()).toList()
                : List.of();
        return new CallerDto(name, roles);
    }
}
