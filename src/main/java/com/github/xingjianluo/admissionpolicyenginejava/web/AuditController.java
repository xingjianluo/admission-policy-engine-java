package com.github.xingjianluo.admissionpolicyenginejava.web;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService;
import com.github.xingjianluo.admissionpolicyenginejava.model.AuditRecord;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.Permission;
import com.github.xingjianluo.admissionpolicyenginejava.security.Authorizer;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.CallerDto;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** 审计查询 HTTP 端点（需要 READ_AUDIT 权限，即 AUDITOR/ADMIN 角色）。 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditService auditService;
    private final Authorizer authorizer;

    public AuditController(AuditService auditService, Authorizer authorizer) {
        this.auditService = auditService;
        this.authorizer = authorizer;
    }

    @GetMapping("/recent")
    public List<AuditRecord> recent(@RequestParam(defaultValue = "50") int limit,
                                    @RequestHeader("X-Caller") String callerHeader) {
        Caller caller = WebMapper.toCaller(parseHeader(callerHeader));
        authorizer.check(caller, Permission.READ_AUDIT);
        return auditService.recent(limit);
    }

    @GetMapping("/by-digest")
    public List<AuditRecord> byDigest(@RequestParam String digest,
                                      @RequestHeader("X-Caller") String callerHeader) {
        Caller caller = WebMapper.toCaller(parseHeader(callerHeader));
        authorizer.check(caller, Permission.READ_AUDIT);
        return auditService.findByDigest(digest);
    }

    private CallerDto parseHeader(String header) {
        if (header == null || header.isBlank()) {
            header = "|";
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
