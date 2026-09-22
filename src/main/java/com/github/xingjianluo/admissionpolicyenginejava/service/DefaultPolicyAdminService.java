package com.github.xingjianluo.admissionpolicyenginejava.service;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService;
import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.AuditRecord;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.Permission;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyStore;
import com.github.xingjianluo.admissionpolicyenginejava.security.Authorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

/**
 * 策略管理应用服务默认实现。
 * <p>
 * 每个写操作先做鉴权（未授权 → UNAUTHORIZED，与策略拒绝无关），
 * 再委托存储的乐观锁/版本链完成原子发布，最后写一条管理审计。
 */
@Service
public class DefaultPolicyAdminService implements PolicyAdminService {

    private static final Logger log = LoggerFactory.getLogger(DefaultPolicyAdminService.class);

    private final PolicyStore policyStore;
    private final Authorizer authorizer;
    private final AuditService auditService;

    public DefaultPolicyAdminService(PolicyStore policyStore, Authorizer authorizer,
                                     AuditService auditService) {
        this.policyStore = policyStore;
        this.authorizer = authorizer;
        this.auditService = auditService;
    }

    @Override
    public PolicySnapshot update(Caller caller, long expectedBaseVersion, List<PolicyRule> rules,
                                 String comment) {
        authorizer.check(caller, Permission.UPDATE_POLICY);
        if (rules == null) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "规则列表不能为 null");
        }
        PolicySnapshot snapshot = policyStore.publish(expectedBaseVersion, rules,
                caller.name(), comment);
        auditService.record(new AuditRecord(
                auditId("update", caller.name(), snapshot.version()),
                Instant.now(), caller.name(), "POLICY_UPDATE", null,
                snapshot.version(), Decision.ALLOW,
                "策略更新成功：基于 v" + expectedBaseVersion + " 发布 v" + snapshot.version()
                        + "，规则数 " + snapshot.rules().size(),
                "comment=" + comment));
        return snapshot;
    }

    @Override
    public PolicySnapshot rollback(Caller caller, long targetVersion) {
        authorizer.check(caller, Permission.ROLLBACK_POLICY);
        PolicySnapshot snapshot = policyStore.rollback(targetVersion, caller.name());
        auditService.record(new AuditRecord(
                auditId("rollback", caller.name(), snapshot.version()),
                Instant.now(), caller.name(), "POLICY_ROLLBACK", null,
                snapshot.version(), Decision.ALLOW,
                "策略回滚成功：v" + snapshot.version() + " 复刻自 v" + targetVersion,
                "target=v" + targetVersion));
        return snapshot;
    }

    @Override
    public PolicySnapshot current(Caller caller) {
        authorizer.check(caller, Permission.READ_POLICY);
        return policyStore.current();
    }

    @Override
    public List<PolicySnapshot> history(Caller caller) {
        authorizer.check(caller, Permission.READ_POLICY);
        return policyStore.history();
    }

    private String auditId(String action, String caller, long newVersion) {
        return action + ":" + caller + ":v" + newVersion;
    }
}
