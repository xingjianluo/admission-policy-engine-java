package com.github.xingjianluo.admissionpolicyenginejava.config;

import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.Severity;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 启动时在空基线 v0 之上发布内置默认策略 v1。
 * <p>
 * 默认策略（条件全部满足时命中）：
 * <ol>
 *   <li>deny-critical-vulns(prio=10, DENY)：存在 CRITICAL 级别漏洞；</li>
 *   <li>deny-missing-provenance(prio=20, DENY)：缺少供应链证明；</li>
 *   <li>deny-unverified-signature(prio=20, DENY)：无签名或签名未验证通过；</li>
 *   <li>deny-untrusted-registry(prio=30, DENY)：来源 registry 不是 gcr.internal。</li>
 * </ol>
 * 无规则命中时评估器 fail-closed 仍为 DENY。显式 ALLOW 与跨优先级冲突由上传策略表达。
 */
@Component
@Order(0)
public class DefaultPolicyInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DefaultPolicyInitializer.class);

    private final PolicyStore policyStore;

    public DefaultPolicyInitializer(PolicyStore policyStore) {
        this.policyStore = policyStore;
    }

    @Override
    public void run(String... args) {
        if (policyStore.current().version() != 0L) {
            return;
        }
        List<PolicyRule> defaults = List.of(
                new PolicyRule("deny-critical-vulns", 10, PolicyEffect.DENY, 1,
                        List.of(new PolicyCondition(ConditionType.SEVERITY_AT_LEAST,
                                Severity.CRITICAL.name())),
                        "存在 CRITICAL 级别漏洞的镜像一律拒绝"),
                new PolicyRule("deny-missing-provenance", 20, PolicyEffect.DENY, 1,
                        List.of(new PolicyCondition(ConditionType.PROVENANCE_MISSING, null)),
                        "必须提供供应链证明"),
                new PolicyRule("deny-unverified-signature", 20, PolicyEffect.DENY, 1,
                        List.of(new PolicyCondition(ConditionType.SIGNATURE_NOT_VERIFIED, null)),
                        "签名工件必须存在且验证通过"),
                new PolicyRule("deny-untrusted-registry", 30, PolicyEffect.DENY, 1,
                        List.of(new PolicyCondition(ConditionType.REGISTRY_NOT_EQUALS,
                                "gcr.internal")),
                        "仅允许来自内部可信 registry gcr.internal 的镜像")
        );
        policyStore.publish(0L, defaults, "system", "内置默认策略 v1");
        log.info("默认策略 v1 已加载，规则: {}", defaults.stream().map(PolicyRule::id).toList());
    }
}
