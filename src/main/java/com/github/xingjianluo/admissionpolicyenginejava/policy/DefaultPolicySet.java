package com.github.xingjianluo.admissionpolicyenginejava.policy;

import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicySet;
import com.github.xingjianluo.admissionpolicyenginejava.model.Severity;

import java.util.List;
import java.util.regex.Pattern;

/**
 * 服务启动时的内置策略集（version=0）。
 */
final class DefaultPolicySet {

    private DefaultPolicySet() {
    }

    static PolicySet create() {
        PolicyRule denyCritical = new PolicyRule(
                "DENY-CRITICAL-CVE",
                "deny-images-with-high-or-critical-cves",
                PolicyEffect.DENY,
                100,
                null,
                null,
                null,
                null,
                null,
                Severity.HIGH,
                null,
                "存在 HIGH/CRITICAL 级别漏洞的镜像一律拒绝");

        PolicyRule allowTrusted = new PolicyRule(
                "ALLOW-TRUSTED-BUILD",
                "allow-from-trusted-source-slsa3",
                PolicyEffect.ALLOW,
                10,
                List.of("registry.example.com", "gcr.io"),
                Pattern.compile("library/.*|platform/.*"),
                List.of("https://git.example.com/platform/.*"),
                null,
                null,
                null,
                3,
                "受信仓库、SLSA3 以上构建允许");

        PolicyRule allowLowRisk = new PolicyRule(
                "ALLOW-LOW-RISK",
                "allow-no-worse-than-medium",
                PolicyEffect.ALLOW,
                5,
                null,
                null,
                null,
                null,
                Severity.MEDIUM,
                null,
                null,
                "漏洞级别不超过 MEDIUM 的镜像允许");

        return new PolicySet(0L, PolicySet.CURRENT_SCHEMA,
                List.of(denyCritical, allowTrusted, allowLowRisk),
                0L,
                "builtin default policy set");
    }
}
