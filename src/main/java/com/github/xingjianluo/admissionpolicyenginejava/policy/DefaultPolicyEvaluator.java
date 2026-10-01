package com.github.xingjianluo.admissionpolicyenginejava.policy;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.DecisionReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;
import com.github.xingjianluo.admissionpolicyenginejava.model.MatchedRule;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.Provenance;
import com.github.xingjianluo.admissionpolicyenginejava.model.Severity;
import com.github.xingjianluo.admissionpolicyenginejava.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * 默认策略评估器。
 * <p>
 * 规则语义：每条规则由若干匹配条件（AND）组成；当镜像满足全部条件时规则命中，
 * 产生其 effect（显式 ALLOW / 显式 DENY）。每个条件的匹配事实都会产出一条
 * 人类可读依据，保证结论可解释。
 * <p>
 * 冲突与覆盖规则（确定性、可复现）：
 * <ol>
 *   <li>命中规则按 priority 降序、id 升序排序；</li>
 *   <li>取排序后第一条作为决定性规则：高优先级 DENY 覆盖低优先级 ALLOW，反之亦然；</li>
 *   <li>同优先级 ALLOW/DENY 冲突时按 id 升序取第一条（固定全序 tie-break，
 *       不依赖集合迭代顺序）；</li>
 *   <li>无任何规则命中时默认拒绝（fail-closed）。</li>
 * </ol>
 * 评估只读取传入的不可变快照，因此与并发策略更新天然隔离。
 */
@Component
public class DefaultPolicyEvaluator implements PolicyEvaluator {

    private static final Logger log = LoggerFactory.getLogger(DefaultPolicyEvaluator.class);

    /** 命中规则的全序：优先级降序，同优先级 id 升序。 */
    private static final Comparator<MatchedRule> ORDER =
            Comparator.comparingInt(MatchedRule::priority).reversed()
                    .thenComparing(MatchedRule::ruleId);

    @Override
    public DecisionReport evaluate(ImageDescriptor d, PolicySnapshot snapshot) {
        List<MatchedRule> matched = new ArrayList<>();
        for (PolicyRule rule : snapshot.rules()) {
            List<String> facts = matchConditions(rule, d, snapshot.version());
            if (facts.size() == rule.conditions().size()) {
                String reason = rule.conditions().isEmpty()
                        ? "无条件规则，匹配任意镜像"
                        : String.join("; ", facts);
                matched.add(new MatchedRule(rule.id(), rule.priority(), rule.effect(), reason));
            }
        }
        matched.sort(ORDER);

        Optional<MatchedRule> decisive = matched.stream().findFirst();
        Decision decision;
        String rationale;
        if (decisive.isEmpty()) {
            decision = Decision.DENY;
            rationale = "无策略规则命中，按 fail-closed 默认拒绝（镜像: " + d.reference()
                    + ", digest: " + d.digest() + ", 策略版本 v" + snapshot.version() + "）";
        } else {
            MatchedRule r = decisive.get();
            decision = r.effect() == PolicyEffect.ALLOW ? Decision.ALLOW : Decision.DENY;
            boolean hasAllow = matched.stream().anyMatch(m -> m.effect() == PolicyEffect.ALLOW);
            boolean hasDeny = matched.stream().anyMatch(m -> m.effect() == PolicyEffect.DENY);
            String conflictNote = (hasAllow && hasDeny)
                    ? "。存在 ALLOW/DENY 显式冲突，按优先级降序(同优先级按规则id升序)由规则 "
                            + r.ruleId() + " 覆盖其余命中规则"
                    : "";
            rationale = "决定性规则 " + r.ruleId() + "(priority=" + r.priority()
                    + ", effect=" + r.effect() + ")，命中依据[" + r.reason() + "]"
                    + conflictNote
                    + "。基于策略版本 v" + snapshot.version() + " 做出 " + decision + " 判定。";
        }

        DecisionReport report = new DecisionReport(decision, snapshot.version(),
                List.copyOf(matched), decisive.orElse(null), rationale);

        log.info("评估完成 reference={} digest={} policyVersion=v{} decision={} matched={} decisive={}",
                d.reference(), d.digest(), snapshot.version(), decision,
                matched.stream().map(m -> m.ruleId() + ":" + m.effect() + "@" + m.priority()).toList(),
                decisive.map(MatchedRule::ruleId).orElse("<none>"));
        return report;
    }

    /**
     * 返回全部已满足条件的事实说明；调用方以“返回数量 == 条件数量”判定规则是否命中。
     */
    private List<String> matchConditions(PolicyRule rule, ImageDescriptor d, long policyVersion) {
        List<String> facts = new ArrayList<>();
        for (PolicyCondition c : rule.conditions()) {
            try {
                String fact = matchOne(rule.id(), c, d, policyVersion);
                if (fact != null) {
                    facts.add(fact);
                }
            } catch (AdmissionException e) {
                if (e.getCode() == ErrorCode.POLICY_RULESET_INVALID) {
                    // 统一给历史坏规则错误补上策略版本，保证单镜像/批量/预演都能据此定位坏版本。
                    throw new AdmissionException(ErrorCode.POLICY_RULESET_INVALID,
                            "线上策略版本 v" + policyVersion + " 中规则 " + rule.id()
                                    + " 的条件参数不合法（" + e.getMessage() + "），"
                                    + "该规则版本不可用于评估，请修复或回滚策略", e);
                }
                throw e;
            }
        }
        return facts;
    }

    private String matchOne(String ruleId, PolicyCondition c, ImageDescriptor d,
                            long policyVersion) {
        String v = c.value();
        // 失败边界：历史上可能已存在绕过校验发布的坏规则（缺参数/格式错误）。
        // 评估期再次识别，以可区分的规则集不合法错误失败，而不是 IllegalArgumentException/NPE → 500。
        if (ConditionParameters.requiresValue(c.type()) && (v == null || v.isBlank())) {
            throw new AdmissionException(ErrorCode.POLICY_RULESET_INVALID,
                    "线上策略版本 v" + policyVersion + " 中规则 " + ruleId + " 的条件 "
                            + c.type() + " 缺少合法参数 value，该规则版本不可用于评估，"
                            + "请修复或回滚策略");
        }
        return switch (c.type()) {
            case SEVERITY_AT_LEAST -> {
                Severity threshold = ConditionParameters.normalizeSeverity(v, ruleId);
                List<Vulnerability> hits = d.vulnerabilities().stream()
                        .filter(x -> x.severity().ordinal() >= threshold.ordinal()).toList();
                yield hits.isEmpty() ? null
                        : "存在 " + hits.size() + " 个级别>=" + threshold + " 的漏洞"
                                + "(如 " + hits.get(0).id() + ")";
            }
            case REGISTRY_EQUALS -> safeEquals(v, d.registry())
                    ? "registry='" + d.registry() + "' 等于 '" + v + "'" : null;
            case REGISTRY_NOT_EQUALS -> d.registry() != null && !d.registry().equals(v)
                    ? "registry='" + d.registry() + "' 不等于 '" + v + "'" : null;
            case REPOSITORY_PREFIX -> d.repository() != null && d.repository().startsWith(v)
                    ? "repository='" + d.repository() + "' 匹配前缀 '" + v + "'" : null;
            case PROVENANCE_PRESENT -> d.provenance() != null
                    ? "已提供供应链证明(builder=" + d.provenance().builderId() + ")" : null;
            case PROVENANCE_MISSING -> d.provenance() == null
                    ? "缺少供应链证明" : null;
            case SIGNATURE_VERIFIED -> Boolean.TRUE.equals(d.signatureValid())
                    ? "签名工件存在且校验通过" : null;
            case SIGNATURE_NOT_VERIFIED -> !Boolean.TRUE.equals(d.signatureValid())
                    ? (d.signatureValid() == null
                            ? "缺少签名工件" : "签名校验未通过(false)") : null;
            case BUILDER_ID_EQUALS -> {
                Provenance p = d.provenance();
                yield p != null && v.equals(p.builderId())
                        ? "builderId='" + v + "' 匹配" : null;
            }
            case SOURCE_URI_PREFIX -> {
                Provenance p = d.provenance();
                yield p != null && p.sourceUri() != null && p.sourceUri().startsWith(v)
                        ? "sourceUri='" + p.sourceUri() + "' 匹配前缀 '" + v + "'" : null;
            }
        };
    }

    private boolean safeEquals(String expected, String actual) {
        return expected != null && expected.equals(actual);
    }
}
