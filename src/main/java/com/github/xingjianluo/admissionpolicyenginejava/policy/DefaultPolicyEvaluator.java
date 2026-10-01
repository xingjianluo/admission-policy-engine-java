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
            // 失败边界：历史坏规则（发布校验完善前已存在的非法条件参数）在匹配时
            // 可能抛出参数解析异常或 NPE，这里统一转成可定位的 POLICY_RULESET_INVALID，
            // 绝不以 500 冒泡；调用方（单镜像/批量/预演）据此给出可判断的反馈。
            final List<String> facts;
            try {
                // 先用与发布/预演入口相同的规约检查本规则参数：即使某坏参数在本镜像上
                // “恰好不抛异常”（如 REGISTRY_EQUALS 缺参会静默不匹配），也必须被确定性地
                // 识别出来，而不是让坏规则继续在线上版本里沉默。
                for (PolicyCondition c : rule.conditions()) {
                    if (c == null) {
                        throw new IllegalArgumentException("条件条目为 null");
                    }
                    ConditionParameters.validate(c.type(), c.value());
                }
                facts = matchConditions(rule, d);
            } catch (AdmissionException e) {
                throw e;
            } catch (RuntimeException e) {
                throw invalidRule(rule, snapshot, e);
            }
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
    private List<String> matchConditions(PolicyRule rule, ImageDescriptor d) {
        List<String> facts = new ArrayList<>();
        for (PolicyCondition c : rule.conditions()) {
            String fact = matchOne(c, d);
            if (fact != null) {
                facts.add(fact);
            }
        }
        return facts;
    }

    private String matchOne(PolicyCondition c, ImageDescriptor d) {
        String v = c.value();
        return switch (c.type()) {
            case SEVERITY_AT_LEAST -> {
                Severity threshold = parseSeverity(c);
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

    /**
     * 解析严重级别阈值：与发布/预演入口共用 {@link ConditionParameters} 的取值规约，
     * 允许大小写与首尾空格差异，非法值抛出可定位异常。
     */
    private Severity parseSeverity(PolicyCondition c) {
        try {
            return ConditionParameters.parseSeverity(c.type(), c.value());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "SEVERITY_AT_LEAST 条件参数非法: " + e.getMessage());
        }
    }

    /**
     * 把匹配期间暴露出来的历史坏规则问题统一包装为 POLICY_RULESET_INVALID，
     * 消息中带上策略版本、规则 id 与根因，方便调用方定位“是哪条已生效规则坏了”。
     */
    private AdmissionException invalidRule(PolicyRule rule, PolicySnapshot snapshot,
                                           RuntimeException cause) {
        String message = "策略版本 v" + snapshot.version() + " 中规则 " + rule.id()
                + " 的条件参数非法，无法完成评估（属历史坏规则，请修正后重新发布）: "
                + cause.getMessage();
        log.warn("评估遇到历史坏规则 policyVersion=v{} rule={} cause={}",
                snapshot.version(), rule.id(), cause.getMessage());
        return new AdmissionException(ErrorCode.POLICY_RULESET_INVALID, message, cause);
    }
}
