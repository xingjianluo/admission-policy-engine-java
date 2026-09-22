package com.github.xingjianluo.admissionpolicyenginejava.policy;

import com.github.xingjianluo.admissionpolicyenginejava.model.AdmissionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.EvaluationResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicySet;
import com.github.xingjianluo.admissionpolicyenginejava.model.RuleHit;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 策略判定器。
 *
 * <p>冲突与覆盖规则（结果可复现）：
 * <ol>
 *   <li>收集全部命中规则；</li>
 *   <li>按优先级降序排序，取命中的最高优先级层；</li>
 *   <li>最高优先级层内同时存在 DENY 与 ALLOW 时，DENY 生效（显式拒绝优先，
 *       同级冲突的解决顺序不依赖规则在文件中的位置，保证确定性）；</li>
 *   <li>最高优先级层只有 ALLOW → ALLOW；</li>
 *   <li>没有任何规则命中 → DENY_NO_MATCH（默认拒绝）。</li>
 * </ol>
 * 评估只接收 {@link PolicySet} 快照，策略并发更新不影响进行中的判定。
 */
@Component
public class PolicyEvaluator {

    public EvaluationResult evaluate(AdmissionRequest request, PolicySet policySnapshot) {
        List<RuleHit> hits = collectHits(request, policySnapshot);

        Decision decision;
        String decisiveRuleId;
        String rationale;

        if (hits.isEmpty()) {
            decision = Decision.DENY_NO_MATCH;
            decisiveRuleId = null;
            rationale = "no allow rule matched; denied by default (policyVersion="
                    + policySnapshot.version() + ")";
        } else {
            int topPriority = hits.get(0).priority();
            List<RuleHit> topLayer = hits.stream()
                    .filter(h -> h.priority() == topPriority)
                    .toList();
            boolean denyAtTop = topLayer.stream()
                    .anyMatch(h -> h.effect() == PolicyEffect.DENY);
            if (denyAtTop) {
                decision = Decision.DENY;
                decisiveRuleId = topLayer.stream()
                        .filter(h -> h.effect() == PolicyEffect.DENY)
                        .map(RuleHit::ruleId)
                        .sorted()
                        .findFirst()
                        .orElseThrow();
                rationale = "explicit DENY at highest priority " + topPriority
                        + " overrides ALLOW; decisive rule=" + decisiveRuleId
                        + " (policyVersion=" + policySnapshot.version() + ")";
            } else {
                decision = Decision.ALLOW;
                decisiveRuleId = topLayer.stream()
                        .map(RuleHit::ruleId)
                        .sorted()
                        .findFirst()
                        .orElseThrow();
                rationale = "ALLOW at highest priority " + topPriority
                        + " with no conflicting DENY; decisive rule=" + decisiveRuleId
                        + " (policyVersion=" + policySnapshot.version() + ")";
            }
        }

        return new EvaluationResult(request.requestId(), decision,
                policySnapshot.version(), hits, decisiveRuleId, rationale,
                System.currentTimeMillis());
    }

    private List<RuleHit> collectHits(AdmissionRequest request, PolicySet policySnapshot) {
        List<RuleHit> hits = new ArrayList<>();
        for (PolicyRule rule : policySnapshot.rules()) {
            String reason = rule.match(request.metadata(), request.scan(),
                    request.provenance());
            if (reason != null) {
                hits.add(new RuleHit(rule.id(), rule.effect(), rule.priority(), reason));
            }
        }
        // 确定性排序：优先级降序；同级 effect(DENY 在前)；再按 ruleId
        hits.sort(Comparator.comparingInt(RuleHit::priority).reversed()
                .thenComparing(h -> h.effect() == PolicyEffect.DENY ? 0 : 1)
                .thenComparing(RuleHit::ruleId));
        return hits;
    }
}
