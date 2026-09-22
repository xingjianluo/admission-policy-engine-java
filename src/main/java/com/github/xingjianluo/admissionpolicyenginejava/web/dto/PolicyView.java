package com.github.xingjianluo.admissionpolicyenginejava.web.dto;

import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicySet;

import java.util.List;

/**
 * 策略集合的对外视图。
 */
public record PolicyView(long version,
                         int schemaVersion,
                         long createdAtEpochMs,
                         String changeComment,
                         List<RuleView> rules) {

    public record RuleView(String id, String name, String effect, int priority,
                           String description) {
        static RuleView from(PolicyRule rule) {
            return new RuleView(rule.id(), rule.name(), rule.effect().name(),
                    rule.priority(), rule.description());
        }
    }

    public static PolicyView from(PolicySet set) {
        return new PolicyView(set.version(), set.schemaVersion(), set.createdAtEpochMs(),
                set.changeComment(), set.rules().stream().map(RuleView::from).toList());
    }
}
