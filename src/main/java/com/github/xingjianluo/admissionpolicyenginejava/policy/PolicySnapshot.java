package com.github.xingjianluo.admissionpolicyenginejava.policy;

import java.time.Instant;
import java.util.List;

/**
 * 某一版本的不可变策略集合。任何一次评估都只引用单个快照，
 * 从而保证评估期间不会看到“半个新版本”。
 */
public record PolicySnapshot(
        long version,
        Instant createdAt,
        String createdBy,
        String changeComment,
        List<PolicyRule> rules
) {
}
