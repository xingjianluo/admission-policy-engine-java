package com.github.xingjianluo.admissionpolicyenginejava.policy;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 内存不可变版本链策略存储。
 * <p>
 * 设计要点：
 * <ul>
 *   <li>每个 {@link PolicySnapshot} 一经创建即不可变（规则列表做防御性拷贝并封装为不可变）。</li>
 *   <li>发布与回滚都在同一把锁内完成“检查当前版本 → 追加新版本”，保证并发更新串行化、
 *       乐观锁不失效、版本号不跳号。</li>
 *   <li>读路径无锁，直接返回快照引用；评估线程拿到快照后，后续任何发布都不影响该引用，
 *       因此一次判定看到的永远是一致版本的策略集合。</li>
 *   <li>回滚不删除历史，而是以目标版本的规则集新建一个快照，保留完整审计轨迹。</li>
 * </ul>
 */
@Component
public class InMemoryPolicyStore implements PolicyStore {

    private static final Logger log = LoggerFactory.getLogger(InMemoryPolicyStore.class);

    private final CopyOnWriteArrayList<PolicySnapshot> versions = new CopyOnWriteArrayList<>();

    public InMemoryPolicyStore() {
        // v0：空策略基线，所有后续更新都基于它做乐观锁。
        versions.add(new PolicySnapshot(0L, Instant.now(), "system", "初始空策略基线", List.of()));
    }

    @Override
    public PolicySnapshot current() {
        return versions.get(versions.size() - 1);
    }

    @Override
    public PolicySnapshot get(long version) {
        if (version < 0 || version >= versions.size()) {
            throw new AdmissionException(ErrorCode.POLICY_VERSION_NOT_FOUND,
                    "策略版本不存在: v" + version + "（当前最新 v" + current().version() + "）");
        }
        return versions.get((int) version);
    }

    @Override
    public PolicySnapshot publish(long expectedBaseVersion, List<PolicyRule> rules,
                                  String by, String comment) {
        if (rules == null) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "规则列表不能为 null");
        }
        synchronized (this) {
            PolicySnapshot head = current();
            if (head.version() != expectedBaseVersion) {
                throw new AdmissionException(ErrorCode.POLICY_VERSION_CONFLICT,
                        "策略版本冲突：期望基于 v" + expectedBaseVersion + " 更新，"
                                + "但当前最新版本为 v" + head.version()
                                + "，请重新读取后再提交");
            }
            List<PolicyRule> validated = validateAndFreeze(rules);
            long nextVersion = head.version() + 1;
            PolicySnapshot snapshot = new PolicySnapshot(nextVersion, Instant.now(), by,
                    comment == null ? "" : comment, validated);
            versions.add(snapshot);
            log.info("发布策略新版本 v{} by={} rules={} base=v{}",
                    nextVersion, by, validated.size(), expectedBaseVersion);
            return snapshot;
        }
    }

    @Override
    public PolicySnapshot rollback(long targetVersion, String by) {
        synchronized (this) {
            PolicySnapshot head = current();
            PolicySnapshot target = get(targetVersion);
            List<PolicyRule> restored = List.copyOf(target.rules());
            long nextVersion = head.version() + 1;
            PolicySnapshot snapshot = new PolicySnapshot(nextVersion, Instant.now(), by,
                    "回滚到 v" + targetVersion + " 的规则集", restored);
            versions.add(snapshot);
            log.info("回滚策略：新建 v{}，规则集复刻自 v{}，by={}", nextVersion, targetVersion, by);
            return snapshot;
        }
    }

    @Override
    public List<PolicySnapshot> history() {
        return List.copyOf(versions);
    }

    @Override
    public List<PolicyRule> validateRules(List<PolicyRule> rules) {
        return validateAndFreeze(rules);
    }

    private List<PolicyRule> validateAndFreeze(List<PolicyRule> rules) {
        List<PolicyRule> frozen = new ArrayList<>(rules.size());
        HashSet<String> ids = new HashSet<>();
        for (PolicyRule rule : rules) {
            if (rule == null) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST, "规则列表中不允许 null 条目");
            }
            if (rule.id() == null || rule.id().isBlank()) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST, "规则缺少 id");
            }
            if (!ids.add(rule.id())) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                        "规则 id 在同一版本内重复: " + rule.id());
            }
            if (rule.effect() == null) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                        "规则 " + rule.id() + " 缺少 effect(ALLOW/DENY)");
            }
            if (rule.schemaVersion() < SUPPORTED_SCHEMA_MIN
                    || rule.schemaVersion() > SUPPORTED_SCHEMA_MAX) {
                throw new AdmissionException(ErrorCode.POLICY_SCHEMA_UNSUPPORTED,
                        "规则 " + rule.id() + " 的 schemaVersion=" + rule.schemaVersion()
                                + " 不在兼容范围 [" + SUPPORTED_SCHEMA_MIN + ", "
                                + SUPPORTED_SCHEMA_MAX + "] 内");
            }
            validateConditions(rule);
            frozen.add(rule);
        }
        return List.copyOf(frozen);
    }

    /** 条件级语义校验：需要 value 的条件必须带非空 value，严重级别阈值必须可识别。 */
    private void validateConditions(PolicyRule rule) {
        List<PolicyCondition> conditions = rule.conditions();
        for (PolicyCondition c : conditions) {
            if (c == null || c.type() == null) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                        "规则 " + rule.id() + " 存在缺少 type 的条件");
            }
            switch (c.type()) {
                case SEVERITY_AT_LEAST -> {
                    if (c.value() == null || c.value().isBlank()) {
                        throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                                "规则 " + rule.id() + " 的 SEVERITY_AT_LEAST 条件缺少 value");
                    }
                    try {
                        Severity threshold = Severity.valueOf(c.value().trim().toUpperCase());
                        if (threshold == Severity.UNKNOWN) {
                            throw new IllegalArgumentException();
                        }
                    } catch (IllegalArgumentException e) {
                        throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                                "规则 " + rule.id() + " 的 SEVERITY_AT_LEAST 阈值无法识别: "
                                        + c.value());
                    }
                }
                case REGISTRY_EQUALS, REGISTRY_NOT_EQUALS, REPOSITORY_PREFIX,
                        BUILDER_ID_EQUALS, SOURCE_URI_PREFIX -> {
                    if (c.value() == null || c.value().isBlank()) {
                        throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                                "规则 " + rule.id() + " 的条件 " + c.type() + " 缺少非空 value");
                    }
                }
                case PROVENANCE_PRESENT, PROVENANCE_MISSING,
                        SIGNATURE_VERIFIED, SIGNATURE_NOT_VERIFIED -> {
                    // 存在性/布尔类条件不需要 value。
                }
            }
        }
    }
}
