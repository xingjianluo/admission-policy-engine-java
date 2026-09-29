package com.github.xingjianluo.admissionpolicyenginejava.policy;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
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
    private final PolicyRuleSetValidator validator;

    public InMemoryPolicyStore() {
        this(new DefaultPolicyRuleSetValidator());
    }

    public InMemoryPolicyStore(PolicyRuleSetValidator validator) {
        this.validator = validator;
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
            List<PolicyRule> validated = validator.validateAndFreeze(rules);
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
}
