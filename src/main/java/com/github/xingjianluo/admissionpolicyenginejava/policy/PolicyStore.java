package com.github.xingjianluo.admissionpolicyenginejava.policy;

import com.github.xingjianluo.admissionpolicyenginejava.exception.PolicyVersionException;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicySet;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 策略版本存储。
 *
 * <p>一致性保证：
 * <ul>
 *   <li>{@link #snapshot()} 返回的 {@link PolicySet} 是不可变对象，
 *       评估全程只读取该快照，更新/回滚并发进行也不会看到“半个新版本”；</li>
 *   <li>更新采用乐观并发：调用方必须给出它所基于的当前版本，
 *       不匹配则抛 {@link PolicyVersionException}；</li>
 *   <li>所有历史版本保留，回滚 = 用历史规则创建一个新版本（版本号仍向前递增），
 *       审计上可区分“回滚自哪个版本”。</li>
 * </ul>
 */
@Component
public class PolicyStore {

    private final AtomicReference<PolicySet> current = new AtomicReference<>();
    private final ConcurrentMap<Long, PolicySet> history = new ConcurrentHashMap<>();
    private final AtomicLong versionSequence = new AtomicLong(0L);

    public PolicyStore() {
        PolicySet builtin = DefaultPolicySet.create();
        history.put(builtin.version(), builtin);
        current.set(builtin);
    }

    /** 返回当前生效策略的不可变快照。 */
    public PolicySet snapshot() {
        return current.get();
    }

    public long currentVersion() {
        return current.get().version();
    }

    public Optional<PolicySet> version(long version) {
        return Optional.ofNullable(history.get(version));
    }

    public List<Long> historyVersions() {
        return history.keySet().stream().sorted().toList();
    }

    /**
     * 基于期望版本提交新规则集合。CAS 保证并发更新只有一个成功。
     *
     * @param expectedVersion 调用方看到的当前版本
     * @param parsed          解析后的新策略内容
     * @param comment         变更说明（审计留痕）
     * @return 提交后生效的新版本
     */
    public PolicySet commitIfMatch(long expectedVersion,
                                   PolicySetParser.ParsedPolicySet parsed,
                                   String comment) {
        synchronized (this) {
            PolicySet currentNow = current.get();
            if (currentNow.version() != expectedVersion) {
                throw new PolicyVersionException(
                        "policy update rejected due to concurrent modification",
                        expectedVersion, currentNow.version());
            }
            long newVersion = versionSequence.incrementAndGet();
            PolicySet next = new PolicySet(newVersion, parsed.schemaVersion(),
                    parsed.rules(), System.currentTimeMillis(),
                    comment == null ? "" : comment);
            history.put(newVersion, next);
            current.set(next);
            return next;
        }
    }

    /**
     * 回滚到历史版本：复制该版本规则并以新的版本号发布，保证版本号单调。
     */
    public PolicySet rollbackIfMatch(long expectedVersion, long targetVersion) {
        synchronized (this) {
            PolicySet currentNow = current.get();
            if (currentNow.version() != expectedVersion) {
                throw new PolicyVersionException(
                        "policy rollback rejected due to concurrent modification",
                        expectedVersion, currentNow.version());
            }
            PolicySet target = history.get(targetVersion);
            if (target == null) {
                throw new PolicyVersionException(
                        "rollback target version does not exist",
                        targetVersion, currentNow.version());
            }
            long newVersion = versionSequence.incrementAndGet();
            PolicySet next = new PolicySet(newVersion, target.schemaVersion(),
                    target.rules(), System.currentTimeMillis(),
                    "rollback to version " + targetVersion);
            history.put(newVersion, next);
            current.set(next);
            return next;
        }
    }
}
