package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.InMemoryPolicyStore;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 策略版本测试：乐观并发控制、版本快照不可变、回滚产生新版本、schema 兼容范围。
 */
class PolicyStoreVersioningTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyStoreVersioningTest.class);

    private InMemoryPolicyStore store;

    private PolicyRule simpleRule(String id, PolicyEffect effect, int schema) {
        return new PolicyRule(id, 10, effect, schema,
                List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS, "gcr.internal")),
                "junit " + id);
    }

    @BeforeEach
    void setUp() {
        store = new InMemoryPolicyStore();
    }

    @Test
    void publishesVersionOnTopOfExpectedBase() {
        PolicySnapshot v1 = store.publish(0L, List.of(simpleRule("r1", PolicyEffect.DENY, 1)),
                "alice", "first");
        assertEquals(1L, v1.version());
        assertEquals(1, store.current().rules().size());
        log.info("[版本] 发布成功 v{} 规则={} by={}", v1.version(),
                v1.rules().stream().map(PolicyRule::id).toList(), v1.createdBy());
    }

    @Test
    void staleBaseVersionCausesConflictNotSilentOverwrite() {
        store.publish(0L, List.of(simpleRule("r1", PolicyEffect.DENY, 1)), "alice", "v1");
        // 另一个客户端仍基于 v0 提交，必须被告知冲突，而不是静默覆盖 v1。
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> store.publish(0L, List.of(simpleRule("r2", PolicyEffect.ALLOW, 1)),
                        "bob", "stale"));
        assertEquals(ErrorCode.POLICY_VERSION_CONFLICT, ex.getCode());
        assertEquals(1L, store.current().version(), "冲突提交不得推进版本");
        log.info("[版本] 并发冲突正确归类 errorCode={} message={}", ex.getCode(), ex.getMessage());
    }

    @Test
    void rollbackCreatesNewVersionWithoutDeletingHistory() {
        store.publish(0L, List.of(simpleRule("v1-rule", PolicyEffect.DENY, 1)), "a", "v1");
        store.publish(1L, List.of(simpleRule("v2-rule", PolicyEffect.ALLOW, 1)), "a", "v2");
        PolicySnapshot rolled = store.rollback(1L, "alice");

        assertEquals(3L, rolled.version(), "回滚必须产生新版本号，不覆盖历史");
        assertEquals(List.of("v1-rule"),
                rolled.rules().stream().map(PolicyRule::id).toList());
        assertEquals(4, store.history().size(), "v0..v3 全部保留");
        assertEquals("v2-rule", store.get(2L).rules().get(0).id(), "历史 v2 仍可读取");
        log.info("[版本] 回滚成功 v3 复刻 v1，历史版本数={} 当前规则={}",
                store.history().size(),
                store.current().rules().stream().map(PolicyRule::id).toList());
    }

    @Test
    void rollbackToMissingVersionIsNotFound() {
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> store.rollback(99L, "alice"));
        assertEquals(ErrorCode.POLICY_VERSION_NOT_FOUND, ex.getCode());
        log.info("[版本] 回滚不存在版本 errorCode={} message={}", ex.getCode(), ex.getMessage());
    }

    @Test
    void schemaVersionOutsideSupportedRangeRejected() {
        PolicyRule tooNew = simpleRule("future", PolicyEffect.DENY, 99);
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> store.publish(0L, List.of(tooNew), "alice", "future"));
        assertEquals(ErrorCode.POLICY_SCHEMA_UNSUPPORTED, ex.getCode());
        log.info("[版本] schema越界 errorCode={} 兼容范围=[{},{}] message={}",
                ex.getCode(),
                com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyStore
                        .SUPPORTED_SCHEMA_MIN,
                com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyStore
                        .SUPPORTED_SCHEMA_MAX,
                ex.getMessage());
    }

    @Test
    void snapshotTakenBeforeUpdateRemainsConsistentAfterConcurrentPublish()
            throws Exception {
        store.publish(0L, List.of(simpleRule("old", PolicyEffect.DENY, 1)), "a", "v1");
        // 评估线程在更新前先固定快照引用
        PolicySnapshot seen = store.current();

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger conflicts = new AtomicInteger();
        AtomicInteger successes = new AtomicInteger();
        List<Future<?>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final long base = 1L; // 所有线程都基于 v1 竞争
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    PolicySnapshot snap = store.publish(base,
                            List.of(simpleRule("r-" + Thread.currentThread().getId(),
                                    PolicyEffect.ALLOW, 1)),
                            "concurrent", "race");
                    successes.incrementAndGet();
                    log.info("[并发] 更新成功 -> v{}", snap.version());
                } catch (AdmissionException e) {
                    if (e.getCode() == ErrorCode.POLICY_VERSION_CONFLICT) {
                        conflicts.incrementAndGet();
                    } else {
                        throw e;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        log.info("[并发] {} 个线程竞争同一 base：成功 {}，版本冲突 {}，最终版本 v{}",
                threads, successes.get(), conflicts.get(), store.current().version());

        assertEquals(1, successes.get(), "同一 base 只能有一个更新成功");
        assertEquals(threads - 1, conflicts.get(), "其余全部收到版本冲突");
        assertEquals(2L, store.current().version(), "版本号严格 +1，无跳号无重复");
        // 关键：评估线程早先持有的快照仍然是 v1，内容不变。
        assertEquals(1L, seen.version());
        assertEquals("old", seen.rules().get(0).id());
        assertTrue(store.history().size() == 3);
    }

    @Test
    void duplicateRuleIdWithinOneVersionRejected() {
        PolicyRule a = simpleRule("dup", PolicyEffect.DENY, 1);
        PolicyRule b = simpleRule("dup", PolicyEffect.ALLOW, 1);
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> store.publish(0L, List.of(a, b), "a", "dup"));
        assertEquals(ErrorCode.INVALID_REQUEST, ex.getCode());
        log.info("[版本] 同版本重复id被拒绝 message={}", ex.getMessage());
    }
}
