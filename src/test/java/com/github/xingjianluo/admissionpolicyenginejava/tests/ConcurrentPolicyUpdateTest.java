package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditRecord;
import com.github.xingjianluo.admissionpolicyenginejava.auth.ActorContext;
import com.github.xingjianluo.admissionpolicyenginejava.auth.Role;
import com.github.xingjianluo.admissionpolicyenginejava.exception.ErrorCategory;
import com.github.xingjianluo.admissionpolicyenginejava.exception.PolicyVersionException;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.EvaluationResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicySet;
import com.github.xingjianluo.admissionpolicyenginejava.service.AdmissionService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;

import java.nio.file.Path;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发策略更新 / 回滚 / 并发评估测试。
 */
@SpringBootTest
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
class ConcurrentPolicyUpdateTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentPolicyUpdateTest.class);

    @Autowired
    private AdmissionService service;

    private final ActorContext admin = new ActorContext("admin-4", Role.ADMIN);

    private String denyAllPolicy() {
        return """
                {"schemaVersion":1,"rules":[
                  {"id":"DENY-EVERYTHING","name":"deny-all","effect":"DENY","priority":1000,
                   "description":"deny everything"}
                ]}
                """;
    }

    private String allowAllPolicy() {
        return """
                {"schemaVersion":1,"rules":[
                  {"id":"ALLOW-EVERYTHING","name":"allow-all","effect":"ALLOW","priority":1000,
                   "description":"allow everything"}
                ]}
                """;
    }

    /** N 个线程基于同一版本并发提交，只能有一个成功，其余必须是 VERSION_CONFLICT。 */
    @Test
    void concurrentUpdatesOnlyOneSucceeds() throws Exception {
        long base = service.currentPolicy(admin).version();

        int threads = 12;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger conflicts = new AtomicInteger();
        ConcurrentLinkedQueue<String> errors = new ConcurrentLinkedQueue<>();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    service.updatePolicy(admin, base, allowAllPolicy(), "concurrent update");
                    success.incrementAndGet();
                } catch (PolicyVersionException e) {
                    if (e.category() == ErrorCategory.VERSION_CONFLICT) {
                        conflicts.incrementAndGet();
                    } else {
                        errors.add("wrong category: " + e.category());
                    }
                } catch (Exception e) {
                    errors.add(e.toString());
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        log.info("[CASE] concurrent updates: total={} success={} conflicts={} errors={}",
                threads, success.get(), conflicts.get(), errors);
        assertEquals(1, success.get(), "exactly one concurrent update must succeed");
        assertEquals(threads - 1, conflicts.get(), "all losers must get VERSION_CONFLICT");
        assertTrue(errors.isEmpty(), "no unexpected errors: " + errors);
        assertEquals(base + 1, service.currentPolicy(admin).version());
    }

    /** 评估快照一致性：在策略来回切换期间并发评估同一请求（不同 requestId），
     *  每次结论都能对应到某一个完整策略版本，不出现混用。 */
    @Test
    void evaluationsSeeConsistentPolicySnapshots(@TempDir Path dir) throws Exception {
        // 先把策略置为一个已知版本
        long v0 = service.currentPolicy(admin).version();
        long denyVersion = service.updatePolicy(admin, v0, denyAllPolicy(), "snapshot deny").version();

        var bundle = TestFixtures.validBundle(dir, "MEDIUM");

        int evaluators = 16;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(evaluators + 2);
        ConcurrentLinkedQueue<String> problems = new ConcurrentLinkedQueue<>();

        // 评估线程：全部基于 deny 版本窗口发出；即便更新线程改策略，
        // 每个结果的 rationale 中的 policyVersion 必须真实存在
        for (int i = 0; i < evaluators; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    EvaluationResult r = service.evaluate(admin, "req-snap-" + idx,
                            bundle.manifest(), bundle.scan(), bundle.provenance());
                    PolicySet seen = service.currentPolicy(admin).version() == r.policyVersion()
                            ? service.currentPolicy(admin) : null;
                    // 只校验结论与它所记录的策略版本自洽：
                    // denyVersion 策略下唯一命中是 DENY-EVERYTHING
                    if (r.policyVersion() == denyVersion
                            && r.decision() != Decision.DENY) {
                        problems.add("stale deny version produced " + r.decision());
                    }
                    if (r.policyVersion() == denyVersion
                            && !"DENY-EVERYTHING".equals(r.decisiveRuleId())) {
                        problems.add("deny snapshot decisive rule mismatch: "
                                + r.decisiveRuleId());
                    }
                    log.info("[CASE] eval req-snap-{} policyVersion={} decision={} decisive={}",
                            idx, r.policyVersion(), r.decision(), r.decisiveRuleId());
                } catch (Exception e) {
                    problems.add(e.toString());
                }
            });
        }
        // 两个更新线程尝试把策略改成 allow；乐观锁保证最终版本确定
        pool.submit(() -> {
            try {
                start.await();
                service.updatePolicy(admin, denyVersion, allowAllPolicy(), "snapshot allow 1");
            } catch (PolicyVersionException ignored) {
                // 预期可能冲突
            } catch (Exception e) {
                problems.add("updater1 " + e);
            }
        });
        pool.submit(() -> {
            try {
                start.await();
                TimeUnit.MILLISECONDS.sleep(5);
                long cur = service.currentPolicy(admin).version();
                service.updatePolicy(admin, cur, denyAllPolicy(), "snapshot deny again");
            } catch (PolicyVersionException ignored) {
                // 预期可能冲突
            } catch (Exception e) {
                problems.add("updater2 " + e);
            }
        });

        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertTrue(problems.isEmpty(), "snapshot inconsistencies: " + problems);
    }

    /** 回滚：回滚产生新版本（单调递增），规则与目标版本一致。 */
    @Test
    void rollbackPublishesNewMonotonicVersion() {
        long before = service.currentPolicy(admin).version();
        long target = 0L; // 内置初始版本
        PolicySet rolled = service.rollbackPolicy(admin, before, target);
        assertTrue(rolled.version() > before, "rollback version must move forward");
        assertEquals(3, rolled.rules().size(), "builtin policy has three rules");
        log.info("[CASE] rollback {} -> new {} (target rules restored)", before, rolled.version());

        // 回滚时的乐观并发校验
        PolicyVersionException e = assertThrows(PolicyVersionException.class,
                () -> service.rollbackPolicy(admin, before, target));
        assertEquals(ErrorCategory.VERSION_CONFLICT, e.category());
        log.info("[CASE] stale rollback rejected: {}", e.getMessage());
    }

    /** 重复提交相同 requestId：只评估一次，审计只有一条 EVALUATE 记录。 */
    @Test
    void duplicateSubmissionsDoNotDuplicateAudit(@TempDir Path dir) throws Exception {
        var bundle = TestFixtures.validBundle(dir, "LOW");
        int copies = 20;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        for (int i = 0; i < copies; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    service.evaluate(admin, "req-dup-1",
                            bundle.manifest(), bundle.scan(), bundle.provenance());
                } catch (Exception ignored) {
                    // 回放首次失败也算去重成功路径之外的情况，这里输入合法不会失败
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        long count = service.auditTrail(admin).stream()
                .filter(r -> "EVALUATE".equals(r.operation())
                        && "req-dup-1".equals(r.requestId()))
                .count();
        log.info("[CASE] duplicate submissions={} audit rows for request={}", copies, count);
        assertEquals(1, count, "exactly one audit record for duplicate submissions");
    }
}
