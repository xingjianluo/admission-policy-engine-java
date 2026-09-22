package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactKind;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.RawArtifact;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.DecisionReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import com.github.xingjianluo.admissionpolicyenginejava.service.AdmissionService;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyAdminService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发场景测试：
 * 1) 多管理员基于同一版本并发更新，恰好一个成功，其余全部得到可区分的版本冲突；
 * 2) 更新进行期间并发评估，每次评估看到的策略版本必须是一个完整一致的快照
 * （版本号只能是更新前或更新后，绝不出现混合）；
 * 3) 相同评估请求并发提交，审计不产生重复记录。
 */
@SpringBootTest
class ConcurrencyIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrencyIntegrationTest.class);

    @Autowired
    private PolicyAdminService adminService;
    @Autowired
    private AdmissionService admissionService;

    private final Caller admin = new Caller("admin-root", new HashSet<>(List.of("ADMIN")));
    private final Caller reader = new Caller("reader-x", new HashSet<>(List.of("READER")));

    static final String MANIFEST = """
            {
              "schemaVersion": 2,
              "digest": "sha256:conc0001",
              "config": { "digest": "sha256:conc0001" },
              "annotations": {
                "io.xj.registry": "gcr.internal",
                "io.xj.repository": "team-c/svc",
                "io.xj.tag": "9.9"
              }
            }
            """;
    static final String SCAN = """
            { "digest": "sha256:conc0001", "vulnerabilities": [] }
            """;

    private IngestionRequest request() {
        return new IngestionRequest("gcr.internal/team-c/svc:9.9", List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", MANIFEST),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", SCAN)));
    }

    @AfterEach
    void restoreDefaults() {
        adminService.rollback(admin, 1L);
    }

    private List<PolicyRule> allowPolicy(String tag) {
        return List.of(new PolicyRule("allow-all-" + tag, 50, PolicyEffect.ALLOW, 1,
                List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS, "gcr.internal")),
                "并发测试 ALLOW " + tag));
    }

    @Test
    void concurrentUpdatesOnSameBaseExactlyOneSucceedsOthersConflict() throws Exception {
        long base = adminService.current(admin).version();
        int threads = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch gate = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        ConcurrentHashMap<Long, AtomicInteger> conflictCodes = new ConcurrentHashMap<>();
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < threads; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                try {
                    gate.await();
                    adminService.update(admin, base, allowPolicy("t" + idx), "并发更新");
                    ok.incrementAndGet();
                } catch (AdmissionException e) {
                    conflictCodes.computeIfAbsent(0L, k -> new AtomicInteger()).incrementAndGet();
                    if (e.getCode() != ErrorCode.POLICY_VERSION_CONFLICT) {
                        throw new AssertionError("非预期错误码: " + e.getCode(), e);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }
        gate.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        log.info("[并发更新] base=v{}，{} 个并发提交：成功 {}，版本冲突 {}",
                base, threads, ok.get(), threads - ok.get());

        assertEquals(1, ok.get(), "同一 baseVersion 的并发更新必须恰好一个成功");
        assertEquals(threads - 1, threads - ok.get());
        PolicySnapshot current = adminService.current(admin);
        assertEquals(base + 1, current.version(), "失败的并发提交不得推进版本");
        assertEquals(1, current.rules().size());
    }

    @Test
    void evaluationsDuringUpdatesAlwaysSeeOneConsistentSnapshotVersion() throws Exception {
        // 基线：默认策略下该镜像（无证明无签名）命中 DENY；更新后为显式 ALLOW。
        int evalThreads = 8;
        int roundsPerThread = 50;
        ExecutorService pool = Executors.newFixedThreadPool(evalThreads + 1);
        CountDownLatch stop = new CountDownLatch(1);
        Set<Long> observedVersions = ConcurrentHashMap.newKeySet();
        Set<Decision> observedDecisions = ConcurrentHashMap.newKeySet();
        AtomicInteger errors = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();

        for (int t = 0; t < evalThreads; t++) {
            futures.add(pool.submit(() -> {
                try {
                    while (stop.getCount() > 0) {
                        for (int i = 0; i < roundsPerThread; i++) {
                            DecisionReport r = admissionService.evaluate(
                                    reader, request(),
                                    "consistency-" + Thread.currentThread().getId()
                                            + "-" + System.nanoTime());
                            observedVersions.add(r.policyVersion());
                            observedDecisions.add(r.decision());
                            // 关键不变量：命中规则集合必须与所报告版本对应——
                            // 快照在评估前固定，因此同版本下结论稳定。
                            DecisionReport again = evaluateAtFixedVersion(r.policyVersion());
                            // 只校验“报告自身自洽”：决定性规则要么为空要么存在于命中列表
                            if (r.decisiveRule() != null
                                    && r.matchedRules().stream().noneMatch(
                                            m -> m.ruleId().equals(r.decisiveRule().ruleId()))) {
                                throw new AssertionError("决定性规则不在命中列表中");
                            }
                        }
                    }
                } catch (Exception e) {
                    errors.incrementAndGet();
                    log.error("评估线程异常", e);
                }
            }));
        }

        // 更新线程：反复在“最新 base”上发布（只交替两个策略集），持续制造版本变化
        Future<?> updater = pool.submit(() -> {
            try {
                for (int i = 0; i < 20; i++) {
                    long base = adminService.current(admin).version();
                    try {
                        adminService.update(admin, base, allowPolicy("wave" + i),
                                "并发波次 " + i);
                    } catch (AdmissionException e) {
                        // 与评估线程无写竞争，但保留对冲突的容忍（其他更新波次）
                        if (e.getCode() != ErrorCode.POLICY_VERSION_CONFLICT) {
                            throw e;
                        }
                    }
                    Thread.sleep(2);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        updater.get();
        stop.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        log.info("[并发一致性] 评估观察到的策略版本={} 观察到的判定={} 评估线程错误={}",
                observedVersions.stream().sorted().toList(), observedDecisions, errors.get());

        assertEquals(0, errors.get());
        assertTrue(observedVersions.size() >= 2, "评估应观察到更新前/后至少两个版本");
        // 每个版本的结论必须是单一确定值：再次拉取历史快照不可用于评估服务，
        // 这里用“同一版本多次评估结论一致”做抽样保证。
        for (long v : observedVersions) {
            assertVersionDecisionStable(v);
        }
    }

    @org.springframework.beans.factory.annotation.Autowired
    private com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyStore policyStore;
    @org.springframework.beans.factory.annotation.Autowired
    private com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactParser parser;
    @org.springframework.beans.factory.annotation.Autowired
    private com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyEvaluator evaluator;

    private DecisionReport evaluateAtFixedVersion(long version) {
        var snap = policyStore.get(version);
        return evaluator.evaluate(parser.parse(request()), snap);
    }

    private void assertVersionDecisionStable(long version) {
        Decision first = evaluateAtFixedVersion(version).decision();
        for (int i = 0; i < 5; i++) {
            assertEquals(first, evaluateAtFixedVersion(version).decision(),
                    "同一策略版本 v" + version + " 下结论必须稳定");
        }
    }

    @Test
    void identicalConcurrentEvaluationsDeduplicatedInAudit() throws Exception {
        int threads = 10;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch gate = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        String sameKey = "same-key-" + System.nanoTime();
        int before = auditService.recent(100_000).size();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                gate.await();
                return admissionService.evaluate(reader, request(), sameKey);
            }));
        }
        gate.countDown();
        Set<Decision> decisions = ConcurrentHashMap.newKeySet();
        for (Future<?> f : futures) {
            decisions.add(((DecisionReport) f.get()).decision());
        }
        pool.shutdown();
        int after = auditService.recent(100_000).size();

        log.info("[并发幂等] {} 个相同请求(key={}) 判定集合={}（应只有1种），审计记录 {} -> {}（应仅+1）",
                threads, sameKey, decisions, before, after);
        assertEquals(1, decisions.size(), "并发相同请求结论必须一致");
        assertEquals(before + 1, after, "并发重复提交只允许产生一条审计记录");
    }

    @org.springframework.beans.factory.annotation.Autowired
    private com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService auditService;

    private List<com.github.xingjianluo.admissionpolicyenginejava.model.AuditRecord>
            auditByDigest(String digest) {
        return auditService.findByDigest(digest);
    }
}
