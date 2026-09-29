package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactParser;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactKind;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.RawArtifact;
import com.github.xingjianluo.admissionpolicyenginejava.model.BatchItemInput;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.ChangeDirection;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalItemResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalReport;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyEvaluator;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyStore;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyAdminService;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyRehearsalService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
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
 * 预演并发自洽性测试：
 * 预演进行的同时管理员持续发布/回滚策略。每一次预演对照的“现网一侧”都必须
 * 锚定同一份当前快照版本——即用该版本快照独立重算的结论必须与预演报告一致，
 * 绝不能出现一半基于旧版本、一半基于新版本的混合对照。
 */
@SpringBootTest
class RehearsalConcurrencyIntegrationTest {

    private static final Logger log =
            LoggerFactory.getLogger(RehearsalConcurrencyIntegrationTest.class);

    @Autowired
    private PolicyRehearsalService rehearsalService;
    @Autowired
    private PolicyAdminService adminService;
    @Autowired
    private PolicyStore policyStore;
    @Autowired
    private ArtifactParser parser;
    @Autowired
    private PolicyEvaluator evaluator;

    private final Caller reader = new Caller("rehe-conc-reader", Set.of("READER"));
    private final Caller admin = new Caller("rehe-conc-admin", Set.of("ADMIN"));

    @AfterEach
    void restoreDefaults() {
        adminService.rollback(admin, 1L);
    }

    static final String MANIFEST = """
            {
              "schemaVersion": 2,
              "digest": "sha256:reheconc1",
              "config": { "digest": "sha256:reheconc1" },
              "annotations": {
                "io.xj.registry": "gcr.internal",
                "io.xj.repository": "team-c/svc",
                "io.xj.tag": "7.7"
              }
            }
            """;
    static final String SCAN =
            "{ \"digest\": \"sha256:reheconc1\", \"vulnerabilities\": [] }";

    private IngestionRequest image() {
        return new IngestionRequest("gcr.internal/team-c/svc:7.7", List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", MANIFEST),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", SCAN)));
    }

    private List<BatchItemInput> batchOf(int n) {
        List<BatchItemInput> items = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            items.add(new BatchItemInput(i, image(), null));
        }
        return items;
    }

    /** 候选规则：无条件 ALLOW，使候选侧恒为 ALLOW；现网侧随版本在 DENY/ALLOW 间变化。 */
    private List<PolicyRule> allowAllCandidate() {
        return List.of(new PolicyRule("candidate-allow-all", 100, PolicyEffect.ALLOW, 1,
                List.of(), "预演候选：全部放行"));
    }

    private List<PolicyRule> publishedAllow() {
        return List.of(new PolicyRule("pub-allow-internal", 100, PolicyEffect.ALLOW, 1,
                List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS, "gcr.internal")),
                "发布：内部放行"));
    }

    @Test
    void rehearsalRemainsSelfConsistentWhilePublishingAndRollingBack() throws Exception {
        final int rehearseThreads = 6;
        final int rounds = 30;
        final int batchSize = 5;
        ExecutorService pool = Executors.newFixedThreadPool(rehearseThreads + 1);
        CountDownLatch stop = new CountDownLatch(1);
        AtomicInteger errors = new AtomicInteger();
        AtomicInteger checks = new AtomicInteger();
        ConcurrentHashMap<Long, AtomicInteger> versionsSeen = new ConcurrentHashMap<>();
        List<Future<?>> futures = new ArrayList<>();

        for (int t = 0; t < rehearseThreads; t++) {
            final int threadIdx = t;
            futures.add(pool.submit(() -> {
                try {
                    while (stop.getCount() > 0) {
                        for (int i = 0; i < rounds; i++) {
                            String key = "rehe-conc-" + threadIdx + "-" + System.nanoTime();
                            RehearsalReport report = rehearsalService.rehearse(
                                    reader, batchOf(batchSize), allowAllCandidate(), key);
                            long v = report.currentPolicyVersion();
                            versionsSeen.computeIfAbsent(v, k -> new AtomicInteger()).incrementAndGet();

                            // 用报告声明的“当前版本”快照独立重算，校验两侧自洽。
                            PolicySnapshot currentSnap = policyStore.get(v);
                            ImageDescriptor descriptor = parser.parse(image());
                            Decision expectedCurrent =
                                    evaluator.evaluate(descriptor, currentSnap).decision();

                            for (RehearsalItemResult item : report.items()) {
                                assertEquals(com.github.xingjianluo.admissionpolicyenginejava
                                        .model.ItemStatus.EVALUATED, item.status());
                                // 关键不变量：现网侧结论必须等于“该报告锚定版本”下的独立重算，
                                // 且报告内每个 item 锚定的版本都相同（在下面统一核对）。
                                assertEquals(expectedCurrent, item.currentReport().decision(),
                                        "现网侧结论必须与所声明版本一致，禁止新旧混合");
                                assertEquals(v, item.currentReport().policyVersion(),
                                        "同一次预演每个条目必须锚定同一份当前快照");
                                assertEquals(Decision.ALLOW, item.candidateReport().decision());
                                // 变化方向必须与双侧结论自洽
                                ChangeDirection expectedDir = expectedCurrent == Decision.ALLOW
                                        ? ChangeDirection.UNCHANGED
                                        : ChangeDirection.DENY_TO_ALLOW;
                                assertEquals(expectedDir, item.change());
                                checks.incrementAndGet();
                            }
                        }
                    }
                } catch (Exception e) {
                    errors.incrementAndGet();
                    log.error("预演线程异常", e);
                }
            }));
        }

        // 管理线程：交替“发布内部放行”与“回滚到默认 v1”，持续制造版本变化。
        Future<?> adminTask = pool.submit(() -> {
            try {
                for (int i = 0; i < 40; i++) {
                    long base = adminService.current(admin).version();
                    if (i % 2 == 0) {
                        try {
                            adminService.update(admin, base, publishedAllow(), "并发发布 " + i);
                        } catch (AdmissionException e) {
                            if (e.getCode() != ErrorCode.POLICY_VERSION_CONFLICT) {
                                throw e;
                            }
                        }
                    } else {
                        adminService.rollback(admin, 1L);
                    }
                    Thread.sleep(1);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        adminTask.get();
        stop.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        log.info("[预演并发自洽] 管理线程交替发布/回滚，预演观察版本分布={}，逐项校验={}，错误={}",
                versionsSeen.keySet().stream().sorted().toList(), checks.get(), errors.get());

        assertEquals(0, errors.get());
        assertTrue(checks.get() > 0);
        assertTrue(versionsSeen.size() >= 2, "预演应观察到发布前/后多个当前版本");
    }
}
