package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.audit.AuditService;
import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactKind;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.BatchItemInput;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.PreparedBatchItem;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.RawArtifact;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.ChangeDirection;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalItemResult;
import com.github.xingjianluo.admissionpolicyenginejava.model.RehearsalReport;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicySnapshot;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyStore;
import com.github.xingjianluo.admissionpolicyenginejava.service.BatchAdmissionService;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyAdminService;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 策略预演并发一致性测试：
 * 预演进行期间，另一线程持续发布/回滚线上策略；每次预演对照都必须基于同一份当前策略
 * 快照（同一次报告内所有 baseline 结论来自同一版本、命中规则都属于该版本），
 * 候选侧结论始终只取决于候选规则；并覆盖并发相同预演的审计去重。
 */
@SpringBootTest
class RehearsalConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(RehearsalConcurrencyTest.class);

    @Autowired
    private BatchAdmissionService batchService;
    @Autowired
    private PolicyAdminService adminService;
    @Autowired
    private PolicyStore policyStore;
    @Autowired
    private AuditService auditService;

    private final Caller admin = new Caller("admin-reh", Set.of("ADMIN"));
    private final Caller reader = new Caller("reader-reh", Set.of("READER"));

    @AfterEach
    void restoreDefaults() {
        adminService.rollback(admin, 1L);
    }

    private static String manifest(String digest, String registry, String repository) {
        return """
                {
                  "schemaVersion": 2,
                  "digest": "%s",
                  "config": { "digest": "%s" },
                  "annotations": {
                    "io.xj.registry": "%s",
                    "io.xj.repository": "%s",
                    "io.xj.tag": "1.0"
                  }
                }
                """.formatted(digest, digest, registry, repository);
    }

    private static String scan(String digest, String... vulns) {
        StringBuilder sb = new StringBuilder("{ \"digest\": \"").append(digest)
                .append("\", \"vulnerabilities\": [");
        for (int i = 0; i < vulns.length; i += 2) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{ \"id\": \"").append(vulns[i]).append("\", ")
                    .append("\"ratings\": [{ \"severity\": \"").append(vulns[i + 1]).append("\" }] }");
        }
        return sb.append("] }").toString();
    }

    private PreparedBatchItem item(String ref, String digest, String registry, String repo,
                                   String... vulns) {
        return PreparedBatchItem.of(new BatchItemInput(ref, List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST",
                        manifest(digest, registry, repo)),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON",
                        scan(digest, vulns)))));
    }

    /** 8 个镜像：4 内部、4 外部，覆盖“内部放行”候选规则下变化/不变化两类。 */
    private List<PreparedBatchItem> mixedBatch() {
        List<PreparedBatchItem> items = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            items.add(item("gcr.internal/team/svc%d:1".formatted(i),
                    "sha256:reh-in-" + i, "gcr.internal", "team/svc" + i));
            items.add(item("docker.example.com/team/svc%d:1".formatted(i),
                    "sha256:reh-ex-" + i, "docker.example.com", "team/svc" + i));
        }
        return List.copyOf(items);
    }

    private List<PolicyRule> candidate() {
        return List.of(new PolicyRule("cand-allow-internal", 100, PolicyEffect.ALLOW, 1,
                List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS, "gcr.internal")),
                "候选：内部放行"));
    }

    private List<PolicyRule> liveAllowPolicy(String wave) {
        return List.of(new PolicyRule("live-allow-" + wave, 100, PolicyEffect.ALLOW, 1,
                List.of(new PolicyCondition(ConditionType.REGISTRY_EQUALS, "gcr.internal")),
                "线上波次 " + wave));
    }

    /**
     * 关键场景：变更线程反复“发布显式 ALLOW → 回滚到默认 v1”，预演线程持续预演。
     */
    @Test
    void rehearsalAmidConcurrentPublishAndRollbackStaysSelfConsistent() throws Exception {
        int rehearseThreads = 6;
        int rounds = 30;
        ExecutorService pool = Executors.newFixedThreadPool(rehearseThreads + 1);
        AtomicInteger errors = new AtomicInteger();
        AtomicInteger rehearsals = new AtomicInteger();
        ConcurrentHashMap<Long, AtomicInteger> baselinesSeen = new ConcurrentHashMap<>();
        List<Future<?>> futures = new ArrayList<>();

        for (int t = 0; t < rehearseThreads; t++) {
            final int threadIdx = t;
            futures.add(pool.submit(() -> {
                try {
                    for (int r = 0; r < rounds; r++) {
                        RehearsalReport report = batchService.rehearse(reader, mixedBatch(),
                                candidate(), "conc-reh-" + threadIdx + "-" + System.nanoTime());
                        rehearsals.incrementAndGet();
                        baselinesSeen.computeIfAbsent(report.baselineVersion(),
                                k -> new AtomicInteger()).incrementAndGet();
                        verifyReportSelfConsistent(report);
                    }
                } catch (Exception e) {
                    errors.incrementAndGet();
                    log.error("预演线程异常", e);
                }
            }));
        }

        Future<?> mutator = pool.submit(() -> {
            try {
                for (int i = 0; i < 25; i++) {
                    long base = adminService.current(admin).version();
                    try {
                        adminService.update(admin, base, liveAllowPolicy("wave" + i),
                                "并发预演波次 " + i);
                        // 在“新版本生效”期间立刻回滚到默认规则集，产生又一个新版本。
                        adminService.rollback(admin, 1L);
                    } catch (AdmissionException e) {
                        if (e.getCode() != ErrorCode.POLICY_VERSION_CONFLICT) {
                            throw e;
                        }
                    }
                    Thread.sleep(1);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        mutator.get();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        log.info("[并发预演] 完成 {} 次预演，错误 {}，观察到的基线版本分布={}",
                rehearsals.get(), errors.get(),
                baselinesSeen.keySet().stream().sorted().toList());

        assertEquals(0, errors.get(), "预演线程不允许出现异常");
        assertEquals(rehearseThreads * rounds, rehearsals.get(), "所有预演轮次都应完成");
        assertTrue(baselinesSeen.size() >= 2,
                "预演期间发生了发布/回滚，应至少观察到两个不同的基线版本，实际="
                        + baselinesSeen.keySet());
    }

    /**
     * 校验单次预演报告自洽：
     * 1) 所有 baseline 结论的 policyVersion 等于报告声明的同一版本（不允许半旧半新）；
     * 2) baseline 命中的每条规则都真实存在于该版本快照且优先级/effect 一致
     *   （若读到混合规则集，命中集合必然对不上任何已存在快照）；
     * 3) baseline 结论与按该快照规则推导的期望结论一致；
     * 4) 候选侧结论只由候选规则决定（内部 ALLOW、外部 fail-closed DENY）；
     * 5) 变化方向与两侧结论一致，汇总计数与逐项一致。
     */
    private void verifyReportSelfConsistent(RehearsalReport report) {
        PolicySnapshot baselineSnap = policyStore.get(report.baselineVersion());
        int changed = 0;
        int allowToDeny = 0;
        int denyToAllow = 0;
        for (RehearsalItemResult item : report.items()) {
            assertNotNull(item.baseline(), "合法项 baseline 不能为 null");
            assertNotNull(item.candidate(), "合法项 candidate 不能为 null");

            assertEquals(report.baselineVersion(), item.baseline().policyVersion(),
                    "同一次预演内不允许 baseline 跨版本（半旧半新）");

            item.baseline().matchedRules().forEach(m -> {
                PolicyRule source = baselineSnap.rules().stream()
                        .filter(r -> r.id().equals(m.ruleId())).findFirst()
                        .orElseThrow(() -> new AssertionError(
                                "baseline 命中规则 " + m.ruleId() + " 不存在于快照 v"
                                        + report.baselineVersion() + "，出现混合规则集"));
                assertEquals(source.priority(), m.priority());
                assertEquals(source.effect(), m.effect());
            });

            boolean internal = item.reference().startsWith("gcr.internal/");
            assertEquals(expectedBaselineDecision(baselineSnap, internal),
                    item.baseline().decision(),
                    "baseline 结论必须与声明版本快照推导一致，reference=" + item.reference());

            Decision expectedCandidate = internal ? Decision.ALLOW : Decision.DENY;
            assertEquals(expectedCandidate, item.candidate().decision(),
                    "候选侧结论只取决于候选规则，reference=" + item.reference());

            assertEquals(item.baseline().decision() != item.candidate().decision(),
                    item.changed());
            if (item.changed()) {
                changed++;
                if (item.baseline().decision() == Decision.ALLOW) {
                    assertEquals(ChangeDirection.ALLOW_TO_DENY, item.direction());
                    allowToDeny++;
                } else {
                    assertEquals(ChangeDirection.DENY_TO_ALLOW, item.direction());
                    denyToAllow++;
                }
            }
        }
        assertEquals(changed, report.changedCount());
        assertEquals(allowToDeny, report.allowToDenyCount());
        assertEquals(denyToAllow, report.denyToAllowCount());
    }

    /**
     * 依据某版本快照规则推导期望 baseline 结论：
     * live-allow-* 规则 priority=100 高于默认护栏（≤30）且只匹配内部镜像，
     * 因此“内部镜像 + 快照含 live-allow-* 规则”时为 ALLOW，其余情况为 DENY。
     */
    private Decision expectedBaselineDecision(PolicySnapshot snap, boolean internal) {
        boolean hasLiveAllow = snap.rules().stream()
                .anyMatch(r -> r.id().startsWith("live-allow-"));
        return (internal && hasLiveAllow) ? Decision.ALLOW : Decision.DENY;
    }

    /** 并发相同预演请求（同幂等键）只允许产生一条预演审计，且所有调用拿到一致结论。 */
    @Test
    void concurrentIdenticalRehearsalsDeduplicatedInAudit() throws Exception {
        int threads = 10;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch gate = new CountDownLatch(1);
        List<Future<RehearsalReport>> futures = new ArrayList<>();
        String key = "conc-same-rehearse-" + System.nanoTime();
        long before = auditService.recent(100_000).stream()
                .filter(r -> "POLICY_REHEARSE".equals(r.action())).count();

        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                gate.await();
                return batchService.rehearse(reader, mixedBatch(), candidate(), key);
            }));
        }
        gate.countDown();
        Set<Integer> distinctChanged = ConcurrentHashMap.newKeySet();
        for (Future<RehearsalReport> f : futures) {
            distinctChanged.add(f.get().changedCount());
        }
        pool.shutdown();
        long after = auditService.recent(100_000).stream()
                .filter(r -> "POLICY_REHEARSE".equals(r.action())).count();

        assertEquals(1, distinctChanged.size(), "并发相同预演的变化数量必须完全一致");
        assertEquals(before + 1, after, "并发重复预演只允许产生一条审计记录");
        log.info("[并发预演-幂等] {} 个相同请求 changedCount 集合={}（应只有1值），审计 {} -> {}（仅+1）",
                threads, distinctChanged, before, after);
    }
}
