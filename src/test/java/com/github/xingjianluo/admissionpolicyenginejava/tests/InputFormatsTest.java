package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.auth.ActorContext;
import com.github.xingjianluo.admissionpolicyenginejava.auth.Role;
import com.github.xingjianluo.admissionpolicyenginejava.model.Decision;
import com.github.xingjianluo.admissionpolicyenginejava.model.EvaluationResult;
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

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 多种本地输入格式测试：docker-v2 / oci-index 清单，trivy / grype 扫描结果。
 * 相同语义的输入无论来源格式，判定结论必须一致。
 */
@SpringBootTest
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
class InputFormatsTest {

    private static final Logger log = LoggerFactory.getLogger(InputFormatsTest.class);

    @Autowired
    private AdmissionService service;

    private final ActorContext admin = new ActorContext("admin-5", Role.ADMIN);

    @Test
    void trivyAndGrypeProduceSameDecision(@TempDir Path dir) throws Exception {
        // trivy 格式
        Path dirA = dir.resolve("a");
        java.nio.file.Files.createDirectories(dirA);
        Path m1 = TestFixtures.manifest(dirA, TestFixtures.DIGEST);
        Path s1 = TestFixtures.trivyScan(dirA, TestFixtures.DIGEST,
                "[" + TestFixtures.vuln("CVE-1", "MEDIUM", "libz") + "]");
        Path p1 = TestFixtures.provenance(dirA, TestFixtures.DIGEST, 3,
                "https://git.example.com/platform/app", "builder-1");

        // grype 格式
        Path dirB = dir.resolve("b");
        java.nio.file.Files.createDirectories(dirB);
        Path m2 = TestFixtures.manifest(dirB, TestFixtures.DIGEST);
        Path s2 = TestFixtures.grypeScan(dirB, TestFixtures.DIGEST,
                "[" + TestFixtures.grypeMatch("CVE-1", "Medium", "libz") + "]");
        Path p2 = TestFixtures.provenance(dirB, TestFixtures.DIGEST, 3,
                "https://git.example.com/platform/app", "builder-1");

        EvaluationResult trivy = service.evaluate(admin, "req-fmt-trivy", m1, s1, p1);
        EvaluationResult grype = service.evaluate(admin, "req-fmt-grype", m2, s2, p2);

        log.info("[CASE] trivy decision={} decisive={}", trivy.decision(), trivy.decisiveRuleId());
        log.info("[CASE] grype decision={} decisive={}", grype.decision(), grype.decisiveRuleId());

        assertEquals(trivy.decision(), grype.decision());
        assertEquals(trivy.decisiveRuleId(), grype.decisiveRuleId());
    }

    @Test
    void ociIndexManifestIsAccepted(@TempDir Path dir) throws Exception {
        Path manifest = TestFixtures.manifestOci(dir, TestFixtures.DIGEST,
                "registry.example.com/platform/svc:2.3");
        Path scan = TestFixtures.grypeScan(dir, TestFixtures.DIGEST,
                "[" + TestFixtures.grypeMatch("CVE-7", "Low", "openssl") + "]");
        Path provenance = TestFixtures.provenance(dir, TestFixtures.DIGEST, 3,
                "https://git.example.com/platform/svc", "builder-1");

        EvaluationResult result = service.evaluate(admin, "req-fmt-oci",
                manifest, scan, provenance);
        log.info("[CASE] oci-index decision={} hits={}", result.decision(),
                result.hits().stream().map(h -> h.ruleId()).toList());
        assertEquals(Decision.ALLOW, result.decision());
    }
}
