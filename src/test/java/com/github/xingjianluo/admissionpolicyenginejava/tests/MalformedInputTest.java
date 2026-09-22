package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.auth.ActorContext;
import com.github.xingjianluo.admissionpolicyenginejava.auth.Role;
import com.github.xingjianluo.admissionpolicyenginejava.exception.ErrorCategory;
import com.github.xingjianluo.admissionpolicyenginejava.exception.IngestException;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestFailureReason;
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
 * 畸形输入测试：字段缺失、指纹不一致、格式不完整均需以可区分原因拒绝，
 * 且错误大类是 INVALID_INPUT，与策略拒绝、未授权区分开。
 */
@SpringBootTest
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
class MalformedInputTest {

    private static final Logger log = LoggerFactory.getLogger(MalformedInputTest.class);

    @Autowired
    private AdmissionService service;

    private final ActorContext admin = new ActorContext("admin-2", Role.ADMIN);

    private IngestException expectReject(String requestId, Path m, Path s, Path p) {
        try {
            service.evaluate(admin, requestId, m, s, p);
            throw new AssertionError("expected IngestException for " + requestId);
        } catch (IngestException e) {
            log.warn("[CASE] request={} category={} reason={} message={}",
                    requestId, e.category(), e.reason(), e.getMessage());
            assertEquals(ErrorCategory.INVALID_INPUT, e.category());
            return e;
        }
    }

    @Test
    void rejectMalformedJson(@TempDir Path dir) throws Exception {
        Path manifest = TestFixtures.write(dir, "bad.json", "{ not-json");
        IngestException e = expectReject("req-bad-1", manifest,
                TestFixtures.validBundle(dir, "LOW").scan(),
                TestFixtures.validBundle(dir, "LOW").provenance());
        assertEquals(IngestFailureReason.MALFORMED_JSON, e.reason());
    }

    @Test
    void rejectUnsupportedManifestFormat(@TempDir Path dir) throws Exception {
        Path manifest = TestFixtures.write(dir, "fmt.json", """
                {"format":"docker-v1-old","reference":"registry.example.com/library/app:1",
                 "digest":"%s"}
                """.formatted(TestFixtures.DIGEST));
        var good = TestFixtures.validBundle(dir, "LOW");
        IngestException e = expectReject("req-bad-2", manifest, good.scan(), good.provenance());
        assertEquals(IngestFailureReason.UNSUPPORTED_MANIFEST_FORMAT, e.reason());
    }

    @Test
    void rejectMissingRequiredField(@TempDir Path dir) throws Exception {
        Path manifest = TestFixtures.write(dir, "nodigest.json", """
                {"format":"docker-v2","reference":"registry.example.com/library/app:1"}
                """);
        var good = TestFixtures.validBundle(dir, "LOW");
        IngestException e = expectReject("req-bad-3", manifest, good.scan(), good.provenance());
        assertEquals(IngestFailureReason.MISSING_REQUIRED_FIELD, e.reason());
    }

    @Test
    void rejectIllegalDigestFormat(@TempDir Path dir) throws Exception {
        Path manifest = TestFixtures.write(dir, "baddigest.json", """
                {"format":"docker-v2","reference":"registry.example.com/library/app:1",
                 "digest":"md5:abc"}
                """);
        var good = TestFixtures.validBundle(dir, "LOW");
        IngestException e = expectReject("req-bad-4", manifest, good.scan(), good.provenance());
        assertEquals(IngestFailureReason.ILLEGAL_DIGEST_FORMAT, e.reason());
    }

    @Test
    void rejectFingerprintMismatch(@TempDir Path dir) throws Exception {
        Path manifest = TestFixtures.manifest(dir, TestFixtures.DIGEST);
        Path scan = TestFixtures.trivyScan(dir, TestFixtures.DIGEST_OTHER,
                "[" + TestFixtures.vuln("CVE-9", "LOW", "x") + "]");
        Path provenance = TestFixtures.provenance(dir, TestFixtures.DIGEST_OTHER, 3,
                "https://git.example.com/platform/app", "builder-1");
        IngestException e = expectReject("req-bad-5", manifest, scan, provenance);
        assertEquals(IngestFailureReason.FINGERPRINT_MISMATCH, e.reason());
    }

    @Test
    void rejectIncompleteVulnerabilityEntry(@TempDir Path dir) throws Exception {
        // 扫描报告中一条漏洞缺少 PkgName：不得静默跳过，必须 INCOMPLETE_ENTRY
        Path manifest = TestFixtures.manifest(dir, TestFixtures.DIGEST);
        Path scan = TestFixtures.write(dir, "incomplete.json", """
                {"scanner":"trivy","imageDigest":"%s",
                 "results":[{"target":"app","vulnerabilities":[
                    {"VulnerabilityID":"CVE-1","Severity":"LOW"}]}
                 ]}
                """.formatted(TestFixtures.DIGEST));
        Path provenance = TestFixtures.provenance(dir, TestFixtures.DIGEST, 3,
                "https://git.example.com/platform/app", "builder-1");
        IngestException e = expectReject("req-bad-6", manifest, scan, provenance);
        assertEquals(IngestFailureReason.INCOMPLETE_ENTRY, e.reason());
    }

    @Test
    void rejectIllegalSeverity(@TempDir Path dir) throws Exception {
        Path manifest = TestFixtures.manifest(dir, TestFixtures.DIGEST);
        Path scan = TestFixtures.write(dir, "badvsev.json", """
                {"scanner":"trivy","imageDigest":"%s",
                 "results":[{"target":"app","vulnerabilities":[
                    {"VulnerabilityID":"CVE-1","Severity":"APOCALYPTIC","PkgName":"x"}]}
                 ]}
                """.formatted(TestFixtures.DIGEST));
        Path provenance = TestFixtures.provenance(dir, TestFixtures.DIGEST, 3,
                "https://git.example.com/platform/app", "builder-1");
        IngestException e = expectReject("req-bad-7", manifest, scan, provenance);
        assertEquals(IngestFailureReason.ILLEGAL_ENUM_VALUE, e.reason());
    }

    @Test
    void rejectProvenanceMissingAttestationDigest(@TempDir Path dir) throws Exception {
        Path manifest = TestFixtures.manifest(dir, TestFixtures.DIGEST);
        Path scan = TestFixtures.trivyScan(dir, TestFixtures.DIGEST,
                "[" + TestFixtures.vuln("CVE-1", "LOW", "x") + "]");
        Path provenance = TestFixtures.write(dir, "prov-noatt.json", """
                {
                  "_type":"https://in-toto.io/Statement/v1",
                  "subject":[{"name":"app","digest":{"sha256":"%s"}}],
                  "predicateType":"https://slsa.dev/provenance/v1",
                  "predicate":{"builder":{"id":"b1"},
                    "buildDefinition":{"externalParameters":{
                      "repository":"https://git.example.com/platform/app","revision":"r1"},
                      "slsaBuildLevel":2}}
                }
                """.formatted("a".repeat(64)));
        IngestException e = expectReject("req-bad-8", manifest, scan, provenance);
        assertEquals(IngestFailureReason.MISSING_REQUIRED_FIELD, e.reason());
    }

    @Test
    void rejectMissingSource(@TempDir Path dir) throws Exception {
        var good = TestFixtures.validBundle(dir, "LOW");
        IngestException e = expectReject("req-bad-9", good.manifest(), good.scan(), null);
        assertEquals(IngestFailureReason.MISSING_SOURCE, e.reason());
    }

    @Test
    void unsupportedSchemaVersionIsRejected(@TempDir Path dir) throws Exception {
        // schemaVersion=99 超出兼容范围，策略更新必须以 INVALID_INPUT 拒绝
        String policy = """
                {"schemaVersion":99,"rules":[]}
                """;
        IngestException e = expectPolicyReject(policy);
        assertEquals(IngestFailureReason.ILLEGAL_ENUM_VALUE, e.reason());
    }

    private IngestException expectPolicyReject(String policyJson) {
        try {
            service.updatePolicy(admin, service.currentPolicy(admin).version(),
                    policyJson, "bad schema");
            throw new AssertionError("expected policy rejection");
        } catch (IngestException e) {
            log.warn("[CASE] policy category={} reason={} message={}",
                    e.category(), e.reason(), e.getMessage());
            assertEquals(ErrorCategory.INVALID_INPUT, e.category());
            return e;
        }
    }
}
