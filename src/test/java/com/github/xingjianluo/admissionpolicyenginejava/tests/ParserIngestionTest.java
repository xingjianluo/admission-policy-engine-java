package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactKind;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.DefaultArtifactParser;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.RawArtifact;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 工件摄入测试：多种本地格式解析 + 字段缺失/指纹不一致/格式不完整的可区分拒绝原因。
 */
class ParserIngestionTest {

    private static final Logger log = LoggerFactory.getLogger(ParserIngestionTest.class);

    private final DefaultArtifactParser parser = new DefaultArtifactParser();

    static final String MANIFEST = """
            {
              "schemaVersion": 2,
              "mediaType": "application/vnd.oci.image.manifest.v1+json",
              "digest": "sha256:abc123",
              "config": { "digest": "sha256:abc123" },
              "annotations": {
                "io.xj.registry": "gcr.internal",
                "io.xj.repository": "team-a/app",
                "io.xj.tag": "1.0.0"
              }
            }
            """;

    static final String SCAN = """
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.5",
              "digest": "sha256:abc123",
              "vulnerabilities": [
                { "id": "CVE-2026-0001", "ratings": [ { "severity": "high" } ],
                  "affects": [ { "ref": "pkg:maven/log4j" } ] },
                { "id": "CVE-2026-0002", "ratings": [ { "severity": "low" } ],
                  "affects": [ { "ref": "pkg:maven/guava" } ] }
              ]
            }
            """;

    static final String PROVENANCE = """
            {
              "_type": "https://in-toto.io/Statement/v0.1",
              "subjectDigest": "sha256:abc123",
              "predicateType": "https://slsa.dev/provenance/v1",
              "predicate": {
                "builder": { "id": "pkg:internal/ci-builder@v2" },
                "invocation": { "configSource": {
                  "uri": "git+https://git.internal/team-a/app",
                  "digest": "sha1:deadbeef" } },
                "materials": [ { "uri": "pkg:generic/base@1" } ]
              }
            }
            """;

    static final String SIGNATURE = """
            { "subjectDigest": "sha256:abc123", "verified": true, "signer": "ci@internal" }
            """;

    @Test
    void parsesAllJsonFormatsIntoUnifiedDescriptor() {
        IngestionRequest req = new IngestionRequest("gcr.internal/team-a/app:1.0.0", List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", MANIFEST),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", SCAN),
                new RawArtifact(ArtifactKind.PROVENANCE, "SLSA-V1-JSON", PROVENANCE),
                new RawArtifact(ArtifactKind.SIGNATURE, "SIGNOTE-JSON", SIGNATURE)));

        ImageDescriptor d = parser.parse(req);

        log.info("[摄入-正常] 统一评估输入: reference={} digest={} registry={} repository={} "
                        + "vulnerabilities={} provenanceBuilder={} sourceUri={} signatureValid={}",
                d.reference(), d.digest(), d.registry(), d.repository(),
                d.vulnerabilities().stream().map(v -> v.id() + ":" + v.severity()).toList(),
                d.provenance().builderId(), d.provenance().sourceUri(), d.signatureValid());

        assertEquals("sha256:abc123", d.digest());
        assertEquals("gcr.internal", d.registry());
        assertEquals("team-a/app", d.repository());
        assertEquals(2, d.vulnerabilities().size());
        assertEquals("pkg:internal/ci-builder@v2", d.provenance().builderId());
        assertEquals(Boolean.TRUE, d.signatureValid());
        assertEquals("git+https://git.internal/team-a/app", d.provenance().sourceUri());
        assertEquals("sha1:deadbeef", d.provenance().sourceRevision());
        assertTrue(d.provenance().materials().contains("pkg:generic/base@1"));
    }

    @Test
    void parsesPropertiesFormatsAndToleratesMissingOptionalArtifacts() {
        String simpleManifest = """
                digest=sha256:def456
                registry=gcr.internal
                repository=team-b/web
                tag=2.3
                """;
        String simpleScan = """
                digest=sha256:def456
                vulnerability.ids=CVE-9001,CVE-9002
                vulnerability.severity.1=medium
                vulnerability.severity.2=critical
                vulnerability.package.1=openssl
                vulnerability.package.2=curl
                """;
        IngestionRequest req = new IngestionRequest("gcr.internal/team-b/web:2.3", List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "SIMPLE-MANIFEST", simpleManifest),
                new RawArtifact(ArtifactKind.VULN_SCAN, "SIMPLE-SCAN", simpleScan)));

        ImageDescriptor d = parser.parse(req);
        log.info("[摄入-simple格式] digest={} vulns={} provenance={} signature={}",
                d.digest(),
                d.vulnerabilities().stream().map(v -> v.id() + ":" + v.severity()).toList(),
                d.provenance(), d.signatureValid());

        assertEquals("sha256:def456", d.digest());
        assertEquals(2, d.vulnerabilities().size());
        assertNull(d.provenance(), "未提供 provenance 工件时应为 null（不静默伪造）");
        assertNull(d.signatureValid(), "未提供签名工件时应为 null");
    }

    @Test
    void malformedJsonIsClassifiedAsMalformedArtifact() {
        RawArtifact bad = new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST",
                "{ this is not json ]");
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> parser.parse(new IngestionRequest("x/y:1", List.of(bad))));
        assertEquals(ErrorCode.MALFORMED_ARTIFACT, ex.getCode());
        log.info("[摄入-畸形JSON] 正确归类 errorCode={} message={}", ex.getCode(), ex.getMessage());
    }

    @Test
    void unsupportedFormatIsRejectedNotSkipped() {
        RawArtifact bad = new RawArtifact(ArtifactKind.MANIFEST, "UNKNOWN-XML", MANIFEST);
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> parser.parse(new IngestionRequest("x/y:1", List.of(bad))));
        assertEquals(ErrorCode.MALFORMED_ARTIFACT, ex.getCode());
        assertTrue(ex.getMessage().contains("不受支持"));
        log.info("[摄入-未知格式] 正确归类 errorCode={} message={}", ex.getCode(), ex.getMessage());
    }

    @Test
    void missingRequiredFieldIsClassifiedDistinctly() {
        // 缺 annotations.registry
        String manifest = """
                { "schemaVersion": 2, "digest": "sha256:abc123",
                  "annotations": { "io.xj.repository": "team-a/app" } }
                """;
        RawArtifact a = new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", manifest);
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> parser.parse(new IngestionRequest("x:1", List.of(a))));
        assertEquals(ErrorCode.MISSING_REQUIRED_FIELD, ex.getCode());
        log.info("[摄入-缺字段] 正确归类 errorCode={} message={}", ex.getCode(), ex.getMessage());
    }

    @Test
    void fingerprintMismatchIsRejectedNotSilentlyIgnored() {
        String scanOther = SCAN.replace("sha256:abc123", "sha256:zzz999");
        IngestionRequest req = new IngestionRequest("gcr.internal/team-a/app:1.0.0", List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", MANIFEST),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", scanOther)));
        AdmissionException ex = assertThrows(AdmissionException.class, () -> parser.parse(req));
        assertEquals(ErrorCode.FINGERPRINT_MISMATCH, ex.getCode());
        assertTrue(ex.getMessage().contains("不一致"));
        log.info("[摄入-指纹冲突] 正确归类 errorCode={} message={}", ex.getCode(), ex.getMessage());
    }

    @Test
    void missingManifestArtifactIsIncompleteSet() {
        RawArtifact scanOnly = new RawArtifact(ArtifactKind.VULN_SCAN, "SIMPLE-SCAN",
                "digest=sha256:abc123\n");
        AdmissionException ex = assertThrows(AdmissionException.class,
                () -> parser.parse(new IngestionRequest("x:1", List.of(scanOnly))));
        assertEquals(ErrorCode.INCOMPLETE_ARTIFACT_SET, ex.getCode());
        log.info("[摄入-工件不全] 正确归类 errorCode={} message={}", ex.getCode(), ex.getMessage());
    }

    @Test
    void incompleteScanEntryMissingSeverityIsRejected() {
        String scan = """
                { "digest": "sha256:abc123",
                  "vulnerabilities": [ { "id": "CVE-X" } ] }
                """;
        IngestionRequest req = new IngestionRequest("x:1", List.of(
                new RawArtifact(ArtifactKind.MANIFEST, "OCI-MANIFEST", MANIFEST),
                new RawArtifact(ArtifactKind.VULN_SCAN, "CYCLONEDX-JSON", scan)));
        AdmissionException ex = assertThrows(AdmissionException.class, () -> parser.parse(req));
        assertEquals(ErrorCode.MISSING_REQUIRED_FIELD, ex.getCode());
        assertNotNull(ex.getMessage());
        log.info("[摄入-扫描条目不完整] 正确归类 errorCode={} message={}", ex.getCode(),
                ex.getMessage());
    }
}
