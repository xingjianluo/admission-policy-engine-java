package com.github.xingjianluo.admissionpolicyenginejava.tests;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 测试夹具：在临时目录构造各类本地输入文件。
 */
final class TestFixtures {

    static final String DIGEST = "sha256:" + "a".repeat(64);
    static final String DIGEST_OTHER = "sha256:" + "b".repeat(64);
    static final String ATTESTATION = "sha256:" + "c".repeat(64);

    private TestFixtures() {
    }

    static Path dir() throws IOException {
        return Files.createTempDirectory("admission-test-");
    }

    static Path write(Path dir, String name, String content) throws IOException {
        Path file = dir.resolve(name);
        Files.writeString(file, content);
        return file;
    }

    static Path manifest(Path dir, String digest) throws IOException {
        return write(dir, "manifest.json", """
                {
                  "format": "docker-v2",
                  "reference": "registry.example.com/library/app:1.0.0",
                  "digest": "%s",
                  "labels": {"app": "demo"}
                }
                """.formatted(digest));
    }

    static Path manifestOci(Path dir, String digest, String reference) throws IOException {
        return write(dir, "manifest-oci.json", """
                {
                  "format": "oci-index",
                  "reference": "%s",
                  "digest": "%s",
                  "mediaTypes": ["application/vnd.oci.image.manifest.v1+json"]
                }
                """.formatted(reference, digest));
    }

    static Path trivyScan(Path dir, String digest, String vulnerabilities) throws IOException {
        return write(dir, "scan.json", """
                {
                  "scanner": "trivy",
                  "imageDigest": "%s",
                  "results": [
                    {"target": "app", "vulnerabilities": %s}
                  ]
                }
                """.formatted(digest, vulnerabilities));
    }

    static String vuln(String id, String severity, String pkg) {
        return """
                {"VulnerabilityID": "%s", "Severity": "%s", "PkgName": "%s", "FixedVersion": "2.0"}
                """.formatted(id, severity, pkg);
    }

    static Path grypeScan(Path dir, String digest, String matches) throws IOException {
        return write(dir, "grype.json", """
                {
                  "scanner": "grype",
                  "imageDigest": "%s",
                  "matches": %s
                }
                """.formatted(digest, matches));
    }

    static String grypeMatch(String id, String severity, String pkg) {
        return """
                {"artifact": {"name": "%s"},
                 "vulnerability": {"id": "%s", "severity": "%s",
                                   "fix": {"versions": ["2.0"]}}}
                """.formatted(pkg, id, severity);
    }

    static Path provenance(Path dir, String imageDigest, int slsaLevel,
                           String sourceUri, String builderId) throws IOException {
        return write(dir, "provenance.json", """
                {
                  "_type": "https://in-toto.io/Statement/v1",
                  "subject": [{"name": "app", "digest": {"sha256": "%s"}}],
                  "predicateType": "https://slsa.dev/provenance/v1",
                  "attestationDigest": "%s",
                  "predicate": {
                    "builder": {"id": "%s"},
                    "buildDefinition": {
                      "externalParameters": {"repository": "%s", "revision": "deadbeef"},
                      "slsaBuildLevel": %d
                    },
                    "materials": ["sha256:%s"]
                  }
                }
                """.formatted(imageDigest.substring("sha256:".length()),
                ATTESTATION, builderId, sourceUri, slsaLevel,
                "d".repeat(64)));
    }

    /** 构造一组默认合法、指纹一致的三文件输入。 */
    static Bundle validBundle(Path dir, String trivySeverity) throws IOException {
        return validBundle(dir, DIGEST, trivySeverity);
    }

    static Bundle validBundle(Path dir, String digest, String trivySeverity) throws IOException {
        Path manifest = manifest(dir, digest);
        Path scan = trivyScan(dir, digest, "[" + vuln("CVE-0001", trivySeverity, "libz") + "]");
        Path provenance = provenance(dir, digest, 3,
                "https://git.example.com/platform/app", "builder-1");
        return new Bundle(manifest, scan, provenance);
    }

    record Bundle(Path manifest, Path scan, Path provenance) {
    }
}
