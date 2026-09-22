package com.github.xingjianluo.admissionpolicyenginejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.admissionpolicyenginejava.exception.IngestException;
import com.github.xingjianluo.admissionpolicyenginejava.model.ScanReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.Severity;
import com.github.xingjianluo.admissionpolicyenginejava.model.Vulnerability;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * 读取本地漏洞扫描结果，支持两种格式：
 * <ul>
 *   <li>trivy：Results[].Vulnerabilities[]，字段 VulnerabilityID/Severity/PkgName/InstalledVersion</li>
 *   <li>grype：matches[].artifact.name / vulnerability.id / vulnerability.severity</li>
 * </ul>
 * 任何条目字段缺失或级别非法都抛 INCOMPLETE_ENTRY / ILLEGAL_ENUM_VALUE，绝不静默跳过。
 */
@Component
public class LocalScanReportReader {

    private static final Set<String> SUPPORTED_SCANNERS = Set.of("trivy", "grype");

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final LocalManifestReader jsonSupport = new LocalManifestReader();

    public ScanReport read(Path file) {
        JsonNode root = jsonSupport.parseJson(file);
        String scanner = LocalManifestReader.textOrNull(root.get("scanner"));
        if (scanner == null || !SUPPORTED_SCANNERS.contains(scanner)) {
            throw new IngestException(IngestFailureReason.MISSING_REQUIRED_FIELD,
                    file.toString(),
                    "field 'scanner' missing or unsupported: " + scanner
                            + ", supported=" + SUPPORTED_SCANNERS);
        }
        String digest = requireDigest(root.get("imageDigest"), file);

        List<Vulnerability> vulns = new ArrayList<>();
        switch (scanner) {
            case "trivy" -> readTrivy(root, file, vulns);
            case "grype" -> readGrype(root, file, vulns);
            default -> throw new IllegalStateException();
        }
        return new ScanReport(digest, scanner, List.copyOf(vulns));
    }

    private void readTrivy(JsonNode root, Path file, List<Vulnerability> out) {
        JsonNode results = root.get("results");
        if (results == null || !results.isArray()) {
            throw new IngestException(IngestFailureReason.MISSING_REQUIRED_FIELD,
                    file.toString(), "trivy report requires array field 'results'");
        }
        int ri = 0;
        for (JsonNode result : results) {
            JsonNode list = result.get("vulnerabilities");
            if (list == null || !list.isArray()) {
                throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                        file.toString(), "results[" + ri + "] missing 'vulnerabilities' array");
            }
            int vi = 0;
            for (JsonNode v : list) {
                String id = requireEntryText(v, "VulnerabilityID", file,
                        "results[" + ri + "].vulnerabilities[" + vi + "]");
                String pkg = requireEntryText(v, "PkgName", file,
                        "results[" + ri + "].vulnerabilities[" + vi + "]");
                Severity severity = parseSeverity(
                        LocalManifestReader.textOrNull(v.get("Severity")), file,
                        "results[" + ri + "].vulnerabilities[" + vi + "]");
                String fixed = LocalManifestReader.textOrNull(v.get("FixedVersion"));
                out.add(new Vulnerability(id, severity, pkg, fixed));
                vi++;
            }
            ri++;
        }
    }

    private void readGrype(JsonNode root, Path file, List<Vulnerability> out) {
        JsonNode matches = root.get("matches");
        if (matches == null || !matches.isArray()) {
            throw new IngestException(IngestFailureReason.MISSING_REQUIRED_FIELD,
                    file.toString(), "grype report requires array field 'matches'");
        }
        int i = 0;
        for (JsonNode m : matches) {
            JsonNode vulnNode = m.get("vulnerability");
            JsonNode artifact = m.get("artifact");
            String where = "matches[" + i + "]";
            if (vulnNode == null || artifact == null) {
                throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                        file.toString(), where + " requires 'vulnerability' and 'artifact'");
            }
            String id = requireEntryText(vulnNode, "id", file, where + ".vulnerability");
            Severity severity = parseSeverity(
                    LocalManifestReader.textOrNull(vulnNode.get("severity")), file,
                    where + ".vulnerability");
            String pkg = requireEntryText(artifact, "name", file, where + ".artifact");
            JsonNode fixNode = vulnNode.get("fix");
            String fixed = fixNode == null ? null
                    : LocalManifestReader.textOrNull(fixNode.get("versions") != null
                            && fixNode.get("versions").isArray()
                            && fixNode.get("versions").size() > 0
                            ? fixNode.get("versions").get(0) : null);
            out.add(new Vulnerability(id, severity, pkg, fixed));
            i++;
        }
    }

    private String requireEntryText(JsonNode node, String field, Path file, String where) {
        if (node == null) {
            throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                    file.toString(), where + " is missing");
        }
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || value.asText().isBlank()) {
            throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                    file.toString(), where + " missing field '" + field + "'");
        }
        return value.asText();
    }

    private Severity parseSeverity(String raw, Path file, String where) {
        if (raw == null || raw.isBlank()) {
            throw new IngestException(IngestFailureReason.ILLEGAL_ENUM_VALUE,
                    file.toString(), where + " severity is missing");
        }
        try {
            return Severity.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IngestException(IngestFailureReason.ILLEGAL_ENUM_VALUE,
                    file.toString(),
                    where + " unknown severity '" + raw + "'");
        }
    }

    private String requireDigest(JsonNode node, Path file) {
        if (node == null || node.isNull() || node.asText().isBlank()) {
            throw new IngestException(IngestFailureReason.MISSING_REQUIRED_FIELD,
                    file.toString(), "required field 'imageDigest' is missing");
        }
        String digest = node.asText();
        if (!digest.startsWith("sha256:") || digest.length() != 7 + 64) {
            throw new IngestException(IngestFailureReason.ILLEGAL_DIGEST_FORMAT,
                    file.toString(), "imageDigest must be sha256:<64 hex chars>: " + digest);
        }
        return digest;
    }
}
