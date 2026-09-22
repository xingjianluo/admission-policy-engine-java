package com.github.xingjianluo.admissionpolicyenginejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;
import com.github.xingjianluo.admissionpolicyenginejava.model.Provenance;
import com.github.xingjianluo.admissionpolicyenginejava.model.Severity;
import com.github.xingjianluo.admissionpolicyenginejava.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * 默认工件解析器。
 * <p>
 * 支持的本地格式：
 * <ul>
 *   <li>清单：{@code OCI-MANIFEST}(JSON)、{@code SIMPLE-MANIFEST}(properties)</li>
 *   <li>扫描：{@code CYCLONEDX-JSON}、{@code SIMPLE-SCAN}(properties)</li>
 *   <li>证明：{@code SLSA-V1-JSON}、{@code SIMPLE-PROVENANCE}(properties)</li>
 *   <li>签名：{@code SIGNOTE-JSON}、{@code SIMPLE-SIGNATURE}(properties)</li>
 * </ul>
 * 错误分类严格区分：
 * <ul>
 *   <li>{@link ErrorCode#MALFORMED_ARTIFACT}：内容无法按声明格式解析；</li>
 *   <li>{@link ErrorCode#MISSING_REQUIRED_FIELD}：可解析但缺必填字段；</li>
 *   <li>{@link ErrorCode#FINGERPRINT_MISMATCH}：工件间 digest 不一致；</li>
 *   <li>{@link ErrorCode#INCOMPLETE_ARTIFACT_SET}：缺少必需工件类别。</li>
 * </ul>
 */
@Component
public class DefaultArtifactParser implements ArtifactParser {

    private static final Logger log = LoggerFactory.getLogger(DefaultArtifactParser.class);
    private static final Set<String> SUPPORTED = Set.of(
            "OCI-MANIFEST", "SIMPLE-MANIFEST",
            "CYCLONEDX-JSON", "SIMPLE-SCAN",
            "SLSA-V1-JSON", "SIMPLE-PROVENANCE",
            "SIGNOTE-JSON", "SIMPLE-SIGNATURE");

    private final ObjectMapper mapper = new ObjectMapper();

    /* ---- 各工件解析得到的片段 ---- */
    private record ManifestFrag(String digest, String reference, String registry,
                                String repository, String tag) {
    }

    private record ScanFrag(String digest, List<Vulnerability> vulnerabilities) {
    }

    private record ProvenanceFrag(String digest, Provenance provenance) {
    }

    private record SignatureFrag(String digest, boolean valid) {
    }

    @Override
    public ImageDescriptor parse(IngestionRequest request) {
        if (request == null) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "评估请求不能为空");
        }
        if (request.reference() == null || request.reference().isBlank()) {
            throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD, "缺少镜像引用 reference");
        }
        List<RawArtifact> artifacts = request.artifacts();
        if (artifacts == null || artifacts.isEmpty()) {
            throw new AdmissionException(ErrorCode.INCOMPLETE_ARTIFACT_SET,
                    "工件集合为空：至少需要一个 MANIFEST 工件");
        }

        // 同类别在一次请求中只允许出现一个：出现多个说明输入不完整/不确定，不能静默丢弃。
        Map<ArtifactKind, RawArtifact> unique = new LinkedHashMap<>();
        for (RawArtifact a : artifacts) {
            if (a == null || a.kind() == null) {
                throw new AdmissionException(ErrorCode.MALFORMED_ARTIFACT,
                        "存在 kind 为空的工件条目");
            }
            if (a.format() == null || !SUPPORTED.contains(a.format())) {
                throw new AdmissionException(ErrorCode.MALFORMED_ARTIFACT,
                        "工件 " + a.kind() + " 的格式 '" + (a == null ? null : a.format())
                                + "' 不受支持，支持: " + SUPPORTED);
            }
            if (a.content() == null || a.content().isBlank()) {
                throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                        "工件 " + a.kind() + "(" + a.format() + ") 内容为空");
            }
            if (unique.put(a.kind(), a) != null) {
                throw new AdmissionException(ErrorCode.INCOMPLETE_ARTIFACT_SET,
                        "工件类别 " + a.kind() + " 在同一请求中出现多次，无法确定唯一来源");
            }
        }
        if (!unique.containsKey(ArtifactKind.MANIFEST)) {
            throw new AdmissionException(ErrorCode.INCOMPLETE_ARTIFACT_SET,
                    "缺少必需工件 MANIFEST（镜像: " + request.reference() + "）");
        }

        ManifestFrag manifest = parseManifest(unique.get(ArtifactKind.MANIFEST));
        ScanFrag scan = unique.containsKey(ArtifactKind.VULN_SCAN)
                ? parseScan(unique.get(ArtifactKind.VULN_SCAN)) : null;
        ProvenanceFrag prov = unique.containsKey(ArtifactKind.PROVENANCE)
                ? parseProvenance(unique.get(ArtifactKind.PROVENANCE)) : null;
        SignatureFrag sig = unique.containsKey(ArtifactKind.SIGNATURE)
                ? parseSignature(unique.get(ArtifactKind.SIGNATURE)) : null;

        // 指纹一致性：所有携带 digest 的工件必须锚定同一个值，绝不静默忽略冲突。
        String anchor = manifest.digest();
        if (anchor == null || anchor.isBlank()) {
            throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                    "清单缺少镜像指纹 digest（镜像: " + request.reference() + "）");
        }
        checkFingerprint("VULN_SCAN", anchor, scan == null ? null : scan.digest());
        checkFingerprint("PROVENANCE", anchor, prov == null ? null : prov.digest());
        checkFingerprint("SIGNATURE", anchor, sig == null ? null : sig.digest());

        ImageDescriptor descriptor = new ImageDescriptor(
                request.reference(),
                anchor,
                manifest.registry(),
                manifest.repository(),
                manifest.tag(),
                scan == null ? List.of() : List.copyOf(scan.vulnerabilities()),
                prov == null ? null : prov.provenance(),
                sig == null ? null : sig.valid());

        log.info("工件摄入成功 reference={} digest={} registry={} repo={} vulns={} provenance={} signature={}",
                descriptor.reference(), descriptor.digest(), descriptor.registry(),
                descriptor.repository(), descriptor.vulnerabilities().size(),
                descriptor.provenance() != null, descriptor.signatureValid());
        return descriptor;
    }

    private void checkFingerprint(String kind, String anchor, String claimed) {
        if (claimed != null && !claimed.isBlank() && !claimed.equals(anchor)) {
            throw new AdmissionException(ErrorCode.FINGERPRINT_MISMATCH,
                    kind + " 声明的指纹 " + claimed + " 与清单锚点指纹 " + anchor + " 不一致");
        }
    }

    // ------------------------------------------------------------------ MANIFEST

    private ManifestFrag parseManifest(RawArtifact a) {
        return switch (a.format()) {
            case "OCI-MANIFEST" -> parseOciManifest(a);
            case "SIMPLE-MANIFEST" -> {
                Properties p = parseProperties(a);
                yield new ManifestFrag(
                        require(p, "digest", a),
                        optional(p, "reference"),
                        require(p, "registry", a),
                        require(p, "repository", a),
                        optional(p, "tag"));
            }
            default -> throw unsupported(a);
        };
    }

    private ManifestFrag parseOciManifest(RawArtifact a) {
        JsonNode root = parseJson(a);
        JsonNode config = root.path("config");
        String digest = firstNonBlank(
                textOrNull(root.get("digest")),
                textOrNull(config.get("digest")),
                root.path("layers").isArray() && root.path("layers").size() > 0
                        ? textOrNull(root.path("layers").get(0).get("digest")) : null);
        if (digest == null) {
            throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                    "OCI 清单缺少 digest（config.digest/layers[0].digest 均缺失）");
        }
        JsonNode ann = root.path("annotations");
        String registry = firstNonBlank(textOrNull(ann.get("io.xj.registry")), null);
        String repository = firstNonBlank(textOrNull(ann.get("io.xj.repository")), null);
        String tag = firstNonBlank(textOrNull(ann.get("io.xj.tag")), null);
        if (registry == null || repository == null) {
            throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                    "OCI 清单 annotations 缺少 io.xj.registry / io.xj.repository");
        }
        return new ManifestFrag(digest, null, registry, repository, tag);
    }

    // ---------------------------------------------------------------------- SCAN

    private ScanFrag parseScan(RawArtifact a) {
        return switch (a.format()) {
            case "SIMPLE-SCAN" -> {
                Properties p = parseProperties(a);
                String digest = require(p, "digest", a);
                List<Vulnerability> vulns = parseSimpleVulns(p);
                yield new ScanFrag(digest, vulns);
            }
            case "CYCLONEDX-JSON" -> {
                JsonNode root = parseJson(a);
                // digest 可选：非清单工件只在声明 digest 时参与指纹一致性校验。
                String digest = textOrNull(root.get("digest"));
                JsonNode vulnNode = root.get("vulnerabilities");
                if (vulnNode == null || !vulnNode.isArray()) {
                    throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                            "CycloneDX 文档缺少 vulnerabilities 数组");
                }
                List<Vulnerability> vulns = new ArrayList<>();
                for (JsonNode v : vulnNode) {
                    String id = textOrNull(v.get("id"));
                    if (id == null) {
                        throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                                "CycloneDX 漏洞条目缺少 id");
                    }
                    String rating = textOrNull(v.path("ratings").isArray()
                            && v.path("ratings").size() > 0
                            ? v.path("ratings").get(0).get("severity") : v.get("severity"));
                    Severity severity = parseSeverity(rating);
                    if (severity == Severity.UNKNOWN) {
                        throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                                "漏洞 " + id + " 缺少可识别的 severity");
                    }
                    String packageName = null;
                    if (v.path("affects").isArray() && v.path("affects").size() > 0) {
                        packageName = textOrNull(v.path("affects").get(0).get("ref"));
                    } else {
                        packageName = textOrNull(v.get("package"));
                    }
                    vulns.add(new Vulnerability(id, severity, packageName));
                }
                yield new ScanFrag(digest, vulns);
            }
            default -> throw unsupported(a);
        };
    }

    private List<Vulnerability> parseSimpleVulns(Properties p) {
        List<Idx> ids = split(p.getProperty("vulnerability.ids"));
        List<Vulnerability> result = new ArrayList<>();
        for (int i = 0; i < ids.size(); i++) {
            // properties 形态把 id/severity/package 压成并行列表；id 行缺失即不完整。
            String id = ids.get(i).id();
            String sevKey = "vulnerability.severity." + (i + 1);
            String sev = p.getProperty(sevKey);
            if (sev == null || sev.isBlank()) {
                throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                        "SIMPLE-SCAN 中漏洞 " + id + " 缺少 " + sevKey);
            }
            Severity severity = parseSeverity(sev.trim());
            if (severity == Severity.UNKNOWN) {
                throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                        "漏洞 " + id + " 的 severity 无法识别: " + sev);
            }
            result.add(new Vulnerability(id, severity, p.getProperty(
                    "vulnerability.package." + (i + 1))));
        }
        return result;
    }

    private record Idx(String id) {
    }

    private List<Idx> split(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        List<Idx> out = new ArrayList<>();
        for (String s : raw.split(",")) {
            String t = s.trim();
            if (!t.isEmpty()) {
                out.add(new Idx(t));
            }
        }
        return out;
    }

    private Severity parseSeverity(String s) {
        if (s == null) {
            return Severity.UNKNOWN;
        }
        try {
            return Severity.valueOf(s.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return Severity.UNKNOWN;
        }
    }

    //--------------------------------------------------------------- PROVENANCE

    private ProvenanceFrag parseProvenance(RawArtifact a) {
        return switch (a.format()) {
            case "SLSA-V1-JSON" -> {
                JsonNode root = parseJson(a);
                String digest = textOrNull(root.get("subjectDigest"));
                JsonNode statement = root.has("predicate") ? root : root;
                String builderId = textOrNull(statement.path("predicate").path("builder")
                        .get("id"));
                if (builderId == null) {
                    builderId = textOrNull(statement.get("builderId"));
                }
                String sourceUri = textOrNull(statement.path("predicate").path("invocation")
                        .path("configSource").get("uri"));
                if (sourceUri == null) {
                    sourceUri = textOrNull(statement.get("sourceUri"));
                }
                String revision = textOrNull(statement.path("predicate").path("invocation")
                        .path("configSource").get("digest"));
                if (revision == null) {
                    revision = textOrNull(statement.get("sourceRevision"));
                }
                if (builderId == null) {
                    throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                            "SLSA 证明缺少 predicate.builder.id");
                }
                if (sourceUri == null) {
                    throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                            "SLSA 证明缺少来源 URI(predicate.invocation.configSource.uri)");
                }
                List<String> materials = new ArrayList<>();
                JsonNode mats = statement.path("predicate").get("materials");
                if (mats != null && mats.isArray()) {
                    mats.forEach(m -> {
                        String uri = textOrNull(m.get("uri"));
                        if (uri != null) {
                            materials.add(uri);
                        }
                    });
                }
                yield new ProvenanceFrag(digest, new Provenance(builderId, sourceUri,
                        revision, List.copyOf(materials), safeJson(root)));
            }
            case "SIMPLE-PROVENANCE" -> {
                Properties p = parseProperties(a);
                String digest = optional(p, "digest");
                String builderId = require(p, "builderId", a);
                String sourceUri = require(p, "sourceUri", a);
                String revision = optional(p, "sourceRevision");
                List<String> materials = split(p.getProperty("materials")).stream()
                        .map(Idx::id).toList();
                yield new ProvenanceFrag(digest, new Provenance(builderId, sourceUri,
                        revision, materials, p.toString()));
            }
            default -> throw unsupported(a);
        };
    }

    //---------------------------------------------------------------- SIGNATURE

    private SignatureFrag parseSignature(RawArtifact a) {
        return switch (a.format()) {
            case "SIGNOTE-JSON" -> {
                JsonNode root = parseJson(a);
                String digest = textOrNull(root.get("subjectDigest"));
                JsonNode verified = root.get("verified");
                if (verified == null || !verified.isBoolean()) {
                    throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                            "SIGNOTE 文档缺少布尔字段 verified");
                }
                yield new SignatureFrag(digest, verified.asBoolean());
            }
            case "SIMPLE-SIGNATURE" -> {
                Properties p = parseProperties(a);
                String digest = optional(p, "digest");
                String verified = require(p, "verified", a);
                if (!"true".equalsIgnoreCase(verified) && !"false".equalsIgnoreCase(verified)) {
                    throw new AdmissionException(ErrorCode.MALFORMED_ARTIFACT,
                            "SIMPLE-SIGNATURE 的 verified 必须为 true/false，实际: " + verified);
                }
                yield new SignatureFrag(digest, Boolean.parseBoolean(verified.trim()));
            }
            default -> throw unsupported(a);
        };
    }

    //--------------------------------------------------------------- utilities

    private JsonNode parseJson(RawArtifact a) {
        try {
            JsonNode node = mapper.readTree(a.content());
            if (node == null || !node.isObject()) {
                throw new AdmissionException(ErrorCode.MALFORMED_ARTIFACT,
                        a.format() + " 内容不是 JSON 对象");
            }
            return node;
        } catch (AdmissionException e) {
            throw e;
        } catch (Exception e) {
            throw new AdmissionException(ErrorCode.MALFORMED_ARTIFACT,
                    a.format() + " JSON 解析失败: " + e.getMessage(), e);
        }
    }

    private Properties parseProperties(RawArtifact a) {
        Properties p = new Properties();
        try {
            p.load(new java.io.StringReader(a.content()));
        } catch (Exception e) {
            throw new AdmissionException(ErrorCode.MALFORMED_ARTIFACT,
                    a.format() + " properties 解析失败: " + e.getMessage(), e);
        }
        return p;
    }

    private String require(Properties p, String key, RawArtifact a) {
        String v = p.getProperty(key);
        if (v == null || v.isBlank()) {
            throw new AdmissionException(ErrorCode.MISSING_REQUIRED_FIELD,
                    a.format() + " 缺少必填字段 '" + key + "'");
        }
        return v.trim();
    }

    private String optional(Properties p, String key) {
        String v = p.getProperty(key);
        return v == null || v.isBlank() ? null : v.trim();
    }

    private String textOrNull(JsonNode node) {
        if (node == null || node.isNull() || !node.isValueNode()) {
            return null;
        }
        String s = node.asText();
        return s == null || s.isBlank() ? null : s.trim();
    }

    private String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v.trim();
            }
        }
        return null;
    }

    private String safeJson(JsonNode root) {
        try {
            return mapper.writeValueAsString(root);
        } catch (Exception e) {
            return "<unserializable>";
        }
    }

    private AdmissionException unsupported(RawArtifact a) {
        return new AdmissionException(ErrorCode.MALFORMED_ARTIFACT,
                a.kind() + " 与格式 " + a.format() + " 不匹配或不受支持");
    }
}
