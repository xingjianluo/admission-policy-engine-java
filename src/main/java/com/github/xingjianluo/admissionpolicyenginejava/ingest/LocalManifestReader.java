package com.github.xingjianluo.admissionpolicyenginejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.admissionpolicyenginejava.exception.IngestException;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageMetadata;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 读取本地镜像清单，支持两种格式：
 * <ul>
 *   <li>docker-v2：application/vnd.docker.distribution.manifest.v2+json 风格</li>
 *   <li>oci-index：application/vnd.oci.image.index.v1+json 风格</li>
 * </ul>
 * 本地文件在标准清单之外附带 reference / labels 字段用于定位与策略匹配。
 */
@Component
public class LocalManifestReader {

    private static final Set<String> SUPPORTED_FORMATS = Set.of("docker-v2", "oci-index");
    private static final String DEFAULT_REGISTRY = "docker.io";

    private final ObjectMapper objectMapper = new ObjectMapper();

    public ImageMetadata read(Path file) {
        JsonNode root = parseJson(file);
        String format = textOrNull(root.get("format"));
        if (format == null || !SUPPORTED_FORMATS.contains(format)) {
            throw new IngestException(IngestFailureReason.UNSUPPORTED_MANIFEST_FORMAT,
                    file.toString(),
                    "unsupported manifest format: " + format
                            + ", supported=" + SUPPORTED_FORMATS);
        }

        String reference = requireTextField(root, "reference", file);
        String digest = requireDigest(root.get("digest"), file);

        List<String> mediaTypes = new ArrayList<>();
        mediaTypes.add(switch (format) {
            case "docker-v2" -> "application/vnd.docker.distribution.manifest.v2+json";
            default -> "application/vnd.oci.image.index.v1+json";
        });
        JsonNode mt = root.get("mediaTypes");
        if (mt != null && mt.isArray()) {
            mt.forEach(n -> mediaTypes.add(n.asText()));
        }

        Map<String, String> labels = new LinkedHashMap<>();
        JsonNode labelsNode = root.get("labels");
        if (labelsNode != null && labelsNode.isObject()) {
            labelsNode.fields().forEachRemaining(e -> labels.put(e.getKey(), e.getValue().asText()));
        }

        String[] parts = splitReference(reference);
        return new ImageMetadata(reference, digest, parts[0], parts[1], parts[2],
                List.copyOf(mediaTypes), Map.copyOf(labels));
    }

    /** 将 name:tag 引用拆成 registry / repository / tag。 */
    private String[] splitReference(String reference) {
        String remainder = reference;
        String registry = DEFAULT_REGISTRY;
        int slash = reference.indexOf('/');
        if (slash > 0 && (reference.startsWith("localhost")
                || reference.substring(0, slash).contains(".")
                || reference.substring(0, slash).contains(":"))) {
            registry = reference.substring(0, slash);
            remainder = reference.substring(slash + 1);
        }
        int colon = remainder.lastIndexOf(':');
        String repository;
        String tag;
        if (colon < 0) {
            repository = remainder;
            tag = "latest";
        } else {
            repository = remainder.substring(0, colon);
            tag = remainder.substring(colon + 1);
        }
        if (repository.isBlank()) {
            throw new IngestException(IngestFailureReason.MISSING_REQUIRED_FIELD,
                    reference, "repository part is empty");
        }
        return new String[]{registry, repository, tag};
    }

    JsonNode parseJson(Path file) {
        if (file == null || !Files.isReadable(file)) {
            throw new IngestException(IngestFailureReason.UNREADABLE_FILE,
                    file == null ? null : file.toString(), "file not found or unreadable");
        }
        try {
            return objectMapper.readTree(Files.readString(file));
        } catch (IOException e) {
            throw new IngestException(IngestFailureReason.MALFORMED_JSON,
                    file.toString(), e.getMessage());
        }
    }

    private String requireTextField(JsonNode root, String field, Path file) {
        JsonNode node = root.get(field);
        if (node == null || node.isNull() || node.asText().isBlank()) {
            throw new IngestException(IngestFailureReason.MISSING_REQUIRED_FIELD,
                    file.toString(), "required field '" + field + "' is missing or blank");
        }
        return node.asText();
    }

    private String requireDigest(JsonNode node, Path file) {
        if (node == null || node.isNull() || node.asText().isBlank()) {
            throw new IngestException(IngestFailureReason.MISSING_REQUIRED_FIELD,
                    file.toString(), "required field 'digest' is missing");
        }
        String digest = node.asText();
        if (!digest.startsWith("sha256:") || digest.length() != 7 + 64) {
            throw new IngestException(IngestFailureReason.ILLEGAL_DIGEST_FORMAT,
                    file.toString(), "digest must be sha256:<64 hex chars>: " + digest);
        }
        return digest;
    }

    static String textOrNull(JsonNode node) {
        return node == null || node.isNull() ? null : node.asText();
    }
}
