package com.github.xingjianluo.admissionpolicyenginejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.admissionpolicyenginejava.exception.IngestException;
import com.github.xingjianluo.admissionpolicyenginejava.model.Provenance;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 读取本地 SLSA 风格供应链证明（statement 形式）：
 * <pre>
 * {
 *   "_type": "https://in-toto.io/Statement/v1",
 *   "subject": [{"name": "...", "digest": {"sha256": "..."}}],
 *   "predicateType": "https://slsa.dev/provenance/v1",
 *   "predicate": {
 *     "builder": {"id": "..."},
 *     "buildDefinition": {
 *       "externalParameters": {"repository": "...", "revision": "..."},
 *       "slsaBuildLevel": 3
 *     },
 *     "materials": ["sha256:..."]
 *   },
 *   "attestationDigest": "sha256:..."
 * }
 * </pre>
 */
@Component
public class LocalProvenanceReader {

    private static final String STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
    private static final String PREDICATE_TYPE = "https://slsa.dev/provenance/v1";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final LocalManifestReader jsonSupport = new LocalManifestReader();

    public Provenance read(Path file) {
        JsonNode root = jsonSupport.parseJson(file);

        String type = LocalManifestReader.textOrNull(root.get("_type"));
        String predicateType = LocalManifestReader.textOrNull(root.get("predicateType"));
        if (!STATEMENT_TYPE.equals(type) || !PREDICATE_TYPE.equals(predicateType)) {
            throw new IngestException(IngestFailureReason.UNSUPPORTED_MANIFEST_FORMAT,
                    file.toString(),
                    "unsupported provenance statement: _type=" + type
                            + ", predicateType=" + predicateType);
        }

        JsonNode subject = root.get("subject");
        if (subject == null || !subject.isArray() || subject.isEmpty()) {
            throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                    file.toString(), "provenance requires non-empty 'subject' array");
        }
        JsonNode subject0 = subject.get(0);
        JsonNode subjectDigest = subject0.path("digest").get("sha256");
        if (subjectDigest == null || subjectDigest.asText().isBlank()) {
            throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                    file.toString(), "subject[0].digest.sha256 is required");
        }
        String imageDigest = normalizeDigest(subjectDigest.asText(), file, "subject[0].digest");

        String attestationDigest = normalizeDigest(
                LocalManifestReader.textOrNull(root.get("attestationDigest")),
                file, "attestationDigest");

        JsonNode predicate = root.get("predicate");
        if (predicate == null || !predicate.isObject()) {
            throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                    file.toString(), "'predicate' object is required");
        }
        String builderId = requireText(predicate.path("builder"), "id", file, "predicate.builder");

        JsonNode buildDef = predicate.get("buildDefinition");
        if (buildDef == null || !buildDef.isObject()) {
            throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                    file.toString(), "predicate.buildDefinition object is required");
        }
        JsonNode params = buildDef.get("externalParameters");
        if (params == null || !params.isObject()) {
            throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                    file.toString(),
                    "predicate.buildDefinition.externalParameters object is required");
        }
        String sourceUri = requireText(params, "repository", file,
                "predicate.buildDefinition.externalParameters");
        String revision = requireText(params, "revision", file,
                "predicate.buildDefinition.externalParameters");

        JsonNode levelNode = buildDef.get("slsaBuildLevel");
        if (levelNode == null || !levelNode.canConvertToInt()) {
            throw new IngestException(IngestFailureReason.ILLEGAL_ENUM_VALUE,
                    file.toString(), "slsaBuildLevel must be an integer");
        }
        int level = levelNode.asInt();
        if (level < 0 || level > 4) {
            throw new IngestException(IngestFailureReason.ILLEGAL_ENUM_VALUE,
                    file.toString(), "slsaBuildLevel out of range [0,4]: " + level);
        }

        List<String> materials = new ArrayList<>();
        JsonNode materialsNode = predicate.get("materials");
        if (materialsNode != null && materialsNode.isArray()) {
            for (JsonNode m : materialsNode) {
                if (m == null || m.asText().isBlank()) {
                    throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                            file.toString(), "materials contains blank entry");
                }
                materials.add(m.asText());
            }
        }

        return new Provenance(imageDigest, sourceUri, revision, builderId, level,
                attestationDigest, List.copyOf(materials));
    }

    private String requireText(JsonNode node, String field, Path file, String where) {
        JsonNode value = node == null ? null : node.get(field);
        if (value == null || value.isNull() || value.asText().isBlank()) {
            throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                    file.toString(), where + " missing field '" + field + "'");
        }
        return value.asText();
    }

    private String normalizeDigest(String raw, Path file, String where) {
        if (raw == null || raw.isBlank()) {
            throw new IngestException(IngestFailureReason.MISSING_REQUIRED_FIELD,
                    file.toString(), where + " digest is missing");
        }
        String digest = raw.startsWith("sha256:") ? raw : "sha256:" + raw;
        if (digest.length() != 7 + 64) {
            throw new IngestException(IngestFailureReason.ILLEGAL_DIGEST_FORMAT,
                    file.toString(),
                    where + " digest must be sha256:<64 hex chars>: " + raw);
        }
        return digest;
    }
}
