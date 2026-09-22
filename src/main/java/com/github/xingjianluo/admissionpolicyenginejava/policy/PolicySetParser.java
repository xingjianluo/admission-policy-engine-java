package com.github.xingjianluo.admissionpolicyenginejava.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.admissionpolicyenginejava.exception.IngestException;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestFailureReason;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicySet;
import com.github.xingjianluo.admissionpolicyenginejava.model.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 策略文件解析器。策略文件形如：
 * <pre>
 * {
 *   "schemaVersion": 1,
 *   "rules": [
 *     {"id":"...","name":"...","effect":"ALLOW|DENY","priority":10,
 *      "registries":["..."],"repositoryPattern":".*","sourceUris":[...],
 *      "builderIds":[...],"maxAllowedSeverity":"MEDIUM","minSlsaLevel":3,
 *      "description":"..."}
 *   ]
 * }
 * </pre>
 * 兼容范围：[PolicySet.MIN_SUPPORTED_SCHEMA, PolicySet.CURRENT_SCHEMA]。
 */
@Component
public class PolicySetParser {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public ParsedPolicySet parse(String json) {
        JsonNode root;
        try {
            root = objectMapper.readTree(json);
        } catch (Exception e) {
            throw new IngestException(IngestFailureReason.MALFORMED_JSON,
                    "policy", e.getMessage());
        }
        if (root == null || !root.isObject()) {
            throw new IngestException(IngestFailureReason.MALFORMED_JSON,
                    "policy", "policy document must be a JSON object");
        }
        JsonNode schemaNode = root.get("schemaVersion");
        if (schemaNode == null || !schemaNode.canConvertToInt()) {
            throw new IngestException(IngestFailureReason.MISSING_REQUIRED_FIELD,
                    "policy", "integer field 'schemaVersion' is required");
        }
        int schemaVersion = schemaNode.asInt();
        if (!PolicySet.isSchemaSupported(schemaVersion)) {
            throw new IngestException(IngestFailureReason.ILLEGAL_ENUM_VALUE,
                    "policy",
                    "schemaVersion " + schemaVersion + " is outside supported range ["
                            + PolicySet.MIN_SUPPORTED_SCHEMA + ", "
                            + PolicySet.CURRENT_SCHEMA + "]");
        }

        JsonNode rulesNode = root.get("rules");
        if (rulesNode == null || !rulesNode.isArray()) {
            throw new IngestException(IngestFailureReason.MISSING_REQUIRED_FIELD,
                    "policy", "array field 'rules' is required");
        }

        List<PolicyRule> rules = new ArrayList<>();
        Set<String> seenIds = new HashSet<>();
        int i = 0;
        for (JsonNode r : rulesNode) {
            String where = "rules[" + i + "]";
            String id = requireText(r, "id", where);
            if (!seenIds.add(id)) {
                throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                        "policy", where + " duplicate rule id '" + id + "'");
            }
            String name = requireText(r, "name", where);
            PolicyEffect effect = parseEffect(requireText(r, "effect", where), where);
            JsonNode priorityNode = r.get("priority");
            if (priorityNode == null || !priorityNode.canConvertToInt()) {
                throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                        "policy", where + " integer field 'priority' is required");
            }
            int priority = priorityNode.asInt();

            List<String> registries = readStringList(r.get("registries"), where, "registries");
            List<String> sourceUris = readStringList(r.get("sourceUris"), where, "sourceUris");
            List<String> builderIds = readStringList(r.get("builderIds"), where, "builderIds");

            Pattern repositoryPattern = null;
            JsonNode patternNode = r.get("repositoryPattern");
            if (patternNode != null && !patternNode.isNull()) {
                try {
                    repositoryPattern = Pattern.compile(patternNode.asText());
                } catch (PatternSyntaxException e) {
                    throw new IngestException(IngestFailureReason.ILLEGAL_ENUM_VALUE,
                            "policy",
                            where + " invalid repositoryPattern: " + e.getMessage());
                }
            }

            Severity maxSeverity = null;
            JsonNode sevNode = r.get("maxAllowedSeverity");
            if (sevNode != null && !sevNode.isNull()) {
                try {
                    maxSeverity = Severity.valueOf(sevNode.asText().trim().toUpperCase());
                } catch (IllegalArgumentException e) {
                    throw new IngestException(IngestFailureReason.ILLEGAL_ENUM_VALUE,
                            "policy",
                            where + " unknown maxAllowedSeverity '" + sevNode.asText() + "'");
                }
            }

            Severity denyAtLeast = null;
            JsonNode denyAtLeastNode = r.get("denyIfSeverityAtLeast");
            if (denyAtLeastNode != null && !denyAtLeastNode.isNull()) {
                try {
                    denyAtLeast = Severity.valueOf(
                            denyAtLeastNode.asText().trim().toUpperCase());
                } catch (IllegalArgumentException e) {
                    throw new IngestException(IngestFailureReason.ILLEGAL_ENUM_VALUE,
                            "policy",
                            where + " unknown denyIfSeverityAtLeast '"
                                    + denyAtLeastNode.asText() + "'");
                }
            }

            Integer minSlsa = null;
            JsonNode slsaNode = r.get("minSlsaLevel");
            if (slsaNode != null && !slsaNode.isNull()) {
                if (!slsaNode.canConvertToInt()) {
                    throw new IngestException(IngestFailureReason.ILLEGAL_ENUM_VALUE,
                            "policy", where + " minSlsaLevel must be an integer");
                }
                minSlsa = slsaNode.asInt();
            }

            JsonNode descNode = r.get("description");
            String description = descNode == null ? "" : descNode.asText();

            rules.add(new PolicyRule(id, name, effect, priority, registries,
                    repositoryPattern, sourceUris, builderIds, maxSeverity,
                    denyAtLeast, minSlsa, description));
            i++;
        }
        return new ParsedPolicySet(schemaVersion, List.copyOf(rules));
    }

    private String requireText(JsonNode node, String field, String where) {
        JsonNode value = node == null ? null : node.get(field);
        if (value == null || value.isNull() || value.asText().isBlank()) {
            throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                    "policy", where + " missing field '" + field + "'");
        }
        return value.asText();
    }

    private List<String> readStringList(JsonNode node, String where, String field) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (!node.isArray()) {
            throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                    "policy", where + " field '" + field + "' must be an array");
        }
        List<String> result = new ArrayList<>();
        for (JsonNode item : node) {
            if (item == null || item.asText().isBlank()) {
                throw new IngestException(IngestFailureReason.INCOMPLETE_ENTRY,
                        "policy", where + " field '" + field + "' contains blank item");
            }
            result.add(item.asText());
        }
        return result;
    }

    private PolicyEffect parseEffect(String raw, String where) {
        try {
            return PolicyEffect.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IngestException(IngestFailureReason.ILLEGAL_ENUM_VALUE,
                    "policy", where + " effect must be ALLOW or DENY, got '" + raw + "'");
        }
    }

    /**
     * 解析结果（不含版本号，版本号由存储分配）。
     */
    public record ParsedPolicySet(int schemaVersion, List<PolicyRule> rules) {
    }
}
