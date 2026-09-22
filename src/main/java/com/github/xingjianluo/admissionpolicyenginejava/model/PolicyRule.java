package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;
import java.util.regex.Pattern;

/**
 * 单条准入策略规则。
 *
 * <p>所有匹配条件为空表示不限制（通配）；非空条件需全部满足才算命中（AND 语义）。
 * priority 越大优先级越高；同优先级下 DENY 优先于 ALLOW。
 *
 * <p>漏洞级别提供两个相互独立的条件，可分别用于 ALLOW / DENY 规则：
 * <ul>
 *   <li>{@code maxAllowedSeverity}：最高漏洞级别不超过该值才命中（ALLOW 规则常用）；</li>
 *   <li>{@code denyIfSeverityAtLeast}：最高漏洞级别达到或超过该值才命中（DENY 规则常用）。</li>
 * </ul>
 */
public final class PolicyRule {

    private final String id;
    private final String name;
    private final PolicyEffect effect;
    private final int priority;
    private final List<String> registries;
    private final Pattern repositoryPattern;
    private final List<String> sourceUris;
    private final List<String> builderIds;
    private final Severity maxAllowedSeverity;
    private final Severity denyIfSeverityAtLeast;
    private final Integer minSlsaLevel;
    private final String description;

    public PolicyRule(String id,
                      String name,
                      PolicyEffect effect,
                      int priority,
                      List<String> registries,
                      Pattern repositoryPattern,
                      List<String> sourceUris,
                      List<String> builderIds,
                      Severity maxAllowedSeverity,
                      Severity denyIfSeverityAtLeast,
                      Integer minSlsaLevel,
                      String description) {
        this.id = id;
        this.name = name;
        this.effect = effect;
        this.priority = priority;
        this.registries = registries == null ? List.of() : List.copyOf(registries);
        this.repositoryPattern = repositoryPattern;
        this.sourceUris = sourceUris == null ? List.of() : List.copyOf(sourceUris);
        this.builderIds = builderIds == null ? List.of() : List.copyOf(builderIds);
        this.maxAllowedSeverity = maxAllowedSeverity;
        this.denyIfSeverityAtLeast = denyIfSeverityAtLeast;
        this.minSlsaLevel = minSlsaLevel;
        this.description = description;
    }

    public String id() { return id; }
    public String name() { return name; }
    public PolicyEffect effect() { return effect; }
    public int priority() { return priority; }
    public List<String> registries() { return registries; }
    public Pattern repositoryPattern() { return repositoryPattern; }
    public List<String> sourceUris() { return sourceUris; }
    public List<String> builderIds() { return builderIds; }
    public Severity maxAllowedSeverity() { return maxAllowedSeverity; }
    public Severity denyIfSeverityAtLeast() { return denyIfSeverityAtLeast; }
    public Integer minSlsaLevel() { return minSlsaLevel; }
    public String description() { return description; }

    /**
     * 判断规则是否命中给定评估输入。命中时返回非空的依据说明，否则返回 null。
     */
    public String match(ImageMetadata metadata, ScanReport scan, Provenance provenance) {
        if (!registries.isEmpty() && !registries.contains(metadata.registry())) {
            return null;
        }
        if (repositoryPattern != null
                && !repositoryPattern.matcher(metadata.repository()).matches()) {
            return null;
        }
        if (!sourceUris.isEmpty() && !sourceUris.contains(provenance.sourceUri())) {
            return null;
        }
        if (!builderIds.isEmpty() && !builderIds.contains(provenance.builderId())) {
            return null;
        }
        if (minSlsaLevel != null && provenance.buildSlsaLevel() < minSlsaLevel) {
            return null;
        }
        Severity top = scan.vulnerabilities().stream()
                .map(Vulnerability::severity)
                .max(Enum::compareTo)
                .orElse(Severity.UNKNOWN);
        if (maxAllowedSeverity != null && top.compareTo(maxAllowedSeverity) > 0) {
            return null;
        }
        if (denyIfSeverityAtLeast != null && top.compareTo(denyIfSeverityAtLeast) < 0) {
            return null;
        }
        return "rule " + id + " (" + name + ") matched: effect=" + effect
                + ", priority=" + priority;
    }
}
