package com.github.xingjianluo.admissionpolicyenginejava.web.dto;

import java.util.List;

/** Web 层请求/响应 DTO 的聚合定义（全部为不可变 record）。 */
public final class WebDtos {

    private WebDtos() {
    }

    public record CallerDto(String name, List<String> roles) {
    }

    public record ArtifactDto(String kind, String format, String content) {
    }

    public record EvaluateRequest(
            String idempotencyKey,
            CallerDto caller,
            String reference,
            List<ArtifactDto> artifacts
    ) {
    }

    public record ConditionDto(String type, String value) {
    }

    public record RuleDto(
            String id,
            Integer priority,
            String effect,
            Integer schemaVersion,
            List<ConditionDto> conditions,
            String description
    ) {
    }

    public record UpdatePolicyRequest(
            CallerDto caller,
            Long expectedBaseVersion,
            String comment,
            List<RuleDto> rules
    ) {
    }

    public record RollbackRequest(CallerDto caller, Long targetVersion) {
    }

    /** 批量评估/预演中的单个镜像项（与单镜像评估同构）。 */
    public record BatchItemDto(String reference, List<ArtifactDto> artifacts) {
    }

    public record BatchEvaluateRequest(
            String idempotencyKey,
            CallerDto caller,
            List<BatchItemDto> items
    ) {
    }

    public record RehearseRequest(
            String idempotencyKey,
            CallerDto caller,
            List<BatchItemDto> items,
            List<RuleDto> candidateRules
    ) {
    }

    public record ApiError(String code, String message, String timestamp) {
    }
}
