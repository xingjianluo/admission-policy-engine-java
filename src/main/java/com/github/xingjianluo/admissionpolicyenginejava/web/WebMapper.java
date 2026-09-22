package com.github.xingjianluo.admissionpolicyenginejava.web;

import com.github.xingjianluo.admissionpolicyenginejava.error.AdmissionException;
import com.github.xingjianluo.admissionpolicyenginejava.error.ErrorCode;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.ArtifactKind;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.ingest.RawArtifact;
import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.model.PolicyEffect;
import com.github.xingjianluo.admissionpolicyenginejava.policy.ConditionType;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyCondition;
import com.github.xingjianluo.admissionpolicyenginejava.policy.PolicyRule;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.ArtifactDto;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.CallerDto;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.ConditionDto;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.EvaluateRequest;
import com.github.xingjianluo.admissionpolicyenginejava.web.dto.WebDtos.RuleDto;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/** Web DTO 与领域对象之间的转换，集中处理请求级字段校验。 */
final class WebMapper {

    private WebMapper() {
    }

    static Caller toCaller(CallerDto dto) {
        if (dto == null || dto.name() == null || dto.name().isBlank()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "缺少调用方身份 caller.name");
        }
        return new Caller(dto.name(),
                dto.roles() == null ? new HashSet<>() : new HashSet<>(dto.roles()));
    }

    static IngestionRequest toIngestion(EvaluateRequest req) {
        if (req == null) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "请求体为空");
        }
        if (req.artifacts() == null || req.artifacts().isEmpty()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "artifacts 不能为空");
        }
        List<RawArtifact> raw = new ArrayList<>(req.artifacts().size());
        for (ArtifactDto a : req.artifacts()) {
            if (a == null || a.kind() == null) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST, "工件缺少 kind");
            }
            final ArtifactKind kind;
            try {
                kind = ArtifactKind.valueOf(a.kind().trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                        "未知工件类别 kind=" + a.kind());
            }
            raw.add(new RawArtifact(kind, a.format(), a.content()));
        }
        return new IngestionRequest(req.reference(), List.copyOf(raw));
    }

    static List<PolicyRule> toRules(List<RuleDto> rules) {
        if (rules == null || rules.isEmpty()) {
            throw new AdmissionException(ErrorCode.INVALID_REQUEST, "rules 不能为空");
        }
        List<PolicyRule> out = new ArrayList<>(rules.size());
        for (RuleDto r : rules) {
            if (r.id() == null || r.id().isBlank()) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST, "规则缺少 id");
            }
            final PolicyEffect effect;
            try {
                effect = PolicyEffect.valueOf(r.effect() == null ? ""
                        : r.effect().trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                        "规则 " + r.id() + " 的 effect 必须为 ALLOW/DENY");
            }
            List<PolicyCondition> conditions = new ArrayList<>();
            if (r.conditions() != null) {
                for (ConditionDto c : r.conditions()) {
                    if (c == null || c.type() == null || c.type().isBlank()) {
                        throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                                "规则 " + r.id() + " 存在缺少 type 的条件");
                    }
                    final ConditionType type;
                    try {
                        type = ConditionType.valueOf(c.type().trim().toUpperCase());
                    } catch (IllegalArgumentException e) {
                        throw new AdmissionException(ErrorCode.INVALID_REQUEST,
                                "规则 " + r.id() + " 的条件类型无法识别: " + c.type());
                    }
                    conditions.add(new PolicyCondition(type, blankToNull(c.value())));
                }
            }
            out.add(new PolicyRule(
                    r.id(),
                    r.priority() == null ? 0 : r.priority(),
                    effect,
                    r.schemaVersion() == null ? 1 : r.schemaVersion(),
                    List.copyOf(conditions),
                    r.description()));
        }
        return List.copyOf(out);
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}
