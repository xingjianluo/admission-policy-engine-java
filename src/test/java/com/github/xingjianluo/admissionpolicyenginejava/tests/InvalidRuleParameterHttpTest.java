package com.github.xingjianluo.admissionpolicyenginejava.tests;

import com.github.xingjianluo.admissionpolicyenginejava.model.Caller;
import com.github.xingjianluo.admissionpolicyenginejava.service.PolicyAdminService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP 层：条件参数非法时发布与预演入口都返回 4xx（422 POLICY_RULESET_INVALID），
 * 调用方拿到可判断的错误码；并与 401 未授权、200 体内 decision=DENY 清楚区分。
 */
@SpringBootTest
@AutoConfigureMockMvc
class InvalidRuleParameterHttpTest {

    @Autowired
    private MockMvc mvc;
    @Autowired
    private PolicyAdminService adminService;

    private final Caller admin = new Caller("http-admin", Set.of("ADMIN"));

    @AfterEach
    void restoreDefaultPolicy() {
        adminService.rollback(admin, 1L);
    }

    private static final String ITEM = """
            {"reference":"gcr.internal/team-i/app:1.0","artifacts":[
              {"kind":"MANIFEST","format":"OCI-MANIFEST","content":"{\\"digest\\":\\"sha256:http0001\\",\\"config\\":{\\"digest\\":\\"sha256:http0001\\"},\\"annotations\\":{\\"io.xj.registry\\":\\"gcr.internal\\",\\"io.xj.repository\\":\\"team-i/app\\"}}"},
              {"kind":"VULN_SCAN","format":"CYCLONEDX-JSON","content":"{\\"digest\\":\\"sha256:http0001\\",\\"vulnerabilities\\":[]}"}]}
            """;

    @Test
    void publishInvalidSeverityReturns422RuleSetInvalidAndNoNewVersion() throws Exception {
        long before = adminService.current(admin).version();
        String body = """
                {"caller":{"name":"http-admin","roles":["ADMIN"]},"expectedBaseVersion":%d,
                 "rules":[{"id":"bad-sev","priority":10,"effect":"DENY","schemaVersion":1,
                           "conditions":[{"type":"SEVERITY_AT_LEAST","value":"URGENT"}]}]}
                """.formatted(before);
        mvc.perform(post("/api/policies/update").contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("POLICY_RULESET_INVALID"))
                .andExpect(jsonPath("$.message").exists());
        org.junit.jupiter.api.Assertions.assertEquals(before,
                adminService.current(admin).version(), "被拒发布不得推进版本");
    }

    @Test
    void publishMissingParameterReturns422RuleSetInvalid() throws Exception {
        long before = adminService.current(admin).version();
        // value 缺省（null）→ 需要参数的 REGISTRY_EQUALS 缺参数
        String body = """
                {"caller":{"name":"http-admin","roles":["ADMIN"]},"expectedBaseVersion":%d,
                 "rules":[{"id":"missing-value","priority":10,"effect":"ALLOW","schemaVersion":1,
                           "conditions":[{"type":"REGISTRY_EQUALS"}]}]}
                """.formatted(before);
        mvc.perform(post("/api/policies/update").contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("POLICY_RULESET_INVALID"));
    }

    @Test
    void rehearsalInvalidCandidateReturns422WithoutComparison() throws Exception {
        String body = """
                {"caller":{"name":"http-reader","roles":["READER"]},
                 "items":[%s],
                 "candidateRules":[{"id":"cand-bad","priority":10,"effect":"DENY","schemaVersion":1,
                    "conditions":[{"type":"SEVERITY_AT_LEAST","value":""}]}]}
                """.formatted(ITEM);
        mvc.perform(post("/api/admission/rehearse").contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("POLICY_RULESET_INVALID"))
                .andExpect(jsonPath("$.items").doesNotExist());
    }

    @Test
    void ruleSetInvalid422IsDistinctFromUnauthorized401() throws Exception {
        long before = adminService.current(admin).version();
        String body = """
                {"caller":{"name":"http-guest","roles":["GUEST"]},"expectedBaseVersion":%d,
                 "rules":[{"id":"x","priority":10,"effect":"DENY","schemaVersion":1,
                           "conditions":[{"type":"SEVERITY_AT_LEAST","value":"URGENT"}]}]}
                """.formatted(before);
        // 鉴权先于规则校验：无权限 → 401 UNAUTHORIZED
        mvc.perform(post("/api/policies/update").contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }

    @Test
    void legalSeverityWithWhitespacePublishes200() throws Exception {
        long before = adminService.current(admin).version();
        String body = """
                {"caller":{"name":"http-admin","roles":["ADMIN"]},"expectedBaseVersion":%d,
                 "rules":[{"id":"ok-sev","priority":10,"effect":"DENY","schemaVersion":1,
                           "conditions":[{"type":"SEVERITY_AT_LEAST","value":" high "}]}]}
                """.formatted(before);
        mvc.perform(post("/api/policies/update").contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value((int) before + 1));
    }
}
