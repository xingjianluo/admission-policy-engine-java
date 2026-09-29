package com.github.xingjianluo.admissionpolicyenginejava.tests;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 批量评估 / 预演 HTTP 通道测试：
 * 鉴权 401 与策略 DENY(200) 分离、批量上限 400、单项坏输入不拖累整批（仍 200）。
 */
@SpringBootTest
@AutoConfigureMockMvc
class BatchWebApiTest {

    private static final Logger log = LoggerFactory.getLogger(BatchWebApiTest.class);

    @Autowired
    private MockMvc mockMvc;

    private static String manifest(String digest, String registry, String repository) {
        return """
                {
                  "schemaVersion": 2,
                  "digest": "%s",
                  "config": { "digest": "%s" },
                  "annotations": {
                    "io.xj.registry": "%s",
                    "io.xj.repository": "%s",
                    "io.xj.tag": "1.0"
                  }
                }
                """.formatted(digest, digest, registry, repository);
    }

    private static String scan(String digest) {
        return "{ \"digest\": \"" + digest + "\", \"vulnerabilities\": [] }";
    }

    private String goodItemJson(int n) {
        String digest = "sha256:web-good-" + n;
        return """
                { "reference": "gcr.internal/team/web%d:1",
                  "artifacts": [
                    { "kind": "MANIFEST", "format": "OCI-MANIFEST", "content": %s },
                    { "kind": "VULN_SCAN", "format": "CYCLONEDX-JSON", "content": %s }
                  ] }
                """.formatted(n, quote(manifest(digest, "gcr.internal", "team/web" + n)),
                quote(scan(digest)));
    }

    private String badItemJson() {
        return """
                { "reference": "gcr.internal/team/bad:1",
                  "artifacts": [
                    { "kind": "MANIFEST", "format": "BOGUS-FORMAT", "content": "{}" }
                  ] }
                """;
    }

    private String quote(String raw) {
        // 紧凑 JSON 字符串转义（测试夹具均为受控多行 JSON）
        StringBuilder sb = new StringBuilder("\"");
        for (char c : raw.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> { }
                case '\t' -> sb.append("\\t");
                default -> sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    @Test
    void batchEvaluateOverLimitReturns400() throws Exception {
        StringBuilder body = new StringBuilder();
        body.append("{\"idempotencyKey\":\"web-limit\",\"caller\":{\"name\":\"w-reader\",\"roles\":[\"READER\"]},\"items\":[");
        for (int i = 0; i < 51; i++) {
            if (i > 0) {
                body.append(',');
            }
            body.append(goodItemJson(i));
        }
        body.append("]}");

        mockMvc.perform(post("/api/admission/batch-evaluate")
                        .contentType(MediaType.APPLICATION_JSON).content(body.toString()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
                .andExpect(jsonPath("$.message").value(
                        org.hamcrest.Matchers.containsString("50")));
        log.info("[Web-批量上限] 51 项 → 400 INVALID_REQUEST（提示上限 50）");
    }

    @Test
    void batchEvaluateBadItemFlaggedButRestReturn200() throws Exception {
        String body = "{\"idempotencyKey\":\"web-mix-" + System.nanoTime()
                + "\",\"caller\":{\"name\":\"w-reader\",\"roles\":[\"READER\"]},\"items\":["
                + goodItemJson(1) + "," + badItemJson() + "," + goodItemJson(2) + "]}";

        mockMvc.perform(post("/api/admission/batch-evaluate")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(3))
                .andExpect(jsonPath("$.succeeded").value(2))
                .andExpect(jsonPath("$.failed").value(1))
                .andExpect(jsonPath("$.items[0].ok").value(true))
                .andExpect(jsonPath("$.items[0].report.decision").value("DENY"))
                .andExpect(jsonPath("$.items[1].ok").value(false))
                .andExpect(jsonPath("$.items[1].errorCode").value("MALFORMED_ARTIFACT"))
                .andExpect(jsonPath("$.items[1].report").doesNotExist())
                .andExpect(jsonPath("$.items[2].ok").value(true));
        log.info("[Web-单项隔离] 3 项含 1 坏输入：整体 200，坏项 errorCode=MALFORMED_ARTIFACT，其余出结论");
    }

    @Test
    void unauthorizedBatchReturns401NotDeny() throws Exception {
        String body = "{\"idempotencyKey\":\"web-401\",\"caller\":{\"name\":\"w-guest\",\"roles\":[\"GUEST\"]},\"items\":["
                + goodItemJson(3) + "]}";

        mockMvc.perform(post("/api/admission/batch-evaluate")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
        log.info("[Web-未授权] GUEST 批量评估 → 401 UNAUTHORIZED（区别于策略 DENY 的 200）");
    }

    @Test
    void rehearseInvalidCandidateSchemaReturns422AndLeavesDenyChannelSeparate() throws Exception {
        String body = """
                {
                  "idempotencyKey": "web-reh-bad",
                  "caller": { "name": "w-reader", "roles": ["READER"] },
                  "items": [ITEMS],
                  "candidateRules": [
                    { "id": "bad", "priority": 1, "effect": "ALLOW", "schemaVersion": 99,
                      "conditions": [] }
                  ]
                }
                """.replace("ITEMS", goodItemJson(4));

        mockMvc.perform(post("/api/admission/rehearse")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("POLICY_SCHEMA_UNSUPPORTED"));
        log.info("[Web-候选非法] schemaVersion=99 → 422 POLICY_SCHEMA_UNSUPPORTED");
    }
}
