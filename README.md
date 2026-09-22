# 容器镜像准入策略评估与审计引擎

用**本地镜像元数据、扫描结果、供应链证明与策略文件**模拟容器镜像准入决策。目标是让
**不同来源、不同权限、并发更新**下的结论保持**一致、可复现、可解释、可审计**。

- Java 21 + Spring Boot 3.4，无外部依赖（内存存储，开箱即跑）
- 多格式工件归一化，畸形输入**显式拒绝并给出可区分原因**，绝不静默跳过
- 策略以**不可变版本链**管理，乐观锁防并发覆盖，回滚保留完整历史
- 一次评估只引用一个不可变策略快照，评估期间不受任何更新影响
- RBAC 鉴权：**鉴权拒绝（401）与策略拒绝（DENY，HTTP 200）严格区分**
- 审计按幂等键去重，并发/重复提交只产生一条记录

---

## 1. 架构与数据流

```
调用方(带角色) + 本地工件
        │
        ▼
 AdmissionController ──► DefaultAdmissionService
                              │ 1. Authorizer 鉴权（未授权 → UNAUTHORIZED，直接拒绝）
                              │ 2. DefaultArtifactParser 归一化
                              │      （畸形/缺字段/指纹冲突/工件不全 → 各自独立错误码）
                              │ 3. PolicyStore.current() 取【不可变快照引用】
                              │ 4. AuditService 原子占位（幂等去重）
                              │ 5. DefaultPolicyEvaluator 基于该快照评估
                              │ 6. 审计落盘（输入指纹 / 策略版本 / 命中规则 / 结论依据）
                              ▼
                        DecisionReport（decision / matchedRules / decisiveRule / rationale）
```

| 包 | 关键组件 | 职责 |
|---|---|---|
| `ingest` | `DefaultArtifactParser` | 多格式工件 → 统一 `ImageDescriptor` |
| `policy` | `PolicyRule` / `PolicyCondition` / `ConditionType` | 策略规则与匹配条件模型 |
| `policy` | `InMemoryPolicyStore` | 不可变版本链、乐观锁发布、回滚 |
| `policy` | `DefaultPolicyEvaluator` | 条件匹配、优先级/冲突裁决、可解释依据 |
| `security` | `RbacAuthorizer` | 角色 → 权限校验 |
| `audit` | `InMemoryAuditService` | 幂等占位 + 去重留痕 |
| `service` | `DefaultAdmissionService` / `DefaultPolicyAdminService` | 用例编排、鉴权与审计 |
| `web` | 3 个 Controller + `GlobalExceptionHandler` | HTTP 接口与错误码映射 |

---

## 2. 支持的本地输入格式

一次评估请求（`POST /api/admission/evaluate`）包含 `reference` 与一组工件。工件类别
`kind` 与格式 `format` 如下：

| kind（类别） | format（格式） | 形态 | 必填 |
|---|---|---|---|
| `MANIFEST` | `OCI-MANIFEST` | JSON，OCI 清单风格 | ✅ 必须存在且唯一 |
| `MANIFEST` | `SIMPLE-MANIFEST` | properties（`key=value`） | ✅ |
| `VULN_SCAN` | `CYCLONEDX-JSON` | JSON，读取 `vulnerabilities[]`（id / `ratings[0].severity` / `affects[0].ref`） | 可选 |
| `VULN_SCAN` | `SIMPLE-SCAN` | properties，漏洞 id 与 severity 用并行列表 | 可选 |
| `PROVENANCE` | `SLSA-V1-JSON` | JSON，SLSA/in-toto 风格（`predicate.builder.id`、`configSource.uri/digest`、`materials`） | 可选 |
| `PROVENANCE` | `SIMPLE-PROVENANCE` | properties（`builderId` / `sourceUri` / `sourceRevision` / `materials`） | 可选 |
| `SIGNATURE` | `SIGNOTE-JSON` | JSON（`subjectDigest` / 布尔 `verified`） | 可选 |
| `SIGNATURE` | `SIMPLE-SIGNATURE` | properties（`digest` / `verified=true|false`） | 可选 |

### 归一化规则

- 所有携带 `digest` 的工件必须与清单锚点指纹**完全一致**；不一致 → 显式拒绝，不静默忽略。
- 非清单工件若不携带 `digest`，则不参与指纹校验（仍要求类别正确、内容可解析）。
- 可选工件缺失时对应字段为 `null` / 空列表（由策略决定是否因此拒绝），**不伪造、不跳过错误条目**。
- 同一类别在一次请求中出现多个 → 拒绝（来源不确定，不允许挑一个）。

### 输入错误分类（相互可区分；均非策略 DENY）

| ErrorCode | 含义 | HTTP |
|---|---|---|
| `MALFORMED_ARTIFACT` | 内容无法按声明格式解析 / 格式标识不支持 / `verified` 非布尔等 | 422 |
| `MISSING_REQUIRED_FIELD` | 可解析但缺必填字段（清单无 digest、漏洞无 severity、证明无 builder.id 等） | 422 |
| `FINGERPRINT_MISMATCH` | 工件间 digest 不一致 | 422 |
| `INCOMPLETE_ARTIFACT_SET` | 缺 MANIFEST、同类工件出现多个、工件集合为空 | 422 |
| `INVALID_REQUEST` | 请求参数本身不合法 | 400 |
| `UNAUTHORIZED` | **鉴权**拒绝（与策略拒绝无关） | 401 |
| `POLICY_VERSION_CONFLICT` | 乐观锁：提交基于的版本已过期 | 409 |
| `POLICY_SCHEMA_UNSUPPORTED` | 规则 schemaVersion 越界 | 422 |
| `POLICY_VERSION_NOT_FOUND` | 回滚/读取的版本不存在 | 404 |

> 关键区分：**输入合法但策略不允许** → 响应体 `decision=DENY`（HTTP 200）；
> **输入本身有问题或无权限** → 上述错误码异常（4xx）。二者通道完全不同。

### 请求示例

```json
{
  "idempotencyKey": "deploy-2026-09-22-001",
  "caller": { "name": "reader-1", "roles": ["READER"] },
  "reference": "gcr.internal/team-a/app:1.0.0",
  "artifacts": [
    { "kind": "MANIFEST", "format": "OCI-MANIFEST", "content": "{ ... OCI 清单 JSON ... }" },
    { "kind": "VULN_SCAN", "format": "CYCLONEDX-JSON", "content": "{ ... }" },
    { "kind": "PROVENANCE", "format": "SLSA-V1-JSON", "content": "{ ... }" },
    { "kind": "SIGNATURE", "format": "SIGNOTE-JSON", "content": "{ ... }" }
  ]
}
```

`SIMPLE-MANIFEST` 示例：

```properties
digest=sha256:def456
registry=gcr.internal
repository=team-b/web
tag=2.3
```

`SIMPLE-SCAN` 示例（并行列表，缺任意 severity 行即拒绝）：

```properties
digest=sha256:def456
vulnerability.ids=CVE-9001,CVE-9002
vulnerability.severity.1=medium
vulnerability.severity.2=critical
vulnerability.package.1=openssl
vulnerability.package.2=curl
```

---

## 3. 策略模型：条件、优先级与冲突规则

### 规则结构

```json
{
  "id": "allow-internal-good",
  "priority": 100,
  "effect": "ALLOW",
  "schemaVersion": 1,
  "conditions": [
    { "type": "REGISTRY_EQUALS", "value": "gcr.internal" }
  ],
  "description": "内部来源显式放行"
}
```

- 一条规则的 `conditions` 之间是 **AND**；全部满足时规则**命中**并产生 `effect`
  （显式 `ALLOW` 或 `DENY`）。`conditions` 为空表示匹配任意镜像。
- 同时提供正/反条件，使“坏镜像命中的 DENY 护栏”与“好镜像命中的 ALLOW 豁免”都能直接表达。

### 条件类型（`ConditionType`）

| 条件类型 | value | 何时匹配 |
|---|---|---|
| `SEVERITY_AT_LEAST` | `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` | 存在严重级别 ≥ 阈值的漏洞 |
| `REGISTRY_EQUALS` / `REGISTRY_NOT_EQUALS` | registry 主机 | registry 等于 / 不等于 |
| `REPOSITORY_PREFIX` | 路径前缀 | repository 前缀匹配 |
| `PROVENANCE_PRESENT` / `PROVENANCE_MISSING` | — | 证明存在 / 缺失 |
| `SIGNATURE_VERIFIED` / `SIGNATURE_NOT_VERIFIED` | — | 签名存在且通过 / 无签名或未通过 |
| `BUILDER_ID_EQUALS` | builderId | `provenance.builder.id` 等于 |
| `SOURCE_URI_PREFIX` | URI 前缀 | `provenance.sourceUri` 前缀匹配 |

### 优先级与冲突裁决（确定性、可复现）

1. 收集所有命中规则，按 **`priority` 降序**，同优先级按 **规则 `id` 升序** 排序；
2. 排序后第一条为**决定性规则**：
   - 高优先级 `DENY` 覆盖低优先级 `ALLOW`；
   - 高优先级 `ALLOW` 覆盖低优先级 `DENY`；
3. **同优先级**出现 ALLOW/DENY 冲突时，以 `id` 升序的固定全序裁决，
   **不依赖集合迭代顺序或规则提交顺序**；
4. 没有任何规则命中时 **fail-closed 默认拒绝**。

结论 `DecisionReport` 中包含：`decision`、`policyVersion`、全部 `matchedRules`
（含每条规则的命中事实 `reason`）、`decisiveRule` 以及说明冲突如何被解决的 `rationale`。
同一输入 + 同一快照，评估任意次结果完全一致（测试中重复 20 次断言一致）。

### 内置默认策略 v1（启动自动加载）

| 规则 | priority | effect | 条件 |
|---|---|---|---|
| `deny-critical-vulns` | 10 | DENY | `SEVERITY_AT_LEAST=CRITICAL` |
| `deny-missing-provenance` | 20 | DENY | `PROVENANCE_MISSING` |
| `deny-unverified-signature` | 20 | DENY | `SIGNATURE_NOT_VERIFIED` |
| `deny-untrusted-registry` | 30 | DENY | `REGISTRY_NOT_EQUALS=gcr.internal` |

默认规则集均为 DENY 护栏；**显式 ALLOW 及其跨优先级冲突由管理员上传的策略集表达**
（见测试 `adminAllowPolicyOverridesDefaultsAndDeniesStillDistinguishable`）。

---

## 4. 策略版本与兼容范围

- 存储维护一条**不可变版本链**：v0 空基线 → v1 内置默认 → v2、v3……，任何已发布快照不可修改。
- **发布**（`POST /api/policies/update`）必须带 `expectedBaseVersion`（乐观锁）：
  - 与当前版本一致才发布新版本（版本号严格 +1，不跳号）；
  - 否则返回 **409 `POLICY_VERSION_CONFLICT`**，调用方需重新读取后再提交。
- **回滚**（`POST /api/policies/rollback`）**不删除历史**，而是用目标版本的规则集
  **新建一个新版本**，完整保留“回滚过”这一事实，便于审计。
- 一次评估在评估前调用 `current()` 固定快照引用；评估期间其他线程发布/回滚都不影响该引用，
  因此任何一次判定看到的都是**一个一致版本的策略集合**，绝不会看到“半个新版本”。

### Schema 兼容范围

- 规则字段 `schemaVersion` 的兼容范围：**[`PolicyStore.SUPPORTED_SCHEMA_MIN`=1,
  `SUPPORTED_SCHEMA_MAX`=2]**（闭区间）。
- 越界（如 99）→ 422 `POLICY_SCHEMA_UNSUPPORTED`，整批更新被拒绝，当前版本不变。
- 同一版本内规则 `id` 必须唯一，`effect` 必须为 ALLOW/DENY，否则 400。

---

## 5. 权限模型（RBAC）

| 角色 | 权限 |
|---|---|
| `READER` | `EVALUATE`（提交准入评估）、`READ_POLICY`（读取策略） |
| `AUDITOR` | READER 全部权限 + `READ_AUDIT`（读取审计） |
| `ADMIN` | 全部权限，含 `UPDATE_POLICY`、`ROLLBACK_POLICY` |

- 无身份 / 未知角色 / 权限不足 → **401 `UNAUTHORIZED`**，消息中明确标注这是鉴权拒绝。
- 写接口在**鉴权通过之后**才做版本检查；因此“无权限”与“版本冲突”“策略拒绝”互不混淆。
- GET 接口调用方通过请求头传递：`X-Caller: name|ROLE1,ROLE2`。

---

## 6. HTTP 接口

| 方法与路径 | 说明 | 权限 |
|---|---|---|
| `POST /api/admission/evaluate` | 提交工件进行准入评估；body 带 `caller` 与 `idempotencyKey` | EVALUATE |
| `POST /api/policies/update` | 发布新策略版本（body 带 `expectedBaseVersion`） | UPDATE_POLICY |
| `POST /api/policies/rollback` | 回滚到 `targetVersion`（产生新版本） | ROLLBACK_POLICY |
| `GET /api/policies/current` | 当前策略快照 | READ_POLICY |
| `GET /api/policies/history` | 全部版本（升序） | READ_POLICY |
| `GET /api/audit/recent?limit=N` | 最近 N 条审计 | READ_AUDIT |
| `GET /api/audit/by-digest?digest=...` | 按镜像指纹查审计 | READ_AUDIT |

### 审计记录（`AuditRecord`）

字段：`id`、`timestamp`、`caller`、`action`（`ADMISSION_EVALUATE` /
`POLICY_UPDATE` / `POLICY_ROLLBACK`）、`imageDigest`、`policyVersion`、
`decision`、`rationale`（最终结论依据）、`detail`（引用与命中规则列表）。

- 幂等键 = SHA-256(`caller | digest | policyVersion | idempotencyKey`)。
- 评估前**原子占位**：并发或重复提交相同键时，只有首个请求真正评估并写一条记录，
  其余请求等待并共享同一结论；不会产生重复记录，也不会状态错乱。

---

## 7. 本地验证方法

### 运行全部测试

```bash
mvn test
```

32 个测试，覆盖四类关键场景，且单测日志中打印**评估输入、命中的策略与最终判定依据**：

| 测试类 | 数量 | 覆盖内容 |
|---|---|---|
| `ParserIngestionTest` | 8 | JSON/properties 双格式解析、畸形 JSON、未知格式、缺字段、指纹不一致、工件不全、扫描条目不完整 |
| `PolicyEvaluatorTest` | 7 | 高优先级 DENY/ALLOW 双向覆盖、同优先级 id tie-break、fail-closed、20 次重复可复现、命中依据可读、无条件规则冲突 |
| `PolicyStoreVersioningTest` | 7 | 乐观锁冲突、回滚产生新版本且保留历史、版本不存在、schema 越界、重复 id、**16 线程并发更新**与快照一致性 |
| `AdmissionIntegrationTest` | 6 | 未授权 vs 策略 DENY 区分、端到端 DENY/ALLOW、审计内容完整、越权更新、READER/AUDITOR 审计权限、重复提交幂等 |
| `ConcurrencyIntegrationTest` | 3 | 12 线程同版本竞争（恰 1 成功其余 409）、更新期间 8 线程×50 轮评估版本自洽稳定、10 个相同并发请求只产生 1 条审计 |

查看带输入/命中规则/判定依据的详细日志：

```bash
mvn -Dtest=PolicyEvaluatorTest test
# 或评估器 INFO 日志（默认即开启）
cat target/surefire-reports/com.github.xingjianluo.admissionpolicyenginejava.tests.PolicyEvaluatorTest-output.txt 2>/dev/null
```

控制台日志样例（评估输入 / 命中策略 / 最终判定三段式）：

```
准入评估输入 caller=reader-x reference=... digest=sha256:... registry=gcr.internal ...
命中策略 policyVersion=v2 matched=[allow-all-wave3(prio=50,effect=ALLOW)] finalDecision=ALLOW rationale=...
写入审计记录 auditId=eval:9f3c... action=ADMISSION_EVALUATE caller=reader-x decision=ALLOW policyVersion=2
```

### 启动服务并手工验证

```bash
mvn -DskipTests package
java -jar target/admission-policy-engine-java-1.0-SNAPSHOT.jar --server.port=8099
```

```bash
# 查看默认策略
curl -s http://localhost:8099/api/policies/current -H "X-Caller: root|ADMIN"

# 发布一条高优先级显式 ALLOW（必须带 expectedBaseVersion）
curl -s -X POST http://localhost:8099/api/policies/update \
  -H "Content-Type: application/json" \
  -d '{"caller":{"name":"root","roles":["ADMIN"]},"expectedBaseVersion":1,"comment":"add allow",
       "rules":[{"id":"allow-in","priority":100,"effect":"ALLOW","schemaVersion":1,
                 "conditions":[{"type":"REGISTRY_EQUALS","value":"gcr.internal"}]}]}'

# 再次用过期 base 更新 -> 409 POLICY_VERSION_CONFLICT
# 回滚到默认规则集 -> 产生新版本
curl -s -X POST http://localhost:8099/api/policies/rollback \
  -H "Content-Type: application/json" \
  -d '{"caller":{"name":"root","roles":["ADMIN"]},"targetVersion":1}'
```

预期的错误分类（冒烟实测）：

- 外部 registry 镜像 → HTTP **200**，`decision=DENY`，命中 `deny-untrusted-registry`
- GUEST 提交评估 / READER 更新策略 → **401 UNAUTHORIZED**
- 畸形 JSON 工件 → **422 MALFORMED_ARTIFACT**
- 工件 digest 与清单不一致 → **422 FINGERPRINT_MISMATCH**
- 两个并发更新同基于 v1 → 第一个 200(v2)，第二个 **409 POLICY_VERSION_CONFLICT**
- `schemaVersion=99` → **422 POLICY_SCHEMA_UNSUPPORTED**（提示兼容范围 [1,2]）
- 相同 `idempotencyKey` 提交两次 → 审计记录仅 +1

---

## 8. 设计要点小结

- **一致性**：快照不可变 + 评估前固定引用 + 版本链读无锁，更新/回滚与评估完全隔离。
- **并发安全**：发布/回滚在同一把锁内“检查当前版本→追加”，配合乐观版本号，保证串行化、
  不跳号、不丢更新；审计用 `putIfAbsent` + 身份 CAS 实现占位/完成。
- **可解释**：每条命中都带事实依据，最终结论说明决定性规则与冲突解决方式。
- **可区分**：输入错误、鉴权拒绝、策略拒绝三条独立通道，错误码与 HTTP 状态码一一对应。
- **可审计**：每次评估/变更留痕，含调用方、镜像指纹、策略版本、命中规则与结论依据。
