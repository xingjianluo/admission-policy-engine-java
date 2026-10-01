# 容器镜像准入策略评估与审计引擎

用**本地镜像元数据、扫描结果、供应链证明与策略文件**模拟容器镜像准入决策。目标是让
**不同来源、不同权限、并发更新**下的结论保持**一致、可复现、可解释、可审计**。

- Java 21 + Spring Boot 3.4，无外部依赖（内存存储，开箱即跑）
- 多格式工件归一化，畸形输入**显式拒绝并给出可区分原因**，绝不静默跳过
- 策略以**不可变版本链**管理，乐观锁防并发覆盖，回滚保留完整历史
- 一次评估只引用一个不可变策略快照，评估期间不受任何更新影响
- RBAC 鉴权：**鉴权拒绝（401）与策略拒绝（DENY，HTTP 200）严格区分**
- 审计按幂等键去重，并发/重复提交只产生一条记录
- **批量评估**：一批镜像逐项出结论，单项坏输入只标记该项不拖垮整批，批量有明确上限
- **策略预演**：用候选规则对同一批镜像给“现网 vs 候选”双侧对照，**不发布、不产生正式版本**
- **规则参数强校验**：严重级别档位/条件参数不合法时，发布与预演在评估前即按
  **422 规则集不合法**整批拒绝（版本与历史不变）；历史坏规则下评估也不以 500 失败，
  单镜像给 422、批量/预演逐项给 `POLICY_ERROR`

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
| `policy` | `PolicyRuleSetValidator` | 规则集合法性校验，**发布与预演共用同一套规则** |
| `security` | `RbacAuthorizer` | 角色 → 权限校验 |
| `audit` | `InMemoryAuditService` | 幂等占位 + 去重留痕 |
| `service` | `DefaultAdmissionService` / `DefaultPolicyAdminService` | 用例编排、鉴权与审计 |
| `service` | `DefaultBatchAdmissionService` / `DefaultPolicyRehearsalService` | 批量评估、候选规则预演对照 |
| `web` | 5 个 Controller + `GlobalExceptionHandler` | HTTP 接口与错误码映射 |

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
| `POLICY_RULESET_INVALID` | **规则集不合法**：条件参数非法（严重级别阈值越界、需参条件缺参数、无参条件带参数等）；发布/预演在评估前整批拒绝，也用于现网历史坏规则的评估反馈 | 422 |
| `POLICY_VERSION_NOT_FOUND` | 回滚/读取的版本不存在 | 404 |

> 关键区分（三条互不相通的通道）：
> - **输入合法但策略不允许** → 响应体 `decision=DENY`（HTTP 200）；
> - **规则集/请求本身有问题** → 上述错误码异常（4xx），例如 `POLICY_RULESET_INVALID` 是 422；
> - **调用方无权限** → 401 `UNAUTHORIZED`。
>
> “规则集不合法（422）”“策略结论拒绝 DENY（200 体内）”“未授权（401）”绝不会互相混淆。

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

### 条件类型（`ConditionType`）与参数取值要求

| 条件类型 | value 要求 | 合法取值 | 何时匹配 |
|---|---|---|---|
| `SEVERITY_AT_LEAST` | **必填**，非空白 | `LOW`/`MEDIUM`/`HIGH`/`CRITICAL`（不区分大小写，允许首尾空格，如 ` high `；**不含 `UNKNOWN`**） | 存在严重级别 ≥ 阈值的漏洞 |
| `REGISTRY_EQUALS` / `REGISTRY_NOT_EQUALS` | **必填**，非空白 | 任意非空白字符串（registry 主机，精确匹配） | registry 等于 / 不等于 |
| `REPOSITORY_PREFIX` | **必填**，非空白 | 任意非空白字符串（路径前缀） | repository 前缀匹配 |
| `BUILDER_ID_EQUALS` | **必填**，非空白 | 任意非空白字符串（builderId） | `provenance.builder.id` 等于 |
| `SOURCE_URI_PREFIX` | **必填**，非空白 | 任意非空白字符串（URI 前缀） | `provenance.sourceUri` 前缀匹配 |
| `PROVENANCE_PRESENT` / `PROVENANCE_MISSING` | **必须留空** | 不接受 value | 证明存在 / 缺失 |
| `SIGNATURE_VERIFIED` / `SIGNATURE_NOT_VERIFIED` | **必须留空** | 不接受 value | 签名存在且通过 / 无签名或未通过 |

参数校验规则（`ConditionParameters`，发布与预演、评估共用同一份规约）：

- 任一“必填 value”条件缺参数（null 或纯空白）→ 规则集不合法；
- 任一“必须留空”条件携带了 value → 规则集不合法；
- `SEVERITY_AT_LEAST` 的值经 `trim().toUpperCase()` 归一化后必须是
  `LOW/MEDIUM/HIGH/CRITICAL` 之一；`UNKNOWN`、其他单词（如 `URGENT`）、数字、空白均拒绝；
- 只要规则集里**有一条**规则的**任一条件**参数不合法，**整份规则集**都按
  **422 `POLICY_RULESET_INVALID`** 拒绝（错误消息会聚合并列出全部违规位置：
  规则 id、条件下标、条件类型与非法 value），不会只拒绝那一条。

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
- 规则内**条件参数**不合法（严重级别阈值越界、需参条件缺参数、无参条件带参数）→
  **422 `POLICY_RULESET_INVALID`，整批更新被拒绝**。所有这些拒绝都发生在
  `PolicyStore.publish` 追加版本**之前**：当前版本不变、版本历史不新增条目，
  也不会写 `POLICY_UPDATE` 成功审计（被拒请求不被记成一次成功发布）。

### 4.1 参数不合法时发布与预演分别如何返回

| 入口 | 校验时机 | 参数不合法时 | 副作用 |
|---|---|---|---|
| `POST /api/policies/update`（发布） | 鉴权后、乐观锁检查后、追加版本**前** | 422 `POLICY_RULESET_INVALID`，整份规则集拒绝 | 不产生新版本、不改当前版本与历史、不记成功发布审计 |
| `POST /api/admission/rehearse`（预演） | 鉴权与批量大小检查后、**处理任何一项与取现网快照之前** | 422 `POLICY_RULESET_INVALID`，整次预演拒绝，响应体不含 `items`/任何对照结论 | 不发布、不产生正式版本、不改动现网、不留对照审计 |

二者调用同一个 `PolicyRuleSetValidator`（内部用同一份 `ConditionParameters` 规约），
因此“同样的非法候选规则”在两个入口得到完全一致的判定，不会出现预演放过、发布拦住
（或反过来）的情况。

> 与“策略结论是拒绝”“未授权”的区分：
> - 规则集不合法 → **422**，`code=POLICY_RULESET_INVALID`，根本不进入评估；
> - 策略结论 DENY → **HTTP 200**，响应体 `decision=DENY`（说明输入合法、只是策略不允许）；
> - 未授权 → **401**，`code=UNAUTHORIZED`（鉴权先于规则校验发生）。

### 4.2 现网已存在历史坏规则版本时的失败边界

发布校验是后来补上的；如果线上因历史操作已经存在带非法条件参数的规则版本，
评估链路不会再以 500 失败，而是给出**可判断、可定位**的反馈（评估器在匹配每条规则前
用同一份参数规约检查，异常统一归类为 `POLICY_RULESET_INVALID`，消息含策略版本与规则 id）：

- **单镜像评估** `/api/admission/evaluate`：返回 **422** `POLICY_RULESET_INVALID`，
  消息指明“策略版本 vX 中规则 Y 的条件参数非法”，而不是 500。
- **批量评估** `/api/admission/batch-evaluate`：整批仍返回 **200**，受坏规则影响的项标
  `status=POLICY_ERROR`、`errorCode=POLICY_RULESET_INVALID`、`report=null`；
  同批其他项照常 `EVALUATED`，输入非法项仍为 `INPUT_ERROR`；汇总字段
  `policyErrorCount` 单独计数（`errorCount` 仍只统计输入错误）。**整批不会以 500 收场**。
- **预演** `/api/admission/rehearse`：候选规则仍在预演开始前整体校验（坏候选 → 422）；
  若坏的是现网版本，则受影响项标 `status=POLICY_ERROR` 且
  `currentReport`/`candidateReport`/`change` 均为 null（**不给出任何对照结论**），
  汇总 `policyErrorCount` 计数，其余项正常对照，整次预演不 500、不产生正式版本。

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
| `POST /api/admission/batch-evaluate` | 批量评估一批镜像，逐项出结论（单项坏输入只标记该项） | EVALUATE |
| `POST /api/admission/rehearse` | 策略预演：候选规则 vs 现网策略双侧对照，不发布、不留正式版本 | EVALUATE |
| `POST /api/policies/update` | 发布新策略版本（body 带 `expectedBaseVersion`） | UPDATE_POLICY |
| `POST /api/policies/rollback` | 回滚到 `targetVersion`（产生新版本） | ROLLBACK_POLICY |
| `GET /api/policies/current` | 当前策略快照 | READ_POLICY |
| `GET /api/policies/history` | 全部版本（升序） | READ_POLICY |
| `GET /api/audit/recent?limit=N` | 最近 N 条审计 | READ_AUDIT |
| `GET /api/audit/by-digest?digest=...` | 按镜像指纹查审计 | READ_AUDIT |

### 审计记录（`AuditRecord`）

字段：`id`、`timestamp`、`caller`、`action`（`ADMISSION_EVALUATE` /
`POLICY_UPDATE` / `POLICY_ROLLBACK` / `BATCH_EVALUATE` /
`BATCH_EVALUATE_INPUT_ERROR` / `BATCH_EVALUATE_POLICY_ERROR` /
`POLICY_REHEARSE` / `POLICY_REHEARSE_INPUT_ERROR` /
`POLICY_REHEARSE_POLICY_ERROR`）、
`imageDigest`、`policyVersion`、`decision`、`rationale`（最终结论依据）、
`detail`（引用与命中规则列表；预演另含候选规则指纹与双侧决定性规则）。

> 被 `POLICY_RULESET_INVALID` 拒绝的发布/预演在写版本或评估之前即中止，
> 不会产生 `POLICY_UPDATE` 成功记录，也不会产生 `POLICY_REHEARSE` 对照记录。

- 幂等键 = SHA-256(`caller | digest | policyVersion | idempotencyKey`)。
- 评估前**原子占位**：并发或重复提交相同键时，只有首个请求真正评估并写一条记录，
  其余请求等待并共享同一结论；不会产生重复记录，也不会状态错乱。

---

## 7. 批量评估与策略预演（上线前看清影响）

### 7.1 批量评估 `POST /api/admission/batch-evaluate`

一次提交一批镜像，**每个镜像各自给出结论**，一眼看出这批里谁过、谁不过。

请求体：

```json
{
  "idempotencyKey": "batch-2026-09-30-001",
  "caller": { "name": "reader-1", "roles": ["READER"] },
  "items": [
    { "reference": "gcr.internal/team-a/app:1.0.0", "artifacts": [ /* 与单次评估相同形态的工件数组 */ ] },
    { "reference": "gcr.internal/team-b/web:2.3",   "artifacts": [ /* ... */ ] }
  ]
}
```

响应（`BatchEvaluationReport`）：

```json
{
  "policyVersion": 1, "totalCount": 3,
  "allowedCount": 0, "deniedCount": 2, "errorCount": 1, "policyErrorCount": 0,
  "items": [
    { "index": 0, "reference": "...", "status": "EVALUATED",
      "report": { "decision": "DENY", "policyVersion": 1, "matchedRules": [ ... ],
                  "decisiveRule": { "ruleId": "deny-missing-provenance", ... }, "rationale": "..." },
      "errorCode": null, "errorMessage": null },
    { "index": 1, "reference": "...", "status": "INPUT_ERROR", "report": null,
      "errorCode": "FINGERPRINT_MISMATCH", "errorMessage": "..." }
  ]
}
```

> `status` 有三种：`EVALUATED`（正常出结论）、`INPUT_ERROR`（该项输入坏）、
> `POLICY_ERROR`（该项输入合法，但现网策略版本含历史坏规则，无法评估；
> 此时 `errorCode=POLICY_RULESET_INVALID`、`report=null`）。

**批量上限与输入要求**

- 单次最多 **`100`** 项（`DefaultBatchAdmissionService.MAX_BATCH_SIZE`，预演同上限）。
  超过 100 → **400 `INVALID_REQUEST`**，提示“超过上限 100，请拆分”；空批同样 400。
- 每个 `items[i]` 的 `reference` 必填、`artifacts` 至少含一个 MANIFEST，
  工件 `kind/format/content` 要求与单次评估完全一致（见第 2 节）。
- **单项坏输入不拖垮整批**：某项畸形 JSON、缺字段、指纹不一致、缺 MANIFEST 等，
  只把该项标为 `status=INPUT_ERROR` 并给出可区分的 `errorCode` / `errorMessage`，
  其余项照常 `EVALUATED` 出结论。结构性错误（缺 reference、未知 kind、空条目）在
  Web 组装阶段即落到该项，同样不影响其他项。
- **单项坏策略不拖垮整批**：若当前生效版本含历史坏规则（条件参数非法），受影响项标为
  `status=POLICY_ERROR`、`errorCode=POLICY_RULESET_INVALID`、`report=null`，
  其余项照常；这类项计入新增的汇总字段 `policyErrorCount`，与 `errorCount`（输入错误）分开。
- 整批在处理任何一项**之前**固定一份当前策略快照引用：整批看到的是同一个
  `policyVersion`，评估期间他人发布/回滚不影响本批。

### 7.2 策略预演 `POST /api/admission/rehearse`

在**不真正发布**的前提下，用一组候选规则对同一批镜像做双侧对照：
现网策略下结论 vs 换成候选规则后结论。

请求体（`items` 形态与批量评估一致，另加 `candidateRules`，规则形态同发布接口）：

```json
{
  "idempotencyKey": "rehe-2026-09-30-001",
  "caller": { "name": "reader-1", "roles": ["READER"] },
  "items": [ { "reference": "...", "artifacts": [ ... ] } ],
  "candidateRules": [
    { "id": "candidate-allow-internal", "priority": 100, "effect": "ALLOW",
      "schemaVersion": 1, "conditions": [ { "type": "REGISTRY_EQUALS", "value": "gcr.internal" } ] }
  ]
}
```

响应（`RehearsalReport`）：

```json
{
  "currentPolicyVersion": 1,
  "candidateFingerprint": "446b9479623943c6",
  "totalCount": 1, "changedCount": 1,
  "allowToDenyCount": 0, "denyToAllowCount": 1, "unchangedCount": 0,
  "errorCount": 0, "policyErrorCount": 0,
  "items": [
    { "index": 0, "reference": "...", "status": "EVALUATED",
      "currentReport":   { "decision": "DENY",  "decisiveRule": { "ruleId": "deny-missing-provenance" } },
      "candidateReport": { "decision": "ALLOW", "decisiveRule": { "ruleId": "candidate-allow-internal" } },
      "change": "DENY_TO_ALLOW", "errorCode": null, "errorMessage": null }
  ]
}
```

**对照结果怎么看**

- 每个有效项同时给 `currentReport`（现网）与 `candidateReport`（候选）两份完整结论，
  各自带 `matchedRules` / `decisiveRule` / `rationale`，**变化时由哪条规则决定一目了然**。
- `change`：
  - `DENY_TO_ALLOW`：现网拒绝、候选放行（新规则会“放过”它）；
  - `ALLOW_TO_DENY`：现网放行、候选拒绝（新规则会“拦下”它，**上线重点风险**）；
  - `UNCHANGED`：两侧一致。
- 汇总字段直接数出变化项数、两个方向各多少、不变多少、输入错误多少。
- `candidateReport.policyVersion` 恒为 **`-1`**（`CANDIDATE_VERSION`），明确标识
  “这是未发布候选”，区别于任何正式版本号；`candidateFingerprint` 是候选规则集内容指纹
  （按规则字段确定性序列化后哈希，与提交顺序无关）。

**安全性与一致性保证**

- **绝不触碰线上**：候选规则只存在于本次请求内存中的候选快照，**不发布、不产生正式版本、
  不改当前策略**；预演后 `/api/policies/current` 版本不变、`/history` 长度不变。
- **候选规则非法与正式发布同规处理**：候选先经与 `POST /policies/update` 完全相同的
  规则集校验（空集、重复 id、缺 effect、`schemaVersion` 越界、**条件参数非法**等），
  非法时在预演开始前即整次拒绝并返回 **422 `POLICY_RULESET_INVALID`**，响应体不含任何
  对照结论，**不会悄悄放过**，现网与版本链均不变。若坏的是**现网**历史版本，则不整批拒绝，
  而是对受影响项给 `status=POLICY_ERROR` 且双侧报告/变化方向均为 null（见 4.2）。
- **对照基于同一份现网策略**：处理任何一项之前取一次当前快照，整次预演的“现网一侧”
  全部锚定该 `currentPolicyVersion`。预演期间即使他人发布/回滚，也不会出现
  一半旧、一半新的对照（并发自洽由测试 900 个逐项校验覆盖）。
- **可复现**：双侧评估都是对不可变快照的纯函数；同一批输入 + 同一份现网策略 +
  同一份候选（指纹相同），重复预演任意次结果完全一致。
- 批量上限、单项坏输入隔离规则与批量评估相同（上限 100）。

### 7.3 鉴权、审计与幂等

- 两个接口都需要 **`EVALUATE`** 权限（READER/AUDITOR/ADMIN）。未授权 →
  **401 `UNAUTHORIZED`**，这与“项内策略结论 DENY（HTTP 200）”是**不同通道**，
  不会把“没权限”误读成“策略不许过”。
- 审计新增动作（`/api/audit/...` 可查）：
  - `BATCH_EVALUATE` / `BATCH_EVALUATE_INPUT_ERROR`
  - `POLICY_REHEARSE` / `POLICY_REHEARSE_INPUT_ERROR`

  记录含**谁（caller）、什么时候（timestamp）、对哪个镜像（imageDigest）、
  用的哪份策略（现网 `policyVersion` + `candidateFingerprint`）、双侧决定性规则与结论**。
- 逐项按幂等键去重：审计 id 由
  `动作 | caller | 现网版本 | 候选指纹(预演) | 整批 idempotencyKey | 下标 | 镜像指纹` 派生。
  **同一批请求用相同 `idempotencyKey` 重复提交，不产生重复审计记录**，结论仍稳定返回；
  不同 `idempotencyKey` 视为不同批次，分别留痕。

---

---

## 8. 本地验证方法

### 运行全部测试

```bash
mvn test
```

46 个既有测试 + 21 个本次新增测试（共 **67** 个），覆盖原有四类关键场景、批量/预演场景
以及本次“条件参数合法性”修复；单测日志中打印
**评估输入、命中的策略与最终判定依据**：

| 测试类 | 数量 | 覆盖内容 |
|---|---|---|
| `ParserIngestionTest` | 8 | JSON/properties 双格式解析、畸形 JSON、未知格式、缺字段、指纹不一致、工件不全、扫描条目不完整 |
| `PolicyEvaluatorTest` | 7 | 高优先级 DENY/ALLOW 双向覆盖、同优先级 id tie-break、fail-closed、20 次重复可复现、命中依据可读、无条件规则冲突 |
| `PolicyStoreVersioningTest` | 7 | 乐观锁冲突、回滚产生新版本且保留历史、版本不存在、schema 越界、重复 id、**16 线程并发更新**与快照一致性 |
| `AdmissionIntegrationTest` | 6 | 未授权 vs 策略 DENY 区分、端到端 DENY/ALLOW、审计内容完整、越权更新、READER/AUDITOR 审计权限、重复提交幂等 |
| `ConcurrencyIntegrationTest` | 3 | 12 线程同版本竞争（恰 1 成功其余 409）、更新期间 8 线程×50 轮评估版本自洽稳定、10 个相同并发请求只产生 1 条审计 |
| `BatchEvaluationIntegrationTest` | 5 | 批量逐项结论与汇总、坏输入只标记该项不影响其他项、空批/超 100 上限拒绝、未授权 401、重复批次不重复留痕 |
| `PolicyRehearsalIntegrationTest` | 8 | 双侧对照与变化方向/决定性规则、预演不发布不留版本、非法候选与发布同规拒绝、6 次重复可复现、坏输入隔离、未授权、重复预演幂等、ALLOW→DENY 方向 |
| `RehearsalConcurrencyIntegrationTest` | 1 | 预演期间管理员持续发布/回滚，6 线程×30 轮×5 项（900 个逐项校验）两侧结论始终锚定同一份当前快照，不出现新旧混合 |
| `PolicyRuleSetValidatorTest` | 6 | 非法严重级别阈值（含 UNKNOWN/乱写词/空白/null）、需参条件缺参数、无参条件带参数一律 POLICY_RULESET_INVALID；多处违规聚合；大小写与首尾空格合法取值通过 |
| `EvaluatorCorruptPolicyTest` | 3 | 现网历史坏规则（坏阈值/缺阈值/缺 registry 参数）在评估期统一抛出可定位的 POLICY_RULESET_INVALID，而非裸异常 |
| `InvalidRuleParameterIntegrationTest` | 7 | 坏阈值/缺参数在发布与预演入口被按规则集不合法拒绝、当前版本与历史不变、被拒发布不留成功审计、被拒预演无对照结论；合法大小写/空格变体通过；历史坏规则下单镜像 422、批量与预演逐项 POLICY_ERROR 不 500；与 DENY/401 区分 |
| `InvalidRuleParameterHttpTest` | 5 | HTTP 层发布/预演对坏参数返回 422 + `POLICY_RULESET_INVALID`、被拒发布版本不变、与 401 区分、带空格合法阈值发布 200 |

> 新增功能不改变既有单镜像评估、批量评估、预演、发布/回滚与审计行为：
> 原有 46 个用例全部不回归。

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

### 手工验证批量评估与预演

```bash
# 批量评估：3 项中混入一个指纹不一致项 → 2 个 DENY + 1 个 INPUT_ERROR
curl -s -X POST http://localhost:8099/api/admission/batch-evaluate \
  -H "Content-Type: application/json" -d '{
    "idempotencyKey":"smoke-batch-1","caller":{"name":"reader-1","roles":["READER"]},
    "items":[
      {"reference":"gcr.internal/team-a/app:1.0.0","artifacts":[
        {"kind":"MANIFEST","format":"OCI-MANIFEST","content":"{\"digest\":\"sha256:smk0001\",\"config\":{\"digest\":\"sha256:smk0001\"},\"annotations\":{\"io.xj.registry\":\"gcr.internal\",\"io.xj.repository\":\"team-a/app\"}}"},
        {"kind":"VULN_SCAN","format":"CYCLONEDX-JSON","content":"{\"digest\":\"sha256:smk0001\",\"vulnerabilities\":[]}"}]},
      {"reference":"gcr.internal/bad:1","artifacts":[
        {"kind":"MANIFEST","format":"OCI-MANIFEST","content":"{\"digest\":\"sha256:smk0003\",\"config\":{\"digest\":\"sha256:smk0003\"},\"annotations\":{\"io.xj.registry\":\"gcr.internal\",\"io.xj.repository\":\"bad\"}}"},
        {"kind":"VULN_SCAN","format":"CYCLONEDX-JSON","content":"{\"digest\":\"sha256:DIFFERENT\",\"vulnerabilities\":[]}"}]}
    ]}'

# 预演：候选规则“内部放行”，看 change=DENY_TO_ALLOW；预演后 current 仍为 v1
curl -s -X POST http://localhost:8099/api/admission/rehearse \
  -H "Content-Type: application/json" -d '{
    "idempotencyKey":"smoke-rehe-1","caller":{"name":"reader-1","roles":["READER"]},
    "items":[{"reference":"gcr.internal/team-a/app:1.0.0","artifacts":[
        {"kind":"MANIFEST","format":"OCI-MANIFEST","content":"{\"digest\":\"sha256:smk0001\",\"config\":{\"digest\":\"sha256:smk0001\"},\"annotations\":{\"io.xj.registry\":\"gcr.internal\",\"io.xj.repository\":\"team-a/app\"}}"},
        {"kind":"VULN_SCAN","format":"CYCLONEDX-JSON","content":"{\"digest\":\"sha256:smk0001\",\"vulnerabilities\":[]}"}]}],
    "candidateRules":[{"id":"candidate-allow-internal","priority":100,"effect":"ALLOW","schemaVersion":1,
      "conditions":[{"type":"REGISTRY_EQUALS","value":"gcr.internal"}]}]}'

# 查留痕：同一指纹下可见 BATCH_EVALUATE 与 POLICY_REHEARSE
curl -s "http://localhost:8099/api/audit/by-digest?digest=sha256:smk0001" -H "X-Caller: aud|AUDITOR"
```

预期：批量响应 `errorCount=1` 且坏项 `status=INPUT_ERROR/errorCode=FINGERPRINT_MISMATCH`，
另一项仍为 `EVALUATED`；预演响应 `denyToAllowCount=1`、`change=DENY_TO_ALLOW`、
`candidateReport.decisiveRule.ruleId=candidate-allow-internal`，预演前后
`/api/policies/current` 都为 v1；GUEST 调两接口 → **401**；101 项 → **400**；
候选 `schemaVersion=99` → **422**；相同 `idempotencyKey` 再发一次审计条数不变。

### 手工复现/验证本次“条件参数合法性”修复

```bash
# 1) 发布：严重级别档位写成允许取值以外的词 -> 422 POLICY_RULESET_INVALID，不产生新版本
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8099/api/policies/update \
  -H "Content-Type: application/json" \
  -d '{"caller":{"name":"root","roles":["ADMIN"]},"expectedBaseVersion":1,
       "rules":[{"id":"bad-sev","priority":10,"effect":"DENY","schemaVersion":1,
                 "conditions":[{"type":"SEVERITY_AT_LEAST","value":"URGENT"}]}]}'
# 预期：422；响应体 code=POLICY_RULESET_INVALID，消息定位到规则 bad-sev
curl -s http://localhost:8099/api/policies/current -H "X-Caller: root|ADMIN"   # 仍是 v1

# 2) 发布：需要参数的条件缺参数（value 留空）-> 同样 422
curl -s -X POST http://localhost:8099/api/policies/update \
  -H "Content-Type: application/json" \
  -d '{"caller":{"name":"root","roles":["ADMIN"]},"expectedBaseVersion":1,
       "rules":[{"id":"missing-value","priority":10,"effect":"ALLOW","schemaVersion":1,
                 "conditions":[{"type":"REGISTRY_EQUALS"}]}]}'

# 3) 合法取值（大小写/首尾空格差异）-> 200，成功产生新版本；随后回滚回 v1
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8099/api/policies/update \
  -H "Content-Type: application/json" \
  -d '{"caller":{"name":"root","roles":["ADMIN"]},"expectedBaseVersion":1,
       "rules":[{"id":"ok-sev","priority":10,"effect":"DENY","schemaVersion":1,
                 "conditions":[{"type":"SEVERITY_AT_LEAST","value":" high "}]}]}'
# 预期：200
curl -s -X POST http://localhost:8099/api/policies/rollback \
  -H "Content-Type: application/json" \
  -d '{"caller":{"name":"root","roles":["ADMIN"]},"targetVersion":1}'

# 4) 预演：候选规则带非法阈值 -> 422，且响应体没有 items/任何对照结论，现网版本不变
curl -s -X POST http://localhost:8099/api/admission/rehearse \
  -H "Content-Type: application/json" -d '{
    "idempotencyKey":"smoke-rehe-bad","caller":{"name":"reader-1","roles":["READER"]},
    "items":[{"reference":"gcr.internal/team-a/app:1.0.0","artifacts":[
        {"kind":"MANIFEST","format":"OCI-MANIFEST","content":"{\"digest\":\"sha256:smk0001\",\"config\":{\"digest\":\"sha256:smk0001\"},\"annotations\":{\"io.xj.registry\":\"gcr.internal\",\"io.xj.repository\":\"team-a/app\"}}"},
        {"kind":"VULN_SCAN","format":"CYCLONEDX-JSON","content":"{\"digest\":\"sha256:smk0001\",\"vulnerabilities\":[]}"}]}],
    "candidateRules":[{"id":"cand-bad","priority":10,"effect":"DENY","schemaVersion":1,
      "conditions":[{"type":"SEVERITY_AT_LEAST","value":"URGENT"}]}]}'
# 预期：HTTP 422，{"code":"POLICY_RULESET_INVALID",...}，无 items 字段
```

> 历史坏规则的失败边界（单镜像 422、批量与预演逐项 `POLICY_ERROR` 不 500）无法通过正常
> 发布接口造数据，因此由自动化测试覆盖：见
> `EvaluatorCorruptPolicyTest`（评估器）与
> `InvalidRuleParameterIntegrationTest#corruptHistoryVersionDoesNotCause500OnAnyEvaluationPath`
> （测试用 `CorruptibleStore` 绕过发布校验植入一条历史坏规则版本，再走三条评估链路断言）。

---

## 9. 设计要点小结

- **一致性**：快照不可变 + 评估前固定引用 + 版本链读无锁，更新/回滚与评估完全隔离。
- **并发安全**：发布/回滚在同一把锁内“检查当前版本→追加”，配合乐观版本号，保证串行化、
  不跳号、不丢更新；审计用 `putIfAbsent` + 身份 CAS 实现占位/完成。
- **可解释**：每条命中都带事实依据，最终结论说明决定性规则与冲突解决方式。
- **可区分**：输入错误、鉴权拒绝、策略拒绝、规则集不合法四条独立通道，
  错误码与 HTTP 状态码一一对应。
- **规则集入口拦截**：发布与预演共用同一参数规约（`ConditionParameters` +
  `PolicyRuleSetValidator`），条件参数非法（严重级别阈值越界、需参条件缺参数、
  无参条件带参数）在写版本/进评估前即以 422 `POLICY_RULESET_INVALID` 整批拒绝，
  当前版本、版本历史、成功审计均保持原样；严重级别阈值允许大小写与首尾空格差异。
- **历史坏规则失败边界**：评估器匹配前对每条规则做同规约参数检查，任何历史遗留坏规则
  都统一归类为可定位的 `POLICY_RULESET_INVALID`（含版本与规则 id）；单镜像返回 422，
  批量/预演逐项 `POLICY_ERROR` 隔离，绝不以 500 收场，预演对坏项不给对照结论。
- **可审计**：每次评估/变更留痕，含调用方、镜像指纹、策略版本、命中规则与结论依据。
- **批量隔离**：批量/预演固定整批一份快照；单项坏输入只标记该项，不拖垮其他项；
  批量上限 100 防止拖垮服务。
- **预演无副作用**：候选规则仅存于请求内候选快照（版本标记 -1，配内容指纹），
  与发布共用同一套规则校验器，但不写版本链；整次预演锚定单一当前版本，
  并发发布/回滚下对照依然自洽，且同输入同策略结果可复现。
