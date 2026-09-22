# 容器镜像准入策略评估与审计引擎（本地模拟）

用本地镜像清单、漏洞扫描结果与供应链证明（SLSA provenance）模拟容器镜像
准入决策。不同来源格式、不同角色权限、并发策略更新下，结论保持一致、
可复现、可解释，且所有操作（含被拒绝操作）可审计。

## 1. 能力总览

| 能力 | 说明 |
| --- | ---|
| 多格式输入 | 镜像清单 `docker-v2` / `oci-index`；扫描结果 `trivy` / `grype`；供应链证明 in-toto Statement v1 / SLSA provenance v1 |
| 严格校验 | 字段缺失、指纹不一致、格式不完整、枚举非法、schema 版本越界均以**可区分的细分原因**拒绝，绝不静默跳过 |
| 策略判定 | 优先级覆盖 + 同级 DENY 优先 + 默认拒绝；命中规则与最终依据完整返回，相同输入结论可复现 |
| 版本快照 | 评估只读取不可变 `PolicySet` 快照；乐观并发控制保证并发更新仅一个成功，其余 409 VERSION_CONFLICT |
| 权限留痕 | 四种权限（评估/更新策略/回滚/读审计）按角色校验；未授权为独立错误大类 UNAUTHORIZED，与策略拒绝可区分 |
| 幂等审计 | 评估以 requestId 为幂等键，并发/重复提交只产生一条审计；失败与未授权也留痕 |

## 2. 支持的输入格式

三类输入均为本地 JSON 文件，通过请求体中的路径指定（见第 6 节）。

### 2.1 镜像清单（`format` 字段区分）

- `docker-v2`：`application/vnd.docker.distribution.manifest.v2+json` 风格
- `oci-index`：`application/vnd.oci.image.index.v1+json` 风格

```json
{
  "format": "docker-v2",
  "reference": "registry.example.com/library/payments:1.4.2",
  "digest": "sha256:<64位十六进制>",
  "labels": {"team": "payments"}
}
```

`reference` 会被拆分为 registry / repository / tag（无 registry 前缀默认 `docker.io`，
无 tag 默认 `latest`）。

### 2.2 扫描结果（`scanner` 字段区分）

- `trivy`：读取 `results[].vulnerabilities[]`（`VulnerabilityID` / `Severity` / `PkgName` / `FixedVersion`）
- `grype`：读取 `matches[].vulnerability` 与 `matches[].artifact`

严重级别取值：`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`（大小写不敏感）。
**任何一条漏洞缺少编号、组件名或级别非法，整个请求被拒绝（INCOMPLETE_ENTRY / ILLEGAL_ENUM_VALUE），
不会静默丢弃该条目。**

### 2.3 供应链证明

in-toto Statement v1 + SLSA provenance v1：`_type` 与 `predicateType` 固定；
`subject[0].digest.sha256` 为绑定的镜像指纹；顶层 `attestationDigest` 为证明自身指纹
（两者都必填）；`predicate.buildDefinition.externalParameters` 中 `repository` /
`revision` 必填，`slsaBuildLevel` 为 0–4 的整数。

### 2.4 指纹一致性

清单 `digest`、扫描报告 `imageDigest`、证明 `subject` 的 sha256 三者必须完全一致，
否则返回 `FINGERPRINT_MISMATCH`（消息中给出期望值与实际值）。三类来源任一文件缺失为
`MISSING_SOURCE`。

## 3. 策略模型：优先级与冲突规则

策略文件示例见 [`examples/policy.json`](examples/policy.json)。

```json
{
  "schemaVersion": 1,
  "rules": [
    {"id": "DENY-HIGH-CRITICAL", "name": "deny-high-or-critical",
     "effect": "DENY", "priority": 100,
     "denyIfSeverityAtLeast": "HIGH", "description": "..."},
    {"id": "ALLOW-TRUSTED", "name": "allow-trusted-source",
     "effect": "ALLOW", "priority": 50,
     "registries": ["registry.example.com"],
     "repositoryPattern": "library/.*|platform/.*",
     "sourceUris": ["https://git.example.com/platform/payments"],
     "minSlsaLevel": 3, "description": "..."}
  ]
}
```

规则匹配条件（全部满足才命中，空条件表示不限制）：

| 字段 | 含义 |
| --- | --- |
| `registries` | registry 白名单 |
| `repositoryPattern` | repository 正则（`matches` 语义，需完全匹配） |
| `sourceUris` | 源码来源精确匹配列表 |
| `builderIds` | 构建方白名单 |
| `minSlsaLevel` | SLSA 等级下限 |
| `maxAllowedSeverity` | 最高漏洞级别**不超过**该值才命中（ALLOW 规则常用） |
| `denyIfSeverityAtLeast` | 最高漏洞级别**达到或超过**该值才命中（DENY 规则常用） |

**冲突解决顺序（确定性，不依赖规则在文件中的位置）：**

1. 收集所有命中的规则；
2. 取命中规则中的**最高优先级层**（priority 越大越高），低优先级规则被覆盖；
3. 最高优先级层内若同时存在 DENY 与 ALLOW，**DENY 生效**（显式拒绝优先）；
   决定性规则在同级 DENY 中按 ruleId 字典序确定；
4. 最高优先级层只有 ALLOW → ALLOW；
5. 没有任何规则命中 → `DENY_NO_MATCH`（默认拒绝）。

判定结果返回：`decision`、`policyVersion`、全部命中 `hits`、`decisiveRuleId`、
`rationale`（人类可读依据，含策略版本），相同输入多次评估结论完全一致。

## 4. 策略版本与兼容范围

- 每条策略集带 `schemaVersion`；服务端接受范围为
  **[1, 1]**（`PolicySet.MIN_SUPPORTED_SCHEMA=1`，`CURRENT_SCHEMA=1`），
  范围外的策略文件以 422 `INVALID_INPUT` 拒绝。
- 每次成功更新分配**单调递增**的版本号；历史版本全部保留。
- **回滚不是恢复旧版本号**，而是把目标历史版本的规则复制为一个新版本发布
  （版本号继续向前），审计上体现“rollback to version N”。
- 更新与回滚都采用乐观并发：请求必须带 `expectedVersion`，与当前版本不一致时
  返回 409 `VERSION_CONFLICT`。
- 评估开始时抓取一次不可变快照，判定全程使用该快照；并发更新不会让一次判定
  看到“半个策略集”。

## 5. 权限模型

调用方身份通过请求头 `X-Actor-Id` 与 `X-Actor-Role` 模拟。

| 角色 | EVALUATE | UPDATE_POLICY | ROLLBACK_POLICY | READ_AUDIT |
| --- | :-: | :-: | :-: | :-: |
| ADMIN | ✓ | ✓ | ✓ | ✓ |
| SECURITY_ENGINEER | ✓ | ✓ | ✓ | ✗ |
| AUDITOR | ✓ | ✗ | ✗ | ✓ |
| SERVICE_ACCOUNT | ✓ | ✗ | ✗ | ✗ |

未授权返回 HTTP 403 与 `errorCategory=UNAUTHORIZED`，与策略判定 DENY（正常业务结论，
HTTP 200，decision 为 DENY/DENY_NO_MATCH）和畸形输入（422 INVALID_INPUT）明确区分。
未授权尝试同样写入审计（operation=`UNAUTHORIZED`）。

## 6. HTTP 接口

| 方法与路径 | 权限 | 说明 |
| --- | --- | --- |
| `POST /api/admission/evaluate` | EVALUATE | 提交三文件路径与 requestId 进行评估 |
| `POST /api/admission/policies` | UPDATE_POLICY | 乐观并发更新策略 |
| `POST /api/admission/policies/rollback` | ROLLBACK_POLICY | 回滚到历史版本 |
| `GET  /api/admission/policies/current` | READ_AUDIT | 查看当前策略 |
| `GET  /api/admission/audit` | READ_AUDIT | 查看全部审计记录 |

评估请求体：

```json
{
  "requestId": "req-001",
  "manifestPath": "examples/manifest.json",
  "scanPath": "examples/scan-trivy.json",
  "provenancePath": "examples/provenance.json"
}
```

错误响应统一形如：`{"errorCategory": "INVALID_INPUT|UNAUTHORIZED|VERSION_CONFLICT",
"message": "[FINGERPRINT_MISMATCH] ... : ..."}`。

输入装配阶段的细分原因（message 前缀，全部属于 INVALID_INPUT）：
`UNREADABLE_FILE`、`MALFORMED_JSON`、`UNSUPPORTED_MANIFEST_FORMAT`、
`MISSING_REQUIRED_FIELD`、`INCOMPLETE_ENTRY`、`FINGERPRINT_MISMATCH`、
`ILLEGAL_DIGEST_FORMAT`、`ILLEGAL_ENUM_VALUE`、`MISSING_SOURCE`。

## 7. 审计与幂等

- 评估审计记录包含：操作者、requestId、镜像指纹、输入摘要（引用/扫描器/漏洞数/
  来源/SLSA）、策略版本、命中规则摘要、最终 decision、决定性规则与依据。
- 相同 `requestId` 的并发或重复提交只评估一次：后续请求回放首次结论（或首次错误），
  审计中只有一条 EVALUATE 记录。
- 策略变更记录旧版本→新版本与说明；失败的变更（版本冲突、策略文件非法）记录
  对应 errorCategory，不改变当前策略。

## 8. 本地验证方法

环境要求：JDK 21、Maven 3.6+。

```bash
# 1) 全量测试（28 个用例：冲突/畸形输入/未授权/并发更新/多格式）
mvn test

# 测试日志中会打印每个用例的评估输入、命中策略与最终判定依据：
#   [evaluate] ... input=image=..., digest=..., vulnCount=..., slsaLevel=...
#   [evaluate] ... matchedRules=ALLOW-LOW-RISK(ALLOW,p5)
#   [evaluate] ... decision=ALLOW decisiveRule=... rationale=...

# 2) 启动服务
mvn spring-boot:run

# 3) 合法镜像评估（默认策略下 MEDIUM 漏洞 => ALLOW）
curl -s -X POST localhost:8080/api/admission/evaluate \
  -H 'Content-Type: application/json' \
  -H 'X-Actor-Id: admin-root' -H 'X-Actor-Role: ADMIN' \
  -d '{"requestId":"smoke-1",
       "manifestPath":"examples/manifest.json",
       "scanPath":"examples/scan-trivy.json",
       "provenancePath":"examples/provenance.json"}'

# 4) 未授权更新（403 UNAUTHORIZED）
curl -i -X POST localhost:8080/api/admission/policies \
  -H 'Content-Type: application/json' \
  -H 'X-Actor-Id: sa-bot' -H 'X-Actor-Role: SERVICE_ACCOUNT' \
  -d '{"expectedVersion":0,"policyJson":"{\"schemaVersion\":1,\"rules\":[]}"}'

# 5) 加载示例策略（版本 0 -> 1）
POLICY=$(python3 -c 'import json;print(json.dumps(open("examples/policy.json").read()))')
curl -s -X POST localhost:8080/api/admission/policies \
  -H 'Content-Type: application/json' \
  -H 'X-Actor-Id: admin-root' -H 'X-Actor-Role: ADMIN' \
  -d "{\"expectedVersion\":0,\"policyJson\":$POLICY,\"comment\":\"load example\"}"

# 6) 回滚 / 查审计
curl -s -X POST localhost:8080/api/admission/policies/rollback \
  -H 'Content-Type: application/json' \
  -H 'X-Actor-Id: admin-root' -H 'X-Actor-Role: ADMIN' \
  -d '{"expectedVersion":1,"targetVersion":0}'
curl -s localhost:8080/api/admission/audit \
  -H 'X-Actor-Id: admin-root' -H 'X-Actor-Role: ADMIN'
```

## 9. 主要代码结构

```
model/       统一领域模型（AdmissionRequest/PolicyRule/PolicySet/EvaluationResult 等）
ingest/      本地多格式读取与统一装配（含指纹交叉校验）
policy/      默认策略、策略文件解析、版本存储（快照+乐观锁）、判定器
auth/        角色、权限与授权服务
audit/       不可变审计记录与幂等审计日志
service/     门面服务：授权→装配→快照判定→审计
web/         REST 接口、DTO、统一错误处理
```
