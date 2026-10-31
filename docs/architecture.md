# pact-ref 架构

## 目标

把 PACT token 上的 `ThingRef` 兑现为可解析、可验证、可失败的制品或动态能力，同时不把制品治理塞进 PACT 引擎。

## 非目标

- 不实现 PACT 的协调语义、Counter、Rule-P、GateExpr。
- 不解析 gate，不替 PACT 做准入判定。
- 不直接写 PACT 存储。
- 不把制品正文、凭据或大 JSON 放进 `ThingRef`。

## 组件

```text
participants
   ├── PACT REST/MCP ──► pactd（Counter、token、ThingRef 字符串）
   │
   └── resolve/invoke ──► pact-refd
                              ├─ ref-core        纯类型/trait
                              ├─ ref-resolver    scheme 路由
                              ├─ ref-invoker     动态能力路由
                              ├─ ref-registry    可选发现
                              ├─ ref-auth        principal/授权/撤销
                              ├─ ref-audit       审计边车
                              └─ adapters        http/git/oci/file/mcp
```

## 依赖规则

| 层 | 允许依赖 | 禁止依赖 |
|---|---|---|
| `ref-core` | 标准库、`pact-ref-spec`（纯规范 crate） | 网络、文件、PACT engine/store |
| `ref-resolver` / `ref-invoker` | `ref-core` | 具体 adapter（由装配层注入） |
| adapters | `ref-core` | PACT engine/store、其他 adapter |
| `ref-registry` / `ref-auth` / `ref-audit` | `ref-core` | PACT engine/store |
| `refd` | 上述 crate | PACT store 直写 |
| `ref-client` | `ref-core` | 具体网络实现 |

`ref-auth` 的 JWT 验签只依赖 `jsonwebtoken` 与 `base64`：它不发起网络请求，JWKS 取回由
`refd` 注入的 `JwksSource` 实现承担（`FileJwksSource` 读本地文件，`HttpJwksSource` 用
`ureq`/rustls 走 HTTPS）。网络来源因此不进 `ref-auth`，测试也能注入假源。

`pact-ref-spec` 由 `pact` 仓库维护，无 IO、无网络、无文件系统，可编译到
`wasm32-unknown-unknown`；引导阶段以 `vendor/pact-ref-spec` 只读快照消费，发布后改为纯版本依赖。

## 数据流

### 静态 resolve

1. 参与者从 PACT token / Counter / Archive 获得 `ThingRef`。
2. 参与者调用 `resolve(domain, type, ref, intent)`（主体来自凭据，不在请求体）。
3. `refd` 按 `(domain, type, scheme)` 选择 profile 与 adapter。
4. adapter 返回不透明 handle、digest、media type、contract、expires_at。
5. 参与者验证并消费制品。
6. 参与者通过正常 `seed` / `produce` 产生 witness token 记录结果。

### 动态 invoke（只读，已实现）

1. 参与者确认 ContractCard 的 profile 为 `mcp-read`（`capability.sideEffect = read-only`）。
2. 参与者带 `idempotency_key` 调用 `POST /v1/invoke`；`reference` 必须落在卡片声明的
   `capability.server.id` 之下。
3. `refd` 经 `InvokerRegistry` 路由到 `mcp` adapter，以 JSON-RPC 2.0 `tools/call` 调用上游。
4. 结果按内容寻址写入 `[materialize].dir/<sha256>.json`，返回 `file://` 的 `resultRef`
   与 `sha256:` 的 `resultDigest`；参与者随后用 `/v1/resolve` 读取，并产生新的 witness token。
5. 审计边车记录 ID、摘要、状态、时间，不记录正文/凭据；上游失败记 `status=failed`。
6. `mcp-mutating` 见下节「动态 mutate（写入）」。

### 动态 mutate（写入，已实现）

1. 参与者确认 ContractCard 的 profile 为 `mcp-mutating`（`capability.sideEffect = mutating`），
   且卡片具备 `tool.inputSchemaDigest`、`idempotency`、`result.materialization`、`auth.audience`
   与非空 `failure`。
2. 参与者带 `idempotencyKey` 调用 `POST /v1/mutate`；`reference` 严格等于
   `<capability.server.id>/<capability.tool.name>`，`operation` 等于 `tool.name`。
3. `refd` 先向 `[mutate].journal` 追加 `intent` 并 fsync，再经 `mcp` adapter 调用上游，
   最后追加 `result` 并 fsync；同键同摘要重放结论，同键异摘要 `409`，结果不明 `409`。
4. 成功结果与只读阶段一致地物化为内容寻址静态引用；参与者随后经 `/v1/resolve` 读取并
   以正常 `seed`/`produce` 产生 witness token。
5. 每次写 attempt 两条审计（`intent`/`result`）；`intent` 审计失败不触达上游。
6. 不做自动 saga/补偿；撤销另立写卡片。实现见 `pact` 仓库 `docs/design.md` §9.20，
   witness/compensation 可运行示例见 `examples/witness-compensation/`（`README.md` 给出
   两条路径与离线校验命令，`services/refd/tests/witness_compensation.rs` 为离线回归）。

## Reference Plane API（resolve/describe/invoke/mutate 均已实现）

契约冻结在 `pact` 仓库的 `spec/ref/v1/reference-plane.openapi.yaml`，设计定案见
`docs/thingref-governance.md` §13.6（resolve/describe）、§13.7（只读 invoke）与
§13.8（写入 mutate）。
`refd` 已按该契约实现 resolve/describe/只读 invoke/写入 mutate（2026-10-31）；
`revoke` 仍未实现。

```text
POST /v1/resolve
  { domain, type, reference, intent, expectedDigest?, pactTokenId? }
  -> 200 { contractId, version, mediaType, digest?, expiresAt?, handle? }

POST /v1/describe
  { domain, type, reference }
  -> 200 ContractDescriptor   # 白名单投影，非完整 ContractCard

POST /v1/invoke
  { domain, type, reference, operation, idempotencyKey, input? }
  -> 200 { status: "succeeded", resultRef, resultDigest }   # 仅只读能力

POST /v1/mutate                # 仅 mutating 能力；经幂等台账
  { domain, type, reference, operation, idempotencyKey, input?, pactTokenId? }
  -> 200 { status: "succeeded", resultRef?, resultDigest?, replayed }   # 仅 mutating 能力

GET /healthz, /readyz         # 不带版本，security: []
```

要点：

- 主体来自验证后的凭据 `sub`；请求体不接受 `actor`。
- v1 只接受 URI；`∅`/`null`/Identifier/裸路径 → `400 InvalidReference`。
- 端点 scope（`ref:resolve` / `ref:describe` / `ref:invoke` / `ref:mutate`）与对象 ACL 两层，并集允许、默认拒绝；只读授权不自动升级为写授权。
- `intent=read` 返回 `handle` + `expiresAt`；`intent=verify` 只校验存在性与摘要，禁止返回 `handle`。
- `invoke` 只接受 `capability.sideEffect = read-only`；`mutating` 一律 `403`；上游失败统一
  `502 UpstreamFailure`，不重试、不轮询。
- `mutate` 只接受 `mutating` 能力，先写幂等台账 `intent` 再触达上游；同键同摘要重放、
  同键异摘要 `409 IdempotencyConflict`、结果不明 `409 IdempotencyInDoubt`、满额
  `503 JournalFull`、台账不可用 `500 JournalUnavailable`。
- `describe` 不透出 `metadata.owner|labels|description`、`parties`、`capability.server`、
  `capability.auth.credentialSource`、`resolution.endpoint`。
- 错误统一信封 `{code, message, traceId, retryable, detail?}`；401 与 403 严格区分。
- 每条已认证请求一条审计事件，审计失败 fail-closed（`500 AuditUnavailable`）。

### `refd` 配置与运行

`refd` 只从显式配置启动：命令行第一个参数或环境变量 `REFD_CONFIG` 指向 `refd.toml`。
启动时整体校验配置与全部 ContractCard，任何一项不合规则拒绝启动（fail-closed）。

```toml
[server]
bind = "127.0.0.1:8080"        # v1 无 TLS，只接受回环地址
allow_plaintext = true         # 回环明文必须显式开启

[auth]
mode = "static"                # deny（默认）| static | oidc

[auth.static]
allow = true
token = "changeme"
subject = "alice"
scopes = ["ref:resolve", "ref:describe"]

# mode = "oidc" 时必须提供 [auth.oidc]；jwks_uri 与 jwks_file 恰有一个
# [auth.oidc]
# issuer = "https://idp.example.com"
# audience = "pact-ref"                                        # 默认 pact-ref
# jwks_uri = "https://idp.example.com/.well-known/jwks.json"    # 仅 https，无 userinfo/fragment
# jwks_file = "jwks.json"                                       # 或本地文件，相对配置文件目录
# algorithms = ["RS256", "ES256", "EdDSA"]                      # 默认这三项
# leeway_seconds = 60                                           # 默认 60，上限 60
# cache_ttl_seconds = 300                                       # 默认 300
# timeout_ms = 5000                                             # 默认 5000，仅 jwks_uri 生效

[audit]
path = "audit.jsonl"           # append-only；相对配置文件目录
fail_open = false              # 默认 fail-closed

[adapter.file]
root = "artifacts"             # 所有 file:// 目标必须 canonicalize 到该目录下

[adapter.https]
allowed_hosts = ["artifacts.example.com"]
timeout_ms = 10000

# 动态只读调用（mcp-read）；存在只读能力 profile 时两段都必需
[materialize]
dir = "materialized"           # 必须已存在且为目录；产物为 <sha256>.json
max_bytes = 1048576            # 缺省 1 MiB，上限 16 MiB

[[mcp_servers]]
id = "mcp://tools.example"     # 与卡片 capability.server.id 一致
endpoint = "https://tools.example/mcp"
timeout_ms = 10000             # 上限 30000
bearer_token_env = "TOOLS_TOKEN"  # 可选；设置则必须非空，否则拒绝启动
allow_plaintext = false        # 仅回环主机可设 true

# 动态写调用（mcp-mutating）；存在写能力 profile 时 journal 必需
# [mutate]
# journal = "mutate.jsonl"     # append-only，单写者，逐条 fsync
# max_entries = 10000          # 缺省 10000，1..=1000000，满额 503 JournalFull

[[acl]]
principal = "alice"
domains = ["build"]
types = ["artifact"]
schemes = ["file"]
operations = ["resolve:read", "resolve:verify", "describe", "invoke", "mutate"]

[[profiles]]
domain = "build"
type = "artifact"
card = "cards/build-artifact.yaml"
```

```sh
REFD_CONFIG=deploy/refd.toml cargo run -p pact-refd
```

`/readyz` 只检查配置已加载与审计 sink 可写；OIDC 模式不在启动或就绪探针中访问 JWKS，
取不到密钥只在请求期以 `401` 体现（不让 `refd` 变成 IdP 代理，也不让探针放大网络请求）。

OIDC 行为要点：

- actor 取验证后的 `sub`；`scope` claim（空格分隔字符串或字符串数组）映射端点 scope，
  与对象 ACL 两层判定，缺 scope 返回 `403`。
- 算法白名单 `RS256`/`ES256`/`EdDSA`；`none`、`HS*`、带 `crit` 头部一律拒绝。
- 有 `kid` 按 `kid` + 算法参数选键；无 `kid` 仅在唯一可用密钥时接受。
- JWKS 有界缓存（≤ 64 密钥、`cache_ttl_seconds`）；未知 `kid` 触发一次强制刷新，
  30s 内不重复刷新。
- 任一失败（缺凭据、签名、`iss`/`aud`/`exp`/`nbf`、JWKS 不可用）统一 `401` +
  `WWW-Authenticate: Bearer realm="pact-ref"`，不区分原因。
- 验签在 `tokio::task::spawn_blocking` 中执行，不阻塞 axum 工作线程。

## 与 PACT 的边界

- PACT daemon 永不调用 `refd`。
- `refd` 永不直接写 PACT 状态。
- 证据走 witness token；补偿走 PACT 正常规则。
- token 的 read gate 通过 ≠ 制品 ACL 通过；两边都要满足。

## 引导阶段

当前 crate 已包含可运行的 `refd` 与 `file`/`https` adapter；其余 adapter 仍是占位。
CI 已覆盖 fmt、clippy、test、docs 与依赖审计。
规范层（`pact-ref-spec` 与 `spec/ref/v1/`）已在 `pact` 仓库落地，本仓库以 vendored 快照消费。
下一步：

1. ~~在 `pact` 仓库抽取 `pact-ref-spec` 与 `spec/ref/v1/`，并把本仓库切换到发布版本。~~
   已完成抽取与快照消费；待规范发布注册表后切换为纯版本依赖。
2. ~~实现 `refd` 的 `/v1/resolve` 与 `/v1/describe`。~~ 已完成（2026-10-31）：`deny`/`static` 认证、scope + 对象 ACL、审计 fail-closed、传输约束与错误信封；14 项集成测试覆盖主要分支。
3. 实现 https/file/git/oci adapter 与 SSRF/路径穿越防护。`file` 与 `https` 已完成；
   `git`/`oci` 仍待实现。
4. ~~实现 `mcp-read` profile 与结果物化。~~ 已完成（2026-10-31）：`POST /v1/invoke`、
   只读闸门、引用归属校验、`mcp` adapter 的 JSON-RPC `tools/call`、内容寻址物化与
   启动 fail-closed（`[materialize]` / `[[mcp_servers]]`）。
   ~~`mcp-mutating`（FR37/D53）实现待做。~~ 已完成（2026-10-31）：`POST /v1/mutate`、
   幂等台账（intent/result 两阶段 fsync、重放、`409`、`503 JournalFull`）、两阶段审计；
   witness/compensation 示例与离线回归见 `examples/witness-compensation/`。
5. 加入一致性测试与审计边车；`refd` 审计已落地，conformance runner 仍是骨架。
6. ~~实现 OIDC（JWT/JWKS）验证器。~~ 已完成（2026-10-31）：`ref-auth` 的
   `OidcAuthenticator` + `JwksSource`，`refd` 的 `[auth.oidc]` 与
   `FileJwksSource`/`HttpJwksSource`；算法白名单、`iss`/`aud`/`exp`/`nbf`、未知 `kid`
   限频刷新、统一 401。单测 11 项 + 集成测试 3 项。
