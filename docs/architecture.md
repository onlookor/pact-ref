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

### 动态 invoke

1. 参与者确认 ContractCard 的 profile（`mcp-read` 或 `mcp-mutating`）。
2. 参与者带 `idempotency_key` 调用 `invoke(...)`。
3. adapter 执行调用，返回状态与可物化结果。
4. 需要长期依赖时，参与者把结果物化为静态 ref，再产生新 token。
5. 审计边车记录 ID、摘要、状态、时间，不记录正文/凭据。

## Reference Plane API（已实现）

契约冻结在 `pact` 仓库的 `spec/ref/v1/reference-plane.openapi.yaml`，设计定案见
`docs/thingref-governance.md` §13.6。首版只含 resolve/describe；invoke/revoke 随动态阶段另行定案。
`refd` 已按该契约实现（2026-10-31）。

```text
POST /v1/resolve
  { domain, type, reference, intent, expectedDigest?, pactTokenId? }
  -> 200 { contractId, version, mediaType, digest?, expiresAt?, handle? }

POST /v1/describe
  { domain, type, reference }
  -> 200 ContractDescriptor   # 白名单投影，非完整 ContractCard

GET /healthz, /readyz         # 不带版本，security: []
```

要点：

- 主体来自验证后的凭据 `sub`；请求体不接受 `actor`。
- v1 只接受 URI；`∅`/`null`/Identifier/裸路径 → `400 InvalidReference`。
- 端点 scope（`ref:resolve` / `ref:describe`）与对象 ACL 两层，并集允许、默认拒绝。
- `intent=read` 返回 `handle` + `expiresAt`；`intent=verify` 只校验存在性与摘要，禁止返回 `handle`。
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
mode = "static"                # deny（默认）| static；oidc 启动即失败

[auth.static]
allow = true
token = "changeme"
subject = "alice"
scopes = ["ref:resolve", "ref:describe"]

[audit]
path = "audit.jsonl"           # append-only；相对配置文件目录
fail_open = false              # 默认 fail-closed

[adapter.file]
root = "artifacts"             # 所有 file:// 目标必须 canonicalize 到该目录下

[adapter.https]
allowed_hosts = ["artifacts.example.com"]
timeout_ms = 10000

[[acl]]
principal = "alice"
domains = ["build"]
types = ["artifact"]
schemes = ["file"]
operations = ["resolve:read", "resolve:verify", "describe"]

[[profiles]]
domain = "build"
type = "artifact"
card = "cards/build-artifact.yaml"
```

```sh
REFD_CONFIG=deploy/refd.toml cargo run -p pact-refd
```

`/readyz` 只检查审计 sink 可写；`[auth] mode = oidc` 尚未实现，启动即报错而不是降级为匿名。

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
4. 实现 `mcp-read` profile 与结果物化。
5. 加入一致性测试与审计边车；`refd` 审计已落地，conformance runner 仍是骨架。
6. 实现 OIDC（JWT/JWKS）验证器；当前 `[auth] mode = oidc` 启动即失败。
