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
| `ref-core` | 仅标准库 | 网络、文件、PACT engine/store |
| `ref-resolver` / `ref-invoker` | `ref-core` | 具体 adapter（由装配层注入） |
| adapters | `ref-core` | PACT engine/store、其他 adapter |
| `ref-registry` / `ref-auth` / `ref-audit` | `ref-core` | PACT engine/store |
| `refd` | 上述 crate | PACT store 直写 |
| `ref-client` | `ref-core` | 具体网络实现 |

## 数据流

### 静态 resolve

1. 参与者从 PACT token / Counter / Archive 获得 `ThingRef`。
2. 参与者调用 `resolve(domain, type, ref, actor, intent)`。
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

## Reference Plane API（规划）

```text
resolve(domain, type, ref, actor, intent) -> {
  handle | bytes | stream,
  digest, media_type,
  contract_id, version,
  expires_at
}

invoke(domain, type, ref, actor, operation, input, idempotency_key) -> {
  status,
  result_ref?, result_digest?,
  error?
}

describe(ref) -> ContractCard
revoke(ref, actor, reason) -> {}
```

## 与 PACT 的边界

- PACT daemon 永不调用 `refd`。
- `refd` 永不直接写 PACT 状态。
- 证据走 witness token；补偿走 PACT 正常规则。
- token 的 read gate 通过 ≠ 制品 ACL 通过；两边都要满足。

## 引导阶段

当前 crate 只定义纯类型、trait 和占位 adapter；CI 已覆盖 fmt、clippy、test、docs 与依赖审计。
下一步：

1. 在 `pact` 仓库抽取 `pact-ref-spec` 与 `spec/ref/v1/`，并把本仓库切换到发布版本。
2. 实现 `refd` 的 resolve/describe 端点。
3. 实现 https/file/git/oci adapter 与 SSRF/路径穿越防护。
4. 实现 mcp-read profile 与结果物化。
5. 加入一致性测试与审计边车。
