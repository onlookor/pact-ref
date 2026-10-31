# pact-ref

PACT 的**物引治理平面**：把 token 上的 `ThingRef` 兑现为可解析、可验证、可失败的制品或动态能力。

本仓库是 `pact` 参考实现的伴生项目，不是 PACT 引擎的一部分。边界原则：

> PACT daemon 永不调用治理平面；治理平面也永不直接写 PACT 状态。参与者是唯一的桥。

## 状态

**可用（v1，2026-10-31）**。`pact-refd` 已实现 HTTP 服务与一致性用例：

- 端点：`GET /healthz`、`GET /readyz`、`POST /v1/resolve`、`POST /v1/describe`、`POST /v1/invoke`、`POST /v1/mutate`。
- 认证：`deny` / 静态令牌（scope + ACL）/ OIDC（JWT + JWKS 文件或 HTTPS）；审计 append-only 且 fail-closed。
- adapter：`file`、`https`、`git`（仅 `git+https`）、`oci`、`mcp`（只读 `tools/call` 与 mutating）。
- 一致性：`conformance/runner` 驱动 `conformance/cases/**/*.yaml`，当前覆盖 `entry/` 23 例。

尚未实现：`revoke`、可选注册表（`ref-registry` 仅有内存实现，未接入 `refd`），以及
`resolve`/`invoke` 数据面 conformance 用例（依赖 adapter 假服务方案）。`/v1/resolve` 与
`/v1/describe` 仍只接受 URI，Identifier 返回 `400 InvalidReference`。

规范层已抽取为 `pact` 仓库的 `pact-ref-spec` 纯 crate 与 `spec/ref/v1/` 正文。本仓库
以 `0.1.0` + `vendor/pact-ref-spec` 只读快照的方式消费，`ref-core` 直接 re-export 规范类型，
不再自建一套校验。工作区共 175 项测试，覆盖引用分类、规范消费、适配器、认证、审计、
端点集成、示例与一致性用例。

## 它解决什么

`ThingRef` 本身只是一个字符串。真正要回答的是：

- 下游拿到 ref 后，怎么找到制品？
- 找到的是不是生产者承诺的那一版？
- 凭什么相信它？谁有权取？
- 上游 token 已消费/归档后，它还在不在？
- 如果是 API / MCP 调用，副作用、幂等、超时和结果物化怎么算？

本仓库负责这些问题的**通道、契约、信任与时效**；PACT 内核继续只负责协调语义，不解析 `ThingRef`。

## 仓库结构

```text
crates/ref-core/       纯类型与 trait：引用形态、请求/响应、错误、策略接口
crates/ref-resolver/   resolve SPI 与适配器注册表
crates/ref-invoker/    invoke SPI 与动态能力
crates/ref-registry/   可选发现与 ContractCard 索引
crates/ref-auth/       principal、授权、audience、撤销
crates/ref-audit/      调用/访问审计边车
crates/ref-client/     参与者 SDK 门面
services/refd/         服务二进制
adapters/              http / git / oci / file / mcp 适配器骨架
conformance/           一致性用例与 runner 骨架
examples/              RefBindings、ContractCard、MCP 配置示例
vendor/                pact-ref-spec 只读快照（含来源与内容摘要）
scripts/               spec 同步与漂移检查脚本
deploy/                Docker / systemd 模板
docs/                  架构、运维、ADR、scheme 说明
```

## 与 PACT 的关系

- `pact` 仓库持有母本、参考实现，以及 `pact-ref-spec` 纯 crate 与 `spec/ref/v1/`（URI profile、
  RefBindings 与 ContractCard schema、Reference Plane OpenAPI）。
- 本仓库消费 `pact-ref-spec` `0.1.0`；引导阶段使用 `vendor/pact-ref-spec` 只读快照，
  规范发布到注册表后删除快照、只留版本号。
- 规范变更走 `scripts/sync-spec.sh --source <path>`，`--check` 用于检测漂移。
- 本仓库不依赖 `pact-engine`、`pact-store`，也不向 PACT 存储直写。
- 解析成功/失败由参与者通过正常的 `seed` / `produce` 产生 witness token 记录。

设计背景见 `pact` 仓库的 `docs/thingref-governance.md`。

## 快速开始

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p pact-refd -- services/refd/refd.toml
```

`pact-refd` 以位置参数读取配置路径（或环境变量 `REFD_CONFIG`）；配置缺失或非法时启动即失败
（fail-closed），不监听端口。

## 参考平面 API

```text
POST /v1/resolve   { domain, type, reference, intent } -> { handle, digest, media_type, contract_id, version, expires_at }
POST /v1/describe  { reference } -> ContractCard 投影
POST /v1/invoke    { domain, type, reference, operation, idempotency_key, input? } -> { status, result_ref?, result_digest?, error? }
POST /v1/mutate    { domain, type, reference, operation, idempotency_key, input?, pact_token_id? } -> { status, replayed, result_ref?, result_digest?, error? }
GET  /healthz | /readyz
```

`revoke` 未实现：v1 不提供撤销端点。

## 安全

- `ThingRef` 会进入 PACT 事件日志、Archive、CPN 颜色集和读审计；**不得包含凭据或密钥**。
- 解析器默认拒绝 `userinfo`、未注册 scheme、超长 URI；对 `file:`、`http(s):` 做 SSRF/路径穿越防护。
- 发现漏洞请按 `SECURITY.md` 私下报告，不要开公开 issue。

## 许可证

MIT，见 `LICENSE`。
