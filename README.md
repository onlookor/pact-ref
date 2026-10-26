# pact-ref

PACT 的**物引治理平面**：把 token 上的 `ThingRef` 兑现为可解析、可验证、可失败的制品或动态能力。

本仓库是 `pact` 参考实现的伴生项目，不是 PACT 引擎的一部分。边界原则：

> PACT daemon 永不调用治理平面；治理平面也永不直接写 PACT 状态。参与者是唯一的桥。

## 状态

引导阶段（bootstrap）。仓库结构、纯类型/trait 骨架、示例、部署模板与 GitHub CI 已就绪；
`pact-refd` 目前只打印装配状态，尚未实现 HTTP 服务、真实适配器与一致性用例。
当前 13 个单元测试覆盖引用分类、scheme 路由、注册表、授权、审计与客户端门面。

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
deploy/                Docker / systemd 模板
docs/                  架构、运维、ADR、scheme 说明
```

## 与 PACT 的关系

- `pact` 仓库持有母本、参考实现，以及将来的 `pact-ref-spec` 纯 crate 与 `spec/ref/v1/`。
- 本仓库消费 `pact-ref-spec` 的发布版本；引导阶段先用 `SPEC_VERSION` 记录预期版本。
- 本仓库不依赖 `pact-engine`、`pact-store`，也不向 PACT 存储直写。
- 解析成功/失败由参与者通过正常的 `seed` / `produce` 产生 witness token 记录。

设计背景见 `pact` 仓库的 `docs/thingref-governance.md`。

## 快速开始

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p pact-refd
```

`pact-refd` 当前只打印引导信息，不监听端口。

## 最小参考平面 API（规划）

```text
resolve(domain, type, ref, actor, intent) -> { handle, digest, media_type, contract_id, version, expires_at }
invoke(domain, type, ref, actor, operation, input, idempotency_key) -> { status, result_ref?, result_digest?, error? }
describe(ref) -> ContractCard
revoke(ref, actor, reason) -> {}
```

## 安全

- `ThingRef` 会进入 PACT 事件日志、Archive、CPN 颜色集和读审计；**不得包含凭据或密钥**。
- 解析器默认拒绝 `userinfo`、未注册 scheme、超长 URI；对 `file:`、`http(s):` 做 SSRF/路径穿越防护。
- 发现漏洞请按 `SECURITY.md` 私下报告，不要开公开 issue。

## 许可证

MIT，见 `LICENSE`。
