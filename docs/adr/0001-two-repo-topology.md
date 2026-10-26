# ADR 0001：两个活跃仓库 + 可选一致性仓库

- 状态：接受
- 日期：2026-10-26

## 背景

物引治理平面需要网络、凭据、对象存储、注册表、审计和多种 scheme 适配器；这些依赖和威胁模型与 PACT 协调内核不同。把治理平面放进 `pact` 仓库会扩大内核依赖、CI 时间和安全面。

## 决策

- `pact` 仓库：参考实现、母本/文档、纯 `pact-ref-spec`、`spec/ref/v1/`、离线 lint。
- `pact-ref` 仓库：治理服务、适配器、registry、auth、audit、SDK、conformance。
- 第三方实现出现后，再拆 `pact-ref-conformance`。
- 跨仓库用发布版本衔接，不用 git submodule，不做跨仓库原子合并。

## 后果

正面：

- PACT 内核保持小、可审计、单二进制形态。
- 治理平面独立发布，适配器可快速演进。
- 权限、CODEOWNERS、项目板、发布列车更简单。

负面：

- 需要维护 spec 兼容矩阵。
- 跨仓库变更需要两段式 PR。
- 本地开发需要同时 checkout 两个仓库。

## 缓解

- `SPEC_VERSION` 记录消费版本。
- spec 变更先合入 `pact`，再发布，再在本仓库实现。
- 一致性测试覆盖 spec 与实现。
