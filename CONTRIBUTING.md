# 贡献指南

## 开发

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

提交 PR 前请确认：

- 不把网络、凭据、对象存储或数据库依赖带进 `crates/ref-core`。
- 不在 `ThingRef` 中写入 secret、bearer token、个人敏感信息。
- 新增 scheme 时同时提交语法、解析器、安全说明与一致性用例。
- 新增 ContractCard 字段时说明它回答的下游问题；不要为“看起来完整”而加字段。
- 任何会影响 PACT 准入的契约差异，不得只写进 ContractCard；先判断能否编码成 `TypeName` 或 witness token。

## 与 `pact` 的跨仓库变更

1. 在 `pact` 仓库提 spec PR（URI profile、RefBindings、ContractCard、Reference Plane API）。
2. 发布 `pact-ref-spec` 版本（引导阶段用 `SPEC_VERSION` 记录预期）。
3. 在本仓库提实现 PR，并在描述中写明消费的 spec 版本。
4. 一致性测试在两个仓库都跑；跨仓库不做原子合并。

## 提交信息

使用 Conventional Commits，例如：

```text
feat(resolver): add https adapter skeleton
docs(adr): record two-repo topology
fix(core): reject empty reference
```

## 许可证

贡献即同意以 MIT 许可证发布。
