## 变更说明

<!-- 说明为什么改、改了什么、影响谁 -->

## 类型

- [ ] spec / schema 变更（需要 `pact` 仓库对应 PR）
- [ ] resolve / invoke / adapter
- [ ] auth / audit / 安全
- [ ] 文档 / 示例
- [ ] 仅引导/脚手架

## 兼容性

- [ ] 不改变线上 API
- [ ] 改变线上 API（已说明兼容窗口/迁移）
- [ ] 改变 ContractCard / RefBindings 字段

消费的 spec 版本：`SPEC_VERSION = ______`

## 检查

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] 没有把网络/凭据/存储依赖带进 `ref-core`
- [ ] 没有把 secret / bearer token / 个人敏感信息写进 `ThingRef`
- [ ] 新增 scheme / ContractCard 字段有安全说明与一致性用例
- [ ] 文档已更新
