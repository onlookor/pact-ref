# Vendored `pact-ref-spec`

本目录是 `pact-ref-spec` 0.1.0 的**只读快照**。`pact-ref` 在规范 crate 正式发布到包注册表之前，
以 `version + path` 方式消费这个快照；这样 CI 与容器构建不需要检出另一个仓库。

规则：

1. 不要直接编辑本目录。修改规范请改 canonical `pact-ref-spec`，再同步过来。
2. 同步使用 `scripts/sync-spec.sh --source <canonical-crate-dir>`；脚本会重写
   `vendor/pact-ref-spec-source.json` 的内容摘要。
3. CI 只校验本地工作区；跨仓库漂移由发布前的 `scripts/sync-spec.sh --source <dir> --check` 检查。
4. 规范 crate 发布到包注册表后，删除本目录，把 `Cargo.toml` 中的依赖改为纯 `version`。
