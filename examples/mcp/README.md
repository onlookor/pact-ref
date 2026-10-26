# MCP 示例

这里放 `mcp-read` 与 `mcp-mutating` 两档 profile 的示例配置。

- `mcp-read`：只读、幂等、结果可物化。
- `mcp-mutating`：有副作用；必须声明幂等键、超时、错误分类、审计与物化策略。

不要只依赖 MCP 的 `readOnlyHint` / `destructiveHint` / `idempotentHint`；它们只是提示，不是契约保证。
