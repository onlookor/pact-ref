# mcp

- 形态：`mcp://server-id/tool@version#schema=sha256:...`
- 类型：动态调用
- 两档：
  - `mcp-read`：read-only、幂等、结果可物化。
  - `mcp-mutating`：显式声明副作用、幂等键、超时、错误分类、审计与物化策略。
- 安全：server identity + trust anchor；auth audience；凭据从 broker 取；不把 bearer token 放进 `ThingRef`。
- 失败：超时按幂等键重试；认证/工具不存在永久；业务失败按 ContractCard 分类。
