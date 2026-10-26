# Scheme 注册表

新增 scheme 必须同时提交：

- 语法与允许的 authority/path；
- 解析器或调用器实现；
- 安全说明（SSRF、路径穿越、凭据、重定向、DNS 重绑定）；
- 定版策略（digest / commit / version）；
- 一致性用例。

| scheme | 类型 | 状态 | 说明 |
|---|---|---|---|
| `https` | 静态/取回 | 骨架 | 可变位置；归档需 digest/ETag |
| `git` | 静态/取回 | 骨架 | 建议用 commit 定版 |
| `oci` | 静态/取回 | 骨架 | 建议用 digest 定版 |
| `file` | 静态/取回 | 骨架 | 仅限共享根目录；拒绝 symlink 逃逸 |
| `mcp` | 动态/调用 | 骨架 | 两档 profile：`mcp-read` / `mcp-mutating` |

未注册 scheme 默认拒绝。`Identifier`（无 scheme）不进入 scheme 路由，必须由 RefBindings 或上游上下文解析。
