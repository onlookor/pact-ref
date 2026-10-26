# git

- 形态：`git://host/repo@commit` 或等价 HTTPS 形式
- 类型：静态取回（不可变 commit）
- 定版：commit hash 必须存在；分支名不作为归档定版
- 安全：只读；禁止在 URL 中携带凭据
- 失败：commit 不存在永久；网络/超时可重试
