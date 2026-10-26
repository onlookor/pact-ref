# https

- 形态：`https://host/path?query#fragment`
- 类型：静态取回（可变位置）
- 定版：归档时要求 `sha256` 或不可变 ETag/version
- 安全：拒绝 userinfo；限制私网、链路本地、云元数据地址；限制重定向；防 DNS 重绑定
- 失败：404/403 永久；超时可重试；digest 不匹配永久
