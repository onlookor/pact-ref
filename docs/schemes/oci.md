# oci

- 形态：`oci://registry/repo@sha256:...`
- 类型：静态取回（不可变 digest）
- 定版：digest 必须存在；tag 不作为归档定版
- 安全：凭据从 broker 取；限制 registry 白名单
- 失败：manifest/blob 不存在永久；网络/超时可重试
