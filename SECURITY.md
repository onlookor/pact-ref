# 安全策略

## 报告漏洞

请通过 GitHub 的 **Private vulnerability reporting** 报告，不要开公开 issue。

报告中请包含：

- 受影响的版本/提交；
- 复现步骤；
- 影响范围（凭据泄露、SSRF、路径穿越、越权解析、日志注入等）；
- 是否涉及 `ThingRef` 中的敏感信息。

## 安全边界

- 本仓库不是 PACT 引擎的信任边界；PACT 的 ACL 与 participant gate 仍由 `pact` 负责。
- 解析器默认拒绝 `userinfo`、未注册 scheme、超长 URI、控制字符。
- `file:` 适配器必须限制根目录与符号链接；`http(s):` 适配器必须做 SSRF 防护（私网、链路本地、云元数据地址、重定向）。
- `ThingRef` 不得包含 bearer token、密钥、个人敏感信息。
- 审计边车默认关闭；开启时只记录 ID、摘要、状态、时间，不记录正文/凭据。

## 支持范围

引导阶段只支持最新 `main`。发布后按 GitHub Releases 的版本支持策略执行。
