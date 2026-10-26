# 一致性用例

规划目录：

```text
cases/
  uri-profile/
  ref-bindings/
  contract-card/
  resolve-https/
  resolve-file/
  mcp-read/
```

每个用例至少包含：

- 输入票面与 RefBindings/ContractCard；
- 期望分类（URI / Identifier / ∅）；
- 期望 resolve/invoke 结果或错误类别；
- 安全负例（userinfo、超长、危险 scheme、路径穿越、SSRF）。
