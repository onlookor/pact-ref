# 一致性用例

用例由 `conformance/runner` 执行：

```bash
cargo test -p pact-ref-conformance-runner          # 随 workspace 回归
cargo run -p pact-ref-conformance-runner           # 默认读取本目录
cargo run -p pact-ref-conformance-runner -- --cases conformance/cases
```

退出码：全部通过 `0`；存在失败用例 `1`；参数/读取/解析错误 `2`。

## 目录

```text
cases/
  entry/            # 入口票面校验（validate_entry）：已落地 23 例
  uri-profile/      # 规划中
  ref-bindings/     # 规划中
  contract-card/    # 规划中
  resolve-https/    # 规划中（待 adapter 假服务方案）
  resolve-file/     # 规划中（待 adapter 假服务方案）
  mcp-read/         # 规划中（待 adapter 假服务方案）
```

## 用例格式

一个文件一个用例：

```yaml
apiVersion: conformance.pact-ref/v1
kind: EntryCase
name: entry/example
spec:
  type: design                 # 对应的 PACT 类型名
  instance: proj_x             # 可选：实例级绑定
  reference:                   # 三态：missing / "null" / value
    state: value
    value: https://example.com/a
  bindings:                    # 可选：RefBindings，形状与 pact.ref/v1 一致
    apiVersion: pact.ref/v1
    kind: RefBindings
    metadata:
      domain: demo
    spec:
      types:
        design:
          ref:
            schemes: [https]
expect:
  outcome: ok                  # ok / error
  reference: https://example.com/a   # ok 时缺省表示期望 ∅
  # error: InvalidThingRef     # error 时必填，取值与 pact-http 入口错误码对齐
  # reason: UserInfoNotAllowed # 可选：SpecError 变体名，区分同一错误码的不同原因
```

`expect.error` 取值：`ThingRefMissing`、`ThingRefRequired`、`ThingRefUnpinned`、
`InvalidThingRef`。

## 已覆盖（`entry/`）

- 三态：字段缺失、显式 `null`、字符串；以及 `required` 下的 `null`。
- URI profile：scheme 小写归一、POSIX/Windows 裸路径、密码型 userinfo 拒绝、
  纯用户名放行（`git+ssh://git@…`）、控制字符、空串、默认/绑定长度上限。
- Identifier 文法：非法字符拒绝、无绑定时放行、绑定未放行时拒绝。
- RefBindings 策略：`required`、`schemes`、`onUnknownScheme`
  （`reject` / `allow` / `treat-as-identifier`）、`allowIdentifier`、`maxLength`、
  `value`、`pinning: required`。

## 未覆盖

- resolve / invoke 数据面行为（https、file、git、oci、mcp adapter 的网络与物化），
  待确定 adapter 假服务方案后补充。
- ContractCard 校验与审计事件形状。

## 安全负例

`entry/` 中的负例覆盖 userinfo、裸路径、控制字符、危险/未知 scheme、超长票面；
路径穿越与 SSRF 属于 resolve 阶段，随对应目录补充。
