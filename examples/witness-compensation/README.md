# witness / compensation 示例

演示治理 §13.8.7 的两条边界：

- **witness**：写成功后的物化结果如何回到 PACT 侧，成为一枚正常 token。
- **compensation**：写失败后**不会**自动补偿；补偿是另一张 `mutating` 卡片，由域内规则显式调用。

## 文件

| 路径 | 作用 |
|---|---|
| `cards/release-deploy.yaml` | `release/deploy@1`，`mcp-mutating`；`failure` 含保留键 `compensation` |
| `cards/release-rollback.yaml` | `release/rollback@1`，补偿能力，同样走 `/v1/mutate` |
| `bindings/release.refs.yaml` | `release` 域的 RefBindings：类型 → scheme/contract/可见性、`declarationDigest` |
| `domain.pact` | `release` 域：`release_request → deployment → release_receipt`、`incident → rollback` |
| `refd.toml` | `refd` 配置：两个 profile、`[[mcp_servers]]`、`[materialize]`、`[mutate]` |
| `materialized/` | 物化结果目录（内容寻址 `<sha256>.json`） |

离线校验（在 `pact` 仓库执行；示例文件名是 `domain.pact`，需显式 `--name release`）：

```bash
pact analyze /path/to/examples/witness-compensation/domain.pact
pact ref digest --name release /path/to/examples/witness-compensation/domain.pact
pact ref lint \
  --bindings /path/to/examples/witness-compensation/bindings \
  --contracts /path/to/examples/witness-compensation/cards \
  --declaration /path/to/examples/witness-compensation/domain.pact \
  --name release --strict
```

改动 `domain.pact` 语义面后，用 `pact ref digest --name release` 更新
`bindings/release.refs.yaml` 的 `metadata.declarationDigest`。卡片与绑定的结构校验
另由 `pact-ref` 的 `crates/ref-core/tests/examples.rs` 覆盖。

## 成功路径（witness）

1. 参与者调用 `POST /v1/mutate`：

   ```json
   {
     "domain": "release",
     "type": "deployment",
     "reference": "mcp://ops.example.com/release-server/release.deploy",
     "operation": "release.deploy",
     "idempotencyKey": "release-42-attempt-1",
     "input": { "releaseId": "42", "version": "2026.10.31" }
   }
   ```

2. `refd` 依次写台账 `intent` → 调用上游 → 物化 → 写台账 `result`，
   返回 `resultRef`（`file://…/<64hex>.json`）与 `resultDigest`（`sha256:…`）。
3. 参与者用 `resultRef` 调 `POST /v1/resolve`（`intent=read`）取得读句柄；
   此时已确认产物可读且摘要一致。
4. 参与者在 PACT 侧正常 `seed`/`produce`，把 `resultRef` 作为 `thing_ref` 写入
   `deployment` token。`refd` 不写 PACT，Counter/Archive 只由 PACT 引擎推进。
5. `reviewer` 消费 `deployment` 产出 `release_receipt`。

重放同一 `idempotencyKey` 与相同 `input` 返回原结论（`replayed: true`），
不会再触达上游；同键异摘要 `409 IdempotencyConflict`。

## 失败路径（compensation）

1. 上游失败时 `POST /v1/mutate` 返回 `502 UpstreamFailure`，台账记录失败结论。
2. **不会**自动调用 `failure.compensation` 指向的 `release.rollback`；
   `refd` 不做 saga、不猜测、不重试。
3. 域内规则决定是否补偿：`oncall` 在 `incident` 存在时，用另一张卡片显式调用
   `POST /v1/mutate`（`type: rollback`、`operation: release.rollback`、新的幂等键）。
4. 补偿本身失败由域负责（可选再立补偿卡片），`refd` 只保证每次写都有
   `intent`/`result` 两条审计。

## 运行

```bash
# 1) 校验卡片与绑定
cargo test -p pact-ref-core --test examples

# 2) 启动治理平面（示例 token 仅本地演示）
cargo run -p pact-refd -- examples/witness-compensation/refd.toml

# 3) 调用（需把 endpoint 换成真实 MCP 服务）
curl -sS -X POST http://127.0.0.1:18090/v1/mutate \
  -H 'authorization: Bearer release-demo-token' \
  -H 'content-type: application/json' \
  -d '{"domain":"release","type":"deployment",
       "reference":"mcp://ops.example.com/release-server/release.deploy",
       "operation":"release.deploy","idempotencyKey":"release-42-attempt-1",
       "input":{"releaseId":"42"}}'
```

离线回归由 `services/refd/tests/witness_compensation.rs` 覆盖：用本地假 MCP
服务替换 `mcp://ops.example.com/release-server`，验证「成功 → resolve → 可写入
PACT 的 witness 前置条件」与「失败 → 不自动补偿 → 显式补偿成功」。

## 边界

- **`refd` 不写 PACT**：witness token 必由参与者 `seed`/`produce` 产生。
- **无自动 saga**：`failure.compensation` 只是保留键；补偿失败由域语义承担。
- **无 `revoke`**：撤销若需要，是另一张写卡片。
- **钉版**：`resultRef` 是 `file://…/<64hex>.json`，不含 `sha256:` 片段，
  因此本示例的 RefBindings 用 `pinning: optional`。若域要求
  `required-at-archive`，参与者应在写入 PACT 前把引用写成
  `resultRef#sha256=<resultDigest 去掉 sha256: 前缀>`，让归档钉版可识别。
- **凭据**：示例 token 与 `[[mcp_servers]]` endpoint 均为占位，部署前必须替换；
  上游 bearer 只从配置注入，不进入请求体、引用或审计。
