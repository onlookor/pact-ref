# pact-ref 运维

## 配置（规划）

| 变量 | 作用 | 默认 |
|---|---|---|
| `PACT_REF_BIND` | 监听地址 | `127.0.0.1:8090` |
| `PACT_REF_SPEC_VERSION` | 消费的 spec 版本 | 由 `SPEC_VERSION` 决定 |
| `PACT_REF_AUTH_MODE` | `deny` / `oidc` / `test` | `deny` |
| `PACT_REF_AUDIT` | `off` / `memory` / `file` | `off` |
| `PACT_REF_RETENTION` | 审计/缓存保留期 | 由 ContractCard 决定 |
| `PACT_REF_ROOT` | `file:` adapter 根目录 | 未设置则禁用 |

## 健康检查（规划）

- `GET /healthz`：进程存活。
- `GET /readyz`：spec 加载、auth 装配、resolver 注册完成。
- `GET /v1/describe/{ref}`：ContractCard 投影。

## 安全

- 默认 `auth=deny`，防止忘记装配授权器。
- `file:` adapter 必须限制根目录、拒绝符号链接逃逸。
- `http(s):` adapter 必须限制私网/链路本地/云元数据地址、重定向与 DNS 重绑定。
- 凭据只从 broker / 环境注入，不写入 `ThingRef`，不写入审计。
- 审计默认关闭；开启时只记录 ID、摘要、状态、时间。

## 规范快照

- `pact-ref-spec` 的 canonical 源在 `pact` 仓库 `crates/pact-ref-spec`。
- 同步：`scripts/sync-spec.sh --source <path-to-pact-ref-spec>`；脚本会复制源码并写入
  `vendor/pact-ref-spec-source.json`（名称、版本、内容摘要）。
- 漂移检查：`scripts/sync-spec.sh --source <path> --check`；发布前必须通过，CI 在能访问
  canonical 源时也应执行。
- 不要直接编辑 `vendor/pact-ref-spec`；规范发布到注册表后删除快照，依赖改为纯 `version`。

## 部署

- Docker：`deploy/docker/Dockerfile`，构建前可用 `deploy/docker/build.sh` 打包镜像
  （上下文为仓库根，vendored spec 已包含在镜像构建上下文中）。
- systemd：`deploy/systemd/pact-refd.service`。
- 与 `pactd` 分开部署；不要在同一进程内运行。
- 治理平面不可用时，PACT 协调仍可继续；参与者显式失败或走补偿。

## 发布

- spec、服务、客户端独立版本。
- 破坏性变更必须提供兼容窗口或迁移说明。
- 发布物附 checksums 与 SBOM。
