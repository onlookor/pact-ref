# 治理

## 范围

本仓库治理的是“物引如何被兑现”：scheme、ContractCard、resolver/invoker、registry、auth、audit。PACT 的协调语义、母本和参考实现仍在 `pact` 仓库。

## 决策类型

| 类型 | 决策方式 |
|---|---|
| 日常实现、适配器、文档 | 维护者 PR 审阅，至少 1 名 code owner |
| 新 scheme | 提交 scheme proposal issue；说明语法、解析器、安全、一致性测试；2 名维护者批准 |
| ContractCard 字段变更 | 提交 contract card proposal；说明下游问题与兼容性；2 名维护者批准 |
| Reference Plane API 变更 | 先在 `pact` spec 变更，再在本仓库实现；需要跨仓库审阅 |
| 安全策略/凭据处理 | `@org/security` 审阅；不得以“方便”为由绕过 |

## 维护者

引导阶段由项目发起人担任临时维护者；团队建立后按 `CODEOWNERS` 分配。

## 版本与兼容

- spec 用语义化版本；Parser/Resolver 必须声明消费的 spec 版本。
- 服务与客户端独立版本；破坏性变更必须提供兼容窗口或迁移说明。
- 跨仓库变更不做原子合并；用发布标签衔接。

## 反模式

- 引擎侧 fetch / invoke / 存在性校验。
- 把内容、二进制、大 JSON、密钥塞进 `ThingRef`。
- 让 PACT gate 读 `ThingRef` 做内容/版本判定。
- 强制全局唯一注册表或“一个 scheme 统一所有制品”。
- 动态 ref 不物化就成为 Archive 终态。
