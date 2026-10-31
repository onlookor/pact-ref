// witness / compensation 示例域
//
// 场景：一次发布（release_request）只能由 releaser 经 `POST /v1/mutate` 触达上游后，
// 用物化结果（deployment）在 PACT 侧产生 witness token；发布失败时，补偿不是自动 saga，
// 而是由 oncall 以另一张 mutating 卡片显式执行 rollback。
//
// 关键点：
// - refd 只登记 ThingRef 字符串，不写 PACT；witness token 由参与者正常 seed/produce 产生。
// - `failure.compensation` 只是卡片上的提示键，域内准入仍由 gate 决定。

types { release_request; deployment; release_receipt; incident; rollback }

preconditions {
    release_request → deployment;
    deployment → release_receipt;
    incident → rollback
}

gates {
    releaser: consumes release_request, produces deployment;
    reviewer: consumes deployment, produces release_receipt;
    oncall:   consumes incident, produces rollback;
    auditor:  reads release_receipt, reads rollback
}

seed_authority {
    requester: seeds release_request;
    monitor:   seeds incident
}
