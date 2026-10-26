//! 引导阶段服务入口：只打印装配状态，不监听端口。
//!
//! 后续接入 Reference Plane API：
//! resolve / invoke / describe / revoke。

use pact_ref_core::API_VERSION;

fn main() {
    let resolvers = pact_ref_resolver::ResolverRegistry::new();
    let invokers = pact_ref_invoker::InvokerRegistry::new();
    let registry = pact_ref_registry::MemoryRegistry::new();
    let audit = pact_ref_audit::MemoryAuditSink::new();
    let _authorizer = pact_ref_auth::DenyAllAuthorizer;

    println!("pact-refd bootstrap");
    println!("api_version={API_VERSION}");
    println!("resolvers={:?}", resolvers.schemes());
    println!("invokers={:?}", invokers.schemes());
    println!("registry_entries={}", registry.len());
    println!("audit_events={}", audit.events().len());
    println!("No endpoints are wired yet. See docs/architecture.md.");
}
