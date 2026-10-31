//! 参与者 SDK 门面。
//!
//! 底层 resolver / invoker 由调用方注入；本 crate 不绑定具体网络实现。

use pact_ref_core::{
    Invocation, InvokeRequest, Invoker, ReferenceError, Resolution, ResolveRequest, Resolver,
};

/// 组合 resolve 与 invoke 的轻量门面。
pub struct Client<R, I> {
    resolver: R,
    invoker: I,
}

impl<R, I> Client<R, I> {
    pub fn new(resolver: R, invoker: I) -> Self {
        Self { resolver, invoker }
    }
}

impl<R: Resolver, I: Invoker> Client<R, I> {
    pub fn resolve(&self, request: &ResolveRequest) -> Result<Resolution, ReferenceError> {
        self.resolver.resolve(request)
    }

    pub fn invoke(&self, request: &InvokeRequest) -> Result<Invocation, ReferenceError> {
        self.invoker.invoke(request)
    }
}

#[cfg(test)]
mod tests {
    use super::Client;
    use pact_ref_core::{
        Invocation, InvocationStatus, InvokeRequest, Invoker, ReferenceError, ReferenceForm,
        Resolution, ResolveRequest, Resolver,
    };

    struct FakeResolver;

    impl Resolver for FakeResolver {
        fn scheme(&self) -> &'static str {
            "https"
        }

        fn resolve(&self, request: &ResolveRequest) -> Result<Resolution, ReferenceError> {
            Ok(Resolution {
                contract_id: "demo/artifact".to_owned(),
                version: "1".to_owned(),
                media_type: "application/octet-stream".to_owned(),
                digest: None,
                expires_at: None,
                handle: Some(request.reference.as_str().unwrap_or("∅").to_owned()),
            })
        }
    }

    struct FakeInvoker;

    impl Invoker for FakeInvoker {
        fn scheme(&self) -> &'static str {
            "mcp"
        }

        fn invoke(&self, _request: &InvokeRequest) -> Result<Invocation, ReferenceError> {
            Ok(Invocation {
                status: InvocationStatus::Succeeded,
                result_ref: Some("https://example.com/result".to_owned()),
                result_digest: None,
                error: None,
            })
        }
    }

    fn resolve_request() -> ResolveRequest {
        ResolveRequest {
            domain: "demo".to_owned(),
            type_name: "artifact".to_owned(),
            reference: ReferenceForm::classify(Some("https://example.com/a")).expect("reference"),
            actor: "alice".to_owned(),
            intent: pact_ref_core::ResolveIntent::Read,
            expected_digest: None,
            pact_token_id: None,
        }
    }

    fn invoke_request() -> InvokeRequest {
        InvokeRequest {
            domain: "demo".to_owned(),
            type_name: "artifact".to_owned(),
            reference: ReferenceForm::classify(Some("mcp://server/tool")).expect("reference"),
            actor: "alice".to_owned(),
            operation: "build".to_owned(),
            idempotency_key: "idem-1".to_owned(),
        }
    }

    #[test]
    fn delegates_resolve_and_invoke() {
        let client = Client::new(FakeResolver, FakeInvoker);
        let resolution = client.resolve(&resolve_request()).expect("resolve");
        assert_eq!(resolution.handle.as_deref(), Some("https://example.com/a"));
        let invocation = client.invoke(&invoke_request()).expect("invoke");
        assert_eq!(invocation.status, InvocationStatus::Succeeded);
        assert_eq!(
            invocation.result_ref.as_deref(),
            Some("https://example.com/result")
        );
    }
}
