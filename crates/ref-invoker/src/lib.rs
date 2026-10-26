//! invoke SPI 与动态能力注册表。
//!
//! 动态调用有副作用、不可重放；结果需要长期依赖时必须物化为静态引用。

use std::collections::HashMap;

use pact_ref_core::{Invocation, InvokeRequest, Invoker, ReferenceError};

/// 按 scheme 路由到动态能力 adapter。
pub struct InvokerRegistry {
    adapters: HashMap<String, Box<dyn Invoker + Send + Sync>>,
}

impl InvokerRegistry {
    pub fn new() -> Self {
        Self {
            adapters: HashMap::new(),
        }
    }

    pub fn register(&mut self, invoker: Box<dyn Invoker + Send + Sync>) {
        self.adapters.insert(invoker.scheme().to_owned(), invoker);
    }

    pub fn invoke(&self, request: &InvokeRequest) -> Result<Invocation, ReferenceError> {
        let scheme = request.reference.scheme().ok_or_else(|| {
            ReferenceError::UnsupportedIdentifier(
                request.reference.as_str().unwrap_or("∅").to_owned(),
            )
        })?;
        let invoker = self
            .adapters
            .get(scheme)
            .ok_or_else(|| ReferenceError::UnknownScheme(scheme.to_owned()))?;
        invoker.invoke(request)
    }

    pub fn schemes(&self) -> Vec<&str> {
        let mut schemes: Vec<&str> = self.adapters.keys().map(String::as_str).collect();
        schemes.sort_unstable();
        schemes
    }
}

impl Default for InvokerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// 测试/引导用：总是返回“未实现”。
pub struct UnavailableInvoker {
    scheme: &'static str,
}

impl UnavailableInvoker {
    pub fn new(scheme: &'static str) -> Self {
        Self { scheme }
    }
}

impl Invoker for UnavailableInvoker {
    fn scheme(&self) -> &'static str {
        self.scheme
    }

    fn invoke(&self, _request: &InvokeRequest) -> Result<Invocation, ReferenceError> {
        Err(ReferenceError::Internal(
            "dynamic invocation is not implemented in bootstrap".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{InvokerRegistry, UnavailableInvoker};
    use pact_ref_core::{InvokeRequest, ReferenceError, ReferenceForm};

    fn request(reference: &str) -> InvokeRequest {
        InvokeRequest {
            domain: "demo".to_owned(),
            type_name: "artifact".to_owned(),
            reference: ReferenceForm::classify(Some(reference)).expect("reference"),
            actor: "alice".to_owned(),
            operation: "build".to_owned(),
            idempotency_key: "idem-1".to_owned(),
        }
    }

    #[test]
    fn routes_by_scheme() {
        let mut registry = InvokerRegistry::new();
        registry.register(Box::new(UnavailableInvoker::new("mcp")));
        assert_eq!(registry.schemes(), vec!["mcp"]);
        let error = registry
            .invoke(&request("mcp://server/tool"))
            .expect_err("must fail");
        assert!(matches!(error, ReferenceError::Internal(_)));
    }

    #[test]
    fn rejects_identifier_without_scheme() {
        let registry = InvokerRegistry::new();
        let error = registry.invoke(&request("REQ-001")).expect_err("must fail");
        assert!(matches!(error, ReferenceError::UnsupportedIdentifier(_)));
    }
}
