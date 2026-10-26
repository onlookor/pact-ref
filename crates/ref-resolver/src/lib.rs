//! resolve SPI 与适配器注册表。具体网络/文件访问由 adapter 实现。

use std::collections::HashMap;

use pact_ref_core::{ReferenceError, Resolution, ResolveRequest, Resolver};

/// 按 scheme 路由到具体 adapter。
pub struct ResolverRegistry {
    adapters: HashMap<String, Box<dyn Resolver + Send + Sync>>,
}

impl ResolverRegistry {
    pub fn new() -> Self {
        Self {
            adapters: HashMap::new(),
        }
    }

    pub fn register(&mut self, resolver: Box<dyn Resolver + Send + Sync>) {
        self.adapters.insert(resolver.scheme().to_owned(), resolver);
    }

    pub fn resolve(&self, request: &ResolveRequest) -> Result<Resolution, ReferenceError> {
        let scheme = request.reference.scheme().ok_or_else(|| {
            ReferenceError::UnsupportedIdentifier(
                request.reference.as_str().unwrap_or("∅").to_owned(),
            )
        })?;
        let resolver = self
            .adapters
            .get(scheme)
            .ok_or_else(|| ReferenceError::UnknownScheme(scheme.to_owned()))?;
        resolver.resolve(request)
    }

    pub fn schemes(&self) -> Vec<&str> {
        let mut schemes: Vec<&str> = self.adapters.keys().map(String::as_str).collect();
        schemes.sort_unstable();
        schemes
    }
}

impl Default for ResolverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// 测试/引导用：把固定引用映射到固定句柄。
pub struct StaticResolver {
    scheme: &'static str,
    mapping: HashMap<String, String>,
}

impl StaticResolver {
    pub fn new(scheme: &'static str) -> Self {
        Self {
            scheme,
            mapping: HashMap::new(),
        }
    }

    pub fn insert(&mut self, reference: impl Into<String>, handle: impl Into<String>) {
        self.mapping.insert(reference.into(), handle.into());
    }
}

impl Resolver for StaticResolver {
    fn scheme(&self) -> &'static str {
        self.scheme
    }

    fn resolve(&self, request: &ResolveRequest) -> Result<Resolution, ReferenceError> {
        let reference = request
            .reference
            .as_str()
            .ok_or_else(|| ReferenceError::UnsupportedIdentifier("∅".to_owned()))?;
        let handle = self
            .mapping
            .get(reference)
            .ok_or_else(|| ReferenceError::NotFound(reference.to_owned()))?;
        Ok(Resolution {
            contract_id: "bootstrap/static".to_owned(),
            version: "0".to_owned(),
            media_type: "application/octet-stream".to_owned(),
            digest: None,
            expires_at: None,
            handle: handle.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ResolverRegistry, StaticResolver};
    use pact_ref_core::{ReferenceForm, ResolveIntent, ResolveRequest};

    fn request(reference: &str) -> ResolveRequest {
        ResolveRequest {
            domain: "demo".to_owned(),
            type_name: "artifact".to_owned(),
            reference: ReferenceForm::classify(Some(reference)).expect("reference"),
            actor: "tester".to_owned(),
            intent: ResolveIntent::Read,
        }
    }

    #[test]
    fn routes_by_scheme() {
        let mut adapter = StaticResolver::new("mem");
        adapter.insert("mem://a", "handle-a");
        let mut registry = ResolverRegistry::new();
        registry.register(Box::new(adapter));
        let resolution = registry.resolve(&request("mem://a")).expect("resolve");
        assert_eq!(resolution.handle, "handle-a");
    }

    #[test]
    fn rejects_identifier_without_scheme() {
        let registry = ResolverRegistry::new();
        let error = registry
            .resolve(&request("REQ-001"))
            .expect_err("must fail");
        assert!(matches!(
            error,
            pact_ref_core::ReferenceError::UnsupportedIdentifier(_)
        ));
    }
}
