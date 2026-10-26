//! MCP capability adapter skeleton。
//!
//! 动态调用有副作用；结果需要长期依赖时必须物化为静态引用。
//! 这里只占位，不实现网络、OAuth 或工具调用。

use pact_ref_core::{
    Invocation, InvokeRequest, Invoker, ReferenceError, Resolution, ResolveRequest, Resolver,
};

pub const SCHEME: &str = "mcp";

pub struct Adapter;

impl Adapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Adapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for Adapter {
    fn scheme(&self) -> &'static str {
        SCHEME
    }

    fn resolve(&self, _request: &ResolveRequest) -> Result<Resolution, ReferenceError> {
        Err(ReferenceError::Internal(
            "mcp resolve is not implemented in bootstrap".to_owned(),
        ))
    }
}

impl Invoker for Adapter {
    fn scheme(&self) -> &'static str {
        SCHEME
    }

    fn invoke(&self, _request: &InvokeRequest) -> Result<Invocation, ReferenceError> {
        Err(ReferenceError::Internal(
            "mcp invoke is not implemented in bootstrap".to_owned(),
        ))
    }
}
