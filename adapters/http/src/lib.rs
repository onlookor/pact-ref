//! HTTPS scheme adapter skeleton。
//!
//! 引导阶段只占位；接入时必须补 SSRF/路径穿越/凭据防护。

use pact_ref_core::{ReferenceError, Resolution, ResolveRequest, Resolver};

pub const SCHEME: &str = "https";

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
            "adapter is not implemented in bootstrap".to_owned(),
        ))
    }
}
