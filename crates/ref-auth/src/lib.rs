//! principal、授权、audience 与撤销骨架。
//!
//! 生产实现必须接入真实身份源；这里的 AllowAll 只用于引导和测试。

use pact_ref_core::{Authorizer, ReferenceError, ReferenceForm, ResolveIntent};

/// 已认证主体。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub audience: String,
}

/// 引导/测试用：允许一切。生产禁用。
pub struct AllowAllAuthorizer;

impl Authorizer for AllowAllAuthorizer {
    fn authorize(
        &self,
        _actor: &str,
        _reference: &ReferenceForm,
        _intent: ResolveIntent,
    ) -> Result<(), ReferenceError> {
        Ok(())
    }
}

/// 默认拒绝，防止忘记装配真实授权器。
pub struct DenyAllAuthorizer;

impl Authorizer for DenyAllAuthorizer {
    fn authorize(
        &self,
        _actor: &str,
        _reference: &ReferenceForm,
        intent: ResolveIntent,
    ) -> Result<(), ReferenceError> {
        Err(ReferenceError::Unauthorized(format!(
            "no authorizer configured for intent {intent:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{AllowAllAuthorizer, DenyAllAuthorizer};
    use pact_ref_core::{Authorizer, ReferenceError, ReferenceForm, ResolveIntent};

    fn reference() -> ReferenceForm {
        ReferenceForm::classify(Some("https://example.com/a")).expect("reference")
    }

    #[test]
    fn allow_all_permits_every_intent() {
        let authorizer = AllowAllAuthorizer;
        assert!(authorizer
            .authorize("alice", &reference(), ResolveIntent::Read)
            .is_ok());
        assert!(authorizer
            .authorize("alice", &reference(), ResolveIntent::Verify)
            .is_ok());
    }

    #[test]
    fn deny_all_rejects_by_default() {
        let authorizer = DenyAllAuthorizer;
        let error = authorizer
            .authorize("alice", &reference(), ResolveIntent::Read)
            .expect_err("must deny");
        assert!(matches!(error, ReferenceError::Unauthorized(_)));
    }
}
