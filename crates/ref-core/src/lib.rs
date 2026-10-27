//! PACT 物引治理的纯类型与策略接口。
//!
//! 本 crate 不读取文件、不访问网络、不依赖 PACT engine/store。
//! 它只定义治理层共享的数据形状和 trait，供 resolver / invoker / registry / auth / audit 实现。

use std::fmt;

pub use pact_ref_spec::{
    BindingMatch, ContractCard, MatchScope, RefBindings, RefRule, ReferenceForm, SpecError,
    API_VERSION,
};

/// 把规范层的引用分类错误映射为治理层错误。
///
/// 入口应先调用本函数完成 URI profile 校验；通过后的 [`ReferenceForm`] 在治理内部保持不透明。
pub fn classify_reference(raw: Option<&str>) -> Result<ReferenceForm, ReferenceError> {
    ReferenceForm::classify(raw).map_err(ReferenceError::from)
}

/// 治理层统一错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceError {
    Empty,
    UnknownScheme(String),
    UnsupportedIdentifier(String),
    InvalidRequest(String),
    NotFound(String),
    Unauthorized(String),
    Expired(String),
    DigestMismatch { expected: String, actual: String },
    Internal(String),
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("reference is empty"),
            Self::UnknownScheme(scheme) => write!(f, "unknown scheme: {scheme}"),
            Self::UnsupportedIdentifier(value) => {
                write!(f, "identifier cannot be resolved: {value}")
            }
            Self::InvalidRequest(message) => write!(f, "invalid request: {message}"),
            Self::NotFound(value) => write!(f, "not found: {value}"),
            Self::Unauthorized(message) => write!(f, "unauthorized: {message}"),
            Self::Expired(value) => write!(f, "expired: {value}"),
            Self::DigestMismatch { expected, actual } => {
                write!(f, "digest mismatch: expected {expected}, actual {actual}")
            }
            Self::Internal(message) => write!(f, "internal error: {message}"),
        }
    }
}

impl std::error::Error for ReferenceError {}

impl From<SpecError> for ReferenceError {
    fn from(error: SpecError) -> Self {
        match error {
            SpecError::EmptyReference => Self::Empty,
            SpecError::InvalidScheme(scheme) => Self::UnknownScheme(scheme),
            SpecError::IdentifierNotAllowed { type_name } => Self::UnsupportedIdentifier(type_name),
            other => Self::InvalidRequest(other.to_string()),
        }
    }
}

/// 解析意图。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveIntent {
    Read,
    Verify,
}

/// 解析请求。`domain` / `type_name` 只用于选择 RefBindings，不用于解释 PACT 语义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRequest {
    pub domain: String,
    pub type_name: String,
    pub reference: ReferenceForm,
    pub actor: String,
    pub intent: ResolveIntent,
}

/// 解析结果。`handle` 是不透明句柄，不把正文塞进治理事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub contract_id: String,
    pub version: String,
    pub media_type: String,
    pub digest: Option<String>,
    pub expires_at: Option<String>,
    pub handle: String,
}

/// 调用请求。动态能力必须显式带幂等键。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeRequest {
    pub domain: String,
    pub type_name: String,
    pub reference: ReferenceForm,
    pub actor: String,
    pub operation: String,
    pub idempotency_key: String,
}

/// 调用状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationStatus {
    Succeeded,
    Failed,
    Pending,
}

/// 调用结果。需要长期依赖时，`result_ref` 必须是可物化的静态引用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub status: InvocationStatus,
    pub result_ref: Option<String>,
    pub result_digest: Option<String>,
    pub error: Option<String>,
}

/// 契约描述的最小投影；完整 ContractCard 由 `pact-ref-spec` 定义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractDescriptor {
    pub contract_id: String,
    pub version: String,
    pub media_type: String,
}

/// 审计事件。只记录 ID、摘要、状态、时间，不记录正文/凭据/个人数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub trace_id: String,
    pub token_id: Option<String>,
    pub actor: String,
    pub reference: String,
    pub contract_id: Option<String>,
    pub operation: Option<String>,
    pub status: String,
    pub result_digest: Option<String>,
    pub timestamp: String,
}

/// scheme 适配器：把一个 URI 兑现为可读句柄。
pub trait Resolver {
    fn scheme(&self) -> &'static str;
    fn resolve(&self, request: &ResolveRequest) -> Result<Resolution, ReferenceError>;
}

/// 动态能力适配器：调用并返回可物化结果。
pub trait Invoker {
    fn scheme(&self) -> &'static str;
    fn invoke(&self, request: &InvokeRequest) -> Result<Invocation, ReferenceError>;
}

/// 可选发现：按引用查 ContractCard 投影。
pub trait Registry {
    fn describe(&self, reference: &ReferenceForm) -> Result<ContractDescriptor, ReferenceError>;
}

/// 授权：token 的读 gate 通过 ≠ 制品 ACL 通过；两边都要满足。
pub trait Authorizer {
    fn authorize(
        &self,
        actor: &str,
        reference: &ReferenceForm,
        intent: ResolveIntent,
    ) -> Result<(), ReferenceError>;
}

/// 审计边车。
pub trait AuditSink {
    fn record(&self, event: &AuditEvent);
}

#[cfg(test)]
mod tests {
    use super::{classify_reference, ReferenceError, ReferenceForm, SpecError};

    #[test]
    fn classifies_uri_and_identifier() {
        assert!(matches!(
            ReferenceForm::classify(Some("https://example.com/a")),
            Ok(ReferenceForm::Uri(_))
        ));
        assert!(matches!(
            ReferenceForm::classify(Some("REQ-001")),
            Ok(ReferenceForm::Identifier(_))
        ));
        assert!(matches!(
            ReferenceForm::classify(None),
            Ok(ReferenceForm::Absent)
        ));
    }

    #[test]
    fn rejects_empty_reference() {
        assert_eq!(
            ReferenceForm::classify(Some("  ")),
            Err(SpecError::EmptyReference)
        );
        assert_eq!(classify_reference(Some("  ")), Err(ReferenceError::Empty));
    }

    #[test]
    fn maps_bare_path_to_invalid_request() {
        assert!(matches!(
            classify_reference(Some("/tmp/a.md")),
            Err(ReferenceError::InvalidRequest(_))
        ));
    }

    #[test]
    fn returns_scheme_only_for_uri() {
        let uri = ReferenceForm::classify(Some("mcp://server/tool")).expect("uri");
        assert_eq!(uri.scheme(), Some("mcp"));
        let identifier = ReferenceForm::classify(Some("REQ-001")).expect("identifier");
        assert_eq!(identifier.scheme(), None);
    }

    #[test]
    fn reexports_bindings_and_contract_types() {
        let bindings = super::RefBindings::new("demo");
        assert_eq!(bindings.api_version, super::API_VERSION);
        assert_eq!(bindings.kind, "RefBindings");
    }
}
