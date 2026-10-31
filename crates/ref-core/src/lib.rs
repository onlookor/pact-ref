//! PACT 物引治理的纯类型与策略接口。
//!
//! 本 crate 不读取文件、不访问网络、不依赖 PACT engine/store。
//! 它只定义治理层共享的数据形状和 trait，供 resolver / invoker / registry / auth / audit 实现。

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

pub use pact_ref_spec::{
    BindingMatch, ContractCard, MatchScope, Materialization, RefBindings, RefRule, ReferenceForm,
    SideEffect, SpecError, API_VERSION,
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
    Timeout(String),
    Upstream(String),
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
            Self::Timeout(message) => write!(f, "upstream timeout: {message}"),
            Self::Upstream(message) => write!(f, "upstream failure: {message}"),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolveIntent {
    Read,
    Verify,
}

impl ResolveIntent {
    /// ACL 中的 operation 名称。
    pub fn operation(&self) -> &'static str {
        match self {
            Self::Read => "resolve:read",
            Self::Verify => "resolve:verify",
        }
    }
}

/// 解析请求。
///
/// `actor` 由服务端在认证后注入，**不来自请求体**；`domain` / `type_name` 只用于选择
/// profile 与 ACL，不用于解释 PACT 语义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRequest {
    pub domain: String,
    pub type_name: String,
    pub reference: ReferenceForm,
    pub actor: String,
    pub intent: ResolveIntent,
    pub expected_digest: Option<String>,
    pub pact_token_id: Option<String>,
}

/// 解析结果。`handle` 是不透明句柄；`intent=verify` 时必须为 `None`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub contract_id: String,
    pub version: String,
    pub media_type: String,
    pub digest: Option<String>,
    pub expires_at: Option<String>,
    pub handle: Option<String>,
}

/// 调用请求。动态能力必须显式带幂等键；`input` 是工具参数，原样交给上游。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeRequest {
    pub domain: String,
    pub type_name: String,
    pub reference: ReferenceForm,
    pub actor: String,
    pub operation: String,
    pub idempotency_key: String,
    pub input: serde_json::Value,
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

/// 动态写请求（D53）。
///
/// 与 [`InvokeRequest`] 形状相同但通道分离：写请求必须先经幂等台账，且只能作用于
/// `mcp-mutating` profile；`input` 是工具参数，原样交给上游。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutateRequest {
    pub domain: String,
    pub type_name: String,
    pub reference: ReferenceForm,
    pub actor: String,
    pub operation: String,
    pub idempotency_key: String,
    pub input: serde_json::Value,
}

/// 写入状态。`Failed` 表示上游明确失败；`in-doubt` 由台账判定，不进入本类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationStatus {
    Succeeded,
    Failed,
}

/// 写入结果。`replayed` 为真表示该结论来自台账重放，而非本次执行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mutation {
    pub status: MutationStatus,
    pub result_ref: Option<String>,
    pub result_digest: Option<String>,
    pub replayed: bool,
}

/// `describe` 的消费者投影白名单（治理 §13.6.6）。
///
/// 不含 `metadata.owner|labels|description`、`parties`、`capability.server`、
/// `capability.auth.credentialSource`、`resolution.endpoint`，也不透出未来新增字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractDescriptor {
    pub contract_id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<CapabilityDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthDescriptor>,
    pub reference: ReferenceDescriptor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleDescriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failure: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer_scope: Option<String>,
}

/// 制品投影。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactDescriptor {
    pub kind: String,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_digest: Option<String>,
    pub digest_policy: String,
}

/// 动态能力投影（不含 `server` 与 `auth.credentialSource`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescriptor {
    pub kind: String,
    pub side_effect: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<ToolDescriptor>,
}

/// 工具投影。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDescriptor {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// 认证投影。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthDescriptor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

/// 票面约束投影。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceDescriptor {
    pub schemes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutable_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinning: Option<PinningDescriptor>,
}

/// 钉版投影。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinningDescriptor {
    pub required_for_archive: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted: Vec<String>,
}

/// 生命周期投影。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleDescriptor {
    pub retention: String,
    pub deletion_policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone_ref: Option<String>,
}

/// 验收投影。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationDescriptor {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conformance: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suite: Option<String>,
}

impl From<&ContractCard> for ContractDescriptor {
    fn from(card: &ContractCard) -> Self {
        let spec = &card.spec;
        let artifact = spec.artifact.as_ref().map(|artifact| ArtifactDescriptor {
            kind: artifact.kind.clone(),
            media_type: artifact.media_type.clone(),
            schema: artifact.schema.clone(),
            schema_digest: artifact.schema_digest.clone(),
            digest_policy: enum_name(&artifact.digest_policy),
        });
        let capability = spec
            .capability
            .as_ref()
            .map(|capability| CapabilityDescriptor {
                kind: capability.kind.clone(),
                side_effect: enum_name(&capability.side_effect),
                timeout_ms: capability.timeout_ms,
                tool: Some(ToolDescriptor {
                    name: capability.tool.name.clone(),
                    version: capability.tool.version.clone(),
                }),
            });
        let auth = spec
            .capability
            .as_ref()
            .and_then(|capability| capability.auth.as_ref())
            .or_else(|| {
                spec.resolution
                    .as_ref()
                    .and_then(|resolution| resolution.auth.as_ref())
            })
            .map(|auth| AuthDescriptor {
                audience: auth.audience.clone(),
                scopes: auth.scopes.clone(),
            });
        let media_type = artifact
            .as_ref()
            .map(|artifact| artifact.media_type.clone())
            .unwrap_or_else(|| "application/json".to_owned());

        Self {
            contract_id: card.metadata.id.clone(),
            version: card.metadata.version.clone(),
            status: Some(enum_name(&card.metadata.status)),
            media_type,
            artifact,
            capability,
            auth,
            reference: ReferenceDescriptor {
                schemes: spec.reference.schemes.clone(),
                uri_pattern: spec.reference.uri_pattern.clone(),
                mutable_allowed: Some(spec.reference.mutable_allowed),
                pinning: spec
                    .reference
                    .pinning
                    .as_ref()
                    .map(|pinning| PinningDescriptor {
                        required_for_archive: pinning.required_for_archive,
                        accepted: pinning.accepted.clone(),
                    }),
            },
            lifecycle: spec
                .lifecycle
                .as_ref()
                .map(|lifecycle| LifecycleDescriptor {
                    retention: lifecycle.retention.clone(),
                    deletion_policy: enum_name(&lifecycle.deletion_policy),
                    tombstone_ref: lifecycle.tombstone_ref.clone(),
                }),
            failure: spec.failure.clone(),
            verification: spec
                .verification
                .as_ref()
                .map(|verification| VerificationDescriptor {
                    conformance: verification.conformance.clone(),
                    suite: verification.suite.clone(),
                }),
            consumer_scope: spec
                .parties
                .as_ref()
                .and_then(|parties| parties.consumer_scope.clone()),
        }
    }
}

/// 用 serde 的 kebab-case 名称序列化枚举，避免在投影层复制枚举定义。
fn enum_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        Ok(other) => other.to_string(),
        Err(_) => String::new(),
    }
}

/// 审计事件。只记录 ID、摘要、状态、时间，不记录正文/凭据/个人数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub trace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    pub actor: String,
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<String>,
    /// 写请求摘要（D53 两阶段审计）；只读路径不填。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
    pub timestamp: String,
}

/// 审计写入失败。`refd` 默认据此返回 `500 AuditUnavailable`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditError {
    pub message: String,
}

impl AuditError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AuditError {}

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

/// 审计边车。`Err` 表示审计不可用；调用方默认 fail-closed。
pub trait AuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError>;

    /// 就绪检查；默认认为可用。
    fn available(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_reference, ContractCard, ContractDescriptor, Mutation, MutationStatus,
        ReferenceError, ReferenceForm, SpecError,
    };

    const CARD: &str = r#"{
      "apiVersion": "pact.ref/v1",
      "kind": "ContractCard",
      "metadata": {
        "id": "build/artifact",
        "version": "1",
        "owner": "build-platform",
        "status": "active",
        "labels": ["internal"],
        "description": "private note"
      },
      "spec": {
        "artifact": {
          "kind": "archive",
          "mediaType": "application/octet-stream",
          "digestPolicy": "optional"
        },
        "reference": {
          "schemes": ["https", "file"],
          "pinning": { "requiredForArchive": true, "accepted": ["sha256"] }
        },
        "parties": {
          "producer": "builder",
          "custodian": "artifacts-team",
          "consumers": ["developer"],
          "consumerScope": "domain:build"
        },
        "resolution": {
          "mode": "fetch",
          "endpoint": "https://internal.example.com",
          "auth": { "audience": "pact-ref", "scopes": ["artifact:read"], "credentialSource": "broker" }
        },
        "lifecycle": { "retention": "P30D", "deletionPolicy": "retain" },
        "failure": { "notFound": "permanent" },
        "verification": { "conformance": ["digest-check"], "suite": "https://example.com/suite" }
      }
    }"#;

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

    #[test]
    fn mutation_carries_replay_flag_and_status() {
        let mutation = Mutation {
            status: MutationStatus::Succeeded,
            result_ref: Some("file:///var/lib/refd/materialized/a.json".to_owned()),
            result_digest: Some("sha256:abc".to_owned()),
            replayed: true,
        };
        assert_eq!(mutation.status, MutationStatus::Succeeded);
        assert!(mutation.replayed);
        assert_eq!(
            mutation.result_ref.as_deref(),
            Some("file:///var/lib/refd/materialized/a.json")
        );
        assert_eq!(MutationStatus::Failed, MutationStatus::Failed);
    }

    #[test]
    fn projects_card_without_owner_or_internal_topology() {
        let card: ContractCard = serde_json::from_str(CARD).expect("card");
        let descriptor = ContractDescriptor::from(&card);
        assert_eq!(descriptor.contract_id, "build/artifact");
        assert_eq!(descriptor.version, "1");
        assert_eq!(descriptor.media_type, "application/octet-stream");
        assert_eq!(descriptor.lifecycle.as_ref().unwrap().retention, "P30D");
        assert_eq!(descriptor.consumer_scope.as_deref(), Some("domain:build"));
        assert!(descriptor.artifact.is_some());
        assert!(descriptor.capability.is_none());

        let json = serde_json::to_value(&descriptor).expect("serialize");
        let text = json.to_string();
        for forbidden in [
            "build-platform",
            "internal",
            "private note",
            "internal.example.com",
            "broker",
            "builder",
            "artifacts-team",
            "secret",
        ] {
            assert!(
                !text.contains(forbidden),
                "projection must not leak {forbidden}: {text}"
            );
        }
    }
}
