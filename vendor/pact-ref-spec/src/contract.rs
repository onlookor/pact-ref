use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::SpecError;
use crate::reference::ReferenceForm;
use crate::{
    is_valid_contract_id, is_valid_scheme, is_valid_sha256, API_VERSION, CONTRACT_CARD_KIND,
};

/// 某类制品的契约卡。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractCard {
    pub api_version: String,
    pub kind: String,
    pub metadata: CardMetadata,
    pub spec: ContractSpec,
}

impl ContractCard {
    pub fn contract_id(&self) -> String {
        format!("{}@{}", self.metadata.id, self.metadata.version)
    }

    /// 结构/取值校验。静态卡与动态卡必须恰好二选一。
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.api_version != API_VERSION {
            return Err(SpecError::InvalidContract(format!(
                "apiVersion must be {API_VERSION}"
            )));
        }
        if self.kind != CONTRACT_CARD_KIND {
            return Err(SpecError::InvalidContract(format!(
                "kind must be {CONTRACT_CARD_KIND}"
            )));
        }
        validate_card_metadata(&self.metadata)?;
        validate_reference_contract(&self.spec.reference)?;

        match (&self.spec.artifact, &self.spec.capability) {
            (Some(artifact), None) => validate_artifact(artifact, &self.spec.reference),
            (None, Some(capability)) => validate_capability(capability, &self.spec.reference),
            (None, None) => Err(SpecError::InvalidContract(
                "spec.artifact or spec.capability is required".to_owned(),
            )),
            (Some(_), Some(_)) => Err(SpecError::InvalidContract(
                "spec.artifact and spec.capability are mutually exclusive".to_owned(),
            )),
        }?;

        if let Some(resolution) = &self.spec.resolution {
            validate_resolution(resolution)?;
        }
        if let Some(parties) = &self.spec.parties {
            validate_parties(parties)?;
        }
        if let Some(lifecycle) = &self.spec.lifecycle {
            validate_lifecycle(lifecycle, &self.spec.reference)?;
        }
        if let Some(verification) = &self.spec.verification {
            validate_verification(verification)?;
        }
        validate_failure_map(&self.spec.failure)?;
        Ok(())
    }
}

/// 契约卡元数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CardMetadata {
    pub id: String,
    pub version: String,
    pub owner: String,
    #[serde(default)]
    pub status: CardStatus,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// 契约卡状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CardStatus {
    #[default]
    Draft,
    Active,
    Deprecated,
    Retired,
}

/// 契约卡主体。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractSpec {
    #[serde(default)]
    pub artifact: Option<ArtifactContract>,
    #[serde(default)]
    pub capability: Option<CapabilityContract>,
    pub reference: ReferenceContract,
    #[serde(default)]
    pub parties: Option<Parties>,
    #[serde(default)]
    pub resolution: Option<Resolution>,
    #[serde(default)]
    pub lifecycle: Option<Lifecycle>,
    #[serde(default)]
    pub failure: BTreeMap<String, String>,
    #[serde(default)]
    pub verification: Option<Verification>,
}

/// 静态制品契约。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactContract {
    pub kind: String,
    pub media_type: String,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub schema_digest: Option<String>,
    pub digest_policy: DigestPolicy,
}

/// 摘要策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DigestPolicy {
    RequiredAtArchive,
    Optional,
    Never,
}

/// 动态能力契约。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityContract {
    pub kind: String,
    pub server: CapabilityServer,
    pub tool: CapabilityTool,
    pub side_effect: SideEffect,
    #[serde(default)]
    pub idempotency: Option<Idempotency>,
    #[serde(default)]
    pub result: Option<ResultContract>,
    #[serde(default)]
    pub auth: Option<Auth>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub failure: BTreeMap<String, String>,
}

/// 能力服务方。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityServer {
    pub id: String,
    #[serde(default)]
    pub trust_anchor: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
}

/// 能力工具。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityTool {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub input_schema_digest: Option<String>,
    #[serde(default)]
    pub output_schema_digest: Option<String>,
}

/// 副作用类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SideEffect {
    ReadOnly,
    Mutating,
}

/// 幂等契约。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Idempotency {
    pub key: String,
    pub semantics: String,
}

/// 调用结果契约。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultContract {
    pub materialization: Materialization,
    #[serde(default)]
    pub returns: Option<String>,
    #[serde(default)]
    pub record_digest: bool,
}

/// 结果物化要求。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Materialization {
    Required,
    Optional,
    Forbidden,
}

/// 认证契约。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Auth {
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub credential_source: Option<String>,
}

/// 票面约束。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReferenceContract {
    pub schemes: Vec<String>,
    #[serde(default)]
    pub uri_pattern: Option<String>,
    #[serde(default)]
    pub pinning: Option<Pinning>,
    #[serde(default)]
    pub mutable_allowed: bool,
    #[serde(default)]
    pub max_length: Option<usize>,
}

/// 钉版要求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pinning {
    pub required_for_archive: bool,
    #[serde(default)]
    pub accepted: Vec<String>,
}

/// 参与方。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Parties {
    pub producer: String,
    pub custodian: String,
    #[serde(default)]
    pub consumers: Vec<String>,
    #[serde(default)]
    pub consumer_scope: Option<String>,
}

/// 取回/调用方式。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resolution {
    pub mode: ResolutionMode,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub auth: Option<Auth>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub retry: Option<String>,
}

/// 取回模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionMode {
    Fetch,
    Stream,
    Registry,
}

/// 生命周期。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lifecycle {
    /// 内容保留期：`permanent` 或正 ISO 8601 duration（如 `P365D`）。
    pub retention: String,
    pub deletion_policy: DeletionPolicy,
    /// tombstone 发布位置的 URI（仅 `tombstone-then-delete` 允许出现）。
    #[serde(default)]
    pub tombstone_ref: Option<String>,
}

/// 删除策略（D44）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeletionPolicy {
    /// 保留内容，不自动删除。
    Retain,
    /// 到期删除内容，不发布 tombstone；归档钉版的契约不得使用。
    Delete,
    /// 到期先发布 tombstone，再删除内容；必须声明 `tombstoneRef`。
    TombstoneThenDelete,
}

/// 验收方式。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Verification {
    #[serde(default)]
    pub conformance: Vec<String>,
    #[serde(default)]
    pub suite: Option<String>,
}

fn validate_card_metadata(metadata: &CardMetadata) -> Result<(), SpecError> {
    if !is_valid_contract_id(&format!("{}@{}", metadata.id, metadata.version)) {
        return Err(SpecError::InvalidContract(format!(
            "metadata id/version must form id@version: {}@{}",
            metadata.id, metadata.version
        )));
    }
    if metadata.owner.trim().is_empty() {
        return Err(SpecError::InvalidContract(
            "metadata.owner must not be empty".to_owned(),
        ));
    }
    if metadata.labels.iter().any(|label| label.trim().is_empty()) {
        return Err(SpecError::InvalidContract(
            "metadata.labels must not contain empty values".to_owned(),
        ));
    }
    Ok(())
}

fn validate_reference_contract(reference: &ReferenceContract) -> Result<(), SpecError> {
    if reference.schemes.is_empty() {
        return Err(SpecError::InvalidContract(
            "spec.reference.schemes must not be empty".to_owned(),
        ));
    }
    for scheme in &reference.schemes {
        if !is_valid_scheme(scheme) {
            return Err(SpecError::InvalidContract(format!(
                "spec.reference.schemes contains invalid scheme {scheme}"
            )));
        }
    }
    if let Some(pattern) = &reference.uri_pattern {
        if pattern.trim().is_empty() {
            return Err(SpecError::InvalidContract(
                "spec.reference.uriPattern must not be empty".to_owned(),
            ));
        }
    }
    if let Some(max) = reference.max_length {
        if max == 0 || max > 65_536 {
            return Err(SpecError::InvalidContract(
                "spec.reference.maxLength must be in 1..=65536".to_owned(),
            ));
        }
    }
    if let Some(pinning) = &reference.pinning {
        if pinning.accepted.iter().any(|value| value.trim().is_empty()) {
            return Err(SpecError::InvalidContract(
                "spec.reference.pinning.accepted must not contain empty values".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_artifact(
    artifact: &ArtifactContract,
    reference: &ReferenceContract,
) -> Result<(), SpecError> {
    if artifact.kind.trim().is_empty() {
        return Err(SpecError::InvalidContract(
            "spec.artifact.kind must not be empty".to_owned(),
        ));
    }
    if artifact.media_type.trim().is_empty() {
        return Err(SpecError::InvalidContract(
            "spec.artifact.mediaType must not be empty".to_owned(),
        ));
    }
    if let Some(digest) = &artifact.schema_digest {
        if !is_valid_sha256(digest) {
            return Err(SpecError::InvalidContract(format!(
                "spec.artifact.schemaDigest must be sha256:<64 hex>: {digest}"
            )));
        }
    }
    if artifact.digest_policy == DigestPolicy::RequiredAtArchive {
        let pinned = reference
            .pinning
            .as_ref()
            .map(|pinning| pinning.required_for_archive)
            .unwrap_or(false);
        if !pinned {
            return Err(SpecError::InvalidContract(
                "digestPolicy=required-at-archive requires reference.pinning.requiredForArchive=true"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_capability(
    capability: &CapabilityContract,
    reference: &ReferenceContract,
) -> Result<(), SpecError> {
    if capability.kind.trim().is_empty() {
        return Err(SpecError::InvalidContract(
            "spec.capability.kind must not be empty".to_owned(),
        ));
    }
    let server = ReferenceForm::classify(Some(&capability.server.id)).map_err(|error| {
        SpecError::InvalidContract(format!("spec.capability.server.id is not a URI: {error}"))
    })?;
    if !server.is_uri() {
        return Err(SpecError::InvalidContract(
            "spec.capability.server.id must be a URI".to_owned(),
        ));
    }
    if capability.kind == "mcp-tool" {
        if server.scheme() != Some("mcp") {
            return Err(SpecError::InvalidContract(
                "mcp-tool capability.server.id must use mcp scheme".to_owned(),
            ));
        }
        if !reference.schemes.iter().any(|scheme| scheme == "mcp") {
            return Err(SpecError::InvalidContract(
                "mcp-tool capability requires mcp in reference.schemes".to_owned(),
            ));
        }
    }
    if capability.tool.name.trim().is_empty() {
        return Err(SpecError::InvalidContract(
            "spec.capability.tool.name must not be empty".to_owned(),
        ));
    }
    for digest in [
        capability.tool.input_schema_digest.as_deref(),
        capability.tool.output_schema_digest.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !is_valid_sha256(digest) {
            return Err(SpecError::InvalidContract(format!(
                "tool schema digest must be sha256:<64 hex>: {digest}"
            )));
        }
    }
    if let Some(timeout) = capability.timeout_ms {
        if timeout == 0 {
            return Err(SpecError::InvalidContract(
                "spec.capability.timeoutMs must be greater than zero".to_owned(),
            ));
        }
    }
    if capability.side_effect == SideEffect::Mutating {
        let idempotency = capability.idempotency.as_ref().ok_or_else(|| {
            SpecError::InvalidContract(
                "mutating capability requires spec.capability.idempotency".to_owned(),
            )
        })?;
        if idempotency.key.trim().is_empty() || idempotency.semantics.trim().is_empty() {
            return Err(SpecError::InvalidContract(
                "idempotency.key and idempotency.semantics must not be empty".to_owned(),
            ));
        }
        let result = capability.result.as_ref().ok_or_else(|| {
            SpecError::InvalidContract(
                "mutating capability requires spec.capability.result".to_owned(),
            )
        })?;
        if result.materialization != Materialization::Required {
            return Err(SpecError::InvalidContract(
                "mutating capability requires result.materialization=required".to_owned(),
            ));
        }
    }
    if let Some(auth) = &capability.auth {
        validate_auth(auth)?;
    }
    validate_failure_map(&capability.failure)
}

fn validate_resolution(resolution: &Resolution) -> Result<(), SpecError> {
    if let Some(timeout) = resolution.timeout_ms {
        if timeout == 0 {
            return Err(SpecError::InvalidContract(
                "spec.resolution.timeoutMs must be greater than zero".to_owned(),
            ));
        }
    }
    if let Some(auth) = &resolution.auth {
        validate_auth(auth)?;
    }
    Ok(())
}

fn validate_auth(auth: &Auth) -> Result<(), SpecError> {
    if auth.scopes.iter().any(|scope| scope.trim().is_empty()) {
        return Err(SpecError::InvalidContract(
            "auth.scopes must not contain empty values".to_owned(),
        ));
    }
    Ok(())
}

fn validate_parties(parties: &Parties) -> Result<(), SpecError> {
    if parties.producer.trim().is_empty() || parties.custodian.trim().is_empty() {
        return Err(SpecError::InvalidContract(
            "parties.producer and parties.custodian must not be empty".to_owned(),
        ));
    }
    if parties
        .consumers
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(SpecError::InvalidContract(
            "parties.consumers must not contain empty values".to_owned(),
        ));
    }
    Ok(())
}

fn validate_lifecycle(
    lifecycle: &Lifecycle,
    reference: &ReferenceContract,
) -> Result<(), SpecError> {
    if !crate::is_valid_retention(&lifecycle.retention) {
        return Err(SpecError::InvalidContract(format!(
            "lifecycle.retention must be `permanent` or a positive ISO 8601 duration such as P365D: {}",
            lifecycle.retention
        )));
    }

    match lifecycle.deletion_policy {
        DeletionPolicy::TombstoneThenDelete => {
            let Some(tombstone_ref) = lifecycle.tombstone_ref.as_deref() else {
                return Err(SpecError::InvalidContract(
                    "deletionPolicy=tombstone-then-delete requires lifecycle.tombstoneRef"
                        .to_owned(),
                ));
            };
            let form = ReferenceForm::classify(Some(tombstone_ref)).map_err(|error| {
                SpecError::InvalidContract(format!("lifecycle.tombstoneRef must be a URI: {error}"))
            })?;
            if !form.is_uri() {
                return Err(SpecError::InvalidContract(
                    "lifecycle.tombstoneRef must be a URI".to_owned(),
                ));
            }
        }
        DeletionPolicy::Retain | DeletionPolicy::Delete => {
            if lifecycle.tombstone_ref.is_some() {
                return Err(SpecError::InvalidContract(
                    "lifecycle.tombstoneRef is only allowed with deletionPolicy=tombstone-then-delete"
                        .to_owned(),
                ));
            }
        }
    }

    let archive_pinned = reference
        .pinning
        .as_ref()
        .map(|pinning| pinning.required_for_archive)
        .unwrap_or(false);
    if archive_pinned && lifecycle.deletion_policy == DeletionPolicy::Delete {
        return Err(SpecError::InvalidContract(
            "deletionPolicy=delete is not allowed for archive-pinned contracts; use retain or tombstone-then-delete"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_verification(verification: &Verification) -> Result<(), SpecError> {
    if verification
        .conformance
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(SpecError::InvalidContract(
            "verification.conformance must not contain empty values".to_owned(),
        ));
    }
    Ok(())
}

fn validate_failure_map(failure: &BTreeMap<String, String>) -> Result<(), SpecError> {
    if failure
        .iter()
        .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
    {
        return Err(SpecError::InvalidContract(
            "failure entries must have non-empty keys and values".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ContractCard, SideEffect};
    use crate::SpecError;

    const STATIC_CARD: &str = r#"{
      "apiVersion": "pact.ref/v1",
      "kind": "ContractCard",
      "metadata": {
        "id": "se/design-review",
        "version": "2",
        "owner": "architecture-guild",
        "status": "active",
        "labels": ["design", "review"]
      },
      "spec": {
        "artifact": {
          "kind": "document",
          "mediaType": "text/markdown; charset=utf-8",
          "schema": "https://schemas.example.com/se/design-review/v2.json",
          "digestPolicy": "required-at-archive"
        },
        "reference": {
          "schemes": ["https", "git"],
          "uriPattern": "https://artifacts.example.com/design/{id}#sha256=<hex>",
          "pinning": { "requiredForArchive": true, "accepted": ["sha256", "git-commit"] },
          "mutableAllowed": false,
          "maxLength": 2048
        },
        "parties": {
          "producer": "architect",
          "custodian": "artifacts-team",
          "consumers": ["developer", "tester"],
          "consumerScope": "domain:se_lifecycle"
        },
        "resolution": {
          "mode": "fetch",
          "endpoint": "https://artifacts.example.com",
          "auth": { "scheme": "oauth2", "audience": "pact-ref", "scopes": ["artifact:read"], "credentialSource": "broker" },
          "timeoutMs": 5000,
          "retry": "none"
        },
        "lifecycle": {
          "retention": "P365D",
          "deletionPolicy": "tombstone-then-delete",
          "tombstoneRef": "urn:pact:tombstone:se/design-review"
        },
        "failure": { "notFound": "permanent", "timeout": "retryable", "onFailure": "emit-witness-token" },
        "verification": { "conformance": ["schema-validation", "digest-check"], "suite": "https://example.com/suite" }
      }
    }"#;

    const MCP_CARD: &str = r#"{
      "apiVersion": "pact.ref/v1",
      "kind": "ContractCard",
      "metadata": { "id": "build/mcp-build", "version": "3", "owner": "build-platform", "status": "active" },
      "spec": {
        "capability": {
          "kind": "mcp-tool",
          "server": {
            "id": "mcp://build.example.com/build-server",
            "trustAnchor": "https://build.example.com/.well-known/mcp",
            "protocol": "2025-06-18"
          },
          "tool": {
            "name": "build.run",
            "version": "3",
            "inputSchemaDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "outputSchemaDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          },
          "sideEffect": "mutating",
          "idempotency": { "key": "token_id + request_id", "semantics": "at-most-once" },
          "result": { "materialization": "required", "returns": "urn:pact:artifact:build-result", "recordDigest": true },
          "auth": { "audience": "pact-ref", "scopes": ["build:run"], "credentialSource": "broker" },
          "timeoutMs": 600000,
          "failure": { "timeout": "retryable-with-idempotency-key", "buildFailed": "permanent" }
        },
        "reference": {
          "schemes": ["mcp"],
          "uriPattern": "mcp://build.example.com/build-server/build.run@3#schema=sha256:<hex>"
        }
      }
    }"#;

    #[test]
    fn validates_static_card() {
        let card: ContractCard = serde_json::from_str(STATIC_CARD).expect("card");
        card.validate().expect("valid");
        assert_eq!(card.contract_id(), "se/design-review@2");
    }

    #[test]
    fn validates_dynamic_card() {
        let card: ContractCard = serde_json::from_str(MCP_CARD).expect("card");
        card.validate().expect("valid");
        let capability = card.spec.capability.as_ref().expect("capability");
        assert_eq!(capability.side_effect, SideEffect::Mutating);
    }

    #[test]
    fn rejects_mutating_without_idempotency() {
        let mut card: ContractCard = serde_json::from_str(MCP_CARD).expect("card");
        card.spec
            .capability
            .as_mut()
            .expect("capability")
            .idempotency = None;
        let error = card.validate().expect_err("reject");
        assert!(matches!(error, SpecError::InvalidContract(_)));
    }

    #[test]
    fn rejects_artifact_and_capability_together() {
        let mut static_card: ContractCard = serde_json::from_str(STATIC_CARD).expect("card");
        let dynamic_card: ContractCard = serde_json::from_str(MCP_CARD).expect("card");
        static_card.spec.capability = dynamic_card.spec.capability;
        let error = static_card.validate().expect_err("reject");
        assert!(matches!(error, SpecError::InvalidContract(_)));
    }

    #[test]
    fn rejects_required_digest_without_archive_pinning() {
        let mut card: ContractCard = serde_json::from_str(STATIC_CARD).expect("card");
        card.spec
            .reference
            .pinning
            .as_mut()
            .expect("pinning")
            .required_for_archive = false;
        let error = card.validate().expect_err("reject");
        assert!(matches!(error, SpecError::InvalidContract(_)));
    }

    #[test]
    fn roundtrips_to_json() {
        let card: ContractCard = serde_json::from_str(STATIC_CARD).expect("card");
        let json = serde_json::to_string(&card).expect("serialize");
        let again: ContractCard = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(card, again);
    }

    #[test]
    fn validates_retention_forms() {
        assert!(crate::is_valid_retention("permanent"));
        assert!(crate::is_valid_retention("P365D"));
        assert!(crate::is_valid_retention("P1Y6M"));
        assert!(crate::is_valid_retention("P2W"));
        assert!(crate::is_valid_retention("PT12H"));
        assert!(crate::is_valid_retention("P1DT2H3M4S"));
        for invalid in [
            "", "P", "PT", "P0D", "0D", "365 days", "P1D2D", "P1W1D", "P1M1Y", "PT1S1H", "P-1D",
            "P1.5D",
        ] {
            assert!(
                !crate::is_valid_retention(invalid),
                "应拒绝保留期 {invalid}"
            );
        }
    }

    #[test]
    fn rejects_invalid_lifecycle_combinations() {
        let mut card: ContractCard = serde_json::from_str(STATIC_CARD).expect("card");
        card.spec.lifecycle.as_mut().expect("lifecycle").retention = "P0D".to_owned();
        assert!(card.validate().is_err());

        let mut card: ContractCard = serde_json::from_str(STATIC_CARD).expect("card");
        card.spec
            .lifecycle
            .as_mut()
            .expect("lifecycle")
            .tombstone_ref = None;
        assert!(card.validate().is_err());

        let mut card: ContractCard = serde_json::from_str(STATIC_CARD).expect("card");
        let lifecycle = card.spec.lifecycle.as_mut().expect("lifecycle");
        lifecycle.deletion_policy = crate::DeletionPolicy::Retain;
        assert!(card.validate().is_err());

        let mut card: ContractCard = serde_json::from_str(STATIC_CARD).expect("card");
        let lifecycle = card.spec.lifecycle.as_mut().expect("lifecycle");
        lifecycle.deletion_policy = crate::DeletionPolicy::Delete;
        lifecycle.tombstone_ref = None;
        assert!(
            card.validate().is_err(),
            "归档钉版的契约不得无 tombstone 删除"
        );
    }

    #[test]
    fn tombstone_ref_must_be_uri() {
        let mut card: ContractCard = serde_json::from_str(STATIC_CARD).expect("card");
        card.spec
            .lifecycle
            .as_mut()
            .expect("lifecycle")
            .tombstone_ref = Some("not a uri".to_owned());
        assert!(card.validate().is_err());
    }
}
