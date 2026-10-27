//! PACT 物引治理的纯规范层。
//!
//! 本 crate 只定义数据形状、URI profile 校验、RefBindings 匹配与 ContractCard 校验。
//! 它不做 IO、不访问网络、不读取文件，可编译到 `wasm32-unknown-unknown`。
//!
//! 线上格式版本由 [`API_VERSION`] 固定；破坏性变更必须升版并登记到
//! `spec/ref/v1/`。

mod bindings;
mod contract;
mod error;
mod reference;

pub use bindings::{
    BindingMatch, BindingsMetadata, BindingsSpec, InstanceBindings, MatchScope, RefBindings,
    RefRule, RefRuleEntry, UnknownSchemePolicy, Visibility,
};
pub use contract::{
    ArtifactContract, Auth, CapabilityContract, CapabilityServer, CapabilityTool, CardMetadata,
    CardStatus, ContractCard, ContractSpec, DigestPolicy, Idempotency, Lifecycle, Materialization,
    Parties, Pinning, ReferenceContract, Resolution, ResolutionMode, ResultContract, SideEffect,
    Verification,
};
pub use error::SpecError;
pub use reference::{
    classify_reference, PinningRequirement, ReferenceForm, DEFAULT_MAX_REFERENCE_LENGTH,
};

/// Reference Plane 的线上 API 版本。
pub const API_VERSION: &str = "pact.ref/v1";

/// RefBindings 的 `kind` 取值。
pub const REF_BINDINGS_KIND: &str = "RefBindings";

/// ContractCard 的 `kind` 取值。
pub const CONTRACT_CARD_KIND: &str = "ContractCard";

/// 校验一个域/实例名：`[A-Za-z0-9_-]{1,128}`。
pub fn is_valid_scope_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// 校验一个小写 URI scheme：`[a-z][a-z0-9+.-]{0,31}`。
pub fn is_valid_scheme(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    value.len() <= 32
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '-' | '.'))
}

/// 校验 `sha256:<64 hex>`。
pub fn is_valid_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// 校验契约 id：`namespace/name@version`。
pub fn is_valid_contract_id(value: &str) -> bool {
    let Some((id, version)) = value.split_once('@') else {
        return false;
    };
    !id.is_empty()
        && !version.is_empty()
        && id.split('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        })
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}
