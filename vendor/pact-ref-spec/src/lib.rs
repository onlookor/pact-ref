//! PACT 物引治理的纯规范层。
//!
//! 本 crate 只定义数据形状、URI profile 校验、RefBindings 匹配与 ContractCard 校验。
//! 它不做 IO、不访问网络、不读取文件，可编译到 `wasm32-unknown-unknown`。
//!
//! 线上格式版本由 [`API_VERSION`] 固定；破坏性变更必须升版并登记到
//! `spec/ref/v1/`。

mod bindings;
mod contract;
mod entry;
mod error;
mod reference;
mod tombstone;

pub use bindings::{
    BindingMatch, BindingsMetadata, BindingsSpec, InstanceBindings, MatchScope, RefBindings,
    RefRule, RefRuleEntry, UnknownSchemePolicy, Visibility,
};
pub use contract::{
    ArtifactContract, Auth, CapabilityContract, CapabilityServer, CapabilityTool, CardMetadata,
    CardStatus, ContractCard, ContractSpec, DeletionPolicy, DigestPolicy, Idempotency, Lifecycle,
    Materialization, Parties, Pinning, ReferenceContract, Resolution, ResolutionMode,
    ResultContract, SideEffect, Verification,
};
pub use entry::{validate_entry, EntryError, EntryRef};
pub use error::SpecError;
pub use reference::{
    classify_identifier, classify_reference, pinned_digest, PinningRequirement, ReferenceForm,
    DEFAULT_MAX_REFERENCE_LENGTH, HARD_MAX_REFERENCE_LENGTH,
};
pub use tombstone::{Tombstone, TombstoneMetadata, TombstoneReason, TombstoneSpec, TOMBSTONE_KIND};

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

/// 校验保留期（D44）：`permanent` 或正的 ISO 8601 duration。
///
/// 接受 `P[nY][nM][nW][nD][T[nH][nM][nS]]`；周（`W`）不得与其他日期分量组合，
/// 分量必须按顺序、只能是非负整数，且总时长必须大于零。
pub fn is_valid_retention(value: &str) -> bool {
    if value == "permanent" {
        return true;
    }
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'P') {
        return false;
    }
    let mut index = 1;
    let mut in_time = false;
    let mut date_rank: Option<u8> = None;
    let mut time_rank: Option<u8> = None;
    let mut saw_component = false;
    let mut non_zero = false;
    let mut has_week = false;
    let mut has_other_date = false;

    while index < bytes.len() {
        if bytes[index] == b'T' {
            if in_time {
                return false;
            }
            in_time = true;
            index += 1;
            if index == bytes.len() {
                return false;
            }
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == start || index == bytes.len() {
            return false;
        }
        let Ok(number) = value[start..index].parse::<u64>() else {
            return false;
        };
        let designator = bytes[index];
        index += 1;
        let rank = match (designator, in_time) {
            (b'Y', false) => 0,
            (b'M', false) => 1,
            (b'W', false) => 2,
            (b'D', false) => 3,
            (b'H', true) => 0,
            (b'M', true) => 1,
            (b'S', true) => 2,
            _ => return false,
        };
        if in_time {
            if time_rank.is_some_and(|previous| rank <= previous) {
                return false;
            }
            time_rank = Some(rank);
        } else {
            if date_rank.is_some_and(|previous| rank <= previous) {
                return false;
            }
            date_rank = Some(rank);
            if designator == b'W' {
                has_week = true;
            } else {
                has_other_date = true;
            }
        }
        if number > 0 {
            non_zero = true;
        }
        saw_component = true;
    }

    saw_component && non_zero && !(has_week && has_other_date) && (!in_time || time_rank.is_some())
}
