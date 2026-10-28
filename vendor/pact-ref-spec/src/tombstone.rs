//! Tombstone 记录（D44）：内容删除后的可发现、可审计证据。
//!
//! Tombstone 是**独立于引擎**的规范对象。PACT 不直接写存储；域作者应把
//! tombstone 作为正常 `seed` / `produce` 的制品，`ThingRef` 指向它。本模块只定义
//! 线上形状与静态校验，供 `pact ref lint`、参考实现与消费者共用。

use serde::{Deserialize, Serialize};

use crate::error::SpecError;
use crate::reference::ReferenceForm;
use crate::{is_valid_contract_id, API_VERSION};

/// Tombstone 的 `kind` 取值。
pub const TOMBSTONE_KIND: &str = "Tombstone";

/// 单个引用被删除/撤销/替换后的 tombstone 记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tombstone {
    pub api_version: String,
    pub kind: String,
    pub metadata: TombstoneMetadata,
    pub spec: TombstoneSpec,
}

impl Tombstone {
    /// 结构/取值校验。
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.api_version != API_VERSION {
            return Err(SpecError::InvalidTombstone(format!(
                "apiVersion must be {API_VERSION}"
            )));
        }
        if self.kind != TOMBSTONE_KIND {
            return Err(SpecError::InvalidTombstone(format!(
                "kind must be {TOMBSTONE_KIND}"
            )));
        }

        let id = ReferenceForm::classify(Some(&self.metadata.id)).map_err(|error| {
            SpecError::InvalidTombstone(format!("metadata.id is not a URI: {error}"))
        })?;
        if !id.is_uri() {
            return Err(SpecError::InvalidTombstone(
                "metadata.id must be a URI".to_owned(),
            ));
        }
        if let Some(owner) = &self.metadata.owner {
            if owner.trim().is_empty() {
                return Err(SpecError::InvalidTombstone(
                    "metadata.owner must not be empty".to_owned(),
                ));
            }
        }

        if !is_valid_contract_id(&self.spec.contract) {
            return Err(SpecError::InvalidTombstone(format!(
                "spec.contract must be id@version: {}",
                self.spec.contract
            )));
        }

        ReferenceForm::classify(Some(&self.spec.reference)).map_err(|error| {
            SpecError::InvalidTombstone(format!("spec.ref is not a valid reference: {error}"))
        })?;

        let deleted_at = parse_rfc3339_utc(&self.spec.deleted_at).ok_or_else(|| {
            SpecError::InvalidTombstone(format!(
                "spec.deletedAt must be RFC3339 UTC with `Z`: {}",
                self.spec.deleted_at
            ))
        })?;
        if let Some(retain_until) = &self.spec.retain_until {
            let retain_until = parse_rfc3339_utc(retain_until).ok_or_else(|| {
                SpecError::InvalidTombstone(format!(
                    "spec.retainUntil must be RFC3339 UTC with `Z`: {retain_until}"
                ))
            })?;
            if retain_until <= deleted_at {
                return Err(SpecError::InvalidTombstone(
                    "spec.retainUntil must be later than spec.deletedAt".to_owned(),
                ));
            }
        }

        let replaced_by = self
            .spec
            .replaced_by
            .as_deref()
            .map(|value| {
                ReferenceForm::classify(Some(value)).map_err(|error| {
                    SpecError::InvalidTombstone(format!(
                        "spec.replacedBy is not a valid reference: {error}"
                    ))
                })
            })
            .transpose()?;
        if replaced_by.is_some_and(|form| form.as_str() == Some(self.spec.reference.as_str())) {
            return Err(SpecError::InvalidTombstone(
                "spec.replacedBy must differ from spec.ref".to_owned(),
            ));
        }
        if self.spec.reason == TombstoneReason::Replaced && self.spec.replaced_by.is_none() {
            return Err(SpecError::InvalidTombstone(
                "reason=replaced requires spec.replacedBy".to_owned(),
            ));
        }

        if let Some(note) = &self.spec.note {
            if note.trim().is_empty() {
                return Err(SpecError::InvalidTombstone(
                    "spec.note must not be empty".to_owned(),
                ));
            }
            if note.len() > 2048 {
                return Err(SpecError::InvalidTombstone(
                    "spec.note must be at most 2048 bytes".to_owned(),
                ));
            }
            if note.chars().any(|c| c.is_control()) {
                return Err(SpecError::InvalidTombstone(
                    "spec.note must not contain control characters".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Tombstone 元数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TombstoneMetadata {
    /// 全局唯一的 tombstone id（URI）。
    pub id: String,
    #[serde(default)]
    pub owner: Option<String>,
}

/// Tombstone 主体。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TombstoneSpec {
    /// 被删除引用所归属的契约（`id@version`）。
    pub contract: String,
    /// 已失效的具体引用；URI 或 legacy Identifier。
    #[serde(rename = "ref")]
    pub reference: String,
    pub reason: TombstoneReason,
    /// 删除生效时间（RFC3339 UTC，带 `Z`）。
    pub deleted_at: String,
    /// tombstone 本身的保留截止时间（可选；必须晚于 `deletedAt`）。
    #[serde(default)]
    pub retain_until: Option<String>,
    /// 替代引用的位置（`reason=replaced` 时必填）。
    #[serde(default)]
    pub replaced_by: Option<String>,
    /// 人类可读说明；不得含控制字符或秘密。
    #[serde(default)]
    pub note: Option<String>,
}

/// Tombstone 原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TombstoneReason {
    Expired,
    Replaced,
    Revoked,
    Compromised,
    Legal,
    Manual,
}

/// 解析 RFC3339 UTC 时间，返回可比较的 `(年, 月, 日, 时, 分, 秒, 纳秒)`。
///
/// 只接受大写 `Z` 结尾；允许 1–9 位小数秒与闰秒（秒 = 60）。
fn parse_rfc3339_utc(value: &str) -> Option<(i32, u32, u32, u32, u32, u32, u32)> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last()? != b'Z'
    {
        return None;
    }
    // 用 `get` 而不是切片：输入可能含多字节字符，固定字节下标不一定落在
    // 字符边界上；越界或非边界一律视为非法时间戳，不 panic。
    let year = digits(value.get(0..4)?)? as i32;
    let month = digits(value.get(5..7)?)?;
    let day = digits(value.get(8..10)?)?;
    let hour = digits(value.get(11..13)?)?;
    let minute = digits(value.get(14..16)?)?;
    let second = digits(value.get(17..19)?)?;

    let fraction = value.get(19..value.len() - 1)?;
    let nanos = if fraction.is_empty() {
        0
    } else {
        let digits = fraction.strip_prefix('.')?;
        if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut padded = digits.to_owned();
        padded.extend(std::iter::repeat_n('0', 9 - digits.len()));
        padded.parse::<u32>().ok()?
    };

    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    Some((year, month, day, hour, minute, second, nanos))
}

fn digits(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::{Tombstone, TombstoneReason};
    use crate::SpecError;

    const TOMBSTONE: &str = r#"{
      "apiVersion": "pact.ref/v1",
      "kind": "Tombstone",
      "metadata": {
        "id": "urn:pact:tombstone:se/design-review:req-001",
        "owner": "artifacts-team"
      },
      "spec": {
        "contract": "se/design-review@2",
        "ref": "https://artifacts.example.com/design/req-001",
        "reason": "expired",
        "deletedAt": "2026-10-27T00:00:00Z",
        "retainUntil": "2027-10-27T00:00:00Z",
        "note": "保留期结束，按契约删除"
      }
    }"#;

    #[test]
    fn validates_tombstone() {
        let tombstone: Tombstone = serde_json::from_str(TOMBSTONE).expect("tombstone");
        tombstone.validate().expect("valid");
        assert_eq!(tombstone.spec.reason, TombstoneReason::Expired);
    }

    #[test]
    fn rejects_replaced_without_replacement() {
        let mut tombstone: Tombstone = serde_json::from_str(TOMBSTONE).expect("tombstone");
        tombstone.spec.reason = TombstoneReason::Replaced;
        let error = tombstone.validate().expect_err("reject");
        assert!(matches!(error, SpecError::InvalidTombstone(_)));
    }

    #[test]
    fn rejects_retain_until_not_after_deleted_at() {
        let mut tombstone: Tombstone = serde_json::from_str(TOMBSTONE).expect("tombstone");
        tombstone.spec.retain_until = Some("2026-10-27T00:00:00Z".to_owned());
        let error = tombstone.validate().expect_err("reject");
        assert!(matches!(error, SpecError::InvalidTombstone(_)));
    }

    #[test]
    fn rejects_invalid_timestamp_and_replacement_identity() {
        let mut tombstone: Tombstone = serde_json::from_str(TOMBSTONE).expect("tombstone");
        tombstone.spec.deleted_at = "2026-02-30T00:00:00Z".to_owned();
        assert!(tombstone.validate().is_err());

        let mut tombstone: Tombstone = serde_json::from_str(TOMBSTONE).expect("tombstone");
        tombstone.spec.replaced_by = Some(tombstone.spec.reference.clone());
        tombstone.spec.reason = TombstoneReason::Replaced;
        assert!(tombstone.validate().is_err());
    }

    #[test]
    fn rejects_bare_path_reference() {
        let mut tombstone: Tombstone = serde_json::from_str(TOMBSTONE).expect("tombstone");
        tombstone.spec.reference = "/tmp/artifact.md".to_owned();
        let error = tombstone.validate().expect_err("reject");
        assert!(matches!(error, SpecError::InvalidTombstone(_)));
    }

    /// 非 ASCII 字符落在固定字段边界内时不得 panic，只报校验错误。
    #[test]
    fn rejects_non_ascii_timestamp_without_panicking() {
        let mut tombstone: Tombstone = serde_json::from_str(TOMBSTONE).expect("tombstone");
        tombstone.spec.deleted_at = "2026-10-27T00:00:0éZ".to_owned();
        let error = tombstone.validate().expect_err("reject");
        assert!(matches!(error, SpecError::InvalidTombstone(_)));
    }
}
