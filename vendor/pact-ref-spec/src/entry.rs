//! 写入路径的入口票面校验（D45/D46/D50）。
//!
//! 本模块把 REST 边界已有的校验语义收为纯函数，供 `pact-http` 与 `pact-wasm`
//! 共用，避免两种分发形态各写一套规范化/策略判定。它只依赖本 crate 的
//! 数据结构，不做 IO，可编译到 `wasm32-unknown-unknown`。

use std::fmt;

use crate::bindings::{RefBindings, UnknownSchemePolicy};
use crate::error::SpecError;
use crate::reference::{
    classify_identifier, pinned_digest, ReferenceForm, DEFAULT_MAX_REFERENCE_LENGTH,
    HARD_MAX_REFERENCE_LENGTH,
};

/// 入口输入的三种状态。
///
/// 对齐母本 `ThingRef ::= URI | Identifier | ∅` 的“表态”语义：
/// 字段缺失（`Missing`）表示调用方没有给出任何表态，显式 `null`（`Absent`）
/// 表示确认没有外部制品，字符串（`Present`）表示有引用。
///
/// JS/WASM 无法区分“省略参数”和“传 `null`”，因此宿主应把两者都映射为
/// `Absent`，而不是 `Missing`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryRef<'a> {
    /// 请求体缺少票面字段。
    Missing,
    /// 显式 `∅`。
    Absent,
    /// 有引用原文。
    Present(&'a str),
}

/// 入口校验错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryError {
    /// 请求体缺少票面字段（作者漏传）。
    Missing,
    /// 结构或 RefBindings 策略拒绝。
    Invalid(SpecError),
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => {
                f.write_str("thing_ref field is missing; pass null to confirm no artifact")
            }
            Self::Invalid(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for EntryError {}

/// 校验并规范化一次写入的票面。
///
/// - 无绑定（`bindings = None`）时只做结构校验：URI profile、Identifier 文法、
///   默认长度上限（[`DEFAULT_MAX_REFERENCE_LENGTH`]）。
/// - 有绑定时再强制 `required` / `allowIdentifier` / `schemes` /
///   `onUnknownScheme` / `value` / `pinning: required` / `maxLength`。
///
/// 成功返回规范化后的票面（scheme 小写）；`∅` 返回 `None`。
pub fn validate_entry(
    bindings: Option<&RefBindings>,
    instance: Option<&str>,
    type_name: &str,
    input: EntryRef<'_>,
) -> Result<Option<String>, EntryError> {
    let raw = match input {
        EntryRef::Missing => return Err(EntryError::Missing),
        EntryRef::Absent => {
            if let Some(bindings) = bindings {
                bindings
                    .resolve(instance, type_name, &ReferenceForm::Absent)
                    .map_err(EntryError::Invalid)?;
            }
            return Ok(None);
        }
        EntryRef::Present(raw) => raw,
    };

    let reference = ReferenceForm::classify_with_limit(Some(raw), HARD_MAX_REFERENCE_LENGTH)
        .map_err(EntryError::Invalid)?;
    let Some(bindings) = bindings else {
        if raw.len() > DEFAULT_MAX_REFERENCE_LENGTH {
            return Err(EntryError::Invalid(SpecError::TooLong {
                actual: raw.len(),
                max: DEFAULT_MAX_REFERENCE_LENGTH,
            }));
        }
        return Ok(reference.as_str().map(str::to_owned));
    };
    let matched = bindings
        .resolve(instance, type_name, &reference)
        .map_err(EntryError::Invalid)?;

    // D46：未知 scheme 的三种处理。`resolve` 只拦 `reject`（缺省），
    // 其余两种在这里落地。
    let mut effective = reference;
    if let ReferenceForm::Uri(uri) = &effective {
        let scheme = effective.scheme().unwrap_or_default().to_owned();
        if scheme_is_unknown(&matched.rule, &scheme) {
            match matched
                .rule
                .on_unknown_scheme
                .unwrap_or(UnknownSchemePolicy::Reject)
            {
                UnknownSchemePolicy::Allow => {}
                UnknownSchemePolicy::TreatAsIdentifier => {
                    if !matched.rule.allow_identifier.unwrap_or(false) {
                        return Err(EntryError::Invalid(SpecError::IdentifierNotAllowed {
                            type_name: type_name.to_owned(),
                        }));
                    }
                    effective = classify_identifier(uri).map_err(EntryError::Invalid)?;
                }
                UnknownSchemePolicy::Reject => {
                    return Err(EntryError::Invalid(SpecError::SchemeNotAllowed {
                        scheme,
                        type_name: type_name.to_owned(),
                    }));
                }
            }
        }
    }

    // D46：`value` 约束非空票面的形态；`∅` 由 `required` 决定。
    if let Some(expected) = matched.rule.value.as_deref() {
        let actual = match &effective {
            ReferenceForm::Uri(_) => "uri",
            ReferenceForm::Identifier(_) => "identifier",
            ReferenceForm::Absent => "null",
        };
        let ok = match expected {
            "none" => effective.is_absent(),
            "uri" => effective.is_uri(),
            "identifier" => effective.is_identifier(),
            _ => true,
        };
        if !ok {
            return Err(EntryError::Invalid(SpecError::ValueFormMismatch {
                expected: expected.to_owned(),
                actual: actual.to_owned(),
            }));
        }
    }

    // D46：写入时钉版（`required-at-archive` 留到 consume）。
    if matched.pins_at_entry() {
        if let Some(value) = effective.as_str() {
            if pinned_digest(value).is_none() {
                return Err(EntryError::Invalid(SpecError::PinningRequired {
                    type_name: type_name.to_owned(),
                    at_archive: false,
                }));
            }
        }
    }

    let max_length = matched
        .rule
        .max_length
        .unwrap_or(DEFAULT_MAX_REFERENCE_LENGTH);
    if raw.len() > max_length {
        return Err(EntryError::Invalid(SpecError::TooLong {
            actual: raw.len(),
            max: max_length,
        }));
    }
    Ok(effective.as_str().map(str::to_owned))
}

/// 有效 `schemes` 非空且不含 `*` 时，不在白名单内的 scheme 视为“未知”。
fn scheme_is_unknown(rule: &crate::bindings::RefRule, scheme: &str) -> bool {
    rule.schemes.as_ref().is_some_and(|allowed| {
        !allowed.is_empty()
            && !allowed
                .iter()
                .any(|candidate| candidate == "*" || candidate == scheme)
    })
}

#[cfg(test)]
mod tests {
    use super::{validate_entry, EntryError, EntryRef};
    use crate::reference::ReferenceForm;
    use crate::{RefBindings, SpecError};

    fn bindings(rule: &str) -> RefBindings {
        let json = format!(
            r#"{{
              "apiVersion": "pact.ref/v1",
              "kind": "RefBindings",
              "metadata": {{ "domain": "proj" }},
              "spec": {{
                "types": {{
                  "design": {{ "ref": {rule} }}
                }}
              }}
            }}"#
        );
        let parsed: RefBindings = serde_json::from_str(&json).expect("bindings");
        parsed.validate().expect("valid bindings");
        parsed
    }

    #[test]
    fn missing_absent_and_present_three_states() {
        assert_eq!(
            validate_entry(None, Some("default"), "design", EntryRef::Missing),
            Err(EntryError::Missing)
        );
        assert_eq!(
            validate_entry(None, Some("default"), "design", EntryRef::Absent),
            Ok(None)
        );
        let normalized = validate_entry(
            None,
            Some("default"),
            "design",
            EntryRef::Present("HTTPS://example.com/a"),
        )
        .expect("valid");
        assert_eq!(normalized.as_deref(), Some("https://example.com/a"));
    }

    #[test]
    fn structural_rules_apply_without_bindings() {
        assert!(matches!(
            validate_entry(None, None, "design", EntryRef::Present("/tmp/a.md")),
            Err(EntryError::Invalid(SpecError::BarePath(_)))
        ));
        assert!(matches!(
            validate_entry(None, None, "design", EntryRef::Present("foo bar")),
            Err(EntryError::Invalid(SpecError::InvalidIdentifier(_)))
        ));
        let long = "a".repeat(2049);
        assert!(matches!(
            validate_entry(None, None, "design", EntryRef::Present(&long)),
            Err(EntryError::Invalid(SpecError::TooLong { .. }))
        ));
    }

    #[test]
    fn bindings_require_presence_and_allow_schemes() {
        let bindings = bindings(r#"{ "required": true, "schemes": ["https"] }"#);
        assert_eq!(
            validate_entry(Some(&bindings), Some("default"), "design", EntryRef::Absent),
            Err(EntryError::Invalid(SpecError::ReferenceRequired))
        );
        assert!(matches!(
            validate_entry(
                Some(&bindings),
                Some("default"),
                "design",
                EntryRef::Present("git://example.com/a")
            ),
            Err(EntryError::Invalid(SpecError::SchemeNotAllowed { .. }))
        ));
        assert_eq!(
            validate_entry(
                Some(&bindings),
                Some("default"),
                "design",
                EntryRef::Present("https://example.com/a")
            ),
            Ok(Some("https://example.com/a".to_owned()))
        );
    }

    #[test]
    fn bindings_can_reject_identifiers_by_default() {
        let bindings = bindings(r#"{ "required": true }"#);
        assert!(matches!(
            validate_entry(
                Some(&bindings),
                Some("default"),
                "design",
                EntryRef::Present("REQ-001")
            ),
            Err(EntryError::Invalid(SpecError::IdentifierNotAllowed { .. }))
        ));
    }

    #[test]
    fn unknown_scheme_policies_take_effect() {
        let allow = bindings(r#"{ "schemes": ["https"], "onUnknownScheme": "allow" }"#);
        assert_eq!(
            validate_entry(
                Some(&allow),
                Some("default"),
                "design",
                EntryRef::Present("mcp://build.example.com/run")
            ),
            Ok(Some("mcp://build.example.com/run".to_owned()))
        );

        let treat = bindings(
            r#"{ "schemes": ["https"], "allowIdentifier": true, "onUnknownScheme": "treat-as-identifier" }"#,
        );
        assert_eq!(
            validate_entry(
                Some(&treat),
                Some("default"),
                "design",
                EntryRef::Present("mcp://build.example.com/run")
            ),
            Ok(Some("mcp://build.example.com/run".to_owned()))
        );

        let reject = bindings(r#"{ "schemes": ["https"] }"#);
        assert!(matches!(
            validate_entry(
                Some(&reject),
                Some("default"),
                "design",
                EntryRef::Present("mcp://build.example.com/run")
            ),
            Err(EntryError::Invalid(SpecError::SchemeNotAllowed { .. }))
        ));
    }

    #[test]
    fn value_and_pinning_rules_apply_at_entry() {
        let uri_only = bindings(r#"{ "value": "uri", "allowIdentifier": true }"#);
        assert!(matches!(
            validate_entry(
                Some(&uri_only),
                Some("default"),
                "design",
                EntryRef::Present("REQ-001")
            ),
            Err(EntryError::Invalid(SpecError::ValueFormMismatch { .. }))
        ));

        let pinned = bindings(r#"{ "pinning": "required" }"#);
        assert!(matches!(
            validate_entry(
                Some(&pinned),
                Some("default"),
                "design",
                EntryRef::Present("https://example.com/design")
            ),
            Err(EntryError::Invalid(SpecError::PinningRequired {
                at_archive: false,
                ..
            }))
        ));
        let hex = "9f".repeat(32);
        let pinned_uri = format!("https://example.com/design#sha256={hex}");
        assert_eq!(
            validate_entry(
                Some(&pinned),
                Some("default"),
                "design",
                EntryRef::Present(&pinned_uri)
            ),
            Ok(Some(pinned_uri))
        );
    }

    #[test]
    fn classify_identifier_remains_available_for_callers() {
        assert_eq!(
            ReferenceForm::classify(Some("REQ-001")).expect("identifier"),
            ReferenceForm::Identifier("REQ-001".to_owned())
        );
    }
}
