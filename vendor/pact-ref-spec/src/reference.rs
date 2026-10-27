use serde::{Deserialize, Serialize};

use crate::error::SpecError;

/// 默认引用长度上限（字节）。
pub const DEFAULT_MAX_REFERENCE_LENGTH: usize = 2048;

/// 票面的三种形态，对应母本 `ThingRef ::= URI | Identifier | ∅`。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReferenceForm {
    /// 带合法 scheme 的 URI。scheme 已被规范化为小写。
    Uri(String),
    /// 无 scheme 的标识符，例如 `REQ-001`。
    Identifier(String),
    /// 确认没有外部制品。
    Absent,
}

impl ReferenceForm {
    /// 按默认长度上限分类。
    pub fn classify(raw: Option<&str>) -> Result<Self, SpecError> {
        Self::classify_with_limit(raw, DEFAULT_MAX_REFERENCE_LENGTH)
    }

    /// 按指定长度上限分类；上限来自 ContractCard 或 RefBindings。
    pub fn classify_with_limit(raw: Option<&str>, max: usize) -> Result<Self, SpecError> {
        let Some(value) = raw else {
            return Ok(Self::Absent);
        };
        if value.trim().is_empty() {
            return Err(SpecError::EmptyReference);
        }
        if value.len() > max {
            return Err(SpecError::TooLong {
                actual: value.len(),
                max,
            });
        }
        if let Some(c) = value.chars().find(|c| c.is_control()) {
            return Err(SpecError::ControlCharacter(c));
        }
        if value.trim() != value {
            return Err(SpecError::MalformedUri(
                "leading or trailing whitespace".to_owned(),
            ));
        }
        if looks_like_bare_path(value) {
            return Err(SpecError::BarePath(value.to_owned()));
        }

        let Some((scheme, rest)) = value.split_once(':') else {
            return Ok(Self::Identifier(value.to_owned()));
        };
        if rest.is_empty() || !is_valid_scheme_text(scheme) {
            return Ok(Self::Identifier(value.to_owned()));
        }
        if has_userinfo(value, scheme) {
            return Err(SpecError::UserInfoNotAllowed);
        }

        let normalized = format!("{}{}", scheme.to_ascii_lowercase(), &value[scheme.len()..]);
        Ok(Self::Uri(normalized))
    }

    /// 稳定的小写 scheme（仅 URI）。
    pub fn scheme(&self) -> Option<&str> {
        match self {
            Self::Uri(value) => value.split_once(':').map(|(scheme, _)| scheme),
            Self::Identifier(_) | Self::Absent => None,
        }
    }

    /// 票面字符串；`∅` 返回 `None`。
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Uri(value) | Self::Identifier(value) => Some(value),
            Self::Absent => None,
        }
    }

    pub fn is_uri(&self) -> bool {
        matches!(self, Self::Uri(_))
    }

    pub fn is_identifier(&self) -> bool {
        matches!(self, Self::Identifier(_))
    }

    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
}

impl fmt::Display for ReferenceForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uri(value) | Self::Identifier(value) => f.write_str(value),
            Self::Absent => f.write_str("∅"),
        }
    }
}

use std::fmt;

/// 把分类错误映射为治理层常用错误；调用方也可以直接使用 [`ReferenceForm::classify`]。
pub fn classify_reference(raw: Option<&str>) -> Result<ReferenceForm, SpecError> {
    ReferenceForm::classify(raw)
}

fn looks_like_bare_path(value: &str) -> bool {
    if value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("~/")
        || value.starts_with('\\')
    {
        return true;
    }
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

fn is_valid_scheme_text(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    value.len() <= 32 && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn has_userinfo(value: &str, scheme: &str) -> bool {
    let prefix = format!("{}://", scheme.to_ascii_lowercase());
    let lower = value.to_ascii_lowercase();
    if !lower.starts_with(&prefix) {
        return false;
    }
    let authority_and_rest = &value[scheme.len() + 3..];
    let authority = authority_and_rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    authority.contains('@')
}

/// 引用钉版强度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PinningRequirement {
    RequiredAtArchive,
    Required,
    #[default]
    Optional,
}

#[cfg(test)]
mod tests {
    use super::{ReferenceForm, SpecError};

    #[test]
    fn classifies_uri_identifier_and_absent() {
        assert_eq!(
            ReferenceForm::classify(Some("https://example.com/a")).expect("uri"),
            ReferenceForm::Uri("https://example.com/a".to_owned())
        );
        assert_eq!(
            ReferenceForm::classify(Some("REQ-001")).expect("identifier"),
            ReferenceForm::Identifier("REQ-001".to_owned())
        );
        assert_eq!(
            ReferenceForm::classify(None).expect("absent"),
            ReferenceForm::Absent
        );
    }

    #[test]
    fn normalizes_scheme_to_lowercase() {
        let reference = ReferenceForm::classify(Some("HTTPS://example.com/a")).expect("uri");
        assert_eq!(reference.scheme(), Some("https"));
        assert_eq!(reference.as_str(), Some("https://example.com/a"));
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_eq!(
            ReferenceForm::classify(Some("  ")),
            Err(SpecError::EmptyReference)
        );
        assert!(matches!(
            ReferenceForm::classify(Some(" https://example.com/a")),
            Err(SpecError::MalformedUri(_))
        ));
    }

    #[test]
    fn rejects_bare_paths() {
        assert!(matches!(
            ReferenceForm::classify(Some("/tmp/a.md")),
            Err(SpecError::BarePath(_))
        ));
        assert!(matches!(
            ReferenceForm::classify(Some("C:\\tmp\\a.md")),
            Err(SpecError::BarePath(_))
        ));
    }

    #[test]
    fn rejects_userinfo_and_control_characters() {
        assert_eq!(
            ReferenceForm::classify(Some("https://user:pass@example.com/a")),
            Err(SpecError::UserInfoNotAllowed)
        );
        assert!(matches!(
            ReferenceForm::classify(Some("https://example.com/a\nb")),
            Err(SpecError::ControlCharacter('\n'))
        ));
    }

    #[test]
    fn enforces_length_limit() {
        let long = format!("https://example.com/{}", "a".repeat(100));
        assert!(matches!(
            ReferenceForm::classify_with_limit(Some(&long), 32),
            Err(SpecError::TooLong { max: 32, .. })
        ));
    }
}
