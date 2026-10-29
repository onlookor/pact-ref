use std::fmt;

/// 规范层错误。只描述“输入不符合 spec”，不表示解析器/网络/授权失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecError {
    /// 引用字符串为空或只有空白。
    EmptyReference,
    /// 裸路径不能作为跨参与者物引。
    BarePath(String),
    /// 引用包含控制字符。
    ControlCharacter(char),
    /// 引用超过长度上限。
    TooLong { actual: usize, max: usize },
    /// URI 形态不合法（空白、缺少 authority 等）。
    MalformedUri(String),
    /// scheme 不合法。
    InvalidScheme(String),
    /// URI authority 中包含 `userinfo`。
    UserInfoNotAllowed,
    /// 无 scheme 的 Identifier 含不允许的字符。
    InvalidIdentifier(String),
    /// 域/实例名不合法。
    InvalidDomain(String),
    /// 摘要格式不合法。
    InvalidDigest(String),
    /// RefBindings 结构或取值不合法。
    InvalidBindings(String),
    /// ContractCard 结构或取值不合法。
    InvalidContract(String),
    /// Tombstone 结构或取值不合法。
    InvalidTombstone(String),
    /// 该类型要求物引，但票面是 `∅`。
    ReferenceRequired,
    /// 该类型不允许当前 scheme。
    SchemeNotAllowed { scheme: String, type_name: String },
    /// 该类型不允许无 scheme 的 Identifier。
    IdentifierNotAllowed { type_name: String },
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyReference => f.write_str("reference is empty"),
            Self::BarePath(value) => {
                write!(f, "bare path is not a cross-participant reference: {value}")
            }
            Self::ControlCharacter(c) => write!(
                f,
                "reference contains control character U+{:04X}",
                *c as u32
            ),
            Self::TooLong { actual, max } => {
                write!(f, "reference is {actual} bytes, limit is {max}")
            }
            Self::MalformedUri(message) => write!(f, "malformed URI: {message}"),
            Self::InvalidScheme(scheme) => write!(f, "invalid scheme: {scheme}"),
            Self::UserInfoNotAllowed => f.write_str("URI userinfo is not allowed in ThingRef"),
            Self::InvalidIdentifier(value) => write!(
                f,
                "identifier contains characters outside ALPHA/DIGIT/_/-/./:/@/#: {value}"
            ),
            Self::InvalidDomain(value) => write!(f, "invalid domain or instance name: {value}"),
            Self::InvalidDigest(value) => write!(f, "invalid sha256 digest: {value}"),
            Self::InvalidBindings(message) => write!(f, "invalid RefBindings: {message}"),
            Self::InvalidContract(message) => write!(f, "invalid ContractCard: {message}"),
            Self::InvalidTombstone(message) => write!(f, "invalid Tombstone: {message}"),
            Self::ReferenceRequired => f.write_str("reference is required by RefBindings"),
            Self::SchemeNotAllowed { scheme, type_name } => {
                write!(f, "scheme {scheme} is not allowed for type {type_name}")
            }
            Self::IdentifierNotAllowed { type_name } => {
                write!(
                    f,
                    "identifier without scheme is not allowed for type {type_name}"
                )
            }
        }
    }
}

impl std::error::Error for SpecError {}
