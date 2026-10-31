//! `refd.toml` 配置解析与启动校验。
//!
//! 校验原则是 fail-closed：无法确认安全的组合直接拒绝启动，而不是降级为宽松默认。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use pact_ref_core::{ContractCard, ContractDescriptor};
use serde::Deserialize;

/// 已加载的 `(domain, type)` profile。
#[derive(Debug, Clone)]
pub struct Profile {
    pub card: ContractCard,
    pub descriptor: ContractDescriptor,
    pub schemes: Vec<String>,
}

/// 顶层配置。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub adapter: AdapterConfig,
    #[serde(default)]
    pub acl: Vec<AclRuleConfig>,
    #[serde(default)]
    pub profiles: Vec<ProfileConfig>,
    /// 配置文件所在目录；相对路径以此为基准。不参与反序列化。
    #[serde(skip)]
    pub base_dir: PathBuf,
}

/// 监听配置。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// 必须是回环地址：v1 不内置 TLS。
    #[serde(default = "default_bind")]
    pub bind: String,
    /// 仅当绑定回环地址时允许明文。
    #[serde(default)]
    pub allow_plaintext: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            allow_plaintext: false,
        }
    }
}

fn default_bind() -> String {
    "127.0.0.1:8080".to_owned()
}

/// 认证配置，默认拒绝。
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default)]
    pub mode: AuthMode,
    #[serde(default, rename = "static")]
    pub static_token: Option<StaticAuthConfig>,
}

/// 认证模式。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    Deny,
    Static,
    Oidc,
}

/// 静态令牌（引导/受控内网）。必须显式 `allow = true`。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticAuthConfig {
    #[serde(default)]
    pub allow: bool,
    pub token: String,
    pub subject: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// 审计配置。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub fail_open: bool,
}

/// adapter 配置。
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    #[serde(default)]
    pub file: Option<FileAdapterConfig>,
    #[serde(default)]
    pub https: Option<HttpsAdapterConfig>,
}

/// `file://` adapter：所有路径必须落在 `root` 下。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileAdapterConfig {
    pub root: PathBuf,
}

/// `https://` adapter：主机 allowlist，默认拒绝。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsAdapterConfig {
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    10_000
}

/// 一条对象 ACL 规则。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclRuleConfig {
    pub principal: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub types: Vec<String>,
    #[serde(default)]
    pub schemes: Vec<String>,
    #[serde(default)]
    pub operations: Vec<String>,
}

/// 一个 `(domain, type)` 对应的 ContractCard。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    pub domain: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub card: PathBuf,
}

impl Config {
    /// 从文件加载；相对路径以配置文件目录为基准。
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("read config {}: {error}", path.display()))?;
        let base_dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Self::from_toml(&text, &base_dir)
    }

    /// 从 TOML 文本加载；`base_dir` 用于解析相对路径。
    pub fn from_toml(text: &str, base_dir: &Path) -> Result<Self, String> {
        let mut config: Config =
            toml::from_str(text).map_err(|error| format!("parse config: {error}"))?;
        config.base_dir = base_dir.to_path_buf();
        Ok(config)
    }

    /// 校验监听与认证配置；不触碰网络。
    pub fn validate(&self) -> Result<(), String> {
        let address: SocketAddr = self.server.bind.parse().map_err(|_| {
            format!(
                "server.bind must be an IP socket address: {}",
                self.server.bind
            )
        })?;
        if !address.ip().is_loopback() || !self.server.allow_plaintext {
            return Err(
                "refd v1 has no TLS listener: bind a loopback address and set \
                 server.allow_plaintext = true for local development"
                    .to_owned(),
            );
        }

        match self.auth.mode {
            AuthMode::Deny => {}
            AuthMode::Static => {
                let static_auth = self.auth.static_token.as_ref().ok_or_else(|| {
                    "auth.mode = static requires an [auth.static] table".to_owned()
                })?;
                if !static_auth.allow {
                    return Err("auth.mode = static requires auth.static.allow = true".to_owned());
                }
                if static_auth.token.is_empty() {
                    return Err("auth.static.token must not be empty".to_owned());
                }
                if static_auth.subject.is_empty() {
                    return Err("auth.static.subject must not be empty".to_owned());
                }
                if static_auth.scopes.is_empty() {
                    return Err("auth.static.scopes must not be empty".to_owned());
                }
            }
            AuthMode::Oidc => {
                return Err(
                    "auth.mode = oidc is not implemented in v1; use static or deny".to_owned(),
                );
            }
        }

        for rule in &self.acl {
            if rule.principal.is_empty()
                || rule.domains.is_empty()
                || rule.types.is_empty()
                || rule.schemes.is_empty()
                || rule.operations.is_empty()
            {
                return Err(
                    "each [[acl]] rule needs principal, domains, types, schemes and operations"
                        .to_owned(),
                );
            }
        }

        let mut seen = HashMap::new();
        for profile in &self.profiles {
            validate_selector("profiles.domain", &profile.domain)?;
            validate_selector("profiles.type", &profile.type_name)?;
            let key = (profile.domain.clone(), profile.type_name.clone());
            if seen.insert(key.clone(), ()).is_some() {
                return Err(format!(
                    "duplicate profile for domain={} type={}",
                    key.0, key.1
                ));
            }
        }
        Ok(())
    }

    /// 加载全部 profile 卡片并校验。
    pub fn load_profiles(&self) -> Result<HashMap<(String, String), Profile>, String> {
        let mut profiles = HashMap::new();
        for entry in &self.profiles {
            let path = self.absolute(&entry.card);
            let text = std::fs::read_to_string(&path)
                .map_err(|error| format!("read contract card {}: {error}", path.display()))?;
            let card: ContractCard = serde_yaml::from_str(&text)
                .map_err(|error| format!("parse contract card {}: {error}", path.display()))?;
            card.validate()
                .map_err(|error| format!("invalid contract card {}: {error}", path.display()))?;
            let profile = Profile {
                descriptor: ContractDescriptor::from(&card),
                schemes: card.spec.reference.schemes.clone(),
                card,
            };
            profiles.insert((entry.domain.clone(), entry.type_name.clone()), profile);
        }
        Ok(profiles)
    }

    /// 审计文件路径（相对路径以配置文件目录为基准）。
    pub fn audit_path(&self) -> PathBuf {
        self.absolute(&self.audit.path)
    }

    /// 相对路径转绝对路径。
    pub fn absolute(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.base_dir.join(path)
        }
    }
}

/// `domain` / `type` 只做长度与控制字符校验，不解释语义。
pub fn validate_selector(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.chars().count() > 255 {
        return Err(format!("{label} exceeds 255 characters"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{label} contains a control character"));
    }
    Ok(())
}
