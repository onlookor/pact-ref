//! 服务状态装配：认证器、ACL、审计 sink、adapter 与 profile 索引。

use std::collections::HashMap;
use std::sync::Arc;

use pact_ref_adapter_file::Adapter as FileAdapter;
use pact_ref_adapter_http::Adapter as HttpAdapter;
use pact_ref_audit::FileAuditSink;
use pact_ref_auth::{Acl, AclRule, Authenticator, DenyAuthenticator, StaticTokenAuthenticator};
use pact_ref_core::AuditSink;
use pact_ref_resolver::ResolverRegistry;

use crate::config::{AuthMode, Config, Profile};

/// 已装配、可共享的服务状态。
pub struct AppState {
    pub authenticator: Arc<dyn Authenticator + Send + Sync>,
    pub acl: Acl,
    pub audit: Arc<dyn AuditSink + Send + Sync>,
    pub audit_fail_open: bool,
    pub resolvers: Arc<ResolverRegistry>,
    pub profiles: HashMap<(String, String), Profile>,
}

impl AppState {
    /// 按配置装配。任何无法确认安全的组合都返回错误，调用方应拒绝启动。
    pub fn from_config(config: Config) -> Result<Self, String> {
        config.validate()?;

        let authenticator: Arc<dyn Authenticator + Send + Sync> = match config.auth.mode {
            AuthMode::Deny => Arc::new(DenyAuthenticator),
            AuthMode::Static => {
                let static_auth = config
                    .auth
                    .static_token
                    .as_ref()
                    .ok_or_else(|| "auth.mode = static requires [auth.static]".to_owned())?;
                Arc::new(StaticTokenAuthenticator::new(
                    static_auth.token.clone(),
                    static_auth.subject.clone(),
                    static_auth.scopes.clone(),
                ))
            }
            AuthMode::Oidc => {
                return Err("auth.mode = oidc is not implemented in v1".to_owned());
            }
        };

        let acl = Acl::new(
            config
                .acl
                .iter()
                .map(|rule| AclRule {
                    principal: rule.principal.clone(),
                    domains: rule.domains.clone(),
                    types: rule.types.clone(),
                    schemes: rule.schemes.clone(),
                    operations: rule.operations.clone(),
                })
                .collect(),
        );

        let audit_path = config.audit_path();
        let audit: Arc<dyn AuditSink + Send + Sync> = Arc::new(
            FileAuditSink::open(&audit_path)
                .map_err(|error| format!("open audit sink {}: {error}", audit_path.display()))?,
        );

        let mut resolvers = ResolverRegistry::new();
        if let Some(file) = &config.adapter.file {
            let root = config.absolute(&file.root);
            let adapter = FileAdapter::new(&root)
                .map_err(|error| format!("file adapter root {}: {error}", root.display()))?;
            resolvers.register(Box::new(adapter));
        }
        if let Some(https) = &config.adapter.https {
            resolvers.register(Box::new(HttpAdapter::new(
                https.allowed_hosts.clone(),
                https.timeout_ms,
            )));
        }

        let profiles = config.load_profiles()?;

        Ok(Self {
            authenticator,
            acl,
            audit,
            audit_fail_open: config.audit.fail_open,
            resolvers: Arc::new(resolvers),
            profiles,
        })
    }

    /// 按 `(domain, type)` 查找 profile。
    pub fn profile(&self, domain: &str, type_name: &str) -> Option<&Profile> {
        self.profiles
            .get(&(domain.to_owned(), type_name.to_owned()))
    }
}
