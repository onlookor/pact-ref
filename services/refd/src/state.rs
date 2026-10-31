//! 服务状态装配：认证器、ACL、审计 sink、adapter 与 profile 索引。

use std::collections::HashMap;
use std::sync::Arc;

use pact_ref_adapter_file::Adapter as FileAdapter;
use pact_ref_adapter_http::Adapter as HttpAdapter;
use pact_ref_adapter_mcp::{Adapter as McpAdapter, ServerConfig as McpServer};
use pact_ref_audit::FileAuditSink;
use pact_ref_auth::oidc::{JwksSource, OidcAuthenticator, OidcSettings};
use pact_ref_auth::{Acl, AclRule, Authenticator, DenyAuthenticator, StaticTokenAuthenticator};
use pact_ref_core::{AuditSink, SideEffect};
use pact_ref_invoker::InvokerRegistry;
use pact_ref_resolver::ResolverRegistry;

use crate::config::{AuthMode, Config, Profile};
use crate::jwks::{FileJwksSource, HttpJwksSource};

/// 已装配、可共享的服务状态。
pub struct AppState {
    pub authenticator: Arc<dyn Authenticator + Send + Sync>,
    pub acl: Acl,
    pub audit: Arc<dyn AuditSink + Send + Sync>,
    pub audit_fail_open: bool,
    pub resolvers: Arc<ResolverRegistry>,
    pub invokers: Arc<InvokerRegistry>,
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
                let oidc = config
                    .auth
                    .oidc
                    .as_ref()
                    .ok_or_else(|| "auth.mode = oidc requires [auth.oidc]".to_owned())?;
                let settings = OidcSettings {
                    issuer: oidc.issuer.clone(),
                    audience: oidc.audience.clone(),
                    algorithms: oidc.algorithms.clone(),
                    leeway_seconds: oidc.leeway_seconds,
                    cache_ttl_seconds: oidc.cache_ttl_seconds,
                };
                let source: Arc<dyn JwksSource + Send + Sync> =
                    match (&oidc.jwks_file, &oidc.jwks_uri) {
                        (Some(file), None) => Arc::new(FileJwksSource::new(config.absolute(file))),
                        (None, Some(uri)) => {
                            Arc::new(HttpJwksSource::new(uri.clone(), oidc.timeout_ms))
                        }
                        _ => {
                            return Err("auth.oidc requires exactly one of jwks_uri or jwks_file"
                                .to_owned())
                        }
                    };
                Arc::new(OidcAuthenticator::new(settings, source))
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

        let mut invokers = InvokerRegistry::new();
        if !config.mcp_servers.is_empty() {
            let materialize = config.materialize.as_ref().ok_or_else(|| {
                "[[mcp_servers]] requires a [materialize] table for invocation results".to_owned()
            })?;
            let dir = config.absolute(&materialize.dir);
            let mut servers = Vec::with_capacity(config.mcp_servers.len());
            for server in &config.mcp_servers {
                let bearer_token = match &server.bearer_token_env {
                    Some(name) => match std::env::var(name) {
                        Ok(value) if !value.trim().is_empty() => Some(value),
                        _ => {
                            return Err(format!(
                                "mcp_servers.bearer_token_env {name} is not set or empty"
                            ))
                        }
                    },
                    None => None,
                };
                servers.push(McpServer {
                    id: server.id.clone(),
                    endpoint: server.endpoint.clone(),
                    timeout_ms: server.timeout_ms,
                    bearer_token,
                });
            }
            let adapter = McpAdapter::new(servers, &dir, materialize.max_bytes)
                .map_err(|error| format!("mcp adapter: {error}"))?;
            invokers.register(Box::new(adapter));
        }

        // 只读能力必须指向已登记的服务端并有物化目录，否则调用阶段无法闭环。
        for ((domain, type_name), profile) in &profiles {
            let Some(capability) = &profile.card.spec.capability else {
                continue;
            };
            if capability.side_effect != SideEffect::ReadOnly {
                continue;
            }
            if config.mcp_server(&capability.server.id).is_none() {
                return Err(format!(
                    "profile {domain}/{type_name} read-only capability requires \
                     mcp_servers.id = {}",
                    capability.server.id
                ));
            }
            if config.materialize.is_none() {
                return Err(format!(
                    "profile {domain}/{type_name} read-only capability requires [materialize]"
                ));
            }
        }

        Ok(Self {
            authenticator,
            acl,
            audit,
            audit_fail_open: config.audit.fail_open,
            resolvers: Arc::new(resolvers),
            invokers: Arc::new(invokers),
            profiles,
        })
    }

    /// 按 `(domain, type)` 查找 profile。
    pub fn profile(&self, domain: &str, type_name: &str) -> Option<&Profile> {
        self.profiles
            .get(&(domain.to_owned(), type_name.to_owned()))
    }
}
