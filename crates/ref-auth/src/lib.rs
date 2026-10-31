//! principal、认证、scope 与对象 ACL 求值。
//!
//! 生产实现必须接入真实身份源；`Deny` 为缺省，`Static` 仅用于引导/受控内网。
//! OIDC（JWT/JWKS）验证器尚未实现，配置为 `oidc` 时服务拒绝启动。

use pact_ref_core::{Authorizer, ReferenceError, ReferenceForm, ResolveIntent};

/// 端点 scope。
pub const SCOPE_RESOLVE: &str = "ref:resolve";
pub const SCOPE_DESCRIBE: &str = "ref:describe";

/// 已认证主体。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub subject: String,
    pub scopes: Vec<String>,
}

impl Identity {
    pub fn new(subject: impl Into<String>, scopes: Vec<String>) -> Self {
        Self {
            subject: subject.into(),
            scopes,
        }
    }

    /// scope 精确匹配；`*` 表示全部 scope。
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes
            .iter()
            .any(|candidate| candidate == scope || candidate == "*")
    }
}

/// 认证失败。对外统一映射为 `401`，不区分原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    Missing,
    Invalid,
}

/// bearer 凭据认证器。
pub trait Authenticator {
    fn authenticate(&self, authorization: Option<&str>) -> Result<Identity, AuthError>;
}

/// 缺省：拒绝一切业务请求。
pub struct DenyAuthenticator;

impl Authenticator for DenyAuthenticator {
    fn authenticate(&self, _authorization: Option<&str>) -> Result<Identity, AuthError> {
        Err(AuthError::Missing)
    }
}

/// 静态令牌认证器（引导/受控内网）。比较使用常量时间算法。
pub struct StaticTokenAuthenticator {
    token: String,
    identity: Identity,
}

impl StaticTokenAuthenticator {
    pub fn new(token: impl Into<String>, subject: impl Into<String>, scopes: Vec<String>) -> Self {
        Self {
            token: token.into(),
            identity: Identity::new(subject, scopes),
        }
    }
}

impl Authenticator for StaticTokenAuthenticator {
    fn authenticate(&self, authorization: Option<&str>) -> Result<Identity, AuthError> {
        let presented = authorization.ok_or(AuthError::Missing)?;
        let token = presented
            .strip_prefix("Bearer ")
            .or_else(|| presented.strip_prefix("bearer "))
            .ok_or(AuthError::Invalid)?;
        if constant_time_eq(token.as_bytes(), self.token.as_bytes()) {
            Ok(self.identity.clone())
        } else {
            Err(AuthError::Invalid)
        }
    }
}

/// 常量时间字节比较：长度不同也遍历较短长度，不提前返回。
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().min(right.len());
    for index in 0..length {
        difference |= usize::from(left[index] ^ right[index]);
    }
    difference == 0
}

/// 一条对象 ACL 规则。规则之间是并集允许、默认拒绝，无 deny 与优先级。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRule {
    pub principal: String,
    pub domains: Vec<String>,
    pub types: Vec<String>,
    pub schemes: Vec<String>,
    pub operations: Vec<String>,
}

/// ACL 集合。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Acl {
    rules: Vec<AclRule>,
}

impl Acl {
    pub fn new(rules: Vec<AclRule>) -> Self {
        Self { rules }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// 任一规则匹配 `(principal, domain, type, scheme, operation)` 即允许。
    pub fn allows(
        &self,
        principal: &str,
        domain: &str,
        type_name: &str,
        scheme: &str,
        operation: &str,
    ) -> bool {
        self.rules.iter().any(|rule| {
            glob_match(&rule.principal, principal)
                && list_matches(&rule.domains, domain)
                && list_matches(&rule.types, type_name)
                && list_matches(&rule.schemes, scheme)
                && list_matches(&rule.operations, operation)
        })
    }
}

fn list_matches(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|pattern| glob_match(pattern, value))
}

/// 简单 glob：`*` 匹配任意长度字符（含空），其余字符逐字匹配。
fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let (mut p, mut v) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_value = 0usize;

    while v < value.len() {
        if p < pattern.len() && pattern[p] == value[v] {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            star_value = v;
            p += 1;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            star_value += 1;
            v = star_value;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// 引导/测试用：允许一切。生产禁用。
pub struct AllowAllAuthorizer;

impl Authorizer for AllowAllAuthorizer {
    fn authorize(
        &self,
        _actor: &str,
        _reference: &ReferenceForm,
        _intent: ResolveIntent,
    ) -> Result<(), ReferenceError> {
        Ok(())
    }
}

/// 默认拒绝，防止忘记装配真实授权器。
pub struct DenyAllAuthorizer;

impl Authorizer for DenyAllAuthorizer {
    fn authorize(
        &self,
        _actor: &str,
        _reference: &ReferenceForm,
        intent: ResolveIntent,
    ) -> Result<(), ReferenceError> {
        Err(ReferenceError::Unauthorized(format!(
            "no authorizer configured for intent {intent:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        glob_match, Acl, AclRule, AllowAllAuthorizer, Authenticator, DenyAllAuthorizer,
        DenyAuthenticator, Identity, StaticTokenAuthenticator, SCOPE_DESCRIBE, SCOPE_RESOLVE,
    };
    use pact_ref_core::{Authorizer, ReferenceError, ReferenceForm, ResolveIntent};

    fn reference() -> ReferenceForm {
        ReferenceForm::classify(Some("https://example.com/a")).expect("reference")
    }

    fn rule() -> AclRule {
        AclRule {
            principal: "team-a/*".to_owned(),
            domains: vec!["build".to_owned()],
            types: vec!["artifact".to_owned()],
            schemes: vec!["https".to_owned(), "file".to_owned()],
            operations: vec!["resolve:read".to_owned(), "describe".to_owned()],
        }
    }

    #[test]
    fn allow_all_permits_every_intent() {
        let authorizer = AllowAllAuthorizer;
        assert!(authorizer
            .authorize("alice", &reference(), ResolveIntent::Read)
            .is_ok());
        assert!(authorizer
            .authorize("alice", &reference(), ResolveIntent::Verify)
            .is_ok());
    }

    #[test]
    fn deny_all_rejects_by_default() {
        let authorizer = DenyAllAuthorizer;
        let error = authorizer
            .authorize("alice", &reference(), ResolveIntent::Read)
            .expect_err("must deny");
        assert!(matches!(error, ReferenceError::Unauthorized(_)));
    }

    #[test]
    fn deny_authenticator_rejects_all() {
        let error = DenyAuthenticator
            .authenticate(Some("Bearer secret"))
            .expect_err("must deny");
        assert_eq!(error, super::AuthError::Missing);
    }

    #[test]
    fn static_authenticator_checks_bearer_token() {
        let authenticator = StaticTokenAuthenticator::new(
            "s3cret",
            "alice",
            vec![SCOPE_RESOLVE.to_owned(), SCOPE_DESCRIBE.to_owned()],
        );
        let identity = authenticator
            .authenticate(Some("Bearer s3cret"))
            .expect("authenticated");
        assert_eq!(identity.subject, "alice");
        assert!(identity.has_scope(SCOPE_RESOLVE));
        assert!(identity.has_scope(SCOPE_DESCRIBE));
        assert!(!identity.has_scope("ref:admin"));

        assert_eq!(
            authenticator.authenticate(Some("Bearer wrong")),
            Err(super::AuthError::Invalid)
        );
        assert_eq!(
            authenticator.authenticate(Some("Basic s3cret")),
            Err(super::AuthError::Invalid)
        );
        assert_eq!(
            authenticator.authenticate(None),
            Err(super::AuthError::Missing)
        );
    }

    #[test]
    fn identity_wildcard_scope_covers_all() {
        let identity = Identity::new("ops", vec!["*".to_owned()]);
        assert!(identity.has_scope(SCOPE_RESOLVE));
        assert!(identity.has_scope("anything"));
    }

    #[test]
    fn acl_is_union_and_default_deny() {
        let acl = Acl::new(vec![rule()]);
        assert!(acl.allows("team-a/alice", "build", "artifact", "https", "resolve:read"));
        assert!(acl.allows("team-a/bob", "build", "artifact", "file", "describe"));
        assert!(!acl.allows("team-b/alice", "build", "artifact", "https", "resolve:read"));
        assert!(!acl.allows("team-a/alice", "other", "artifact", "https", "resolve:read"));
        assert!(!acl.allows("team-a/alice", "build", "artifact", "oci", "resolve:read"));
        assert!(!acl.allows(
            "team-a/alice",
            "build",
            "artifact",
            "https",
            "resolve:verify"
        ));
        assert!(Acl::default().is_empty());
        assert!(!Acl::default().allows("team-a/alice", "build", "artifact", "https", "describe"));
    }

    #[test]
    fn glob_matches_prefix_and_anywhere() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("team-a/*", "team-a/alice"));
        assert!(!glob_match("team-a/*", "team-b/alice"));
        assert!(glob_match("*-admin", "ops-admin"));
        assert!(glob_match("a*b*c", "a1b2c"));
        assert!(!glob_match("a*b*c", "a1b2"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactly"));
    }
}
