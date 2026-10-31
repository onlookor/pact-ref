//! OIDC 资源服务器验证器：JWT/JWKS 验签、声明校验与 scope 映射（D51）。
//!
//! 只验证 IdP 签发的 JWT，不内置授权服务器，也不做发现文档。JWKS 来源由调用方注入，
//! 本模块只持有有界缓存；任何拉取/解析/验签失败一律映射为 `401`。

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};

use crate::{AuthError, Authenticator, Identity};

/// 未知 `kid` 触发的强制刷新最小间隔。
const FORCE_REFRESH_MIN: Duration = Duration::from_secs(30);
/// JWKS 密钥数量上限。
const MAX_KEYS: usize = 64;

/// JWKS 字节来源。`refd` 注入文件或 HTTPS 实现；测试可注入固定内容。
pub trait JwksSource: Send + Sync {
    fn fetch(&self) -> Result<Vec<u8>, String>;
}

/// OIDC 验证参数。
#[derive(Debug, Clone)]
pub struct OidcSettings {
    pub issuer: String,
    pub audience: String,
    pub algorithms: Vec<String>,
    pub leeway_seconds: u64,
    pub cache_ttl_seconds: u64,
}

#[derive(Default)]
struct Cache {
    jwks: Option<JwkSet>,
    fetched_at: Option<Instant>,
    last_force: Option<Instant>,
}

/// OIDC 验证器。
pub struct OidcAuthenticator {
    settings: OidcSettings,
    source: Arc<dyn JwksSource + Send + Sync>,
    cache: Mutex<Cache>,
}

impl OidcAuthenticator {
    pub fn new(settings: OidcSettings, source: Arc<dyn JwksSource + Send + Sync>) -> Self {
        Self {
            settings,
            source,
            cache: Mutex::new(Cache::default()),
        }
    }

    fn jwks(&self, force: bool) -> Result<JwkSet, AuthError> {
        let mut cache = self.cache.lock().map_err(|_| AuthError::Invalid)?;
        let now = Instant::now();
        if !force {
            if let (Some(set), Some(at)) = (&cache.jwks, cache.fetched_at) {
                if now.duration_since(at) < Duration::from_secs(self.settings.cache_ttl_seconds) {
                    return Ok(set.clone());
                }
            }
        } else if let Some(at) = cache.last_force {
            // 未知 kid 的刷新必须限频；限频窗口内复用当前缓存。
            if now.duration_since(at) < FORCE_REFRESH_MIN {
                return cache.jwks.clone().ok_or(AuthError::Invalid);
            }
        }

        let bytes = self.source.fetch().map_err(|_| AuthError::Invalid)?;
        let mut set: JwkSet = serde_json::from_slice(&bytes).map_err(|_| AuthError::Invalid)?;
        if set.keys.is_empty() {
            return Err(AuthError::Invalid);
        }
        set.keys.truncate(MAX_KEYS);
        cache.jwks = Some(set.clone());
        cache.fetched_at = Some(now);
        if force {
            cache.last_force = Some(now);
        }
        Ok(set)
    }

    fn select_key(&self, kid: Option<&str>, alg: Algorithm) -> Result<Jwk, AuthError> {
        let set = self.jwks(false)?;
        if let Some(key) = pick_key(&set, kid, alg) {
            return Ok(key);
        }
        // 未知 kid：允许一次限频刷新后重试。
        let refreshed = self.jwks(true)?;
        pick_key(&refreshed, kid, alg).ok_or(AuthError::Invalid)
    }
}

impl Authenticator for OidcAuthenticator {
    fn authenticate(&self, authorization: Option<&str>) -> Result<Identity, AuthError> {
        let presented = authorization.ok_or(AuthError::Missing)?;
        let token = presented
            .strip_prefix("Bearer ")
            .or_else(|| presented.strip_prefix("bearer "))
            .ok_or(AuthError::Invalid)?;

        let header = decode_header(token).map_err(|_| AuthError::Invalid)?;
        let alg_name = algorithm_name(header.alg).ok_or(AuthError::Invalid)?;
        if !self
            .settings
            .algorithms
            .iter()
            .any(|allowed| allowed == alg_name)
        {
            return Err(AuthError::Invalid);
        }
        if has_crit(token) {
            return Err(AuthError::Invalid);
        }

        let key = self.select_key(header.kid.as_deref(), header.alg)?;
        let decoding = DecodingKey::from_jwk(&key).map_err(|_| AuthError::Invalid)?;

        let mut validation = Validation::new(header.alg);
        validation.leeway = self.settings.leeway_seconds;
        validation.validate_nbf = true;
        validation.set_audience(&[self.settings.audience.as_str()]);
        validation.set_issuer(&[self.settings.issuer.as_str()]);
        validation.required_spec_claims.insert("iss".to_owned());
        validation.required_spec_claims.insert("aud".to_owned());

        let data: TokenData<serde_json::Value> =
            decode(token, &decoding, &validation).map_err(|_| AuthError::Invalid)?;
        let claims = data.claims;

        let subject = claims
            .get("sub")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .ok_or(AuthError::Invalid)?
            .to_owned();

        Ok(Identity::new(subject, scopes(&claims)))
    }
}

/// 只允许白名单内的非对称算法；`none` 与 `HS*` 不在此列。
fn algorithm_name(algorithm: Algorithm) -> Option<&'static str> {
    match algorithm {
        Algorithm::RS256 => Some("RS256"),
        Algorithm::ES256 => Some("ES256"),
        Algorithm::EdDSA => Some("EdDSA"),
        _ => None,
    }
}

fn pick_key(set: &JwkSet, kid: Option<&str>, alg: Algorithm) -> Option<Jwk> {
    match kid {
        Some(kid) => set
            .keys
            .iter()
            .find(|key| key.common.key_id.as_deref() == Some(kid) && matches_alg(key, alg))
            .cloned(),
        None => {
            // 无 kid 时仅当唯一可用密钥才接受，避免算法混淆。
            let mut candidates = set.keys.iter().filter(|key| matches_alg(key, alg));
            let first = candidates.next()?.clone();
            if candidates.next().is_some() {
                None
            } else {
                Some(first)
            }
        }
    }
}

fn matches_alg(key: &Jwk, alg: Algorithm) -> bool {
    match (alg, &key.algorithm) {
        (Algorithm::RS256, AlgorithmParameters::RSA(_)) => true,
        (Algorithm::ES256, AlgorithmParameters::EllipticCurve(params)) => {
            params.curve == EllipticCurve::P256
        }
        (Algorithm::EdDSA, AlgorithmParameters::OctetKeyPair(params)) => {
            params.curve == EllipticCurve::Ed25519
        }
        _ => false,
    }
}

/// JOSE `crit` 头部参数一律拒绝（当前无支持的扩展）。
fn has_crit(token: &str) -> bool {
    let Some(segment) = token.split('.').next() else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(segment) else {
        return false;
    };
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    header
        .get("crit")
        .and_then(|value| value.as_array())
        .is_some_and(|values| !values.is_empty())
}

/// `scope`：空格分隔字符串或字符串数组；其他形态视为无 scope。
fn scopes(claims: &serde_json::Value) -> Vec<String> {
    match claims.get("scope") {
        Some(serde_json::Value::String(raw)) => raw.split_whitespace().map(str::to_owned).collect(),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::{JwksSource, OidcAuthenticator, OidcSettings};
    use crate::{AuthError, Authenticator, SCOPE_RESOLVE};

    const ISSUER: &str = "https://issuer.example.com";
    const AUDIENCE: &str = "pact-ref";

    struct Signer {
        kid: String,
        pkcs8: Vec<u8>,
        public: Vec<u8>,
    }

    impl Signer {
        fn new(kid: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
                .expect("generate key")
                .as_ref()
                .to_vec();
            let pair = Ed25519KeyPair::from_pkcs8(&pkcs8).expect("key pair");
            Self {
                kid: kid.to_owned(),
                pkcs8,
                public: pair.public_key().as_ref().to_vec(),
            }
        }

        fn jwks(&self) -> Vec<u8> {
            serde_json::json!({
                "keys": [{
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": self.kid,
                    "x": URL_SAFE_NO_PAD.encode(&self.public),
                    "alg": "EdDSA",
                    "use": "sig",
                }]
            })
            .to_string()
            .into_bytes()
        }

        fn token(&self, claims: serde_json::Value) -> String {
            let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
            header.kid = Some(self.kid.clone());
            encode(&header, &claims, &EncodingKey::from_ed_der(&self.pkcs8)).expect("sign")
        }
    }

    struct StaticSource {
        body: Mutex<Vec<u8>>,
        calls: AtomicUsize,
    }

    impl StaticSource {
        fn new(body: Vec<u8>) -> Self {
            Self {
                body: Mutex::new(body),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl JwksSource for StaticSource {
        fn fetch(&self) -> Result<Vec<u8>, String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.body.lock().expect("body").clone())
        }
    }

    fn settings() -> OidcSettings {
        OidcSettings {
            issuer: ISSUER.to_owned(),
            audience: AUDIENCE.to_owned(),
            algorithms: vec!["EdDSA".to_owned()],
            leeway_seconds: 60,
            cache_ttl_seconds: 300,
        }
    }

    fn claims(now: u64) -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "alice",
            "exp": now + 300,
            "scope": "ref:resolve ref:describe",
        })
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    }

    fn authenticator<S: JwksSource + 'static>(source: std::sync::Arc<S>) -> OidcAuthenticator {
        OidcAuthenticator::new(settings(), source)
    }

    #[test]
    fn accepts_valid_token_and_maps_subject_and_scopes() {
        let signer = Signer::new("key-1");
        let source = std::sync::Arc::new(StaticSource::new(signer.jwks()));
        let authenticator = authenticator(source);
        let token = signer.token(claims(now()));

        let identity = authenticator
            .authenticate(Some(&format!("Bearer {token}")))
            .expect("authenticated");
        assert_eq!(identity.subject, "alice");
        assert!(identity.has_scope(SCOPE_RESOLVE));
        assert!(identity.has_scope("ref:describe"));
    }

    #[test]
    fn accepts_scope_array_claim() {
        let signer = Signer::new("key-1");
        let source = std::sync::Arc::new(StaticSource::new(signer.jwks()));
        let authenticator = authenticator(source);
        let mut claims = claims(now());
        claims["scope"] = serde_json::json!([SCOPE_RESOLVE]);
        let token = signer.token(claims);

        let identity = authenticator
            .authenticate(Some(&format!("Bearer {token}")))
            .expect("authenticated");
        assert_eq!(identity.scopes, vec![SCOPE_RESOLVE.to_owned()]);
    }

    #[test]
    fn rejects_expired_token() {
        let signer = Signer::new("key-1");
        let source = std::sync::Arc::new(StaticSource::new(signer.jwks()));
        let authenticator = authenticator(source);
        let mut claims = claims(now());
        claims["exp"] = serde_json::json!(now() - 3600);
        let token = signer.token(claims);

        assert_eq!(
            authenticator.authenticate(Some(&format!("Bearer {token}"))),
            Err(AuthError::Invalid)
        );
    }

    #[test]
    fn rejects_future_nbf_beyond_leeway() {
        let signer = Signer::new("key-1");
        let source = std::sync::Arc::new(StaticSource::new(signer.jwks()));
        let authenticator = authenticator(source);
        let mut claims = claims(now());
        claims["nbf"] = serde_json::json!(now() + 3600);
        let token = signer.token(claims);

        assert_eq!(
            authenticator.authenticate(Some(&format!("Bearer {token}"))),
            Err(AuthError::Invalid)
        );
    }

    #[test]
    fn rejects_wrong_issuer_and_audience() {
        let signer = Signer::new("key-1");
        let source = std::sync::Arc::new(StaticSource::new(signer.jwks()));
        let authenticator = authenticator(source);

        let mut wrong_issuer = claims(now());
        wrong_issuer["iss"] = serde_json::json!("https://other.example.com");
        assert_eq!(
            authenticator.authenticate(Some(&format!("Bearer {}", signer.token(wrong_issuer)))),
            Err(AuthError::Invalid)
        );

        let mut wrong_audience = claims(now());
        wrong_audience["aud"] = serde_json::json!("other-service");
        assert_eq!(
            authenticator.authenticate(Some(&format!("Bearer {}", signer.token(wrong_audience)))),
            Err(AuthError::Invalid)
        );
    }

    #[test]
    fn rejects_alg_none_and_hmac() {
        let signer = Signer::new("key-1");
        let source = std::sync::Arc::new(StaticSource::new(signer.jwks()));
        let authenticator = authenticator(source);

        let payload = URL_SAFE_NO_PAD.encode(claims(now()).to_string());
        let unsigned = format!("{}.{payload}.", URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#));
        assert_eq!(
            authenticator.authenticate(Some(&format!("Bearer {unsigned}"))),
            Err(AuthError::Invalid)
        );

        let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("key-1".to_owned());
        let hmac = encode(
            &header,
            &claims(now()),
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("sign");
        assert_eq!(
            authenticator.authenticate(Some(&format!("Bearer {hmac}"))),
            Err(AuthError::Invalid)
        );
    }

    #[test]
    fn rejects_non_empty_crit_header() {
        let signer = Signer::new("key-1");
        let source = std::sync::Arc::new(StaticSource::new(signer.jwks()));
        let authenticator = authenticator(source);

        let header = URL_SAFE_NO_PAD.encode(
            serde_json::json!({"alg": "EdDSA", "kid": "key-1", "crit": ["exp"]}).to_string(),
        );
        let payload = URL_SAFE_NO_PAD.encode(claims(now()).to_string());
        let token = format!("{header}.{payload}.signature");
        assert_eq!(
            authenticator.authenticate(Some(&format!("Bearer {token}"))),
            Err(AuthError::Invalid)
        );
    }

    #[test]
    fn unknown_kid_refreshes_once_then_is_rate_limited() {
        use std::collections::VecDeque;

        struct SequenceSource {
            bodies: Mutex<VecDeque<Vec<u8>>>,
            calls: AtomicUsize,
        }

        impl JwksSource for SequenceSource {
            fn fetch(&self) -> Result<Vec<u8>, String> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                let mut bodies = self.bodies.lock().expect("bodies");
                if bodies.len() > 1 {
                    Ok(bodies.pop_front().expect("body"))
                } else {
                    Ok(bodies.front().expect("body").clone())
                }
            }
        }

        impl SequenceSource {
            fn calls(&self) -> usize {
                self.calls.load(Ordering::Relaxed)
            }
        }

        let old = Signer::new("old-key");
        let new = Signer::new("new-key");
        let source = std::sync::Arc::new(SequenceSource {
            bodies: Mutex::new(VecDeque::from(vec![old.jwks(), new.jwks()])),
            calls: AtomicUsize::new(0),
        });
        let authenticator = authenticator(std::sync::Arc::clone(&source));
        let token = new.token(claims(now()));

        // 第一次未知 kid：强制刷新拿到新 JWKS。
        let identity = authenticator
            .authenticate(Some(&format!("Bearer {token}")))
            .expect("authenticated after refresh");
        assert_eq!(identity.subject, "alice");
        assert_eq!(source.calls(), 2);

        // 未知 kid 再次出现：限频窗口内不得重复拉取。
        let unknown = Signer::new("other-key");
        let other = unknown.token(claims(now()));
        assert_eq!(
            authenticator.authenticate(Some(&format!("Bearer {other}"))),
            Err(AuthError::Invalid)
        );
        assert_eq!(source.calls(), 2);
        assert_eq!(
            authenticator
                .authenticate(Some(&format!("Bearer {token}")))
                .map(|identity| identity.subject),
            Ok("alice".to_owned())
        );
    }

    #[test]
    fn jwks_failure_is_invalid() {
        struct Failing;
        impl JwksSource for Failing {
            fn fetch(&self) -> Result<Vec<u8>, String> {
                Err("unreachable".to_owned())
            }
        }

        let signer = Signer::new("key-1");
        let authenticator = OidcAuthenticator::new(settings(), std::sync::Arc::new(Failing));
        let token = signer.token(claims(now()));
        assert_eq!(
            authenticator.authenticate(Some(&format!("Bearer {token}"))),
            Err(AuthError::Invalid)
        );
    }

    #[test]
    fn missing_or_malformed_credentials_are_rejected() {
        let signer = Signer::new("key-1");
        let source = std::sync::Arc::new(StaticSource::new(signer.jwks()));
        let authenticator = authenticator(source);

        assert_eq!(authenticator.authenticate(None), Err(AuthError::Missing));
        assert_eq!(
            authenticator.authenticate(Some("Basic abc")),
            Err(AuthError::Invalid)
        );
        assert_eq!(
            authenticator.authenticate(Some("Bearer not-a-jwt")),
            Err(AuthError::Invalid)
        );
    }

    #[test]
    fn caches_jwks_until_ttl() {
        let signer = Signer::new("key-1");
        let source = std::sync::Arc::new(StaticSource::new(signer.jwks()));
        let authenticator = authenticator(std::sync::Arc::clone(&source));
        let token = signer.token(claims(now()));

        for _ in 0..3 {
            authenticator
                .authenticate(Some(&format!("Bearer {token}")))
                .expect("authenticated");
        }
        // 首次拉取后命中缓存，不再重复读取来源。
        assert_eq!(source.calls(), 1);
    }
}
