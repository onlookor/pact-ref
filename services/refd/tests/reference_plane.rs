//! `refd` 端点契约集成测试：传输约束、认证/scope/ACL、resolve/describe 与审计闭环。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http_body_util::BodyExt;
use jsonwebtoken::{encode, EncodingKey, Header};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tower::ServiceExt;

use pact_ref_core::{AuditError, AuditEvent, AuditSink};
use pact_refd::{router, AppState, Config};

const CARD: &str = r#"
apiVersion: pact.ref/v1
kind: ContractCard
metadata:
  id: build/artifact
  version: "1"
  owner: build-platform
  status: active
spec:
  artifact:
    kind: archive
    mediaType: application/octet-stream
    digestPolicy: optional
  reference:
    schemes: ["file"]
    mutableAllowed: false
  lifecycle:
    retention: P30D
    deletionPolicy: retain
"#;

static SEQ: AtomicU32 = AtomicU32::new(0);

struct Fixture {
    dir: PathBuf,
    state: Arc<AppState>,
}

impl Fixture {
    fn new(scopes: &[&str], operations: &[&str]) -> Self {
        Self::build(scopes, operations, &["build"], false, None)
    }

    fn with_domains(scopes: &[&str], operations: &[&str], domains: &[&str]) -> Self {
        Self::build(scopes, operations, domains, false, None)
    }

    fn with_audit(
        scopes: &[&str],
        operations: &[&str],
        fail_open: bool,
        audit: Arc<dyn AuditSink + Send + Sync>,
    ) -> Self {
        Self::build(scopes, operations, &["build"], fail_open, Some(audit))
    }

    fn build(
        scopes: &[&str],
        operations: &[&str],
        domains: &[&str],
        fail_open: bool,
        audit: Option<Arc<dyn AuditSink + Send + Sync>>,
    ) -> Self {
        let unique = format!(
            "refd-test-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(dir.join("artifacts")).expect("artifact dir");
        std::fs::write(dir.join("artifacts").join("artifact.bin"), b"hello refd")
            .expect("artifact");
        std::fs::write(dir.join("card.yaml"), CARD).expect("card");

        let scopes = quoted(scopes);
        let operations = quoted(operations);
        let domains = quoted(domains);
        let config = format!(
            r#"
[server]
bind = "127.0.0.1:8080"
allow_plaintext = true

[auth]
mode = "static"

[auth.static]
allow = true
token = "s3cret"
subject = "alice"
scopes = [{scopes}]

[audit]
path = "audit.jsonl"
fail_open = {fail_open}

[adapter.file]
root = "artifacts"

[[acl]]
principal = "alice"
domains = [{domains}]
types = ["artifact"]
schemes = ["file"]
operations = [{operations}]

[[profiles]]
domain = "build"
type = "artifact"
card = "card.yaml"
"#
        );
        let config = Config::from_toml(&config, &dir).expect("config");
        let mut state = AppState::from_config(config).expect("state");
        if let Some(audit) = audit {
            state.audit = audit;
        }
        Self {
            dir,
            state: Arc::new(state),
        }
    }

    fn router(&self) -> Router {
        router(Arc::clone(&self.state))
    }

    fn artifact_uri(&self) -> String {
        format!(
            "file://{}",
            self.dir.join("artifacts").join("artifact.bin").display()
        )
    }

    fn audit_events(&self) -> Vec<serde_json::Value> {
        let Ok(text) = std::fs::read_to_string(self.dir.join("audit.jsonl")) else {
            return Vec::new();
        };
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("audit json"))
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn quoted(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

async fn send(router: Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = router.oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

fn post(path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", "Bearer s3cret")
        .header("content-type", "application/json")
        .header("x-trace-id", "test-trace")
        .body(Body::from(body.to_string()))
        .expect("request")
}

fn resolve_body(fixture: &Fixture, intent: &str) -> serde_json::Value {
    serde_json::json!({
        "domain": "build",
        "type": "artifact",
        "reference": fixture.artifact_uri(),
        "intent": intent,
    })
}

fn describe_body(fixture: &Fixture) -> serde_json::Value {
    serde_json::json!({
        "domain": "build",
        "type": "artifact",
        "reference": fixture.artifact_uri(),
    })
}

#[tokio::test]
async fn health_probes_are_open() {
    let fixture = Fixture::new(&["ref:resolve"], &["resolve:read"]);
    let router = fixture.router();
    for path in ["/healthz", "/readyz"] {
        let request = Request::builder().uri(path).body(Body::empty()).unwrap();
        let (status, _, _) = send(router.clone(), request).await;
        assert_eq!(status, StatusCode::OK, "{path}");
    }
}

#[tokio::test]
async fn missing_credentials_are_rejected() {
    let fixture = Fixture::new(&["ref:resolve"], &["resolve:read"]);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/resolve")
        .header("content-type", "application/json")
        .body(Body::from(resolve_body(&fixture, "read").to_string()))
        .unwrap();
    let (status, headers, body) = send(fixture.router(), request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok()),
        Some("Bearer realm=\"pact-ref\"")
    );
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "Unauthorized");
}

#[tokio::test]
async fn missing_endpoint_scope_is_forbidden() {
    let fixture = Fixture::new(&["ref:describe"], &["resolve:read"]);
    let (status, _, body) = send(
        fixture.router(),
        post("/v1/resolve", resolve_body(&fixture, "read")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "Forbidden");
}

#[tokio::test]
async fn read_resolves_with_handle_expiry_and_digest() {
    let fixture = Fixture::new(&["ref:resolve"], &["resolve:read"]);
    let (status, headers, body) = send(
        fixture.router(),
        post("/v1/resolve", resolve_body(&fixture, "read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");
    assert_eq!(headers.get("x-trace-id").unwrap(), "test-trace");

    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["contractId"], "build/artifact");
    assert_eq!(json["version"], "1");
    assert_eq!(json["mediaType"], "application/octet-stream");
    assert!(json["digest"].as_str().unwrap().starts_with("sha256:"));
    assert!(json["handle"].as_str().unwrap().starts_with("file://"));
    assert!(json["expiresAt"].as_str().unwrap().ends_with('Z'));

    let events = fixture.audit_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["traceId"], "test-trace");
    assert_eq!(events[0]["actor"], "alice");
    assert_eq!(events[0]["status"], "ok");
    assert_eq!(events[0]["operation"], "resolve:read");
    assert_eq!(events[0]["contractId"], "build/artifact");
    assert!(events[0]["resultDigest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(events[0].get("handle").is_none());
}

#[tokio::test]
async fn verify_never_returns_handle() {
    let fixture = Fixture::new(&["ref:resolve"], &["resolve:verify"]);
    let (status, _, body) = send(
        fixture.router(),
        post("/v1/resolve", resolve_body(&fixture, "verify")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert!(json.get("handle").is_none());
    assert!(json.get("expiresAt").is_none());
    assert_eq!(fixture.audit_events()[0]["operation"], "resolve:verify");
}

#[tokio::test]
async fn describe_projects_without_owner() {
    let fixture = Fixture::new(&["ref:describe"], &["describe"]);
    let (status, headers, body) = send(
        fixture.router(),
        post("/v1/describe", describe_body(&fixture)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");
    let text = String::from_utf8(body).expect("utf8");
    assert!(!text.contains("build-platform"), "leaked owner: {text}");
    let json: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(json["contractId"], "build/artifact");
    assert_eq!(json["reference"]["schemes"][0], "file");
    assert_eq!(fixture.audit_events()[0]["operation"], "describe");
}

#[tokio::test]
async fn non_uri_reference_is_rejected() {
    let fixture = Fixture::new(&["ref:resolve"], &["resolve:read"]);
    let body = serde_json::json!({
        "domain": "build",
        "type": "artifact",
        "reference": "REQ-001",
        "intent": "read",
    });
    let (status, _, body) = send(fixture.router(), post("/v1/resolve", body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "InvalidReference");
    assert_eq!(fixture.audit_events()[0]["status"], "InvalidReference");
}

#[tokio::test]
async fn unknown_profile_is_not_found() {
    let fixture = Fixture::with_domains(&["ref:resolve"], &["resolve:read"], &["build", "other"]);
    let body = serde_json::json!({
        "domain": "other",
        "type": "artifact",
        "reference": fixture.artifact_uri(),
        "intent": "read",
    });
    let (status, _, body) = send(fixture.router(), post("/v1/resolve", body)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "NotFound");
}

#[tokio::test]
async fn acl_denies_unlisted_scheme() {
    let fixture = Fixture::new(&["ref:resolve"], &["resolve:read"]);
    let body = serde_json::json!({
        "domain": "build",
        "type": "artifact",
        "reference": "https://example.com/a",
        "intent": "read",
    });
    let (status, _, body) = send(fixture.router(), post("/v1/resolve", body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "Forbidden");
}

#[tokio::test]
async fn digest_mismatch_returns_conflict() {
    let fixture = Fixture::new(&["ref:resolve"], &["resolve:verify"]);
    let body = serde_json::json!({
        "domain": "build",
        "type": "artifact",
        "reference": fixture.artifact_uri(),
        "intent": "verify",
        "expectedDigest": format!("sha256:{}", "0".repeat(64)),
    });
    let (status, _, body) = send(fixture.router(), post("/v1/resolve", body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "DigestMismatch");
    assert_eq!(
        json["detail"]["expected"],
        format!("sha256:{}", "0".repeat(64))
    );
    assert!(json["detail"]["actual"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[tokio::test]
async fn rejects_other_methods_content_types_and_bad_trace() {
    let fixture = Fixture::new(&["ref:resolve"], &["resolve:read"]);
    let router = fixture.router();

    let get = Request::builder()
        .method("GET")
        .uri("/v1/resolve")
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = send(router.clone(), get).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers.get("allow").unwrap(), "POST");

    let text = Request::builder()
        .method("POST")
        .uri("/v1/resolve")
        .header("authorization", "Bearer s3cret")
        .header("content-type", "text/plain")
        .body(Body::from("{}"))
        .unwrap();
    let (status, _, _) = send(router.clone(), text).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let bad_trace = Request::builder()
        .method("POST")
        .uri("/v1/resolve")
        .header("authorization", "Bearer s3cret")
        .header("content-type", "application/json")
        .header("x-trace-id", "bad trace!")
        .body(Body::from(resolve_body(&fixture, "read").to_string()))
        .unwrap();
    let (status, headers, body) = send(router.clone(), bad_trace).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(headers.get("x-trace-id").is_some());
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "InvalidRequest");
}

#[tokio::test]
async fn rejects_oversized_body() {
    let fixture = Fixture::new(&["ref:resolve"], &["resolve:read"]);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/resolve")
        .header("authorization", "Bearer s3cret")
        .header("content-type", "application/json")
        .body(Body::from(vec![b'x'; 70 * 1024]))
        .unwrap();
    let (status, _, body) = send(fixture.router(), request).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "RequestTooLarge");
}

// ---------------------------------------------------------------------------
// OIDC（D51）
// ---------------------------------------------------------------------------

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

    fn jwks(&self) -> String {
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
    }

    fn token(&self, claims: serde_json::Value) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        encode(&header, &claims, &EncodingKey::from_ed_der(&self.pkcs8)).expect("sign")
    }
}

struct OidcFixture {
    dir: PathBuf,
    state: Arc<AppState>,
    signer: Signer,
}

impl OidcFixture {
    fn new(operations: &[&str]) -> Self {
        let unique = format!(
            "refd-oidc-test-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(dir.join("artifacts")).expect("artifact dir");
        std::fs::write(dir.join("artifacts").join("artifact.bin"), b"hello refd")
            .expect("artifact");
        std::fs::write(dir.join("card.yaml"), CARD).expect("card");

        let signer = Signer::new("key-1");
        std::fs::write(dir.join("jwks.json"), signer.jwks()).expect("jwks");

        let operations = quoted(operations);
        let config = format!(
            r#"
[server]
bind = "127.0.0.1:8080"
allow_plaintext = true

[auth]
mode = "oidc"

[auth.oidc]
issuer = "https://issuer.example.com"
audience = "pact-ref"
jwks_file = "jwks.json"

[audit]
path = "audit.jsonl"

[adapter.file]
root = "artifacts"

[[acl]]
principal = "alice"
domains = ["build"]
types = ["artifact"]
schemes = ["file"]
operations = [{operations}]

[[profiles]]
domain = "build"
type = "artifact"
card = "card.yaml"
"#
        );
        let config = Config::from_toml(&config, &dir).expect("config");
        let state = AppState::from_config(config).expect("state");
        Self {
            dir,
            state: Arc::new(state),
            signer,
        }
    }

    fn router(&self) -> Router {
        router(Arc::clone(&self.state))
    }

    fn artifact_uri(&self) -> String {
        format!(
            "file://{}",
            self.dir.join("artifacts").join("artifact.bin").display()
        )
    }

    fn claims(&self, scope: Option<&str>) -> serde_json::Value {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let mut claims = serde_json::json!({
            "iss": "https://issuer.example.com",
            "aud": "pact-ref",
            "sub": "alice",
            "exp": now + 300,
        });
        if let Some(scope) = scope {
            claims["scope"] = serde_json::json!(scope);
        }
        claims
    }
}

impl Drop for OidcFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn post_with_token(path: &str, body: serde_json::Value, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("x-trace-id", "oidc-trace")
        .body(Body::from(body.to_string()))
        .expect("request")
}

fn oidc_resolve_body(fixture: &OidcFixture) -> serde_json::Value {
    serde_json::json!({
        "domain": "build",
        "type": "artifact",
        "reference": fixture.artifact_uri(),
        "intent": "read",
    })
}

#[tokio::test]
async fn oidc_valid_token_is_accepted() {
    let fixture = OidcFixture::new(&["resolve:read"]);
    let token = fixture.signer.token(fixture.claims(Some("ref:resolve")));
    let (status, _, body) = send(
        fixture.router(),
        post_with_token("/v1/resolve", oidc_resolve_body(&fixture), &token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {:?}",
        String::from_utf8_lossy(&body)
    );
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["contractId"], "build/artifact");

    let audit: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture.dir.join("audit.jsonl")).expect("audit"),
    )
    .expect("audit json");
    assert_eq!(audit["actor"], "alice");
}

#[tokio::test]
async fn oidc_expired_and_wrong_audience_are_unauthorized() {
    let fixture = OidcFixture::new(&["resolve:read"]);

    let mut expired = fixture.claims(Some("ref:resolve"));
    expired["exp"] = serde_json::json!(0);
    let token = fixture.signer.token(expired);
    let (status, headers, _) = send(
        fixture.router(),
        post_with_token("/v1/resolve", oidc_resolve_body(&fixture), &token),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer realm=\"pact-ref\"")
    );

    let mut wrong_audience = fixture.claims(Some("ref:resolve"));
    wrong_audience["aud"] = serde_json::json!("other-service");
    let token = fixture.signer.token(wrong_audience);
    let (status, _, _) = send(
        fixture.router(),
        post_with_token("/v1/resolve", oidc_resolve_body(&fixture), &token),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let mut wrong_issuer = fixture.claims(Some("ref:resolve"));
    wrong_issuer["iss"] = serde_json::json!("https://other.example.com");
    let token = fixture.signer.token(wrong_issuer);
    let (status, _, _) = send(
        fixture.router(),
        post_with_token("/v1/resolve", oidc_resolve_body(&fixture), &token),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn oidc_token_without_endpoint_scope_is_forbidden() {
    let fixture = OidcFixture::new(&["resolve:read"]);
    let token = fixture.signer.token(fixture.claims(Some("ref:describe")));
    let (status, _, body) = send(
        fixture.router(),
        post_with_token("/v1/resolve", oidc_resolve_body(&fixture), &token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "Forbidden");
}

struct FailingSink;

impl AuditSink for FailingSink {
    fn record(&self, _event: &AuditEvent) -> Result<(), AuditError> {
        Err(AuditError::new("audit disk full"))
    }
}

#[tokio::test]
async fn audit_failure_is_fail_closed_by_default() {
    let fixture = Fixture::with_audit(
        &["ref:resolve"],
        &["resolve:read"],
        false,
        Arc::new(FailingSink),
    );
    let (status, _, body) = send(
        fixture.router(),
        post("/v1/resolve", resolve_body(&fixture, "read")),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "AuditUnavailable");
}

#[tokio::test]
async fn audit_failure_is_allowed_only_with_explicit_fail_open() {
    let fixture = Fixture::with_audit(
        &["ref:resolve"],
        &["resolve:read"],
        true,
        Arc::new(FailingSink),
    );
    let (status, _, body) = send(
        fixture.router(),
        post("/v1/resolve", resolve_body(&fixture, "read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["contractId"], "build/artifact");
}
