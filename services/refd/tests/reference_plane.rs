//! `refd` 端点契约集成测试：传输约束、认证/scope/ACL、resolve/describe 与审计闭环。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
use pact_refd::journal::{request_digest, Journal, KeyScope, Lookup};
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

// ---------------------------------------------------------------------------
// 动态只读调用（FR36 / D52）：mcp-read → invoke → 物化 → resolve 闭环
// ---------------------------------------------------------------------------

const MCP_OK_RESPONSE: &str =
    r#"{"jsonrpc":"2.0","id":"idem-1","result":{"content":[{"type":"text","text":"42"}]}}"#;
const MCP_ERROR_RESPONSE: &str =
    r#"{"jsonrpc":"2.0","id":"idem-1","error":{"code":-32000,"message":"upstream exploded"}}"#;

fn mcp_card(server_id: &str, side_effect: &str) -> String {
    format!(
        r#"
apiVersion: pact.ref/v1
kind: ContractCard
metadata:
  id: query/answer
  version: "1"
  owner: query-platform
  status: active
spec:
  capability:
    kind: mcp-tool
    server:
      id: {server_id}
    tool:
      name: query.run
      inputSchemaDigest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    sideEffect: {side_effect}
    idempotency:
      key: request-id
      semantics: at-most-once
    result:
      materialization: required
    auth:
      audience: pact-ref
      scopes: ["query:read"]
    timeoutMs: 5000
    failure:
      upstream: "502"
  reference:
    schemes: ["mcp", "file"]
    mutableAllowed: false
"#
    )
}

/// 构造一份指向只读能力卡片的配置；`mcp` / `materialize` 用于制造启动失败场景。
fn mcp_config(server_id: &str, endpoint: &str, mcp: bool, materialize: bool) -> String {
    let mcp_section = if mcp {
        format!(
            r#"
[[mcp_servers]]
id = "{server_id}"
endpoint = "{endpoint}"
allow_plaintext = true
timeout_ms = 5000
"#
        )
    } else {
        String::new()
    };
    let materialize_section = if materialize {
        "[materialize]\ndir = \"materialized\"\n"
    } else {
        ""
    };
    format!(
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
scopes = ["ref:invoke", "ref:resolve"]

[audit]
path = "audit.jsonl"

[adapter.file]
root = "."

[[acl]]
principal = "alice"
domains = ["query"]
types = ["answer"]
schemes = ["mcp", "file"]
operations = ["invoke", "resolve:read"]

[[profiles]]
domain = "query"
type = "answer"
card = "card.yaml"

{mcp_section}
{materialize_section}

[mutate]
journal = "mutate.jsonl"
"#
    )
}

/// 假 MCP 服务端：接受一次连接，读完 `Content-Length` 指定的请求体后回固定 JSON-RPC 响应。
fn fake_mcp_server(body: &'static str) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake mcp");
    let address = listener.local_addr().expect("addr");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let request = read_http_request(&mut stream);
        assert!(request.contains("\"tools/call\""), "unexpected request");
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).expect("write");
        let _ = stream.flush();
    });
    (format!("http://{address}"), handle)
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let read = stream.read(&mut buffer).expect("read request");
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);
        let text = String::from_utf8_lossy(&data).to_string();
        if let Some(header_end) = text.find("\r\n\r\n") {
            let length = text[..header_end]
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if data.len() >= header_end + 4 + length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&data).to_string()
}

struct McpFixture {
    dir: PathBuf,
    reference: String,
    state: Arc<AppState>,
    _server: std::thread::JoinHandle<()>,
}

impl McpFixture {
    fn new(operations: &[&str], side_effect: &str, response: &'static str) -> Self {
        let (endpoint, server) = fake_mcp_server(response);
        let address = endpoint
            .strip_prefix("http://")
            .expect("http endpoint")
            .to_owned();
        let server_id = format!("mcp://{address}");

        let unique = format!(
            "refd-mcp-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(dir.join("materialized")).expect("materialize dir");
        std::fs::write(dir.join("card.yaml"), mcp_card(&server_id, side_effect)).expect("card");

        let mut config = mcp_config(&server_id, &endpoint, true, true);
        config = config.replace(
            r#"operations = ["invoke", "resolve:read"]"#,
            &format!("operations = [{}]", quoted(operations)),
        );
        let config = Config::from_toml(&config, &dir).expect("config");
        let state = AppState::from_config(config).expect("state");
        Self {
            dir,
            reference: format!("{server_id}/query.run"),
            state: Arc::new(state),
            _server: server,
        }
    }

    fn router(&self) -> Router {
        router(Arc::clone(&self.state))
    }

    fn invoke_body(&self) -> serde_json::Value {
        serde_json::json!({
            "domain": "query",
            "type": "answer",
            "reference": self.reference,
            "operation": "query.run",
            "idempotencyKey": "idem-1",
            "input": { "q": "life" },
        })
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

impl Drop for McpFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn invoke_materializes_result_and_resolves_it() {
    let fixture = McpFixture::new(&["invoke", "resolve:read"], "read-only", MCP_OK_RESPONSE);
    let (status, _, body) = send(fixture.router(), post("/v1/invoke", fixture.invoke_body())).await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["status"], "succeeded");
    let result_ref = json["resultRef"].as_str().expect("resultRef").to_owned();
    let result_digest = json["resultDigest"]
        .as_str()
        .expect("resultDigest")
        .to_owned();
    assert!(result_ref.starts_with("file://"));
    assert!(result_digest.starts_with("sha256:"));

    // 物化结果可再次经静态 resolve 取回，形成闭环。
    let path = result_ref.strip_prefix("file://").expect("file uri");
    let materialized = std::fs::read_to_string(path).expect("materialized result");
    assert!(materialized.contains("\"text\":\"42\""));

    let (status, _, body) = send(
        fixture.router(),
        post(
            "/v1/resolve",
            serde_json::json!({
                "domain": "query",
                "type": "answer",
                "reference": result_ref,
                "intent": "read",
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["digest"], result_digest);
    assert_eq!(json["contractId"], "query/answer");
    assert_eq!(json["version"], "1");

    let events = fixture.audit_events();
    let invoke = events
        .iter()
        .find(|event| event["operation"] == "invoke")
        .expect("invoke audit event");
    assert_eq!(invoke["status"], "ok");
    assert_eq!(invoke["resultDigest"], result_digest);
}

#[tokio::test]
async fn invoke_rejects_mutating_capability() {
    let fixture = McpFixture::new(&["invoke"], "mutating", MCP_OK_RESPONSE);
    let (status, _, body) = send(fixture.router(), post("/v1/invoke", fixture.invoke_body())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "Forbidden");
}

#[tokio::test]
async fn invoke_requires_object_acl_operation() {
    let fixture = McpFixture::new(&["resolve:read"], "read-only", MCP_OK_RESPONSE);
    let (status, _, body) = send(fixture.router(), post("/v1/invoke", fixture.invoke_body())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "Forbidden");
}

#[tokio::test]
async fn upstream_failure_is_bad_gateway_and_audited_as_failed() {
    let fixture = McpFixture::new(&["invoke"], "read-only", MCP_ERROR_RESPONSE);
    let (status, _, body) = send(fixture.router(), post("/v1/invoke", fixture.invoke_body())).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "UpstreamFailure");

    let events = fixture.audit_events();
    let invoke = events
        .iter()
        .find(|event| event["operation"] == "invoke")
        .expect("invoke audit event");
    assert_eq!(invoke["status"], "failed");
    assert!(invoke["resultDigest"].is_null());
}

#[test]
fn read_only_profile_requires_registered_mcp_server() {
    let (endpoint, server) = fake_mcp_server(MCP_OK_RESPONSE);
    let address = endpoint.strip_prefix("http://").expect("http");
    let server_id = format!("mcp://{address}");
    let dir = std::env::temp_dir().join(format!(
        "refd-mcp-missing-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(dir.join("materialized")).expect("dir");
    std::fs::write(dir.join("card.yaml"), mcp_card(&server_id, "read-only")).expect("card");

    let config = mcp_config(&server_id, &endpoint, false, true);
    let config = Config::from_toml(&config, &dir).expect("config");
    let error = match AppState::from_config(config) {
        Ok(_) => panic!("state must fail closed"),
        Err(error) => error,
    };
    assert!(
        error.contains("mcp_servers.id"),
        "unexpected error: {error}"
    );

    let _ = server;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn read_only_profile_requires_materialize() {
    let (endpoint, server) = fake_mcp_server(MCP_OK_RESPONSE);
    let address = endpoint.strip_prefix("http://").expect("http");
    let server_id = format!("mcp://{address}");
    let dir = std::env::temp_dir().join(format!(
        "refd-mcp-nomaterialize-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(dir.join("materialized")).expect("dir");
    std::fs::write(dir.join("card.yaml"), mcp_card(&server_id, "read-only")).expect("card");

    let config = mcp_config(&server_id, &endpoint, true, false);
    let config = Config::from_toml(&config, &dir).expect("config");
    let error = match AppState::from_config(config) {
        Ok(_) => panic!("state must fail closed"),
        Err(error) => error,
    };
    assert!(error.contains("[materialize]"), "unexpected error: {error}");

    let _ = server;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mcp_endpoint_plaintext_requires_explicit_loopback() {
    let dir = std::env::temp_dir().join(format!(
        "refd-mcp-endpoint-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(dir.join("materialized")).expect("dir");

    let public = mcp_config(
        "mcp://upstream.example",
        "http://upstream.example",
        true,
        true,
    );
    let config = Config::from_toml(&public, &dir).expect("config");
    let error = config
        .validate()
        .expect_err("non-loopback http must be rejected");
    assert!(error.contains("loopback"), "unexpected error: {error}");

    let tls = mcp_config(
        "mcp://upstream.example",
        "https://upstream.example",
        true,
        true,
    );
    let config = Config::from_toml(&tls, &dir).expect("config");
    config.validate().expect("https endpoint is allowed");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 动态写（FR37 / D53）：mutate → 台账 → 上游 → 物化 → resolve 闭环
// ---------------------------------------------------------------------------

/// 可计数的假 MCP 服务端：非阻塞 accept，统计实际收到的 `tools/call` 次数。
struct CountingMcpServer {
    endpoint: String,
    calls: Arc<AtomicU32>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl CountingMcpServer {
    fn start(body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake mcp");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("addr");
        let calls = Arc::new(AtomicU32::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let calls_bg = Arc::clone(&calls);
        let stop_bg = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !stop_bg.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let request = read_http_request(&mut stream);
                        assert!(request.contains("\"tools/call\""), "unexpected request");
                        calls_bg.fetch_add(1, Ordering::SeqCst);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            endpoint: format!("http://{address}"),
            calls,
            stop,
            handle: Some(handle),
        }
    }

    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for CountingMcpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// 启动前预置台账记录，用于构造 in-doubt 与满额场景。
enum Preload {
    None,
    IntentOnly {
        key: String,
        input: serde_json::Value,
    },
    Terminal {
        key: String,
        input: serde_json::Value,
    },
}

struct MutateFixture {
    dir: PathBuf,
    reference: String,
    state: Arc<AppState>,
    server: CountingMcpServer,
}

impl MutateFixture {
    fn new(
        scopes: &[&str],
        operations: &[&str],
        side_effect: &str,
        response: &'static str,
    ) -> Self {
        Self::build(
            scopes,
            operations,
            side_effect,
            response,
            1000,
            None,
            Preload::None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        scopes: &[&str],
        operations: &[&str],
        side_effect: &str,
        response: &'static str,
        max_entries: usize,
        audit: Option<Arc<dyn AuditSink + Send + Sync>>,
        preload: Preload,
    ) -> Self {
        let server = CountingMcpServer::start(response);
        let address = server
            .endpoint
            .strip_prefix("http://")
            .expect("http endpoint")
            .to_owned();
        let server_id = format!("mcp://{address}");
        let reference = format!("{server_id}/query.run");

        let unique = format!(
            "refd-mutate-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(dir.join("materialized")).expect("materialize dir");
        std::fs::write(dir.join("card.yaml"), mcp_card(&server_id, side_effect)).expect("card");

        if !matches!(preload, Preload::None) {
            let journal =
                Journal::open(&dir.join("mutate.jsonl"), max_entries).expect("seed journal");
            let (key, input, terminal) = match preload {
                Preload::None => unreachable!(),
                Preload::IntentOnly { key, input } => (key, input, false),
                Preload::Terminal { key, input } => (key, input, true),
            };
            let digest = request_digest("query", "answer", &reference, "query.run", &input);
            let scope = KeyScope {
                actor: "alice".to_owned(),
                domain: "query".to_owned(),
                type_name: "answer".to_owned(),
                reference: reference.clone(),
                operation: "query.run".to_owned(),
                idempotency_key: key,
            };
            journal.begin(&scope, &digest, "seed").expect("seed intent");
            if terminal {
                journal
                    .finish(&scope, &digest, "succeeded", None, None, "seed")
                    .expect("seed result");
            }
        }

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

[adapter.file]
root = "."

[[acl]]
principal = "alice"
domains = ["query"]
types = ["answer"]
schemes = ["mcp", "file"]
operations = [{operations}]

[[profiles]]
domain = "query"
type = "answer"
card = "card.yaml"

[[mcp_servers]]
id = "{server_id}"
endpoint = "{server_endpoint}"
allow_plaintext = true
timeout_ms = 5000

[materialize]
dir = "materialized"

[mutate]
journal = "mutate.jsonl"
max_entries = {max_entries}
"#,
            scopes = quoted(scopes),
            operations = quoted(operations),
            server_endpoint = server.endpoint,
        );
        let config = Config::from_toml(&config, &dir).expect("config");
        let mut state = AppState::from_config(config).expect("state");
        if let Some(audit) = audit {
            state.audit = audit;
        }
        Self {
            dir,
            reference,
            state: Arc::new(state),
            server,
        }
    }

    fn router(&self) -> Router {
        router(Arc::clone(&self.state))
    }

    fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "domain": "query",
            "type": "answer",
            "reference": self.reference,
            "operation": "query.run",
            "idempotencyKey": "idem-1",
            "input": { "q": "life" },
        })
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

    fn journal_lookup(&self) -> Lookup {
        let digest = request_digest(
            "query",
            "answer",
            &self.reference,
            "query.run",
            &serde_json::json!({ "q": "life" }),
        );
        let scope = KeyScope {
            actor: "alice".to_owned(),
            domain: "query".to_owned(),
            type_name: "answer".to_owned(),
            reference: self.reference.clone(),
            operation: "query.run".to_owned(),
            idempotency_key: "idem-1".to_owned(),
        };
        Journal::open(&self.dir.join("mutate.jsonl"), 1000)
            .expect("journal")
            .lookup(&scope, &digest)
            .expect("lookup")
    }
}

impl Drop for MutateFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 只在第 `fail_at` 次写入失败，其余成功；用于「result 审计失败」场景。
struct FailNthSink {
    fail_at: u32,
    calls: AtomicU32,
}

impl AuditSink for FailNthSink {
    fn record(&self, _event: &AuditEvent) -> Result<(), AuditError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_at {
            Err(AuditError::new("injected audit failure"))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn mutate_materializes_result_and_resolves_it() {
    let fixture = MutateFixture::new(
        &["ref:mutate", "ref:resolve"],
        &["mutate", "resolve:read"],
        "mutating",
        MCP_OK_RESPONSE,
    );
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body: {}",
        String::from_utf8_lossy(&body)
    );
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["status"], "succeeded");
    assert_eq!(json["replayed"], false);
    let result_ref = json["resultRef"].as_str().expect("resultRef").to_owned();
    let result_digest = json["resultDigest"]
        .as_str()
        .expect("resultDigest")
        .to_owned();
    assert!(result_ref.starts_with("file://"));
    assert!(result_digest.starts_with("sha256:"));
    assert_eq!(fixture.server.calls(), 1);

    match fixture.journal_lookup() {
        Lookup::Replay(record) => {
            assert!(record.succeeded());
            assert_eq!(record.result_ref.as_deref(), Some(result_ref.as_str()));
            assert_eq!(
                record.result_digest.as_deref(),
                Some(result_digest.as_str())
            );
        }
        other => panic!("expected replay, got {other:?}"),
    }

    // 写结论物化为静态引用后，可经只读 resolve 取回，形成闭环。
    let (status, _, body) = send(
        fixture.router(),
        post(
            "/v1/resolve",
            serde_json::json!({
                "domain": "query",
                "type": "answer",
                "reference": result_ref,
                "intent": "read",
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "resolve failed: {:?}", body);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["digest"], result_digest);

    // 两阶段审计：intent（requestDigest）与 result（resultDigest）。
    let events = fixture.audit_events();
    let mutate_events: Vec<&serde_json::Value> = events
        .iter()
        .filter(|event| event["operation"] == "mutate")
        .collect();
    assert_eq!(mutate_events.len(), 2, "events: {events:?}");
    assert_eq!(mutate_events[0]["status"], "ok");
    assert!(mutate_events[0]["requestDigest"]
        .as_str()
        .expect("request digest")
        .starts_with("sha256:"));
    assert!(mutate_events[0].get("resultDigest").is_none());
    assert_eq!(mutate_events[1]["status"], "ok");
    assert_eq!(mutate_events[1]["resultDigest"], result_digest);
}

#[tokio::test]
async fn mutate_replays_same_key_without_calling_upstream() {
    let fixture = MutateFixture::new(&["ref:mutate"], &["mutate"], "mutating", MCP_OK_RESPONSE);
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(status, StatusCode::OK);
    let first: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(first["replayed"], false);

    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(status, StatusCode::OK);
    let second: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(second["replayed"], true);
    assert_eq!(second["status"], "succeeded");
    assert_eq!(second["resultRef"], first["resultRef"]);
    assert_eq!(second["resultDigest"], first["resultDigest"]);

    assert_eq!(fixture.server.calls(), 1, "replay must not reach upstream");
}

#[tokio::test]
async fn mutate_same_key_different_digest_conflicts() {
    let fixture = MutateFixture::new(&["ref:mutate"], &["mutate"], "mutating", MCP_OK_RESPONSE);
    let (status, _, _) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(status, StatusCode::OK);

    let mut conflicting = fixture.body();
    conflicting["input"] = serde_json::json!({ "q": "other" });
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", conflicting)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "IdempotencyConflict");
    assert_eq!(fixture.server.calls(), 1);
}

#[tokio::test]
async fn mutate_in_doubt_is_rejected_without_calling_upstream() {
    let fixture = MutateFixture::build(
        &["ref:mutate"],
        &["mutate"],
        "mutating",
        MCP_OK_RESPONSE,
        1000,
        None,
        Preload::IntentOnly {
            key: "idem-1".to_owned(),
            input: serde_json::json!({ "q": "life" }),
        },
    );
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "IdempotencyInDoubt");
    assert_eq!(fixture.server.calls(), 0);
}

#[tokio::test]
async fn mutate_requires_mutate_scope() {
    let fixture = MutateFixture::new(&["ref:invoke"], &["mutate"], "mutating", MCP_OK_RESPONSE);
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "Forbidden");
    assert_eq!(fixture.server.calls(), 0);
}

#[tokio::test]
async fn mutate_requires_object_acl_mutate_operation() {
    let fixture = MutateFixture::new(&["ref:mutate"], &["invoke"], "mutating", MCP_OK_RESPONSE);
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "Forbidden");
    assert_eq!(fixture.server.calls(), 0);
}

#[tokio::test]
async fn mutate_rejects_read_only_capability() {
    let fixture = MutateFixture::new(&["ref:mutate"], &["mutate"], "read-only", MCP_OK_RESPONSE);
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "Forbidden");
    assert_eq!(fixture.server.calls(), 0);
}

#[tokio::test]
async fn mutate_rejects_reference_or_operation_mismatch() {
    let fixture = MutateFixture::new(&["ref:mutate"], &["mutate"], "mutating", MCP_OK_RESPONSE);

    let mut wrong_operation = fixture.body();
    wrong_operation["operation"] = serde_json::json!("other.run");
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", wrong_operation)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "InvalidReference");

    let mut wrong_reference = fixture.body();
    wrong_reference["reference"] = serde_json::json!("mcp://other.example/query.run");
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", wrong_reference)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "InvalidReference");

    assert_eq!(fixture.server.calls(), 0);
}

#[tokio::test]
async fn mutate_intent_audit_failure_does_not_reach_upstream() {
    let fixture = MutateFixture::build(
        &["ref:mutate"],
        &["mutate"],
        "mutating",
        MCP_OK_RESPONSE,
        1000,
        Some(Arc::new(FailingSink)),
        Preload::None,
    );
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "AuditUnavailable");
    assert_eq!(fixture.server.calls(), 0, "intent audit must gate upstream");
    assert_eq!(fixture.journal_lookup(), Lookup::InDoubt);
}

#[tokio::test]
async fn mutate_result_audit_failure_recovers_by_replay() {
    let fixture = MutateFixture::build(
        &["ref:mutate"],
        &["mutate"],
        "mutating",
        MCP_OK_RESPONSE,
        1000,
        Some(Arc::new(FailNthSink {
            fail_at: 2,
            calls: AtomicU32::new(0),
        })),
        Preload::None,
    );
    // 第 1 次写审计成功、第 2 次（result）失败：响应 500，但台账已有结论。
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "AuditUnavailable");
    assert_eq!(fixture.server.calls(), 1);

    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "replay: {}",
        String::from_utf8_lossy(&body)
    );
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["status"], "succeeded");
    assert_eq!(json["replayed"], true);
    assert_eq!(fixture.server.calls(), 1);
}

#[tokio::test]
async fn mutate_journal_full_is_unavailable() {
    let fixture = MutateFixture::build(
        &["ref:mutate"],
        &["mutate"],
        "mutating",
        MCP_OK_RESPONSE,
        2,
        None,
        Preload::Terminal {
            key: "seed-1".to_owned(),
            input: serde_json::json!({ "seed": true }),
        },
    );
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "JournalFull");
    assert_eq!(fixture.server.calls(), 0);
}

#[tokio::test]
async fn mutate_upstream_failure_is_bad_gateway_and_replays() {
    let fixture = MutateFixture::new(&["ref:mutate"], &["mutate"], "mutating", MCP_ERROR_RESPONSE);
    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "UpstreamFailure");
    assert_eq!(fixture.server.calls(), 1);

    let (status, _, body) = send(fixture.router(), post("/v1/mutate", fixture.body())).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "UpstreamFailure");
    assert_eq!(json["detail"]["replayed"], true);
    assert_eq!(fixture.server.calls(), 1);
}

#[test]
fn mutating_profile_requires_journal() {
    let (endpoint, server) = fake_mcp_server(MCP_OK_RESPONSE);
    let address = endpoint.strip_prefix("http://").expect("http");
    let server_id = format!("mcp://{address}");
    let dir = std::env::temp_dir().join(format!(
        "refd-mutate-nojournal-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(dir.join("materialized")).expect("dir");
    std::fs::write(dir.join("card.yaml"), mcp_card(&server_id, "mutating")).expect("card");

    let config = mcp_config(&server_id, &endpoint, true, true)
        .replace("[mutate]\njournal = \"mutate.jsonl\"\n", "");
    let config = Config::from_toml(&config, &dir).expect("config");
    let error = match AppState::from_config(config) {
        Ok(_) => panic!("state must fail closed"),
        Err(error) => error,
    };
    assert!(
        error.contains("[mutate].journal"),
        "unexpected error: {error}"
    );

    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}
