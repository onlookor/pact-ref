//! witness / compensation 示例的可运行证据（FR37 / 治理 §13.8.7）。
//!
//! 两条断言链：
//! 1. 写成功 → `resultRef` → `/v1/resolve` → 该引用可按示例 RefBindings 写入 PACT 的 witness token；
//! 2. 写失败 → **不自动补偿**（补偿卡片调用次数为 0）→ 由域内规则显式调用补偿卡片。
//!
//! 示例卡片来自 `examples/witness-compensation/`，只把占位 server id 换成
//! 本地假 MCP 服务地址，保证「示例可跑」而不是另写一份测试专用卡片。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use pact_ref_core::{RefBindings, ReferenceForm};
use pact_refd::{router, AppState, Config};

const PLACEHOLDER_SERVER: &str = "mcp://ops.example.com/release-server";
const MCP_OK_RESPONSE: &str =
    r#"{"jsonrpc":"2.0","id":"idem-1","result":{"content":[{"type":"text","text":"ok"}]}}"#;
const MCP_ERROR_RESPONSE: &str =
    r#"{"jsonrpc":"2.0","id":"idem-1","error":{"code":-32000,"message":"deploy failed"}}"#;

static SEQ: AtomicU32 = AtomicU32::new(0);

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/witness-compensation")
}

/// 假 MCP 服务：按工具名计数，可指定哪些工具返回上游错误。
struct FakeMcp {
    endpoint: String,
    calls: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FakeMcp {
    fn start(failing: &[&str]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake mcp");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("addr");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let calls_bg = Arc::clone(&calls);
        let stop_bg = Arc::clone(&stop);
        let failing: Vec<String> = failing.iter().map(|tool| (*tool).to_owned()).collect();
        let handle = std::thread::spawn(move || {
            while !stop_bg.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let request = read_http_request(&mut stream);
                        assert!(request.contains("\"tools/call\""), "unexpected request");
                        let tool = ["release.deploy", "release.rollback"]
                            .into_iter()
                            .find(|tool| request.contains(&format!("\"name\":\"{tool}\"")))
                            .unwrap_or("unknown");
                        calls_bg.lock().expect("calls").push(tool.to_owned());
                        let body = if failing.iter().any(|name| name == tool) {
                            MCP_ERROR_RESPONSE
                        } else {
                            MCP_OK_RESPONSE
                        };
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

    fn server_id(&self) -> String {
        format!(
            "mcp://{}",
            self.endpoint
                .strip_prefix("http://")
                .expect("http endpoint")
        )
    }

    fn calls(&self, tool: &str) -> usize {
        self.calls
            .lock()
            .expect("calls")
            .iter()
            .filter(|name| name.as_str() == tool)
            .count()
    }
}

impl Drop for FakeMcp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct Fixture {
    dir: PathBuf,
    server: FakeMcp,
    state: Arc<AppState>,
}

impl Fixture {
    fn new(failing: &[&str]) -> Self {
        let server = FakeMcp::start(failing);
        let server_id = server.server_id();

        let unique = format!(
            "refd-witness-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(dir.join("cards")).expect("cards dir");
        std::fs::create_dir_all(dir.join("materialized")).expect("materialized dir");
        for name in ["release-deploy.yaml", "release-rollback.yaml"] {
            let text = std::fs::read_to_string(examples_dir().join("cards").join(name))
                .unwrap_or_else(|error| panic!("read example card {name}: {error}"));
            let text = text.replace(PLACEHOLDER_SERVER, &server_id);
            std::fs::write(dir.join("cards").join(name), text).expect("write card");
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
subject = "release-bot"
scopes = ["ref:resolve", "ref:mutate"]

[audit]
path = "audit.jsonl"

[adapter.file]
root = "materialized"

[[acl]]
principal = "release-bot"
domains = ["release"]
types = ["deployment", "rollback"]
schemes = ["mcp", "file"]
operations = ["mutate", "resolve:read"]

[[profiles]]
domain = "release"
type = "deployment"
card = "cards/release-deploy.yaml"

[[profiles]]
domain = "release"
type = "rollback"
card = "cards/release-rollback.yaml"

[[mcp_servers]]
id = "{server_id}"
endpoint = "{endpoint}"
allow_plaintext = true
timeout_ms = 5000

[materialize]
dir = "materialized"

[mutate]
journal = "mutate.jsonl"
max_entries = 64
"#,
            endpoint = server.endpoint,
        );
        let config = Config::from_toml(&config, &dir).expect("config");
        let state = AppState::from_config(config).expect("state");
        Self {
            dir,
            server,
            state: Arc::new(state),
        }
    }

    fn router(&self) -> Router {
        router(Arc::clone(&self.state))
    }

    fn deploy_body(&self) -> serde_json::Value {
        serde_json::json!({
            "domain": "release",
            "type": "deployment",
            "reference": format!("{}/release.deploy", self.server.server_id()),
            "operation": "release.deploy",
            "idempotencyKey": "release-42-attempt-1",
            "input": { "releaseId": "42" },
        })
    }

    fn rollback_body(&self) -> serde_json::Value {
        serde_json::json!({
            "domain": "release",
            "type": "rollback",
            "reference": format!("{}/release.rollback", self.server.server_id()),
            "operation": "release.rollback",
            "idempotencyKey": "rollback-42-1",
            "input": { "releaseId": "42" },
        })
    }

    fn audit_mutations(&self) -> Vec<serde_json::Value> {
        let Ok(text) = std::fs::read_to_string(self.dir.join("audit.jsonl")) else {
            return Vec::new();
        };
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("audit json"))
            .filter(|event| event["operation"] == "mutate")
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
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

async fn send(router: Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = router.oneshot(request).await.expect("response");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, body)
}

fn post(path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", "Bearer s3cret")
        .header("content-type", "application/json")
        .header("x-trace-id", "witness-trace")
        .body(Body::from(body.to_string()))
        .expect("request")
}

fn example_bindings() -> RefBindings {
    let path = examples_dir().join("bindings/release.refs.yaml");
    let text = std::fs::read_to_string(path).expect("read bindings");
    let bindings: RefBindings = serde_yaml::from_str(&text).expect("bindings");
    bindings.validate().expect("valid bindings");
    bindings
}

fn assert_binding_accepts(
    bindings: &RefBindings,
    type_name: &str,
    reference: &str,
    contract: &str,
) {
    let form = ReferenceForm::classify(Some(reference)).expect("reference form");
    let matched = bindings
        .resolve(None, type_name, &form)
        .unwrap_or_else(|error| panic!("{type_name} binding rejected {reference}: {error}"));
    assert_eq!(matched.rule.contract.as_deref(), Some(contract));
}

#[tokio::test]
async fn witness_flow_resolves_mutate_result_for_pact_token() {
    let fixture = Fixture::new(&[]);
    let (status, body) = send(fixture.router(), post("/v1/mutate", fixture.deploy_body())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "mutate: {}",
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
    assert_eq!(fixture.server.calls("release.deploy"), 1);
    assert_eq!(
        fixture.server.calls("release.rollback"),
        0,
        "success must not compensate"
    );

    // witness 前置条件：参与者先经 `/v1/resolve` 确认物化结果可读且摘要一致。
    let (status, body) = send(
        fixture.router(),
        post(
            "/v1/resolve",
            serde_json::json!({
                "domain": "release",
                "type": "deployment",
                "reference": result_ref,
                "intent": "read",
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "resolve: {}",
        String::from_utf8_lossy(&body)
    );
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["digest"], result_digest);

    // 该引用可按示例 RefBindings 作为 `deployment` 类型写入 PACT（witness token）。
    assert_binding_accepts(
        &example_bindings(),
        "deployment",
        &result_ref,
        "release/deploy@1",
    );

    // 两阶段审计：同一次写 attempt 的 intent + result。
    assert_eq!(fixture.audit_mutations().len(), 2);
}

#[tokio::test]
async fn failure_does_not_auto_compensate_until_explicitly_invoked() {
    let fixture = Fixture::new(&["release.deploy"]);
    let (status, body) = send(fixture.router(), post("/v1/mutate", fixture.deploy_body())).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["code"], "UpstreamFailure");
    assert_eq!(
        fixture.server.calls("release.rollback"),
        0,
        "refd must not run compensation automatically"
    );

    // 失败结论可重放，且仍不触达上游、不触发补偿。
    let (status, body) = send(fixture.router(), post("/v1/mutate", fixture.deploy_body())).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["detail"]["replayed"], true);
    assert_eq!(fixture.server.calls("release.deploy"), 1);
    assert_eq!(fixture.server.calls("release.rollback"), 0);

    // 域内规则显式调用补偿卡片：另一张 mutating 卡片、独立幂等键。
    let (status, body) = send(
        fixture.router(),
        post("/v1/mutate", fixture.rollback_body()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "rollback: {}",
        String::from_utf8_lossy(&body)
    );
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["status"], "succeeded");
    assert_eq!(json["replayed"], false);
    assert_eq!(fixture.server.calls("release.rollback"), 1);
    assert_eq!(fixture.server.calls("release.deploy"), 1);

    let result_ref = json["resultRef"].as_str().expect("resultRef").to_owned();
    assert_binding_accepts(
        &example_bindings(),
        "rollback",
        &result_ref,
        "release/rollback@1",
    );
}

/// README 的钉版边界：`resultRef` 本身不含 `sha256:`；追加 `#sha256=<digest>` 后
/// 仍是合法 `file` URI，且能匹配同一类型绑定，供要求 `required-at-archive` 的域使用。
#[test]
fn witness_reference_can_carry_digest_fragment_for_pinning() {
    let bindings = example_bindings();
    let base = "file:///srv/pact/materialized/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.json";
    let pinned = format!("{base}#sha256={}", "a".repeat(64));
    assert_binding_accepts(&bindings, "deployment", &pinned, "release/deploy@1");
}

fn _assert_example_files_exist(root: &Path) {
    for relative in [
        "cards/release-deploy.yaml",
        "cards/release-rollback.yaml",
        "bindings/release.refs.yaml",
        "domain.pact",
        "refd.toml",
        "README.md",
    ] {
        assert!(root.join(relative).is_file(), "missing {relative}");
    }
}

#[test]
fn example_directory_is_complete() {
    _assert_example_files_exist(&examples_dir());
}
