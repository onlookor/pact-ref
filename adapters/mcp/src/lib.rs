//! `mcp://` 动态只读 adapter（FR36 / D52）。
//!
//! 只实现 `tools/call`：按配置把服务标识映射到 HTTPS 端点，调用后把 JSON-RPC `result`
//! 原样物化为内容寻址的 `file://` 引用。引用里不带凭据，上游 bearer 令牌只从配置注入。
//! 端点类型（是否 HTTPS）由装配层校验；adapter 自身不做重定向、不解析 userinfo。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pact_ref_core::{
    Invocation, InvocationStatus, InvokeRequest, Invoker, ReferenceError, Resolution,
    ResolveRequest, Resolver,
};
use sha2::{Digest, Sha256};

pub const SCHEME: &str = "mcp";

/// 单个已登记 MCP 服务端。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// 与卡片 `capability.server.id` 相同的 `mcp://` 服务标识。
    pub id: String,
    /// 调用端点（装配层要求 HTTPS）。
    pub endpoint: String,
    pub timeout_ms: u64,
    /// 上游 bearer 令牌；由装配层从环境变量解析，不进入引用或审计。
    pub bearer_token: Option<String>,
}

/// 已登记的服务端。
struct Server {
    id: String,
    endpoint: String,
    bearer_token: Option<String>,
    agent: ureq::Agent,
}

pub struct Adapter {
    servers: Vec<Server>,
    materialize_dir: PathBuf,
    max_bytes: usize,
}

impl Adapter {
    /// `materialize_dir` 必须已存在且为目录；所有结果写入该目录。
    pub fn new(
        servers: Vec<ServerConfig>,
        materialize_dir: impl Into<PathBuf>,
        max_bytes: usize,
    ) -> std::io::Result<Self> {
        let materialize_dir = std::fs::canonicalize(materialize_dir.into())?;
        if !materialize_dir.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "materialize dir must be a directory",
            ));
        }
        let servers = servers
            .into_iter()
            .map(|server| Server {
                id: server.id,
                endpoint: server.endpoint,
                bearer_token: server.bearer_token,
                agent: ureq::AgentBuilder::new()
                    .timeout(Duration::from_millis(server.timeout_ms))
                    .redirects(0)
                    .build(),
            })
            .collect();
        Ok(Self {
            servers,
            materialize_dir,
            max_bytes,
        })
    }

    /// 找到最长的匹配服务标识，并返回剩余的工具名。
    fn route<'a>(&'a self, reference: &str) -> Result<(&'a Server, String), ReferenceError> {
        if !reference.starts_with("mcp://") {
            return Err(ReferenceError::InvalidRequest("not an mcp URI".to_owned()));
        }
        let server = self
            .servers
            .iter()
            .filter(|server| {
                reference == server.id
                    || reference
                        .strip_prefix(&server.id)
                        .is_some_and(|tail| tail.starts_with('/'))
            })
            .max_by_key(|server| server.id.len())
            .ok_or_else(|| {
                ReferenceError::NotFound(format!(
                    "mcp server is not registered: {}",
                    server_identity(reference)
                ))
            })?;
        let tail = &reference[server.id.len()..];
        let tool = tail
            .strip_prefix('/')
            .unwrap_or_default()
            .split('#')
            .next()
            .unwrap_or_default()
            .split('@')
            .next()
            .unwrap_or_default();
        if tool.is_empty() {
            return Err(ReferenceError::InvalidRequest(
                "mcp reference must name a tool".to_owned(),
            ));
        }
        Ok((server, tool.to_owned()))
    }

    fn materialize(&self, result: &serde_json::Value) -> Result<(String, String), ReferenceError> {
        let bytes = serde_json::to_vec(result)
            .map_err(|error| ReferenceError::Internal(format!("serialize result: {error}")))?;
        if bytes.len() > self.max_bytes {
            return Err(ReferenceError::Upstream(format!(
                "mcp result exceeds {} bytes",
                self.max_bytes
            )));
        }
        let digest = hex_encode(&Sha256::digest(&bytes));
        let path = self.materialize_dir.join(format!("{digest}.json"));
        if !path.is_file() {
            let temporary = self
                .materialize_dir
                .join(format!(".{digest}.{}.tmp", std::process::id()));
            std::fs::write(&temporary, &bytes).map_err(|error| {
                ReferenceError::Internal(format!("write materialized result: {error}"))
            })?;
            if let Err(error) = std::fs::rename(&temporary, &path) {
                let _ = std::fs::remove_file(&temporary);
                if !path.is_file() {
                    return Err(ReferenceError::Internal(format!(
                        "commit materialized result: {error}"
                    )));
                }
            }
        }
        Ok((file_uri(&path), format!("sha256:{digest}")))
    }
}

impl Resolver for Adapter {
    fn scheme(&self) -> &'static str {
        SCHEME
    }

    fn resolve(&self, _request: &ResolveRequest) -> Result<Resolution, ReferenceError> {
        Err(ReferenceError::InvalidRequest(
            "mcp references are invoked, not resolved".to_owned(),
        ))
    }
}

impl Invoker for Adapter {
    fn scheme(&self) -> &'static str {
        SCHEME
    }

    fn invoke(&self, request: &InvokeRequest) -> Result<Invocation, ReferenceError> {
        let reference = request
            .reference
            .as_str()
            .ok_or_else(|| ReferenceError::UnsupportedIdentifier("∅".to_owned()))?;
        let (server, tool) = self.route(reference)?;

        let arguments = if request.input.is_null() {
            serde_json::json!({})
        } else {
            request.input.clone()
        };
        let envelope = serde_json::json!({
            "jsonrpc": "2.0",
            "id": request.idempotency_key,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments },
        });
        let body = serde_json::to_string(&envelope)
            .map_err(|error| ReferenceError::Internal(format!("serialize request: {error}")))?;

        let mut call = server
            .agent
            .post(&server.endpoint)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream");
        if let Some(token) = &server.bearer_token {
            call = call.set("Authorization", &format!("Bearer {token}"));
        }
        let response = call.send_string(&body).map_err(|error| match error {
            ureq::Error::Status(401 | 403, _) => ReferenceError::Unauthorized(server.id.clone()),
            ureq::Error::Status(404, _) => ReferenceError::NotFound(server.id.clone()),
            ureq::Error::Status(408 | 504, _) => ReferenceError::Timeout(server.id.clone()),
            ureq::Error::Status(_, _) => {
                ReferenceError::Upstream(format!("mcp upstream refused {}", server.id))
            }
            ureq::Error::Transport(_) => {
                ReferenceError::Upstream(format!("mcp upstream unavailable: {}", server.id))
            }
        })?;

        let limit = self.max_bytes.saturating_add(64 * 1024) as u64;
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|error| ReferenceError::Upstream(format!("read mcp response: {error}")))?;
        if bytes.len() as u64 >= limit {
            return Err(ReferenceError::Upstream(
                "mcp response exceeds the configured bound".to_owned(),
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| ReferenceError::Upstream("mcp response is not JSON".to_owned()))?;

        if let Some(error) = value.get("error") {
            return Ok(failed(format!(
                "mcp error {}",
                error
                    .get("code")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or_default()
            )));
        }
        let result = value
            .get("result")
            .ok_or_else(|| ReferenceError::Upstream("mcp response has no result".to_owned()))?;
        if result
            .get("isError")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(failed(error_text(result)));
        }

        let (result_ref, result_digest) = self.materialize(result)?;
        Ok(Invocation {
            status: InvocationStatus::Succeeded,
            result_ref: Some(result_ref),
            result_digest: Some(result_digest),
            error: None,
        })
    }
}

fn failed(message: String) -> Invocation {
    Invocation {
        status: InvocationStatus::Failed,
        result_ref: None,
        result_digest: None,
        error: Some(truncate(message, 512)),
    }
}

/// 只透出工具自报的错误文本，不回显请求参数或凭据。
fn error_text(result: &serde_json::Value) -> String {
    result
        .get("content")
        .and_then(serde_json::Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|item| {
                item.get("text")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
        })
        .unwrap_or_else(|| "mcp tool reported an error".to_owned())
}

fn truncate(mut value: String, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value;
    }
    value = value.chars().take(limit).collect();
    value.push('…');
    value
}

fn server_identity(reference: &str) -> String {
    let rest = reference.strip_prefix("mcp://").unwrap_or(reference);
    let authority = rest.split('/').next().unwrap_or_default();
    format!("mcp://{authority}")
}

fn file_uri(path: &Path) -> String {
    let mut uri = String::from("file://");
    for byte in path.to_string_lossy().bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            uri.push(byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread::JoinHandle;

    use super::{Adapter, ServerConfig};
    use pact_ref_core::{
        InvocationStatus, InvokeRequest, Invoker, ReferenceError, ReferenceForm, Resolver,
    };

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn materialize_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pact-ref-mcp-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    fn adapter(endpoint: &str, max_bytes: usize) -> Adapter {
        Adapter::new(
            vec![ServerConfig {
                id: "mcp://build.example.com/build-server".to_owned(),
                endpoint: endpoint.to_owned(),
                timeout_ms: 2_000,
                bearer_token: Some("upstream-secret".to_owned()),
            }],
            materialize_dir(),
            max_bytes,
        )
        .expect("adapter")
    }

    fn request() -> InvokeRequest {
        InvokeRequest {
            domain: "build".to_owned(),
            type_name: "capability".to_owned(),
            reference: ReferenceForm::classify(Some(
                "mcp://build.example.com/build-server/build.run@3",
            ))
            .expect("reference"),
            actor: "alice".to_owned(),
            operation: "build".to_owned(),
            idempotency_key: "idem-1".to_owned(),
            input: serde_json::json!({ "target": "demo" }),
        }
    }

    /// 一次性假 MCP 服务端；返回端点与线程，线程产出收到的请求文本。
    fn fake_server(status: &'static str, body: String) -> (String, JoinHandle<(String, String)>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = stream.read(&mut chunk).expect("read");
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if let Some(position) = find_headers_end(&buffer) {
                    let head = String::from_utf8_lossy(&buffer[..position]).into_owned();
                    let length = head
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("Content-Length:")
                                .or_else(|| line.strip_prefix("content-length:"))
                        })
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or_default();
                    if buffer.len() >= position + 4 + length {
                        break;
                    }
                }
            }
            let position = find_headers_end(&buffer).expect("headers");
            let head = String::from_utf8_lossy(&buffer[..position]).into_owned();
            let body_text = String::from_utf8_lossy(&buffer[position + 4..]).into_owned();
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).expect("write");
            (head, body_text)
        });
        (format!("http://{address}/mcp"), handle)
    }

    fn find_headers_end(buffer: &[u8]) -> Option<usize> {
        buffer.windows(4).position(|window| window == b"\r\n\r\n")
    }

    #[test]
    fn invokes_and_materializes_result() {
        let (endpoint, server) = fake_server(
            "200 OK",
            r#"{"jsonrpc":"2.0","id":"idem-1","result":{"content":[{"type":"text","text":"built"}]}}"#
                .to_owned(),
        );
        let invocation = adapter(&endpoint, 1024 * 1024)
            .invoke(&request())
            .expect("invoke");
        assert_eq!(invocation.status, InvocationStatus::Succeeded);
        let result_ref = invocation.result_ref.expect("result ref");
        let path = result_ref
            .strip_prefix("file://")
            .expect("file uri")
            .to_owned();
        let materialized = std::fs::read(&path).expect("materialized");
        assert_eq!(
            String::from_utf8(materialized).expect("utf8"),
            r#"{"content":[{"text":"built","type":"text"}]}"#
        );
        assert!(invocation
            .result_digest
            .as_deref()
            .is_some_and(|digest| digest.starts_with("sha256:")));

        let (head, body) = server.join().expect("server");
        assert!(head
            .to_ascii_lowercase()
            .contains("authorization: bearer upstream-secret"));
        assert!(body.contains("\"method\":\"tools/call\""));
        assert!(body.contains("\"name\":\"build.run\""));
        assert!(body.contains("\"target\":\"demo\""));
    }

    #[test]
    fn returns_failed_for_jsonrpc_error() {
        let (endpoint, server) = fake_server(
            "200 OK",
            r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"no such tool"}}"#.to_owned(),
        );
        let invocation = adapter(&endpoint, 1024).invoke(&request()).expect("invoke");
        assert_eq!(invocation.status, InvocationStatus::Failed);
        assert!(invocation.result_ref.is_none());
        assert!(invocation.error.is_some_and(|text| text.contains("-32601")));
        server.join().expect("server");
    }

    #[test]
    fn returns_failed_for_tool_error() {
        let (endpoint, server) = fake_server(
            "200 OK",
            r#"{"jsonrpc":"2.0","result":{"isError":true,"content":[{"type":"text","text":"denied"}]}}"#
                .to_owned(),
        );
        let invocation = adapter(&endpoint, 1024).invoke(&request()).expect("invoke");
        assert_eq!(invocation.status, InvocationStatus::Failed);
        assert_eq!(invocation.error.as_deref(), Some("denied"));
        server.join().expect("server");
    }

    #[test]
    fn rejects_unregistered_server_without_network() {
        let adapter = Adapter::new(Vec::new(), materialize_dir(), 1024).expect("adapter");
        assert!(matches!(
            adapter.invoke(&request()),
            Err(ReferenceError::NotFound(_))
        ));

        let registered = adapter_with_dead_endpoint();
        assert!(matches!(
            registered.invoke(&InvokeRequest {
                reference: ReferenceForm::classify(Some("mcp://build.example.com/build-server"))
                    .expect("reference"),
                ..request()
            }),
            Err(ReferenceError::InvalidRequest(_))
        ));
    }

    fn adapter_with_dead_endpoint() -> Adapter {
        Adapter::new(
            vec![ServerConfig {
                id: "mcp://build.example.com/build-server".to_owned(),
                endpoint: "http://127.0.0.1:9/mcp".to_owned(),
                timeout_ms: 100,
                bearer_token: None,
            }],
            materialize_dir(),
            1024,
        )
        .expect("adapter")
    }

    #[test]
    fn maps_upstream_status() {
        let (endpoint, server) = fake_server("500 Internal Server Error", "{}".to_owned());
        let error = adapter(&endpoint, 1024)
            .invoke(&request())
            .expect_err("upstream");
        assert!(matches!(error, ReferenceError::Upstream(_)));
        server.join().expect("server");
    }

    #[test]
    fn rejects_result_above_bound() {
        let body =
            r#"{"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"0123456789"}]}}"#;
        let (endpoint, server) = fake_server("200 OK", body.to_owned());
        let error = adapter(&endpoint, 16)
            .invoke(&request())
            .expect_err("too large");
        assert!(matches!(error, ReferenceError::Upstream(_)));
        server.join().expect("server");
    }

    #[test]
    fn resolve_is_not_supported() {
        use pact_ref_core::{ResolveIntent, ResolveRequest};
        let adapter = adapter("https://build.example.com/mcp", 1024);
        let error = adapter
            .resolve(&ResolveRequest {
                domain: "build".to_owned(),
                type_name: "capability".to_owned(),
                reference: ReferenceForm::classify(Some(
                    "mcp://build.example.com/build-server/build.run",
                ))
                .expect("reference"),
                actor: "alice".to_owned(),
                intent: ResolveIntent::Read,
                expected_digest: None,
                pact_token_id: None,
            })
            .expect_err("unsupported");
        assert!(matches!(error, ReferenceError::InvalidRequest(_)));
    }
}
