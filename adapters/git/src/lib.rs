//! `git+https://` scheme adapter。
//!
//! 只解析 `git+https://<host>[/<path>][@<rev>]`：authority（`host` 或 `host:port`）必须在
//! 配置的 allowlist 内（默认拒绝），拒绝 userinfo/query/fragment 与控制字符。取回只走
//! smart HTTP 的引用通告 `GET <repo>/info/refs?service=git-upload-pack`，不克隆仓库、
//! 不落盘，响应有 2 MiB 上限。`<rev>` 缺省 `HEAD`，解析顺序为：40/64 位提交号、`HEAD`、
//! `refs/...`、`refs/heads/<rev>`、`refs/tags/<rev>^{}`（peeled）、`refs/tags/<rev>`。
//!
//! v1 默认 HTTPS；仅当 authority 是回环主机且显式 `allow_plaintext` 时降级为 `http://`。
//!
//! `git+ssh://` 在 v1 显式不支持：不 spawn 进程、不持有 SSH 凭据，直接返回
//! `UnsupportedIdentifier`。`git+file://` 同样不实现，避免引入路径穿越面。
//!
//! git 提交号不是 `uri-profile.md` §4 规定的 `sha256:<64 hex>` 内容摘要，因此不写入
//! `digest`，只钉在 `handle` 上；`media_type` 留空由 `refd` 回填。

use std::io::Read;
use std::time::Duration;

use pact_ref_core::{ReferenceError, Resolution, ResolveRequest, Resolver};

pub const SCHEME: &str = "git+https";
pub const SSH_SCHEME: &str = "git+ssh";

/// smart HTTP 引用通告的 `Accept`。
pub const UPLOAD_PACK_ACCEPT: &str = "application/x-git-upload-pack-advertisement";

/// 单次引用通告允许读取的响应字节上限 2 MiB。
pub const MAX_ADVERTISEMENT_BYTES: usize = 2 * 1024 * 1024;

pub struct Adapter {
    allowed_hosts: Vec<String>,
    allow_plaintext: bool,
    agent: ureq::Agent,
}

impl Adapter {
    /// `allowed_hosts` 为 `host` 或 `host:port`；匹配大小写不敏感、端口须一致。
    pub fn new(allowed_hosts: Vec<String>, timeout_ms: u64, allow_plaintext: bool) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_millis(timeout_ms))
            .redirects(0)
            .build();
        Self {
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
            allow_plaintext,
            agent,
        }
    }

    fn is_allowed(&self, authority: &str) -> bool {
        self.allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(authority))
    }
}

impl Default for Adapter {
    fn default() -> Self {
        Self::new(Vec::new(), 10_000, false)
    }
}

/// `git+ssh://` 在 v1 显式不支持。
pub struct SshAdapter;

impl SshAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SshAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for SshAdapter {
    fn scheme(&self) -> &'static str {
        SSH_SCHEME
    }

    fn resolve(&self, _request: &ResolveRequest) -> Result<Resolution, ReferenceError> {
        Err(ReferenceError::UnsupportedIdentifier(
            "git+ssh is not supported in v1".to_owned(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitReference {
    authority: String,
    repository: String,
    rev: String,
}

fn parse_reference(reference: &str) -> Result<GitReference, ReferenceError> {
    let rest = reference
        .strip_prefix("git+https://")
        .ok_or_else(|| ReferenceError::InvalidRequest("not a git+https:// URI".to_owned()))?;
    if rest.is_empty()
        || rest
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\u{7f}')
    {
        return Err(ReferenceError::InvalidRequest(
            "git URI contains control characters".to_owned(),
        ));
    }
    if rest.contains(['?', '#']) {
        return Err(ReferenceError::InvalidRequest(
            "git URI must not contain a query or fragment".to_owned(),
        ));
    }

    let (authority, path) = rest.split_once('/').ok_or_else(|| {
        ReferenceError::InvalidRequest("git URI is missing a repository path".to_owned())
    })?;
    if authority.is_empty() || authority.contains('@') {
        return Err(ReferenceError::InvalidRequest(
            "git URI must not carry userinfo".to_owned(),
        ));
    }
    if !is_valid_authority(authority) {
        return Err(ReferenceError::InvalidRequest(
            "git URI host is not a valid host[:port]".to_owned(),
        ));
    }

    let (repository, rev) = match path.rsplit_once('@') {
        Some((repository, rev)) => (repository, rev),
        None => (path, "HEAD"),
    };
    if !is_valid_repository(repository) {
        return Err(ReferenceError::InvalidRequest(
            "git repository path is not valid".to_owned(),
        ));
    }
    validate_rev(rev)?;

    Ok(GitReference {
        authority: authority.to_owned(),
        repository: repository.to_owned(),
        rev: rev.to_owned(),
    })
}

/// authority 只接受 `host`、`host:port` 或 `[v6]:port`；不允许 userinfo。
fn is_valid_authority(authority: &str) -> bool {
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let (host, port) = split_authority(authority);
    if host.is_empty() {
        return false;
    }
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        if port.parse::<u16>().map(|value| value == 0).unwrap_or(true) {
            return false;
        }
    }
    if authority.starts_with('[') {
        return authority
            .strip_prefix('[')
            .and_then(|rest| rest.split_once(']'))
            .map(|(inner, _)| !inner.is_empty() && inner.parse::<std::net::Ipv6Addr>().is_ok())
            .unwrap_or(false);
    }
    host.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && !host.starts_with('.')
        && !host.ends_with('.')
}

fn split_authority(authority: &str) -> (&str, Option<&str>) {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            return (host, tail.strip_prefix(':'));
        }
        return (authority, None);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    }
}

/// 仓库路径：分段由字母/数字/`._~-` 组成；不得为空、`.`、`..`。
fn is_valid_repository(repository: &str) -> bool {
    if repository.is_empty() || repository.len() > 1024 {
        return false;
    }
    repository.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-')
            })
    })
}

/// 解析后的修订：提交号、`HEAD`、完整 ref 或短分支/标签名；禁止 `..` 与 `@{`。
fn validate_rev(rev: &str) -> Result<(), ReferenceError> {
    if rev.is_empty()
        || rev.len() > 255
        || rev.chars().any(|c| c.is_control() || c.is_whitespace())
        || !rev
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
        || rev.contains("..")
        || rev.contains("//")
        || rev.contains("@{")
        || rev.starts_with('/')
        || rev.ends_with('/')
    {
        return Err(ReferenceError::InvalidRequest(
            "git revision is not valid".to_owned(),
        ));
    }
    Ok(())
}

fn is_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// 解析 smart HTTP 引用通告，返回 `(ref, oid)` 列表。
fn parse_advertisement(body: &[u8]) -> Result<Vec<(String, String)>, ReferenceError> {
    let mut refs = Vec::new();
    let mut cursor = 0usize;
    let mut first_payload = true;
    let mut seen_service = false;

    while cursor + 4 <= body.len() {
        let header = std::str::from_utf8(&body[cursor..cursor + 4])
            .map_err(|_| ReferenceError::Upstream("git pkt-line length is not ASCII".to_owned()))?;
        let length = usize::from_str_radix(header, 16).map_err(|_| {
            ReferenceError::Upstream("git pkt-line length is not hexadecimal".to_owned())
        })?;
        match length {
            0..=2 => {
                cursor += 4;
                continue;
            }
            3 => {
                return Err(ReferenceError::Upstream(
                    "git pkt-line length 3 is invalid".to_owned(),
                ));
            }
            _ => {}
        }
        let end = cursor
            .checked_add(length)
            .filter(|end| *end <= body.len())
            .ok_or_else(|| ReferenceError::Upstream("git pkt-line is truncated".to_owned()))?;
        let payload = &body[cursor + 4..end];
        cursor = end;

        let payload = std::str::from_utf8(payload).map_err(|_| {
            ReferenceError::Upstream("git advertisement is not valid UTF-8".to_owned())
        })?;
        let line = payload.trim_end_matches(['\n', '\r']);

        if first_payload {
            first_payload = false;
            match line.strip_prefix("# service=") {
                Some("git-upload-pack") => seen_service = true,
                _ => {
                    return Err(ReferenceError::Upstream(
                        "git advertisement is missing the upload-pack service header".to_owned(),
                    ))
                }
            }
            continue;
        }

        if line.is_empty() {
            continue;
        }
        let (oid, name_and_caps) = line.split_once(' ').ok_or_else(|| {
            ReferenceError::Upstream("git advertisement ref line is malformed".to_owned())
        })?;
        if !is_oid(oid) {
            return Err(ReferenceError::Upstream(
                "git advertisement ref oid is not 40 or 64 hex digits".to_owned(),
            ));
        }
        let name = name_and_caps.split('\0').next().unwrap_or_default();
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(ReferenceError::Upstream(
                "git advertisement ref name is invalid".to_owned(),
            ));
        }
        refs.push((name.to_owned(), oid.to_ascii_lowercase()));
    }

    if !seen_service {
        return Err(ReferenceError::Upstream(
            "git advertisement is missing the upload-pack service header".to_owned(),
        ));
    }
    Ok(refs)
}

fn resolve_rev(refs: &[(String, String)], rev: &str) -> Result<String, ReferenceError> {
    if is_oid(rev) {
        return Ok(rev.to_ascii_lowercase());
    }
    let mut candidates = Vec::new();
    if rev == "HEAD" {
        candidates.push("HEAD".to_owned());
    }
    if rev.starts_with("refs/") {
        candidates.push(rev.to_owned());
    } else {
        candidates.push(format!("refs/heads/{rev}"));
        candidates.push(format!("refs/tags/{rev}^{{}}"));
        candidates.push(format!("refs/tags/{rev}"));
    }
    for candidate in candidates {
        if let Some((_, oid)) = refs.iter().find(|(name, _)| name == &candidate) {
            return Ok(oid.clone());
        }
    }
    Err(ReferenceError::NotFound(rev.to_owned()))
}

impl Resolver for Adapter {
    fn scheme(&self) -> &'static str {
        SCHEME
    }

    fn resolve(&self, request: &ResolveRequest) -> Result<Resolution, ReferenceError> {
        let reference = request
            .reference
            .as_str()
            .ok_or_else(|| ReferenceError::UnsupportedIdentifier("∅".to_owned()))?;
        let parsed = parse_reference(reference)?;
        if !self.is_allowed(&parsed.authority) {
            return Err(ReferenceError::NotFound(reference.to_owned()));
        }

        let scheme = if self.allow_plaintext && is_loopback(&parsed.authority) {
            "http"
        } else {
            "https"
        };
        let url = format!(
            "{scheme}://{}/{}/info/refs?service=git-upload-pack",
            parsed.authority, parsed.repository
        );
        let response = self
            .agent
            .get(&url)
            .set("Accept", UPLOAD_PACK_ACCEPT)
            .call()
            .map_err(|error| map_error(error, reference))?;

        let mut body = Vec::new();
        response
            .into_reader()
            .take((MAX_ADVERTISEMENT_BYTES + 1) as u64)
            .read_to_end(&mut body)
            .map_err(|error| map_io_error(error, reference))?;
        if body.len() > MAX_ADVERTISEMENT_BYTES {
            return Err(ReferenceError::Upstream(format!(
                "git advertisement exceeds {MAX_ADVERTISEMENT_BYTES} bytes"
            )));
        }

        let refs = parse_advertisement(&body)?;
        let commit = resolve_rev(&refs, &parsed.rev)
            .map_err(|_| ReferenceError::NotFound(reference.to_owned()))?;
        let handle = format!(
            "{SCHEME}://{}/{}@{commit}",
            parsed.authority, parsed.repository
        );

        Ok(Resolution {
            contract_id: String::new(),
            version: String::new(),
            media_type: String::new(),
            digest: None,
            expires_at: None,
            handle: Some(handle),
        })
    }
}

fn is_loopback(authority: &str) -> bool {
    let (host, _) = split_authority(authority);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

fn map_error(error: ureq::Error, reference: &str) -> ReferenceError {
    match error {
        ureq::Error::Status(408 | 504, _) => ReferenceError::Timeout(reference.to_owned()),
        ureq::Error::Status(404 | 410, _) => ReferenceError::NotFound(reference.to_owned()),
        ureq::Error::Status(401 | 403, _) => ReferenceError::Unauthorized(reference.to_owned()),
        ureq::Error::Status(_, _) => {
            ReferenceError::Upstream(format!("git upstream refused {reference}"))
        }
        ureq::Error::Transport(_) => {
            ReferenceError::Upstream(format!("git upstream unavailable for {reference}"))
        }
    }
}

fn map_io_error(error: std::io::Error, reference: &str) -> ReferenceError {
    if error.kind() == std::io::ErrorKind::TimedOut {
        ReferenceError::Timeout(reference.to_owned())
    } else {
        ReferenceError::Upstream(format!("git upstream unavailable for {reference}"))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    use super::{parse_advertisement, parse_reference, Adapter, GitReference, SshAdapter};
    use pact_ref_core::{ReferenceError, ReferenceForm, ResolveIntent, ResolveRequest, Resolver};

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const PACKED_COMMIT: &str = "89abcdef0123456789abcdef0123456789abcdef";

    fn request(reference: &str) -> ResolveRequest {
        ResolveRequest {
            domain: "demo".to_owned(),
            type_name: "source".to_owned(),
            reference: ReferenceForm::classify(Some(reference)).expect("reference"),
            actor: "tester".to_owned(),
            intent: ResolveIntent::Read,
            expected_digest: None,
            pact_token_id: None,
        }
    }

    fn raw_request(reference: &str) -> ResolveRequest {
        ResolveRequest {
            reference: ReferenceForm::Uri(reference.to_owned()),
            ..request("git+https://host/org/repo")
        }
    }

    fn pkt(payload: &str) -> String {
        format!("{:04x}{payload}", payload.len() + 4)
    }

    fn advertisement(refs: &[(&str, &str, bool)]) -> Vec<u8> {
        let mut body = pkt("# service=git-upload-pack\n");
        body.push_str("0000");
        for (name, oid, caps) in refs {
            let line = if *caps {
                format!("{oid} {name}\0side-band-64k symref=HEAD:refs/heads/main\n")
            } else {
                format!("{oid} {name}\n")
            };
            body.push_str(&pkt(&line));
        }
        body.push_str("0000");
        body.into_bytes()
    }

    fn fake_git(body: Vec<u8>) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let authority = format!("127.0.0.1:{}", listener.local_addr().expect("addr").port());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("timeout");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut request = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                request.push_str(&line);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                super::UPLOAD_PACK_ACCEPT,
                body.len()
            );
            stream.write_all(response.as_bytes()).expect("write");
            stream.write_all(&body).expect("write body");
            request
        });
        (authority, handle)
    }

    fn fake_status(status: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let authority = format!("127.0.0.1:{}", listener.local_addr().expect("addr").port());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut request = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                request.push_str(&line);
            }
            let response =
                format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            stream.write_all(response.as_bytes()).expect("write");
            request
        });
        (authority, handle)
    }

    #[test]
    fn parses_repository_and_revision() {
        assert_eq!(
            parse_reference("git+https://git.example.com/org/repo@v1.2.3").expect("parse"),
            GitReference {
                authority: "git.example.com".to_owned(),
                repository: "org/repo".to_owned(),
                rev: "v1.2.3".to_owned(),
            }
        );
        assert_eq!(
            parse_reference("git+https://git.example.com:8443/org/repo")
                .expect("parse")
                .rev,
            "HEAD"
        );
        assert_eq!(
            parse_reference(&format!("git+https://git.example.com/org/repo@{COMMIT}"))
                .expect("parse")
                .rev,
            COMMIT
        );
    }

    #[test]
    fn rejects_invalid_references() {
        for reference in [
            "git+https://user:pass@git.example.com/org/repo",
            "git+https://git.example.com/org/../repo",
            "git+https://git.example.com/org/repo@bad rev",
            "git+https://git.example.com/org/repo@v1..2",
            "git+https://git.example.com/org/repo@refs/heads/v1@{0}",
            "git+https://git.example.com/org/repo?x=1",
            "git+ssh://git@git.example.com/org/repo",
            "https://git.example.com/org/repo",
        ] {
            assert!(
                parse_reference(reference).is_err(),
                "must reject {reference}"
            );
        }
    }

    #[test]
    fn parses_smart_http_advertisement() {
        let body = advertisement(&[
            ("HEAD", COMMIT, true),
            ("refs/heads/main", COMMIT, false),
            ("refs/tags/v1.0", PACKED_COMMIT, false),
            ("refs/tags/v1.0^{}", COMMIT, false),
        ]);
        let refs = parse_advertisement(&body).expect("parse");
        assert_eq!(refs[0], ("HEAD".to_owned(), COMMIT.to_owned()));
        assert_eq!(
            refs.iter()
                .find(|(name, _)| name == "refs/tags/v1.0")
                .map(|(_, oid)| oid.as_str()),
            Some(PACKED_COMMIT)
        );

        // 缺少 service 头、声明了错误服务、pkt-line 被截断都必须显式失败。
        assert!(parse_advertisement(b"").is_err());
        assert!(parse_advertisement(b"001e# service=git-receive-pack\n0000").is_err());
        assert!(parse_advertisement(b"001e# service=git-upload-pack\n0000").is_ok());
        assert!(parse_advertisement(b"0020# service=git-upload-pack\n0000").is_err());
    }

    #[test]
    fn resolves_head_branch_tag_and_commit() {
        let body = advertisement(&[
            ("HEAD", COMMIT, true),
            ("refs/heads/main", COMMIT, false),
            ("refs/tags/v1.0", PACKED_COMMIT, false),
            ("refs/tags/v1.0^{}", COMMIT, false),
        ]);

        let (authority, handle) = fake_git(body.clone());
        let adapter = Adapter::new(vec![authority.clone()], 2_000, true);
        let resolution = adapter
            .resolve(&request(&format!("git+https://{authority}/org/repo")))
            .expect("resolve");
        assert_eq!(
            resolution.handle.as_deref(),
            Some(format!("git+https://{authority}/org/repo@{COMMIT}").as_str())
        );
        assert!(resolution.digest.is_none());
        assert!(resolution.media_type.is_empty());
        let seen = handle.join().expect("server");
        assert!(
            seen.starts_with("GET /org/repo/info/refs?service=git-upload-pack "),
            "{seen}"
        );
        assert!(seen.to_ascii_lowercase().contains("accept:"));

        let (authority, handle) = fake_git(body.clone());
        let adapter = Adapter::new(vec![authority.clone()], 2_000, true);
        let resolution = adapter
            .resolve(&request(&format!("git+https://{authority}/org/repo@main")))
            .expect("resolve branch");
        assert!(resolution
            .handle
            .as_deref()
            .unwrap()
            .ends_with(&format!("@{COMMIT}")));
        handle.join().expect("server");

        let (authority, handle) = fake_git(body.clone());
        let adapter = Adapter::new(vec![authority.clone()], 2_000, true);
        let resolution = adapter
            .resolve(&request(&format!("git+https://{authority}/org/repo@v1.0")))
            .expect("resolve tag");
        assert!(resolution
            .handle
            .as_deref()
            .unwrap()
            .ends_with(&format!("@{COMMIT}")));
        handle.join().expect("server");

        let (authority, handle) = fake_git(body);
        let adapter = Adapter::new(vec![authority.clone()], 2_000, true);
        let resolution = adapter
            .resolve(&request(&format!(
                "git+https://{authority}/org/repo@{PACKED_COMMIT}"
            )))
            .expect("resolve commit");
        assert!(resolution
            .handle
            .as_deref()
            .unwrap()
            .ends_with(&format!("@{PACKED_COMMIT}")));
        handle.join().expect("server");
    }

    #[test]
    fn rejects_unknown_revision_and_unlisted_host() {
        let body = advertisement(&[("HEAD", COMMIT, true)]);
        let (authority, handle) = fake_git(body);
        let adapter = Adapter::new(vec![authority.clone()], 2_000, true);
        let error = adapter
            .resolve(&request(&format!(
                "git+https://{authority}/org/repo@missing"
            )))
            .expect_err("missing rev");
        assert!(matches!(error, ReferenceError::NotFound(_)));
        handle.join().expect("server");

        let adapter = Adapter::new(vec!["git.example.com".to_owned()], 1_000, false);
        let error = adapter
            .resolve(&request("git+https://evil.example.com/org/repo"))
            .expect_err("host");
        assert!(matches!(error, ReferenceError::NotFound(_)));
        assert!(matches!(
            adapter.resolve(&raw_request(
                "git+https://user:pass@git.example.com/org/repo"
            )),
            Err(ReferenceError::InvalidRequest(_))
        ));
    }

    #[test]
    fn maps_upstream_statuses() {
        for (status, not_found) in [("404 Not Found", true), ("403 Forbidden", false)] {
            let (authority, handle) = fake_status(status);
            let adapter = Adapter::new(vec![authority.clone()], 2_000, true);
            let error = adapter
                .resolve(&request(&format!("git+https://{authority}/org/repo")))
                .expect_err("status");
            if not_found {
                assert!(matches!(error, ReferenceError::NotFound(_)), "{error:?}");
            } else {
                assert!(
                    matches!(error, ReferenceError::Unauthorized(_)),
                    "{error:?}"
                );
            }
            handle.join().expect("server");
        }
    }

    #[test]
    fn rejects_malformed_advertisement() {
        // 包头声明 0x0020 字节，但实际不足。
        assert!(parse_advertisement(b"0020# service=git-upload-pack\n").is_err());
        // pkt-line 长度为 3 非法。
        assert!(parse_advertisement(b"001e# service=git-upload-pack\n0003").is_err());
    }

    #[test]
    fn ssh_adapter_is_explicitly_unsupported() {
        let adapter = SshAdapter::new();
        assert_eq!(adapter.scheme(), "git+ssh");
        assert!(matches!(
            adapter.resolve(&raw_request("git+ssh://git@git.example.com/org/repo")),
            Err(ReferenceError::UnsupportedIdentifier(_))
        ));
    }
}
