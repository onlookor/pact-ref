//! `oci://` scheme adapter。
//!
//! 只解析 `oci://<registry>/<repository>[:tag][@sha256:<hex>]`：registry 必须在配置的
//! allowlist 内（默认拒绝），拒绝 userinfo/query/fragment 与控制字符，仓库名按 OCI 分发
//! 规范的小写文法校验。取回用 `HEAD /v2/<repo>/manifests/<tag|digest>`，不下载 manifest
//! 正文；摘要统一归一化为 `sha256:<64 位小写 hex>`，其余算法视为上游失败。
//!
//! v1 默认 HTTPS；仅当 registry 是回环主机且显式 `allow_plaintext` 时降级为 `http://`
//! （本地开发/测试）。

use std::time::Duration;

use pact_ref_core::{ReferenceError, Resolution, ResolveRequest, Resolver};

pub const SCHEME: &str = "oci";

/// manifest 探测的 `Accept`：覆盖 OCI image manifest/index、artifact manifest 与 Docker v2。
pub const MANIFEST_ACCEPT: &str = concat!(
    "application/vnd.oci.image.index.v1+json, ",
    "application/vnd.oci.image.manifest.v1+json, ",
    "application/vnd.oci.artifact.manifest.v1+json, ",
    "application/vnd.docker.distribution.manifest.list.v2+json, ",
    "application/vnd.docker.distribution.manifest.v2+json"
);

/// 单次 manifest 探测允许读取的响应字节上限（只读头部，防御性上限）。
pub const MAX_MANIFEST_RESPONSE_BYTES: usize = 1024 * 1024;

pub struct Adapter {
    registries: Vec<String>,
    allow_plaintext: bool,
    agent: ureq::Agent,
}

impl Adapter {
    /// `registries` 为 `host` 或 `host:port`；匹配大小写不敏感、端口须一致。
    pub fn new(registries: Vec<String>, timeout_ms: u64, allow_plaintext: bool) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_millis(timeout_ms))
            .redirects(0)
            .build();
        Self {
            registries: registries
                .into_iter()
                .map(|registry| registry.to_ascii_lowercase())
                .collect(),
            allow_plaintext,
            agent,
        }
    }

    fn is_allowed(&self, registry: &str) -> bool {
        self.registries
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(registry))
    }
}

impl Default for Adapter {
    fn default() -> Self {
        Self::new(Vec::new(), 10_000, false)
    }
}

/// 解析后的 OCI 引用。`digest` 与 `tag` 至多一个由调用方优先选择，缺省 tag 为 `latest`。
#[derive(Debug, Clone, PartialEq, Eq)]
struct OciReference {
    registry: String,
    repository: String,
    tag: Option<String>,
    digest: Option<String>,
}

impl OciReference {
    /// `HEAD` 请求使用的 manifest 引用：钉版摘要优先，其次是 tag，最后是 `latest`。
    fn manifest_reference(&self) -> String {
        if let Some(digest) = &self.digest {
            return digest.clone();
        }
        self.tag.clone().unwrap_or_else(|| "latest".to_owned())
    }
}

fn parse_reference(reference: &str) -> Result<OciReference, ReferenceError> {
    let rest = reference
        .strip_prefix("oci://")
        .ok_or_else(|| ReferenceError::InvalidRequest("not an oci:// URI".to_owned()))?;
    if rest.is_empty()
        || rest
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\u{7f}')
    {
        return Err(ReferenceError::InvalidRequest(
            "oci URI contains control characters".to_owned(),
        ));
    }
    if rest.contains(['?', '#']) {
        return Err(ReferenceError::InvalidRequest(
            "oci URI must not contain a query or fragment".to_owned(),
        ));
    }

    let (authority, path) = rest.split_once('/').ok_or_else(|| {
        ReferenceError::InvalidRequest("oci URI is missing a repository path".to_owned())
    })?;
    if authority.is_empty() || authority.contains('@') {
        return Err(ReferenceError::InvalidRequest(
            "oci URI must not carry userinfo".to_owned(),
        ));
    }
    if !is_valid_authority(authority) {
        return Err(ReferenceError::InvalidRequest(
            "oci URI registry is not a valid host[:port]".to_owned(),
        ));
    }
    if path.is_empty() {
        return Err(ReferenceError::InvalidRequest(
            "oci URI is missing a repository path".to_owned(),
        ));
    }

    let (name_and_tag, digest) = match path.rsplit_once('@') {
        Some((name, digest)) => (name, Some(validate_digest(digest)?)),
        None => (path, None),
    };
    let last_slash = name_and_tag.rfind('/');
    let tag_split = name_and_tag
        .rfind(':')
        .filter(|index| last_slash.is_none_or(|slash| *index > slash));
    let (repository, tag) = match tag_split {
        Some(index) => (&name_and_tag[..index], Some(&name_and_tag[index + 1..])),
        None => (name_and_tag, None),
    };
    if !is_valid_repository(repository) {
        return Err(ReferenceError::InvalidRequest(
            "oci repository name is not valid".to_owned(),
        ));
    }
    if let Some(tag) = tag {
        validate_tag(tag)?;
    }

    Ok(OciReference {
        registry: authority.to_owned(),
        repository: repository.to_owned(),
        tag: tag.map(str::to_owned),
        digest,
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

/// 仓库名：小写字母/数字，分段由 `.`、`_`、`-` 连接；不得有空段或 `..`。
fn is_valid_repository(repository: &str) -> bool {
    if repository.is_empty() || repository.len() > 255 {
        return false;
    }
    repository.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
            && segment
                .bytes()
                .next()
                .map(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                .unwrap_or(false)
            && segment
                .bytes()
                .last()
                .map(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                .unwrap_or(false)
    })
}

/// tag 文法：`[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`。
fn validate_tag(tag: &str) -> Result<(), ReferenceError> {
    let bytes = tag.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(ReferenceError::InvalidRequest(
            "oci tag is not valid".to_owned(),
        ))
    }
}

/// 钉版摘要只接受 `sha256:<64 位小写 hex>`（`uri-profile.md` §4）。
fn validate_digest(digest: &str) -> Result<String, ReferenceError> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(ReferenceError::InvalidRequest(
            "oci digest must use sha256:<64 lowercase hex>".to_owned(),
        ));
    };
    if hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(format!("sha256:{hex}"))
    } else {
        Err(ReferenceError::InvalidRequest(
            "oci digest must use sha256:<64 lowercase hex>".to_owned(),
        ))
    }
}

/// 归一化上游 `Docker-Content-Digest`；只接受 sha256，其余算法视为不可用。
fn normalize_digest(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let (algorithm, hex) = trimmed.split_once(':')?;
    if !algorithm.eq_ignore_ascii_case("sha256") || hex.len() != 64 {
        return None;
    }
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("sha256:{}", hex.to_ascii_lowercase()))
}

fn is_loopback(authority: &str) -> bool {
    let (host, _) = split_authority(authority);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
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
        if !self.is_allowed(&parsed.registry) {
            return Err(ReferenceError::NotFound(reference.to_owned()));
        }

        let scheme = if self.allow_plaintext && is_loopback(&parsed.registry) {
            "http"
        } else {
            "https"
        };
        let url = format!(
            "{scheme}://{}/v2/{}/manifests/{}",
            parsed.registry,
            parsed.repository,
            parsed.manifest_reference()
        );
        let response = self
            .agent
            .head(&url)
            .set("Accept", MANIFEST_ACCEPT)
            .call()
            .map_err(|error| map_error(error, reference))?;
        if response
            .header("Content-Length")
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > MAX_MANIFEST_RESPONSE_BYTES)
        {
            return Err(ReferenceError::Upstream(format!(
                "oci manifest response exceeds {MAX_MANIFEST_RESPONSE_BYTES} bytes"
            )));
        }

        let header_digest = response
            .header("Docker-Content-Digest")
            .and_then(normalize_digest);
        let digest = match (&parsed.digest, header_digest) {
            (Some(expected), Some(actual)) if expected != &actual => {
                return Err(ReferenceError::DigestMismatch {
                    expected: expected.clone(),
                    actual,
                })
            }
            (Some(expected), _) => expected.clone(),
            (None, Some(actual)) => actual,
            (None, None) => {
                return Err(ReferenceError::Upstream(format!(
                    "oci registry returned no digest for {reference}"
                )))
            }
        };

        let media_type = response
            .header("Content-Type")
            .map(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned()
            })
            .unwrap_or_default();
        let handle = format!("oci://{}/{}@{}", parsed.registry, parsed.repository, digest);

        Ok(Resolution {
            contract_id: String::new(),
            version: String::new(),
            media_type,
            digest: Some(digest),
            expires_at: None,
            handle: Some(handle),
        })
    }
}

fn map_error(error: ureq::Error, reference: &str) -> ReferenceError {
    match error {
        ureq::Error::Status(408 | 504, _) => ReferenceError::Timeout(reference.to_owned()),
        ureq::Error::Status(404 | 410, _) => ReferenceError::NotFound(reference.to_owned()),
        ureq::Error::Status(401 | 403, _) => ReferenceError::Unauthorized(reference.to_owned()),
        ureq::Error::Status(_, _) => {
            ReferenceError::Upstream(format!("oci upstream refused {reference}"))
        }
        ureq::Error::Transport(_) => {
            ReferenceError::Upstream(format!("oci upstream unavailable for {reference}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    use super::{normalize_digest, parse_reference, Adapter, OciReference};
    use pact_ref_core::{ReferenceError, ReferenceForm, ResolveIntent, ResolveRequest, Resolver};

    const DIGEST: &str = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    fn request(reference: &str) -> ResolveRequest {
        ResolveRequest {
            domain: "demo".to_owned(),
            type_name: "image".to_owned(),
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
            ..request("oci://registry.example.com/team/image:1")
        }
    }

    /// 启动只服务一次请求的假 registry，返回 authority 与收到的请求行/头。
    fn fake_registry(
        status: &'static str,
        headers: Vec<(&'static str, String)>,
    ) -> (String, std::thread::JoinHandle<String>) {
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
            let mut response =
                format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n");
            for (name, value) in headers {
                response.push_str(&format!("{name}: {value}\r\n"));
            }
            response.push_str("\r\n");
            stream.write_all(response.as_bytes()).expect("write");
            request
        });
        (authority, handle)
    }

    #[test]
    fn parses_repository_tag_and_digest() {
        assert_eq!(
            parse_reference("oci://registry.example.com/team/image:1.0").expect("parse"),
            OciReference {
                registry: "registry.example.com".to_owned(),
                repository: "team/image".to_owned(),
                tag: Some("1.0".to_owned()),
                digest: None,
            }
        );
        assert_eq!(
            parse_reference(&format!("oci://registry.example.com/team/image@{DIGEST}"))
                .expect("parse")
                .digest
                .as_deref(),
            Some(DIGEST)
        );
        assert_eq!(
            parse_reference(&format!(
                "oci://registry.example.com:5000/team/image:v1@{DIGEST}"
            ))
            .expect("parse")
            .manifest_reference(),
            DIGEST
        );
        assert_eq!(
            parse_reference("oci://registry.example.com/team/image")
                .expect("parse")
                .manifest_reference(),
            "latest"
        );
    }

    #[test]
    fn rejects_invalid_references() {
        for reference in [
            "oci://user:pass@registry.example.com/team/image:1",
            "oci://registry.example.com/Team/Image:1",
            "oci://registry.example.com/team/../image:1",
            "oci://registry.example.com/team/image:bad tag",
            "oci://registry.example.com/team/image@sha256:ABCDEF",
            "oci://registry.example.com/team/image?x=1",
        ] {
            assert!(
                parse_reference(reference).is_err(),
                "must reject {reference}"
            );
        }
        assert!(normalize_digest("sha256:ABC").is_none());
        assert!(normalize_digest("md5:abc").is_none());
        assert_eq!(
            normalize_digest(&format!("sha256:{}", "A".repeat(64))),
            Some(format!("sha256:{}", "a".repeat(64)))
        );
    }

    #[test]
    fn rejects_registry_outside_allowlist_without_network() {
        let adapter = Adapter::new(vec!["registry.example.com".to_owned()], 1000, false);
        assert!(matches!(
            adapter.resolve(&request("oci://evil.example.com/team/image:1")),
            Err(ReferenceError::NotFound(_))
        ));
        assert!(matches!(
            adapter.resolve(&raw_request(
                "oci://user:pass@registry.example.com/team/image:1"
            )),
            Err(ReferenceError::InvalidRequest(_))
        ));
        assert!(matches!(
            adapter.resolve(&request("https://registry.example.com/team/image:1")),
            Err(ReferenceError::InvalidRequest(_))
        ));
        assert!(Adapter::new(Vec::new(), 1000, false)
            .resolve(&request("oci://registry.example.com/team/image:1"))
            .is_err());
    }

    #[test]
    fn resolves_manifest_against_fake_registry_and_pins_handle() {
        let (authority, handle) = fake_registry(
            "200 OK",
            vec![
                ("Docker-Content-Digest", DIGEST.to_owned()),
                (
                    "Content-Type",
                    "application/vnd.oci.image.manifest.v1+json".to_owned(),
                ),
            ],
        );
        let adapter = Adapter::new(vec![authority.clone()], 2_000, true);
        let resolution = adapter
            .resolve(&request(&format!("oci://{authority}/team/image:1.0")))
            .expect("resolve");
        assert_eq!(resolution.digest.as_deref(), Some(DIGEST));
        assert_eq!(
            resolution.media_type,
            "application/vnd.oci.image.manifest.v1+json"
        );
        assert_eq!(
            resolution.handle.as_deref(),
            Some(format!("oci://{authority}/team/image@{DIGEST}").as_str())
        );
        let seen = handle.join().expect("server");
        assert!(
            seen.starts_with("HEAD /v2/team/image/manifests/1.0 "),
            "{seen}"
        );
        assert!(seen.to_ascii_lowercase().contains("accept:"));
    }

    #[test]
    fn rejects_pinned_digest_mismatch_and_missing_digest() {
        let (authority, handle) = fake_registry(
            "200 OK",
            vec![(
                "Docker-Content-Digest",
                format!("sha256:{}", "b".repeat(64)),
            )],
        );
        let adapter = Adapter::new(vec![authority.clone()], 2_000, true);
        let error = adapter
            .resolve(&request(&format!("oci://{authority}/team/image@{DIGEST}")))
            .expect_err("mismatch");
        assert!(matches!(error, ReferenceError::DigestMismatch { .. }));
        handle.join().expect("server");

        let (authority, handle) = fake_registry("200 OK", Vec::new());
        let adapter = Adapter::new(vec![authority.clone()], 2_000, true);
        let error = adapter
            .resolve(&request(&format!("oci://{authority}/team/image:1")))
            .expect_err("no digest");
        assert!(matches!(error, ReferenceError::Upstream(_)));
        handle.join().expect("server");
    }

    #[test]
    fn maps_upstream_statuses() {
        for (status, matches_not_found) in [("404 Not Found", true), ("401 Unauthorized", false)] {
            let (authority, handle) = fake_registry(status, Vec::new());
            let adapter = Adapter::new(vec![authority.clone()], 2_000, true);
            let error = adapter
                .resolve(&request(&format!("oci://{authority}/team/image:1")))
                .expect_err("status");
            if matches_not_found {
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
    fn falls_back_to_pinned_digest_without_header() {
        let (authority, handle) = fake_registry("200 OK", Vec::new());
        let adapter = Adapter::new(vec![authority.clone()], 2_000, true);
        let resolution = adapter
            .resolve(&request(&format!("oci://{authority}/team/image@{DIGEST}")))
            .expect("resolve");
        assert_eq!(resolution.digest.as_deref(), Some(DIGEST));
        handle.join().expect("server");
    }
}
