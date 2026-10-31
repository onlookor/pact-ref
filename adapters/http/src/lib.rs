//! `https://` scheme adapter。
//!
//! v1 用 `HEAD` 做存在性与摘要校验，不下载正文。只允许配置中的主机（默认拒绝），
//! 拒绝 userinfo 与重定向，降低 SSRF 风险。摘要优先取 `Digest: sha-256=<base64>`，
//! 其次 `X-Checksum-Sha256`；都没有时省略 `digest`。

use std::time::Duration;

use pact_ref_core::{ReferenceError, Resolution, ResolveRequest, Resolver};

pub const SCHEME: &str = "https";

pub struct Adapter {
    allowed_hosts: Vec<String>,
    agent: ureq::Agent,
}

impl Adapter {
    pub fn new(allowed_hosts: Vec<String>, timeout_ms: u64) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_millis(timeout_ms))
            .redirects(0)
            .build();
        Self {
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
            agent,
        }
    }

    fn host(reference: &str) -> Result<&str, ReferenceError> {
        let rest = reference
            .strip_prefix("https://")
            .ok_or_else(|| ReferenceError::InvalidRequest("not an https URI".to_owned()))?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return Err(ReferenceError::InvalidRequest(
                "https URI must not carry userinfo".to_owned(),
            ));
        }
        let host = match authority.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
            _ => authority,
        };
        if host.is_empty() {
            return Err(ReferenceError::InvalidRequest(
                "https URI has no host".to_owned(),
            ));
        }
        Ok(host)
    }
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
        let host = Self::host(reference)?;
        if !self
            .allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            return Err(ReferenceError::NotFound(reference.to_owned()));
        }

        let response = self
            .agent
            .head(reference)
            .call()
            .map_err(|error| match error {
                ureq::Error::Status(404 | 410, _) => ReferenceError::NotFound(reference.to_owned()),
                ureq::Error::Status(401 | 403, _) => {
                    ReferenceError::Unauthorized(reference.to_owned())
                }
                ureq::Error::Status(_, _) => {
                    ReferenceError::Upstream(format!("https upstream refused {reference}"))
                }
                ureq::Error::Transport(_) => {
                    ReferenceError::Upstream(format!("https upstream unavailable for {reference}"))
                }
            })?;

        let digest = response
            .header("Digest")
            .and_then(parse_digest_header)
            .or_else(|| {
                response
                    .header("X-Checksum-Sha256")
                    .map(|value| format!("sha256:{}", value.to_ascii_lowercase()))
            });
        let media_type = response
            .header("Content-Type")
            .unwrap_or("application/octet-stream")
            .to_owned();

        Ok(Resolution {
            contract_id: String::new(),
            version: String::new(),
            media_type,
            digest,
            expires_at: None,
            handle: Some(reference.to_owned()),
        })
    }
}

/// 解析 `Digest: sha-256=<base64>`（大小写不敏感，可含多个算法）。
///
/// 兼容直接给 64 位十六进制的上游；两者都归一化为 `sha256:<hex>`。
fn parse_digest_header(value: &str) -> Option<String> {
    for part in value.split(',') {
        let (algorithm, encoded) = part.trim().split_once('=')?;
        if algorithm.eq_ignore_ascii_case("sha-256") {
            let encoded = encoded.trim();
            if encoded.len() == 64 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Some(format!("sha256:{}", encoded.to_ascii_lowercase()));
            }
            let bytes = base64_decode(encoded)?;
            if bytes.len() == 32 {
                return Some(format!("sha256:{}", hex_encode(&bytes)));
            }
        }
    }
    None
}

fn base64_decode(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        accumulator = accumulator.checked_shl(6)? | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    Some(output)
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
    use super::{base64_decode, parse_digest_header, Adapter};
    use pact_ref_core::{ReferenceError, ReferenceForm, ResolveIntent, ResolveRequest, Resolver};

    fn request(reference: &str) -> ResolveRequest {
        ResolveRequest {
            domain: "demo".to_owned(),
            type_name: "artifact".to_owned(),
            reference: ReferenceForm::classify(Some(reference)).expect("reference"),
            actor: "tester".to_owned(),
            intent: ResolveIntent::Read,
            expected_digest: None,
            pact_token_id: None,
        }
    }

    /// 绕过 `classify` 的校验，直接构造 URI 形态，验证 adapter 自身的防御。
    fn raw_request(reference: &str) -> ResolveRequest {
        ResolveRequest {
            reference: ReferenceForm::Uri(reference.to_owned()),
            ..request("https://artifacts.example.com/a")
        }
    }

    #[test]
    fn rejects_hosts_outside_allowlist_without_network() {
        let adapter = Adapter::new(vec!["artifacts.example.com".to_owned()], 1000);
        assert!(matches!(
            adapter.resolve(&request("https://evil.example.com/a")),
            Err(ReferenceError::NotFound(_))
        ));
        assert!(matches!(
            adapter.resolve(&raw_request("https://user:pass@artifacts.example.com/a")),
            Err(ReferenceError::InvalidRequest(_))
        ));
        assert!(matches!(
            adapter.resolve(&request("file:///tmp/a")),
            Err(ReferenceError::InvalidRequest(_))
        ));
        assert!(Adapter::new(Vec::new(), 1000)
            .resolve(&request("https://artifacts.example.com/a"))
            .is_err());
    }

    #[test]
    fn parses_digest_headers() {
        let digest = parse_digest_header(
            "sha-256=2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        .expect("hex digest");
        assert!(digest.starts_with("sha256:"));
        let base64 = "sha-256=LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
        assert_eq!(
            parse_digest_header(base64).as_deref(),
            Some("sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
        assert_eq!(parse_digest_header("md5=abc"), None);
    }

    #[test]
    fn decodes_base64() {
        assert_eq!(base64_decode("aGVsbG8="), Some(b"hello".to_vec()));
        assert_eq!(base64_decode("aGVsbG8"), Some(b"hello".to_vec()));
        assert_eq!(base64_decode("!!!"), None);
    }
}
