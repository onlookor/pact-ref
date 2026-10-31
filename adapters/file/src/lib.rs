//! `file://` scheme adapter。
//!
//! 只允许 `file:///abs/path` 或 `file://localhost/abs/path`；路径必须落在配置的根目录内，
//! 解析前做百分号解码与 `canonicalize`，防止路径穿越。凭据不入 URL。

use std::io::Read;
use std::path::{Path, PathBuf};

use pact_ref_core::{ReferenceError, Resolution, ResolveRequest, Resolver};
use sha2::{Digest, Sha256};

pub const SCHEME: &str = "file";

pub struct Adapter {
    root: PathBuf,
}

impl Adapter {
    /// `root` 必须已存在；解析时所有目标都必须 canonicalize 到该目录之下。
    pub fn new(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        let root = std::fs::canonicalize(&root)?;
        if !root.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "file adapter root must be a directory",
            ));
        }
        Ok(Self { root })
    }

    fn resolve_path(&self, reference: &str) -> Result<PathBuf, ReferenceError> {
        let rest = reference
            .strip_prefix("file://")
            .ok_or_else(|| ReferenceError::InvalidRequest("not a file URI".to_owned()))?;
        let (host, raw_path) = if rest.starts_with('/') {
            ("", rest)
        } else {
            let (host, _path) = rest
                .split_once('/')
                .ok_or_else(|| ReferenceError::InvalidRequest("file URI has no path".to_owned()))?;
            (host, &rest[host.len()..])
        };
        if !host.is_empty() && host != "localhost" {
            return Err(ReferenceError::InvalidRequest(
                "file URI host must be empty or localhost".to_owned(),
            ));
        }
        if raw_path.is_empty() || !raw_path.starts_with('/') {
            return Err(ReferenceError::InvalidRequest(
                "file URI path must be absolute".to_owned(),
            ));
        }
        let decoded = percent_decode(raw_path)?;
        let target = Path::new(&decoded);
        if target
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(ReferenceError::InvalidRequest(
                "file URI must not contain ..".to_owned(),
            ));
        }
        let canonical = std::fs::canonicalize(target)
            .map_err(|_| ReferenceError::NotFound(reference.to_owned()))?;
        if !canonical.starts_with(&self.root) {
            return Err(ReferenceError::NotFound(reference.to_owned()));
        }
        if !canonical.is_file() {
            return Err(ReferenceError::NotFound(reference.to_owned()));
        }
        Ok(canonical)
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
        let path = self.resolve_path(reference)?;
        let mut file = std::fs::File::open(&path)
            .map_err(|_| ReferenceError::NotFound(reference.to_owned()))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| ReferenceError::Internal(format!("read file: {error}")))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let digest = format!("sha256:{:x}", hasher.finalize());
        Ok(Resolution {
            contract_id: String::new(),
            version: String::new(),
            media_type: media_type(&path).to_owned(),
            digest: Some(digest),
            expires_at: None,
            handle: Some(reference.to_owned()),
        })
    }
}

fn media_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
    {
        "json" => "application/json",
        "md" => "text/markdown; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "tar" => "application/x-tar",
        "zst" => "application/zstd",
        "gz" => "application/gzip",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

/// 只解码 `%XX`；非法转义直接拒绝，不做宽松解释。
fn percent_decode(value: &str) -> Result<String, ReferenceError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(ReferenceError::InvalidRequest(
                    "invalid percent escape in file URI".to_owned(),
                ));
            }
            let high = hex_value(bytes[index + 1])?;
            let low = hex_value(bytes[index + 2])?;
            decoded.push(high << 4 | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| ReferenceError::InvalidRequest("file URI path is not UTF-8".to_owned()))
}

fn hex_value(byte: u8) -> Result<u8, ReferenceError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ReferenceError::InvalidRequest(
            "invalid percent escape in file URI".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::Adapter;
    use pact_ref_core::{ReferenceError, ReferenceForm, ResolveIntent, ResolveRequest, Resolver};
    use std::io::Write;

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

    struct Fixture {
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "pact-ref-file-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_nanos())
                    .unwrap_or_default()
            ));
            std::fs::create_dir_all(root.join("nested")).expect("create root");
            let mut file = std::fs::File::create(root.join("nested/a.md")).expect("create");
            file.write_all(b"hello").expect("write");
            Self { root }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn resolves_file_inside_root_with_digest_and_media_type() {
        let fixture = Fixture::new();
        let adapter = Adapter::new(&fixture.root).expect("adapter");
        let reference = format!("file://{}/nested/a.md", fixture.root.display());
        let resolution = adapter.resolve(&request(&reference)).expect("resolve");
        assert_eq!(
            resolution.digest.as_deref(),
            Some("sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
        assert_eq!(resolution.media_type, "text/markdown; charset=utf-8");
        assert_eq!(resolution.handle.as_deref(), Some(reference.as_str()));
    }

    #[test]
    fn accepts_localhost_authority_and_percent_encoding() {
        let fixture = Fixture::new();
        let adapter = Adapter::new(&fixture.root).expect("adapter");
        let reference = format!("file://localhost{}/nested/a.md", fixture.root.display());
        assert!(adapter.resolve(&request(&reference)).is_ok());

        let encoded = format!("file://{}/nested/a%2Emd", fixture.root.display());
        assert!(adapter.resolve(&request(&encoded)).is_ok());
    }

    #[test]
    fn rejects_outside_root_traversal_and_non_file_schemes() {
        let fixture = Fixture::new();
        let adapter = Adapter::new(&fixture.root).expect("adapter");
        let outside = fixture.root.parent().expect("parent").join("outside.txt");
        let _ = std::fs::write(&outside, b"x");
        let reference = format!("file://{}", outside.display());
        assert!(matches!(
            adapter.resolve(&request(&reference)),
            Err(ReferenceError::NotFound(_))
        ));
        let _ = std::fs::remove_file(&outside);

        let traversal = format!("file://{}/../escape", fixture.root.display());
        assert!(matches!(
            adapter.resolve(&request(&traversal)),
            Err(ReferenceError::InvalidRequest(_))
        ));

        assert!(matches!(
            adapter.resolve(&request("https://example.com/a")),
            Err(ReferenceError::InvalidRequest(_))
        ));
    }

    #[test]
    fn rejects_invalid_percent_escape() {
        let fixture = Fixture::new();
        let adapter = Adapter::new(&fixture.root).expect("adapter");
        let reference = format!("file://{}/nested/a%ZZ.md", fixture.root.display());
        assert!(matches!(
            adapter.resolve(&request(&reference)),
            Err(ReferenceError::InvalidRequest(_))
        ));
    }
}
