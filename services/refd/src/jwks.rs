//! JWKS 字节来源：本地文件（测试/离线）与 HTTPS（生产）。
//!
//! 网络来源只允许 `https://`，不跟随重定向，超时与响应体上限均来自配置。

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use pact_ref_auth::oidc::JwksSource;

use crate::config::MAX_JWKS_BYTES;

/// 本地 JWKS 文件。
pub struct FileJwksSource {
    path: PathBuf,
}

impl FileJwksSource {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl JwksSource for FileJwksSource {
    fn fetch(&self) -> Result<Vec<u8>, String> {
        let metadata = std::fs::metadata(&self.path)
            .map_err(|error| format!("read {}: {error}", self.path.display()))?;
        if !metadata.is_file() {
            return Err(format!("{} is not a regular file", self.path.display()));
        }
        if metadata.len() > MAX_JWKS_BYTES as u64 {
            return Err(format!(
                "{} exceeds {MAX_JWKS_BYTES} bytes",
                self.path.display()
            ));
        }
        std::fs::read(&self.path).map_err(|error| format!("read {}: {error}", self.path.display()))
    }
}

/// HTTPS JWKS 来源。
pub struct HttpJwksSource {
    uri: String,
    timeout_ms: u64,
}

impl HttpJwksSource {
    pub fn new(uri: String, timeout_ms: u64) -> Self {
        Self { uri, timeout_ms }
    }
}

impl JwksSource for HttpJwksSource {
    fn fetch(&self) -> Result<Vec<u8>, String> {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_millis(self.timeout_ms))
            .redirects(0)
            .build();
        let response = agent
            .get(&self.uri)
            .set("accept", "application/json")
            .call()
            .map_err(|error| format!("fetch {}: {error}", self.uri))?;
        let status = response.status();
        if !(200..300).contains(&status) {
            return Err(format!("fetch {}: HTTP {status}", self.uri));
        }
        let mut body = Vec::new();
        response
            .into_reader()
            .take(MAX_JWKS_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|error| format!("read {}: {error}", self.uri))?;
        if body.len() > MAX_JWKS_BYTES {
            return Err(format!("{} exceeds {MAX_JWKS_BYTES} bytes", self.uri));
        }
        Ok(body)
    }
}
