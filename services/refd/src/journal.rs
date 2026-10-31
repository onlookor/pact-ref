//! `POST /v1/mutate` 的 append-only 幂等台账（D53）。
//!
//! 每次写 attempt 落两行：`intent` 与 `result`。写入用 `O_APPEND` + `fsync`，
//! 保证「台账先于上游」；重启时逐行解析，半行尾部（崩溃残留）截断并告警，
//! 非法完整行直接拒绝启动。台账只记录键作用域、请求摘要与结论，不记录 `input`
//! 或上游正文。

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `[mutate].max_entries` 上限。
pub const MAX_ENTRIES_LIMIT: usize = 1_000_000;

/// 台账键作用域：同一组值视为同一次逻辑写。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyScope {
    pub actor: String,
    pub domain: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub reference: String,
    pub operation: String,
    pub idempotency_key: String,
}

/// 台账中已落定的写结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationRecord {
    /// `succeeded` 或 `failed`。
    pub status: String,
    pub result_ref: Option<String>,
    pub result_digest: Option<String>,
}

impl MutationRecord {
    pub fn succeeded(&self) -> bool {
        self.status == "succeeded"
    }
}

/// 查询结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// 无记录，可执行。
    Execute,
    /// 同键异摘要。
    Conflict,
    /// 有 intent 无 result：上次调用窗口内崩溃，不猜测、不重试。
    InDoubt,
    /// 已有终态结论，重放。
    Replay(MutationRecord),
}

/// 台账不可用的两类错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// 无法打开/追加/fsync/加锁：fail-closed，绝不「无台账写上游」。
    Unavailable(String),
    /// 条目数达到 `max_entries`。
    Full,
    /// 同键摘要冲突（防御性；正常路径由 `lookup` 先行判定）。
    Conflict,
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => write!(f, "journal unavailable: {message}"),
            Self::Full => f.write_str("journal is full"),
            Self::Conflict => f.write_str("journal key conflict"),
        }
    }
}

impl std::error::Error for JournalError {}

/// 单行台账记录。两种 `kind` 共用一个结构，便于拒绝未知字段。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    kind: String,
    key_scope: KeyScope,
    request_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result_digest: Option<String>,
    ts: String,
}

struct Record {
    digest: String,
    result: Option<MutationRecord>,
}

struct Inner {
    file: File,
    entries: usize,
    records: HashMap<KeyScope, Record>,
}

impl Inner {
    fn append(&mut self, entry: &Entry) -> Result<(), JournalError> {
        let mut line = serde_json::to_string(entry)
            .map_err(|error| JournalError::Unavailable(format!("serialize entry: {error}")))?;
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .map_err(|error| JournalError::Unavailable(format!("append entry: {error}")))?;
        self.file
            .sync_data()
            .map_err(|error| JournalError::Unavailable(format!("fsync entry: {error}")))?;
        self.entries += 1;
        Ok(())
    }
}

/// 幂等台账。单写者：内部互斥保证同一进程内串行追加。
pub struct Journal {
    path: PathBuf,
    max_entries: usize,
    inner: Mutex<Inner>,
}

impl Journal {
    /// 打开并恢复台账。父目录必须已存在；文件缺失时创建。
    pub fn open(path: &Path, max_entries: usize) -> Result<Self, String> {
        if max_entries == 0 || max_entries > MAX_ENTRIES_LIMIT {
            return Err(format!(
                "mutate.max_entries must be in 1..={MAX_ENTRIES_LIMIT}"
            ));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let metadata = std::fs::metadata(parent)
                    .map_err(|error| format!("mutate journal dir {}: {error}", parent.display()))?;
                if !metadata.is_dir() {
                    return Err(format!(
                        "mutate journal dir is not a directory: {}",
                        parent.display()
                    ));
                }
            }
        }

        let (records, entries) = load(path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| format!("open mutate journal {}: {error}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            max_entries,
            inner: Mutex::new(Inner {
                file,
                entries,
                records,
            }),
        })
    }

    /// 查询键作用域。
    pub fn lookup(&self, key: &KeyScope, digest: &str) -> Result<Lookup, JournalError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| JournalError::Unavailable("journal mutex poisoned".to_owned()))?;
        Ok(match inner.records.get(key) {
            None => Lookup::Execute,
            Some(record) if record.digest != digest => Lookup::Conflict,
            Some(record) => match &record.result {
                None => Lookup::InDoubt,
                Some(result) => Lookup::Replay(result.clone()),
            },
        })
    }

    /// 落 `intent` 并 fsync。必须在调用上游之前完成。
    pub fn begin(&self, key: &KeyScope, digest: &str, ts: &str) -> Result<(), JournalError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| JournalError::Unavailable("journal mutex poisoned".to_owned()))?;
        if let Some(record) = inner.records.get(key) {
            if record.digest != digest || record.result.is_some() {
                return Err(JournalError::Conflict);
            }
            // 同一 intent 重复落盘（异常路径）：视为已记录，避免重复行。
            return Ok(());
        }
        if inner.entries >= self.max_entries {
            return Err(JournalError::Full);
        }
        inner.append(&Entry {
            kind: "intent".to_owned(),
            key_scope: key.clone(),
            request_digest: digest.to_owned(),
            status: None,
            result_ref: None,
            result_digest: None,
            ts: ts.to_owned(),
        })?;
        inner.records.insert(
            key.clone(),
            Record {
                digest: digest.to_owned(),
                result: None,
            },
        );
        Ok(())
    }

    /// 落 `result` 并 fsync。`status` 只能是 `succeeded` 或 `failed`。
    pub fn finish(
        &self,
        key: &KeyScope,
        digest: &str,
        status: &str,
        result_ref: Option<&str>,
        result_digest: Option<&str>,
        ts: &str,
    ) -> Result<(), JournalError> {
        if status != "succeeded" && status != "failed" {
            return Err(JournalError::Unavailable(format!(
                "unknown mutation status: {status}"
            )));
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| JournalError::Unavailable("journal mutex poisoned".to_owned()))?;
        match inner.records.get(key) {
            Some(record) if record.digest == digest && record.result.is_none() => {}
            Some(_) => return Err(JournalError::Conflict),
            None => {
                return Err(JournalError::Unavailable(
                    "result without intent".to_owned(),
                ))
            }
        }
        if inner.entries >= self.max_entries {
            return Err(JournalError::Full);
        }
        let record = MutationRecord {
            status: status.to_owned(),
            result_ref: result_ref.map(str::to_owned),
            result_digest: result_digest.map(str::to_owned),
        };
        inner.append(&Entry {
            kind: "result".to_owned(),
            key_scope: key.clone(),
            request_digest: digest.to_owned(),
            status: Some(record.status.clone()),
            result_ref: record.result_ref.clone(),
            result_digest: record.result_digest.clone(),
            ts: ts.to_owned(),
        })?;
        if let Some(existing) = inner.records.get_mut(key) {
            existing.result = Some(record);
        }
        Ok(())
    }

    /// 台账路径（诊断用）。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// 读取并校验既有台账；返回索引与条目数。
fn load(path: &Path) -> Result<(HashMap<KeyScope, Record>, usize), String> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((HashMap::new(), 0))
        }
        Err(error) => {
            return Err(format!("read mutate journal {}: {error}", path.display()));
        }
    };
    if data.is_empty() {
        return Ok((HashMap::new(), 0));
    }

    // 半行尾部是崩溃残留：截断到最后一条完整行并告警。
    let complete_len = match data.iter().rposition(|byte| *byte == b'\n') {
        Some(index) => index + 1,
        None => 0,
    };
    if complete_len < data.len() {
        eprintln!(
            "refd: truncating partial tail of mutate journal {} ({} bytes)",
            path.display(),
            data.len() - complete_len
        );
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|error| format!("truncate mutate journal {}: {error}", path.display()))?;
        file.set_len(complete_len as u64)
            .map_err(|error| format!("truncate mutate journal {}: {error}", path.display()))?;
        file.sync_all()
            .map_err(|error| format!("truncate mutate journal {}: {error}", path.display()))?;
    }

    let text = std::str::from_utf8(&data[..complete_len])
        .map_err(|_| format!("mutate journal {} is not UTF-8", path.display()))?;
    let mut records: HashMap<KeyScope, Record> = HashMap::new();
    let mut entries = 0usize;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let invalid = |reason: String| {
            format!(
                "mutate journal {} line {}: {reason}",
                path.display(),
                index + 1
            )
        };
        let entry: Entry =
            serde_json::from_str(line).map_err(|error| invalid(error.to_string()))?;
        entries += 1;
        match entry.kind.as_str() {
            "intent" => {
                if entry.status.is_some()
                    || entry.result_ref.is_some()
                    || entry.result_digest.is_some()
                {
                    return Err(invalid("intent must not carry a result".to_owned()));
                }
                match records.get(&entry.key_scope) {
                    None => {
                        records.insert(
                            entry.key_scope,
                            Record {
                                digest: entry.request_digest,
                                result: None,
                            },
                        );
                    }
                    Some(existing)
                        if existing.digest == entry.request_digest && existing.result.is_none() => {
                    }
                    Some(_) => return Err(invalid("conflicting intent".to_owned())),
                }
            }
            "result" => {
                let status = entry
                    .status
                    .as_deref()
                    .ok_or_else(|| invalid("result requires status".to_owned()))?;
                if status != "succeeded" && status != "failed" {
                    return Err(invalid(format!("unknown status: {status}")));
                }
                let Some(existing) = records.get(&entry.key_scope) else {
                    return Err(invalid("result without intent".to_owned()));
                };
                if existing.digest != entry.request_digest {
                    return Err(invalid("result digest does not match intent".to_owned()));
                }
                if existing.result.is_some() {
                    return Err(invalid("duplicate result".to_owned()));
                }
                let record = Record {
                    digest: existing.digest.clone(),
                    result: Some(MutationRecord {
                        status: status.to_owned(),
                        result_ref: entry.result_ref,
                        result_digest: entry.result_digest,
                    }),
                };
                records.insert(entry.key_scope, record);
            }
            other => return Err(invalid(format!("unknown entry kind: {other}"))),
        }
    }
    Ok((records, entries))
}

/// `requestDigest = sha256(canonicalJson({domain, type, reference, operation, input}))`。
///
/// 紧凑 JSON、键按字典序（`BTreeMap` 保证），与 D49 的规范化风格一致。
pub fn request_digest(
    domain: &str,
    type_name: &str,
    reference: &str,
    operation: &str,
    input: &serde_json::Value,
) -> String {
    let mut canonical = BTreeMap::new();
    canonical.insert("domain", serde_json::Value::String(domain.to_owned()));
    canonical.insert("input", input.clone());
    canonical.insert("operation", serde_json::Value::String(operation.to_owned()));
    canonical.insert("reference", serde_json::Value::String(reference.to_owned()));
    canonical.insert("type", serde_json::Value::String(type_name.to_owned()));
    let text = serde_json::to_string(&canonical).unwrap_or_default();
    format!("sha256:{}", hex_digest(text.as_bytes()))
}

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{request_digest, Journal, JournalError, KeyScope, Lookup, MAX_ENTRIES_LIMIT};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "refd-journal-{label}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn key(idempotency_key: &str) -> KeyScope {
        KeyScope {
            actor: "alice".to_owned(),
            domain: "query".to_owned(),
            type_name: "answer".to_owned(),
            reference: "mcp://erp.example/query.run".to_owned(),
            operation: "query.run".to_owned(),
            idempotency_key: idempotency_key.to_owned(),
        }
    }

    #[test]
    fn intent_without_result_is_in_doubt() {
        let path = temp_path("in-doubt");
        let journal = Journal::open(&path, 10).expect("journal");
        let digest = request_digest(
            "query",
            "answer",
            "mcp://a/query.run",
            "query.run",
            &serde_json::json!({"q": "1"}),
        );
        journal.begin(&key("k1"), &digest, "t0").expect("begin");
        assert_eq!(
            journal.lookup(&key("k1"), &digest).expect("lookup"),
            Lookup::InDoubt
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn same_key_same_digest_replays_result_after_restart() {
        let path = temp_path("replay");
        let digest = request_digest(
            "query",
            "answer",
            "mcp://a/query.run",
            "query.run",
            &serde_json::json!({"q": "1"}),
        );
        {
            let journal = Journal::open(&path, 10).expect("journal");
            journal.begin(&key("k1"), &digest, "t0").expect("begin");
            journal
                .finish(
                    &key("k1"),
                    &digest,
                    "succeeded",
                    Some("file:///tmp/result.json"),
                    Some("sha256:abc"),
                    "t1",
                )
                .expect("finish");
        }
        let journal = Journal::open(&path, 10).expect("reopen");
        match journal.lookup(&key("k1"), &digest).expect("lookup") {
            Lookup::Replay(record) => {
                assert!(record.succeeded());
                assert_eq!(
                    record.result_ref.as_deref(),
                    Some("file:///tmp/result.json")
                );
                assert_eq!(record.result_digest.as_deref(), Some("sha256:abc"));
            }
            other => panic!("expected replay, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn same_key_different_digest_conflicts() {
        let path = temp_path("conflict");
        let journal = Journal::open(&path, 10).expect("journal");
        let first = request_digest(
            "query",
            "answer",
            "mcp://a/query.run",
            "query.run",
            &serde_json::json!({"q": "1"}),
        );
        let second = request_digest(
            "query",
            "answer",
            "mcp://a/query.run",
            "query.run",
            &serde_json::json!({"q": "2"}),
        );
        journal.begin(&key("k1"), &first, "t0").expect("begin");
        assert_eq!(
            journal.lookup(&key("k1"), &second).expect("lookup"),
            Lookup::Conflict
        );
        assert_eq!(
            journal.begin(&key("k1"), &second, "t1"),
            Err(JournalError::Conflict)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn failed_result_replays_failed() {
        let path = temp_path("failed");
        let journal = Journal::open(&path, 10).expect("journal");
        let digest = request_digest(
            "query",
            "answer",
            "mcp://a/query.run",
            "query.run",
            &serde_json::json!({"q": "1"}),
        );
        journal.begin(&key("k1"), &digest, "t0").expect("begin");
        journal
            .finish(&key("k1"), &digest, "failed", None, None, "t1")
            .expect("finish");
        match journal.lookup(&key("k1"), &digest).expect("lookup") {
            Lookup::Replay(record) => {
                assert!(!record.succeeded());
                assert!(record.result_ref.is_none());
            }
            other => panic!("expected replay, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn journal_rejects_when_full() {
        let path = temp_path("full");
        let journal = Journal::open(&path, 2).expect("journal");
        let digest = request_digest(
            "query",
            "answer",
            "mcp://a/query.run",
            "query.run",
            &serde_json::json!({}),
        );
        journal.begin(&key("k1"), &digest, "t0").expect("begin");
        journal
            .finish(&key("k1"), &digest, "succeeded", None, None, "t1")
            .expect("finish");
        assert_eq!(
            journal.begin(&key("k2"), &digest, "t2"),
            Err(JournalError::Full)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn recovers_from_truncated_tail_and_rejects_invalid_lines() {
        let path = temp_path("tail");
        let digest = request_digest(
            "query",
            "answer",
            "mcp://a/query.run",
            "query.run",
            &serde_json::json!({}),
        );
        {
            let journal = Journal::open(&path, 10).expect("journal");
            journal.begin(&key("k1"), &digest, "t0").expect("begin");
        }
        // 追加半行（模拟崩溃残留）。
        {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("append");
            file.write_all(b"{\"kind\":\"result\"").expect("tail");
        }
        let journal = Journal::open(&path, 10).expect("reopen truncates tail");
        assert_eq!(
            journal.lookup(&key("k1"), &digest).expect("lookup"),
            Lookup::InDoubt
        );
        drop(journal);

        // 非法完整行拒绝启动。
        std::fs::write(&path, b"not json\n").expect("write invalid");
        assert!(Journal::open(&path, 10).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn request_digest_is_canonical_and_key_order_independent() {
        let left = serde_json::json!({"b": 2, "a": 1});
        let right = serde_json::json!({"a": 1, "b": 2});
        let first = request_digest("query", "answer", "mcp://a/query.run", "query.run", &left);
        let second = request_digest("query", "answer", "mcp://a/query.run", "query.run", &right);
        assert_eq!(first, second);
        assert!(first.starts_with("sha256:"));
        assert_eq!(first.len(), "sha256:".len() + 64);
    }

    #[test]
    fn max_entries_limit_is_enforced() {
        let path = temp_path("limit");
        assert!(Journal::open(&path, 0).is_err());
        assert!(Journal::open(&path, MAX_ENTRIES_LIMIT + 1).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
