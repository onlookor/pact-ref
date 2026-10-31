//! 访问/调用审计边车。
//!
//! 只记录 ID、摘要、状态、时间；不记录正文、凭据或个人数据。
//! `FileAuditSink` 逐行追加并 `fsync`；写入失败返回 `Err`，由调用方 fail-closed。

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use pact_ref_core::{AuditError, AuditEvent, AuditSink};

/// 内存实现，供测试与本地开发使用。
pub struct MemoryAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemoryAuditSink {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn events(&self) -> Vec<AuditEvent> {
        match self.events.lock() {
            Ok(events) => events.clone(),
            Err(_) => Vec::new(),
        }
    }
}

impl Default for MemoryAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        match self.events.lock() {
            Ok(mut events) => {
                events.push(event.clone());
                Ok(())
            }
            Err(_) => Err(AuditError::new("memory audit lock poisoned")),
        }
    }
}

/// append-only 文件审计：每行一个 JSON 事件，写入后 `flush` + `sync_data`。
pub struct FileAuditSink {
    path: PathBuf,
    file: Mutex<File>,
}

impl FileAuditSink {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for FileAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| AuditError::new("audit file lock poisoned"))?;
        let mut line = serde_json::to_vec(event)
            .map_err(|error| AuditError::new(format!("serialize audit event: {error}")))?;
        line.push(b'\n');
        file.write_all(&line)
            .map_err(|error| AuditError::new(format!("write audit event: {error}")))?;
        file.flush()
            .map_err(|error| AuditError::new(format!("flush audit event: {error}")))?;
        file.sync_data()
            .map_err(|error| AuditError::new(format!("sync audit event: {error}")))?;
        Ok(())
    }

    fn available(&self) -> bool {
        self.file.lock().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{FileAuditSink, MemoryAuditSink};
    use pact_ref_core::{AuditEvent, AuditSink};

    fn event(trace_id: &str) -> AuditEvent {
        AuditEvent {
            trace_id: trace_id.to_owned(),
            token_id: Some("01J00000000000000000000000".to_owned()),
            actor: "alice".to_owned(),
            reference: "https://example.com/a".to_owned(),
            domain: Some("build".to_owned()),
            type_name: Some("artifact".to_owned()),
            contract_id: Some("demo/artifact".to_owned()),
            operation: Some("resolve".to_owned()),
            status: "ok".to_owned(),
            result_digest: None,
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn records_events_in_order() {
        let sink = MemoryAuditSink::new();
        sink.record(&event("trace-1")).expect("record");
        sink.record(&event("trace-2")).expect("record");
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].trace_id, "trace-1");
        assert_eq!(events[1].trace_id, "trace-2");
    }

    #[test]
    fn appends_json_lines_and_omits_absent_fields() {
        let path = std::env::temp_dir().join(format!(
            "pact-ref-audit-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        {
            let sink = FileAuditSink::open(&path).expect("open");
            sink.record(&event("trace-1")).expect("record");
            sink.record(&event("trace-2")).expect("record");
            assert_eq!(sink.path(), path.as_path());
        }
        let content = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"traceId\":\"trace-1\""));
        assert!(!lines[0].contains("resultDigest"));
        assert!(lines[0].ends_with('}'));
        let _ = std::fs::remove_file(&path);
    }
}
