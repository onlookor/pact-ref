//! 访问/调用审计边车。
//!
//! 只记录 ID、摘要、状态、时间；不记录正文、凭据或个人数据。

use std::sync::Mutex;

use pact_ref_core::{AuditEvent, AuditSink};

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
    fn record(&self, event: &AuditEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryAuditSink;
    use pact_ref_core::{AuditEvent, AuditSink};

    fn event(trace_id: &str) -> AuditEvent {
        AuditEvent {
            trace_id: trace_id.to_owned(),
            token_id: Some("01J00000000000000000000000".to_owned()),
            actor: "alice".to_owned(),
            reference: "https://example.com/a".to_owned(),
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
        sink.record(&event("trace-1"));
        sink.record(&event("trace-2"));
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].trace_id, "trace-1");
        assert_eq!(events[1].trace_id, "trace-2");
    }
}
