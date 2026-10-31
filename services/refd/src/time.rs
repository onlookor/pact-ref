//! 无第三方依赖的 UTC 时间格式化与 trace id 生成。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static TRACE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 生成符合 `[A-Za-z0-9._:-]{1,128}` 的相关 ID。
pub fn new_trace_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let counter = TRACE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:032x}{:08x}{:016x}", nanos, std::process::id(), counter)
}

/// 当前时间加 `seconds`，RFC3339 UTC。
pub fn now_plus(seconds: u64) -> String {
    rfc3339(SystemTime::now() + Duration::from_secs(seconds))
}

/// RFC3339 UTC（秒精度），例如 `2026-10-31T12:05:00Z`。
pub fn rfc3339(timestamp: SystemTime) -> String {
    let seconds = timestamp
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let days = (seconds / 86_400) as i64;
    let of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        of_day / 3_600,
        (of_day % 3_600) / 60,
        of_day % 60
    )
}

/// Howard Hinnant 的 days-to-civil 算法。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::{civil_from_days, rfc3339};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn formats_known_timestamps() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(1_790_812_800)),
            "2026-10-01T00:00:00Z"
        );
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn trace_ids_are_unique_and_well_formed() {
        let first = super::new_trace_id();
        let second = super::new_trace_id();
        assert_ne!(first, second);
        assert!(first.len() <= 128);
        assert!(first
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c)));
    }
}
