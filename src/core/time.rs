//! Rust-only helper (no TS counterpart): JS `Date` semantics on top of `jiff`.
//!
//! The TS library leans on `new Date().toISOString()`, `Date.parse()` and `now.getTime()`.
//! These helpers reproduce exactly the subset the protocol relies on.

use jiff::{civil, tz::TimeZone, Timestamp};

/// `new Date().toISOString()` → `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn now_iso() -> String {
    to_iso_string(Timestamp::now())
}

/// `date.toISOString()` (always millisecond precision, always UTC `Z`).
pub fn to_iso_string(ts: Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// `Date.parse(s)` in epoch milliseconds, or `None` for NaN.
///
/// Accepts RFC 3339 / ISO 8601 with an offset, date-time without an offset (treated as UTC),
/// and date-only values (UTC midnight, as in ECMAScript).
pub fn parse_iso_millis(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(ts) = s.parse::<Timestamp>() {
        return Some(ts.as_millisecond());
    }
    if let Ok(dt) = s.parse::<civil::DateTime>() {
        return dt.to_zoned(TimeZone::UTC).ok().map(|z| z.timestamp().as_millisecond());
    }
    if let Ok(d) = s.parse::<civil::Date>() {
        return d.to_zoned(TimeZone::UTC).ok().map(|z| z.timestamp().as_millisecond());
    }
    None
}

/// `!isNaN(new Date(s).getTime())`.
pub fn is_valid_date(s: &str) -> bool {
    parse_iso_millis(s).is_some()
}

/// `now.getTime()`; `None` means "the current time".
pub fn resolve_now(now: Option<Timestamp>) -> Timestamp {
    now.unwrap_or_else(Timestamp::now)
}
