//! Auto-spill output module.
//!
//! When CLI output exceeds a configurable token threshold, the full result is
//! written to a temporary file (spill file) and only a lightweight JSON metadata
//! envelope is printed to stdout. This prevents context explosion when AI agents
//! invoke commands that produce very large outputs (e.g. decompiling a huge
//! function, listing thousands of strings).
//!
//! Token estimation uses a simple heuristic: ~4 bytes per token (approximation
//! for GPT-4/Claude tokenizers on mixed code/text). This avoids heavy
//! dependencies like tiktoken while remaining accurate enough for threshold
//! decisions.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Default spill threshold in estimated tokens.
/// Outputs exceeding this will be written to a file instead of stdout.
pub const DEFAULT_SPILL_TOKEN_LIMIT: usize = 10_000;

/// Approximate bytes-per-token ratio for estimation.
/// Conservative estimate: 3.5-4 bytes/token for code-heavy content.
const BYTES_PER_TOKEN: f64 = 3.8;

/// Result of processing output through the spill mechanism.
pub struct SpillResult {
    /// What should be printed to stdout.
    pub stdout_output: String,
    /// Whether the output was spilled to a file.
    pub spilled: bool,
    /// Path to spill file (if spilled).
    pub spill_path: Option<PathBuf>,
}

/// Estimate token count from byte length.
fn estimate_tokens(byte_len: usize) -> usize {
    (byte_len as f64 / BYTES_PER_TOKEN).ceil() as usize
}

/// Get the spill directory: $TMPDIR/ida-rs-spills/YYYYMMDD/
fn spill_dir() -> PathBuf {
    let tmp = std::env::temp_dir();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    // Civil date from Unix timestamp (Rata Die algorithm, no leap-second edge cases)
    let days = (secs / 86400) as i64;
    let (year, month, day) = civil_from_days(days);
    let date_str = format!("{:04}{:02}{:02}", year, month, day);

    tmp.join("ida-rs-spills").join(date_str)
}

/// Convert days since Unix epoch to (year, month, day).
/// Algorithm from Howard Hinnant's date library (public domain).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Inverse of `civil_from_days` (same source algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// Spill directories older than this many days are pruned on the next spill.
const SPILL_RETENTION_DAYS: i64 = 3;

/// Best-effort cleanup of dated spill dirs older than the retention window.
/// `base` is the `ida-rs-spills` directory; `today_days` is the current day
/// number (days since epoch). Never fails the caller: all errors are ignored.
fn prune_old_spills(base: &Path, today_days: i64) {
    let entries = match fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.len() != 8 || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let parsed = (
            name[0..4].parse::<i64>(),
            name[4..6].parse::<u32>(),
            name[6..8].parse::<u32>(),
        );
        let (Ok(y), Ok(m), Ok(d)) = parsed else { continue };
        let dir_days = days_from_civil(y, m, d);
        if today_days - dir_days > SPILL_RETENTION_DAYS {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// Generate a spill filename based on operation name and timestamp.
/// Includes PID and nanoseconds so concurrent CLI processes cannot collide.
fn spill_filename(op: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let subsec = now.subsec_millis();
    let nanos = now.subsec_nanos();
    // Use HH:MM:SS-ms as part of filename
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    format!(
        "{}-{:02}{:02}{:02}_{:03}-p{}-{:09}.json",
        op.replace('.', "_"),
        hours,
        minutes,
        seconds,
        subsec,
        std::process::id(),
        nanos
    )
}

/// Compute SHA-256 hex digest of data.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Build the metadata envelope returned when output is spilled.
fn build_envelope(
    spill_path: &Path,
    data: &[u8],
    token_estimate: usize,
    value: &Value,
) -> Value {
    let summary = match value {
        Value::Array(arr) => serde_json::json!({
            "kind": "array",
            "count": arr.len()
        }),
        Value::Object(obj) => {
            let keys: Vec<&String> = obj.keys().take(10).collect();
            serde_json::json!({
                "kind": "object",
                "keys": keys,
                "count": obj.len()
            })
        }
        Value::String(s) => serde_json::json!({
            "kind": "string",
            "chars": s.len()
        }),
        _ => serde_json::json!({
            "kind": format!("{}", value_type_name(value))
        }),
    };

    serde_json::json!({
        "ok": true,
        "spilled": true,
        "artifact_path": spill_path.to_string_lossy(),
        "format": "json",
        "bytes": data.len(),
        "tokens_estimate": token_estimate,
        "sha256": sha256_hex(data),
        "summary": summary,
        "hint": "Output exceeded token limit. Full result saved to artifact_path. Use `cat` or read the file to access complete data."
    })
}

fn value_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Process output through the auto-spill mechanism.
///
/// If `token_limit` is 0, spilling is disabled (pass-through).
/// If the rendered JSON output exceeds `token_limit` estimated tokens,
/// write it to a spill file and return metadata instead.
pub fn maybe_spill(
    result: &Value,
    op: &str,
    token_limit: usize,
) -> anyhow::Result<SpillResult> {
    // Render the output
    let rendered = serde_json::to_string_pretty(result)?;
    let bytes = rendered.as_bytes();
    let token_estimate = estimate_tokens(bytes.len());

    // If disabled or under threshold, pass through
    if token_limit == 0 || token_estimate <= token_limit {
        return Ok(SpillResult {
            stdout_output: rendered,
            spilled: false,
            spill_path: None,
        });
    }

    // Spill to file
    let dir = spill_dir();
    fs::create_dir_all(&dir)?;
    let filename = spill_filename(op);
    let path = dir.join(&filename);

    let mut file = fs::File::create(&path)?;
    file.write_all(bytes)?;
    file.flush()?;

    // Best-effort retention: prune dated spill dirs older than the window.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    if let Some(base) = dir.parent() {
        prune_old_spills(base, (now.as_secs() / 86400) as i64);
    }

    // Build envelope
    let envelope = build_envelope(&path, bytes, token_estimate, result);
    let envelope_str = serde_json::to_string_pretty(&envelope)?;

    // Also log to stderr for visibility
    eprintln!(
        "[spill] Output too large ({} tokens est. > {} limit). Saved to: {}",
        token_estimate,
        token_limit,
        path.display()
    );

    Ok(SpillResult {
        stdout_output: envelope_str,
        spilled: true,
        spill_path: Some(path),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_date_roundtrip() {
        // days_from_civil must invert civil_from_days over a wide range.
        for days in [-719_468, -1, 0, 1, 19_000, 20_463, 30_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "days={}", days);
        }
    }

    #[test]
    fn spill_filename_is_unique_and_sanitized() {
        let a = spill_filename("decompile");
        let b = spill_filename("decompile");
        assert_ne!(a, b, "consecutive filenames must differ");
        let c = spill_filename("target.load");
        assert!(!c.contains('.') || c.ends_with(".json"));
        assert!(c.starts_with("target_load-"));
    }

    #[test]
    fn prune_old_spills_removes_only_old_dated_dirs() {
        let base = std::env::temp_dir().join(format!(
            "ida-rs-spill-prune-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();

        let today_days = 20_463; // arbitrary fixed "today"
        let (ty, tm, td) = civil_from_days(today_days);
        let (oy, om, od) = civil_from_days(today_days - 10);
        let today_dir = base.join(format!("{:04}{:02}{:02}", ty, tm, td));
        let old_dir = base.join(format!("{:04}{:02}{:02}", oy, om, od));
        let junk_dir = base.join("not-a-date");
        fs::create_dir_all(&today_dir).unwrap();
        fs::create_dir_all(&old_dir).unwrap();
        fs::create_dir_all(&junk_dir).unwrap();
        fs::write(old_dir.join("x.json"), b"{}").unwrap();
        fs::write(today_dir.join("y.json"), b"{}").unwrap();

        prune_old_spills(&base, today_days);

        assert!(today_dir.exists(), "today's dir must survive");
        assert!(junk_dir.exists(), "non-date dirs must survive");
        assert!(!old_dir.exists(), "old dir must be pruned");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn maybe_spill_passthrough_under_threshold() {
        let v = serde_json::json!({"small": true});
        let out = maybe_spill(&v, "test", 10_000).unwrap();
        assert!(!out.spilled);
        assert!(out.stdout_output.contains("\"small\": true"));

        // threshold 0 disables spilling entirely
        let big = serde_json::json!(vec!["x"; 100_000]);
        let out = maybe_spill(&big, "test", 0).unwrap();
        assert!(!out.spilled);
    }
}
