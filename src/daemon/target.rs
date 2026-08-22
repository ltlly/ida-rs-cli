//! Target management: load, unload, switch between multiple IDBs.
//!
//! All IDB operations MUST happen on the main thread (idalib requirement).
//! The TargetManager is NOT thread-safe by itself - it is meant to be accessed
//! only from the main thread via the request dispatch loop.

use idalib::{IDBOpenOptions, IDB};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::info;

/// Information about a loaded target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    pub id: String,
    pub path: String,
    pub filename: String,
    pub file_type: String,
    pub processor: String,
    pub bits: u32,
    pub function_count: usize,
}

/// Internal record holding the IDB and metadata.
struct TargetRecord {
    /// Always Some when the target is loaded.
    pub idb: Option<IDB>,
    pub info: TargetInfo,
}

/// Manages multiple loaded IDB targets.
/// NOT thread-safe - must be accessed only from the IDA main thread.
pub struct TargetManager {
    targets: HashMap<String, TargetRecord>,
    active_id: Option<String>,
    next_id: u64,
}

impl Default for TargetManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetManager {
    pub fn new() -> Self {
        Self {
            targets: HashMap::new(),
            active_id: None,
            next_id: 1,
        }
    }

    /// Load a new target (binary or IDB). Returns target info on success.
    /// MUST be called from the IDA main thread.
    pub fn load(&mut self, path: &str, auto_analyse: bool, idb_out: Option<&str>) -> Result<TargetInfo, String> {
        let expanded = expand_path(path);
        info!("Loading target: {}", expanded.display());

        let start = Instant::now();
        let db = open_idb(&expanded, auto_analyse, idb_out)?;
        let elapsed = start.elapsed().as_secs();

        let meta = db.meta();
        let filename = expanded
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string());

        let id = format!("t{}", self.next_id);
        self.next_id += 1;

        let target_info = TargetInfo {
            id: id.clone(),
            path: expanded.display().to_string(),
            filename,
            file_type: format!("{:?}", meta.filetype()),
            processor: db.processor().long_name(),
            bits: if meta.is_64bit() {
                64
            } else if meta.is_32bit_exactly() {
                32
            } else {
                16
            },
            function_count: db.function_count(),
        };

        let record = TargetRecord {
            idb: Some(db),
            info: target_info.clone(),
        };

        self.targets.insert(id.clone(), record);

        // Set as active if it's the first/only target
        if self.active_id.is_none() {
            self.active_id = Some(id.clone());
        }

        info!("Target loaded: {} ({}s)", target_info.filename, elapsed);
        Ok(target_info)
    }

    /// Seed the ID allocator so the next loaded target gets `id`
    /// (e.g. "t3"). Used by per-target worker subprocesses so their single
    /// target carries the router-assigned ID. Non-"t<N>" IDs are ignored.
    pub fn seed_next_id(&mut self, id: &str) {
        if let Some(n) = id.strip_prefix('t').and_then(|s| s.parse::<u64>().ok()) {
            self.next_id = n;
        }
    }

    /// Close and unload a target by ID.
    pub fn close(&mut self, target_id: &str) -> Result<(), String> {
        if self.targets.remove(target_id).is_none() {
            return Err(format!("Target not found: {}", target_id));
        }

        // If the closed target was active, switch to another or None
        if self.active_id.as_deref() == Some(target_id) {
            self.active_id = self.targets.keys().next().cloned();
        }

        info!("Target closed: {}", target_id);
        Ok(())
    }

    /// List all loaded targets.
    pub fn list(&self) -> Vec<TargetInfo> {
        self.targets.values().map(|r| r.info.clone()).collect()
    }

    /// Get the active target ID.
    pub fn active_id(&self) -> Option<&str> {
        self.active_id.as_deref()
    }

    /// Set the active target by ID.
    pub fn set_active(&mut self, target_id: &str) -> Result<(), String> {
        if !self.targets.contains_key(target_id) {
            return Err(format!("Target not found: {}", target_id));
        }
        self.active_id = Some(target_id.to_string());
        Ok(())
    }

    /// Resolve a target selector to an ID.
    /// Selector can be: target ID, filename substring, or None/"active" for current.
    pub fn resolve(&self, selector: Option<&str>) -> Result<String, String> {
        if self.targets.is_empty() {
            return Err("No targets loaded. Use 'target load -f <path>' first.".to_string());
        }

        match selector {
            None | Some("active") | Some("") => self
                .active_id
                .clone()
                .ok_or_else(|| "No active target".to_string()),
            Some(sel) => {
                // Try exact ID match
                if self.targets.contains_key(sel) {
                    return Ok(sel.to_string());
                }
                // Try filename/path substring match
                let matches: Vec<_> = self
                    .targets
                    .iter()
                    .filter(|(_, r)| r.info.filename.contains(sel) || r.info.path.contains(sel))
                    .collect();
                match matches.len() {
                    0 => Err(format!("No target matching '{}'", sel)),
                    1 => Ok(matches[0].0.clone()),
                    _ => Err(format!(
                        "Ambiguous selector '{}': matches {} targets",
                        sel,
                        matches.len()
                    )),
                }
            }
        }
    }

    /// Get an immutable reference to the IDB Option for a target.
    /// Handlers expect `&Option<IDB>`.
    pub fn get_idb(&self, target_id: &str) -> Result<&Option<IDB>, String> {
        let record = self
            .targets
            .get(target_id)
            .ok_or_else(|| format!("Target not found: {}", target_id))?;
        Ok(&record.idb)
    }

    /// Get a mutable reference to the IDB Option for a target.
    /// For mutating handlers that expect `&mut Option<IDB>`.
    pub fn get_idb_mut(&mut self, target_id: &str) -> Result<&mut Option<IDB>, String> {
        let record = self
            .targets
            .get_mut(target_id)
            .ok_or_else(|| format!("Target not found: {}", target_id))?;
        Ok(&mut record.idb)
    }

    /// Test-only: insert a target record without opening a real IDB.
    #[cfg(test)]
    pub(crate) fn insert_dummy(&mut self, filename: &str, path: &str) -> String {
        let id = format!("t{}", self.next_id);
        self.next_id += 1;
        let info = TargetInfo {
            id: id.clone(),
            path: path.to_string(),
            filename: filename.to_string(),
            file_type: String::new(),
            processor: String::new(),
            bits: 64,
            function_count: 0,
        };
        self.targets.insert(id.clone(), TargetRecord { idb: None, info });
        if self.active_id.is_none() {
            self.active_id = Some(id.clone());
        }
        id
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn expand_path(path: &str) -> PathBuf {
    path.strip_prefix("~/")
        .and_then(|stripped| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(stripped)))
        .unwrap_or_else(|| PathBuf::from(path))
}

fn idb_path_for_raw_binary(path: &Path) -> PathBuf {
    let mut raw_idb = OsString::from(path.as_os_str());
    raw_idb.push(".i64");
    PathBuf::from(raw_idb)
}

/// True when the path names an existing IDA database rather than a raw binary.
pub fn is_idb_path(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    ext == "i64" || ext == "idb" || ext == "id0"
}

/// Effective IDB output path for a load: `None` for existing-IDB inputs,
/// otherwise the explicit `--idb-out` or `<file>.i64` next to the input.
/// The router uses this to detect output-path conflicts before spawning a
/// worker; `open_idb` uses it for the actual open.
pub fn effective_idb_out(path: &Path, idb_out: Option<&str>) -> Option<PathBuf> {
    if is_idb_path(path) {
        return None;
    }
    Some(match idb_out {
        Some(out) => expand_path(out),
        None => idb_path_for_raw_binary(path),
    })
}

fn open_idb(path: &Path, auto_analyse: bool, idb_out: Option<&str>) -> Result<IDB, String> {
    if is_idb_path(path) {
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(auto_analyse).save(true);
        opts.arg("-A");
        opts.open(path)
            .map_err(|e| format!("Failed to open IDB: {}: {}", path.display(), e))
    } else {
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(auto_analyse);
        // effective_idb_out returns Some for raw binaries
        let out_path = effective_idb_out(path, idb_out)
            .ok_or_else(|| "internal: raw binary without idb out path".to_string())?;
        opts.arg("-A");
        opts.idb(&out_path)
            .save(true)
            .open(path)
            .map_err(|e| format!("Failed to open binary: {}: {}", path.display(), e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_prefers_exact_id_then_substring() {
        let mut mgr = TargetManager::new();
        let t1 = mgr.insert_dummy("libalpha.so", "/tmp/libalpha.so");
        let t2 = mgr.insert_dummy("beta.bin", "/work/beta.bin");

        // Exact ID match wins.
        assert_eq!(mgr.resolve(Some("t2")).as_deref(), Ok("t2"));
        // Filename substring.
        assert_eq!(mgr.resolve(Some("alpha")).as_deref(), Ok("t1"));
        // Path substring.
        assert_eq!(mgr.resolve(Some("/work")).as_deref(), Ok("t2"));
        // None / "active" / "" resolve to the active target (first loaded).
        assert_eq!(mgr.resolve(None).as_deref(), Ok(t1.as_str()));
        assert_eq!(mgr.resolve(Some("active")).as_deref(), Ok(t1.as_str()));
        assert_eq!(mgr.resolve(Some("")).as_deref(), Ok(t1.as_str()));
        // No match is an error; a substring matching both is ambiguous.
        assert!(mgr.resolve(Some("nope")).is_err());
        assert_eq!(mgr.resolve(Some("tmp")).as_deref(), Ok(t1.as_str())); // only t1 has /tmp
        assert!(mgr.resolve(Some("/")).is_err()); // both paths contain '/'
        let _ = t2;
    }

    #[test]
    fn resolve_ambiguous_selector_errors() {
        let mut mgr = TargetManager::new();
        mgr.insert_dummy("foo-a.so", "/x/foo-a.so");
        mgr.insert_dummy("foo-b.so", "/x/foo-b.so");
        let err = mgr.resolve(Some("foo")).unwrap_err();
        assert!(err.contains("Ambiguous"), "unexpected error: {err}");
    }

    #[test]
    fn resolve_without_targets_errors() {
        let mgr = TargetManager::new();
        assert!(mgr.resolve(None).is_err());
    }

    #[test]
    fn seed_next_id_controls_next_allocation() {
        let mut mgr = TargetManager::new();
        mgr.seed_next_id("t7");
        assert_eq!(mgr.insert_dummy("a", "/a"), "t7");
        assert_eq!(mgr.insert_dummy("b", "/b"), "t8");

        let mut mgr2 = TargetManager::new();
        mgr2.seed_next_id("bogus");
        assert_eq!(mgr2.insert_dummy("a", "/a"), "t1");
    }

    #[test]
    fn is_idb_path_by_extension() {
        assert!(is_idb_path(Path::new("/x/app.i64")));
        assert!(is_idb_path(Path::new("/x/app.IDB")));
        assert!(is_idb_path(Path::new("/x/app.id0")));
        assert!(!is_idb_path(Path::new("/x/app.so")));
        assert!(!is_idb_path(Path::new("/x/noext")));
    }

    #[test]
    fn effective_idb_out_defaults_and_explicit() {
        // Existing-IDB input: no output path.
        assert_eq!(effective_idb_out(Path::new("/x/app.i64"), None), None);
        assert_eq!(
            effective_idb_out(Path::new("/x/app.i64"), Some("/tmp/ignored.i64")),
            None
        );
        // Raw binary: default <file>.i64.
        assert_eq!(
            effective_idb_out(Path::new("/x/app.so"), None),
            Some(PathBuf::from("/x/app.so.i64"))
        );
        // Raw binary with explicit output.
        assert_eq!(
            effective_idb_out(Path::new("/x/app.so"), Some("/out/app.i64")),
            Some(PathBuf::from("/out/app.i64"))
        );
    }

    #[test]
    fn expand_path_handles_tilde() {
        let home = std::env::var_os("HOME").expect("HOME set");
        assert_eq!(
            expand_path("~/x/y.so"),
            PathBuf::from(home).join("x/y.so")
        );
        assert_eq!(expand_path("/abs/p"), PathBuf::from("/abs/p"));
        assert_eq!(expand_path("rel/p"), PathBuf::from("rel/p"));
    }
}
