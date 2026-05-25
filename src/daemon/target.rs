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
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn expand_path(path: &str) -> PathBuf {
    path.strip_prefix("~/")
        .and_then(|stripped| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(stripped)))
        .unwrap_or_else(|| PathBuf::from(path))
}

fn idb_path_for_raw_binary(path: &Path) -> PathBuf {
    let mut raw_idb = OsString::from(path.as_os_str());
    raw_idb.push(".i64");
    PathBuf::from(raw_idb)
}

fn open_idb(path: &Path, auto_analyse: bool, idb_out: Option<&str>) -> Result<IDB, String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_idb = ext == "i64" || ext == "idb" || ext == "id0";

    if is_idb {
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(auto_analyse).save(true);
        opts.arg("-A");
        opts.open(path)
            .map_err(|e| format!("Failed to open IDB: {}: {}", path.display(), e))
    } else {
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(true);
        let out_path = if let Some(out) = idb_out {
            PathBuf::from(out)
        } else {
            idb_path_for_raw_binary(path)
        };
        opts.arg("-A");
        opts.idb(&out_path)
            .save(true)
            .open(path)
            .map_err(|e| format!("Failed to open binary: {}: {}", path.display(), e))
    }
}
