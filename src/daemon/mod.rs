//! Daemon mode: persistent background process with Unix socket IPC.
//!
//! Architecture:
//! - Main thread: IDA worker loop (required by idalib)
//! - Tokio runtime thread: Unix socket server accepting JSON requests
//! - TargetManager: manages multiple loaded IDBs with target switching

pub mod protocol;
pub mod server;
pub mod target;

pub use protocol::{Request, Response};
pub use server::run_daemon;
pub use target::TargetManager;

use std::path::PathBuf;

/// Default socket path for the daemon.
pub fn socket_path() -> PathBuf {
    let cache_dir = dirs_cache_dir();
    cache_dir.join("ida-rs-cli.sock")
}

/// Registry file path (records daemon PID, socket, start time).
pub fn registry_path() -> PathBuf {
    let cache_dir = dirs_cache_dir();
    cache_dir.join("daemon.json")
}

fn dirs_cache_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join("Library/Caches/ida-rs-cli");
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
            return PathBuf::from(xdg).join("ida-rs-cli");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".cache/ida-rs-cli");
        }
    }
    PathBuf::from("/tmp/ida-rs-cli")
}
