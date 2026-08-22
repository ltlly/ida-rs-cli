//! Daemon mode: router process + one worker subprocess per target.
//!
//! Architecture:
//! - Router (`ida-rs-cli daemon start`): pure tokio process. Owns the public
//!   Unix socket, tracks targets, spawns/reaps workers, forwards requests.
//!   Holds no IDB itself, so it stays responsive even when a worker wedges.
//! - Worker (`ida-rs-cli daemon worker --sock <path> --id <n>`, hidden):
//!   per-target subprocess. Initializes idalib on its main thread and holds
//!   exactly one IDB. idalib permits only one open IDB per process (its `IDB`
//!   keeps the process-global library mutex locked for its lifetime), so
//!   multi-target support requires process isolation - this mirrors the
//!   upstream MCP pool model of one child process per database.
//! - Workers exit on their own if the router dies: the router holds each
//!   worker's stdin pipe open, and the worker watches stdin for EOF.

pub mod protocol;
pub mod router;
pub mod target;
pub mod worker;

pub use protocol::{Request, Response};
pub use router::run_router;
pub use target::TargetManager;
pub use worker::run_worker;

use std::path::PathBuf;

/// Router -> worker operation timeout (matches upstream MAX_TIMEOUT_SECS).
pub const WORKER_OP_TIMEOUT_SECS: u64 = 600;
/// Timeout for connecting to a worker's socket.
pub const WORKER_CONNECT_TIMEOUT_SECS: u64 = 5;
/// Timeout waiting for a freshly spawned worker to start accepting.
pub const WORKER_BOOT_TIMEOUT_SECS: u64 = 30;
/// Grace period for a worker to exit after being asked to shut down.
pub const WORKER_STOP_TIMEOUT_SECS: u64 = 5;
/// Default CLI client read timeout (slightly above the worker op timeout so
/// the daemon's own timeout error reaches the client first).
pub const CLIENT_DEFAULT_TIMEOUT_SECS: u64 = WORKER_OP_TIMEOUT_SECS + 30;
/// CLI timeout for `daemon status` (must stay short to be useful when the
/// daemon is wedged).
pub const CLIENT_STATUS_TIMEOUT_SECS: u64 = 3;
/// CLI timeout for `daemon stop`.
pub const CLIENT_STOP_TIMEOUT_SECS: u64 = 20;
/// Maximum accepted length of a single JSON protocol line.
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// Default socket path for the daemon (router).
pub fn socket_path() -> PathBuf {
    let cache_dir = dirs_cache_dir();
    cache_dir.join("ida-rs-cli.sock")
}

/// Registry file path (records daemon PID, socket, start time).
pub fn registry_path() -> PathBuf {
    let cache_dir = dirs_cache_dir();
    cache_dir.join("daemon.json")
}

/// Directory holding per-target worker sockets.
pub fn worker_dir() -> PathBuf {
    dirs_cache_dir().join("workers")
}

/// Socket path for the worker serving target `id`.
/// Scoped by router PID so a worker from a previous daemon incarnation can
/// never unlink the new daemon's worker socket while exiting.
pub fn worker_socket_path(id: &str) -> PathBuf {
    worker_dir().join(format!("r{}-{}.sock", std::process::id(), id))
}

/// Log file used by `daemon start --background`.
pub fn log_path() -> PathBuf {
    dirs_cache_dir().join("daemon.log")
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

/// Check whether a process exists (and we may signal it).
pub fn pid_alive(pid: u32) -> bool {
    // kill(pid, 0): 0 on success, ESRCH if no such process, EPERM if it
    // exists but belongs to another user.
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if ret == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Read a single newline-terminated line with a hard size cap.
///
/// Unlike `AsyncBufReadExt::lines`, this bounds memory usage when a peer
/// sends data without ever emitting a newline. The stream position is left
/// right after the newline, so callers may keep reading subsequent lines.
/// Returns Ok(0) on clean EOF before any byte.
pub async fn read_line_capped<R>(
    reader: &mut tokio::io::BufReader<R>,
    out: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<usize>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    out.clear();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(out.len());
        }
        match available.iter().position(|b| *b == b'\n') {
            Some(pos) => {
                out.extend_from_slice(&available[..pos]);
                reader.consume(pos + 1);
                if out.len() > max {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("protocol line exceeds {} bytes", max),
                    ));
                }
                return Ok(out.len());
            }
            None => {
                let n = available.len();
                out.extend_from_slice(available);
                reader.consume(n);
                if out.len() > max {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("protocol line exceeds {} bytes", max),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_alive_reports_self() {
        assert!(pid_alive(std::process::id()));
        // PID 0 is not a valid target for liveness here; a very large PID
        // almost certainly does not exist.
        assert!(!pid_alive(4_000_000));
    }

    #[tokio::test]
    async fn read_line_capped_reads_multiple_lines() {
        let data: &[u8] = b"first\nsecond\npartial";
        let mut reader = tokio::io::BufReader::new(data);
        let mut out = Vec::new();

        let n = read_line_capped(&mut reader, &mut out, 1024).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(out.as_slice(), b"first");
        let n = read_line_capped(&mut reader, &mut out, 1024).await.unwrap();
        assert_eq!(n, 6);
        assert_eq!(out.as_slice(), b"second");
        // EOF without trailing newline still yields the partial line.
        let n = read_line_capped(&mut reader, &mut out, 1024).await.unwrap();
        assert_eq!(n, 7);
        assert_eq!(out.as_slice(), b"partial");
        // Then clean EOF.
        let n = read_line_capped(&mut reader, &mut out, 1024).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn read_line_capped_rejects_overlong_line() {
        let data: &[u8] = b"0123456789abcdef\n";
        let mut reader = tokio::io::BufReader::new(data);
        let mut out = Vec::new();
        let err = read_line_capped(&mut reader, &mut out, 8).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
