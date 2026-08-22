//! End-to-end test for the CLI daemon: the multi-target regression test.
//!
//! Spawns the real `ida-rs-cli` daemon and drives the actual client binary
//! through the exact flow that used to deadlock: loading a second target
//! while the first is loaded. Requires a local IDA Pro install (idalib) and
//! is therefore gated: it only runs with `--ignored` and `IDA_RS_CLI_E2E=1`,
//! and skips cleanly when another daemon already owns the socket.
//!
//!   IDA_RS_CLI_E2E=1 cargo test --test daemon_e2e -- --ignored --nocapture

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ida-rs-cli");

/// Fail fast when the daemon is broken: the CLI's own read timeout is what
/// turns a wedged daemon into a test failure instead of a hung test run.
const CLIENT_TIMEOUT_SECS: &str = "60";

fn cli(args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env("IDA_CLI_TIMEOUT_SECS", CLIENT_TIMEOUT_SECS)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output()
}

fn cli_ok(args: &[&str]) -> String {
    let out = cli(args).expect("failed to run ida-rs-cli");
    assert!(
        out.status.success(),
        "ida-rs-cli {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn socket_path() -> PathBuf {
    let home = std::env::var_os("HOME").expect("HOME set");
    #[cfg(target_os = "macos")]
    {
        PathBuf::from(home).join("Library/Caches/ida-rs-cli/ida-rs-cli.sock")
    }
    #[cfg(not(target_os = "macos"))]
    {
        let xdg = std::env::var("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(home).join(".cache"));
        xdg.join("ida-rs-cli/ida-rs-cli.sock")
    }
}

fn daemon_running() -> bool {
    socket_path().exists()
        && cli(&["daemon", "status"])
            .map(|o| {
                let err = String::from_utf8_lossy(&o.stderr);
                err.contains("Status: healthy")
            })
            .unwrap_or(false)
}

/// Kill the daemon no matter how the test exits.
struct DaemonGuard(Option<Child>);

impl DaemonGuard {
    fn start() -> Self {
        let child = Command::new(BIN)
            .args(["daemon", "start"])
            .env("IDA_CLI_TIMEOUT_SECS", CLIENT_TIMEOUT_SECS)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn daemon");
        let mut guard = Self(Some(child));
        guard.wait_ready();
        guard
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if daemon_running() {
                return;
            }
            if let Some(ref mut child) = self.0 {
                if let Ok(Some(status)) = child.try_wait() {
                    panic!("daemon exited during startup: {}", status);
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("daemon did not become ready in 30s");
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        // Ask nicely first, then make sure.
        let _ = cli(&["daemon", "stop"]);
        if let Some(mut child) = self.0.take() {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    _ if Instant::now() >= deadline => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    _ => std::thread::sleep(Duration::from_millis(100)),
                }
            }
        }
    }
}

/// Copy a small system binary to a fresh temp dir under two different names.
fn make_fixture(dir: &Path, name: &str) -> PathBuf {
    let src = if cfg!(target_os = "macos") { "/bin/echo" } else { "/bin/true" };
    let dst = dir.join(name);
    fs_extra_copy(src, &dst);
    dst
}

fn fs_extra_copy(src: &str, dst: &Path) {
    let data = std::fs::read(src).expect("read fixture source");
    let mut f = std::fs::File::create(dst).expect("create fixture");
    f.write_all(&data).expect("write fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755));
    }
}

fn load_target(path: &Path) -> serde_json::Value {
    let stdout = cli_ok(&["target", "load", "-f", &path.display().to_string()]);
    serde_json::from_str(&stdout).expect("target load output is JSON")
}

#[test]
#[ignore = "requires a local IDA Pro install; run with IDA_RS_CLI_E2E=1"]
fn second_target_load_does_not_hang() {
    if std::env::var("IDA_RS_CLI_E2E").ok().as_deref() != Some("1") {
        eprintln!("skipped: set IDA_RS_CLI_E2E=1 to run");
        return;
    }
    if daemon_running() {
        eprintln!("skipped: a daemon is already running on this machine");
        return;
    }

    let dir = std::env::temp_dir().join(format!("ida-rs-cli-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bin_a = make_fixture(&dir, "e2e_a.bin");
    let bin_b = make_fixture(&dir, "e2e_b.bin");

    let _daemon = DaemonGuard::start();

    // First load must succeed...
    let t1 = load_target(&bin_a);
    assert_eq!(t1["id"], "t1");
    assert!(t1["function_count"].as_u64().unwrap_or(0) > 0);

    // ...and the second load is the regression: before the router/worker
    // split this deadlocked the daemon on idalib's process-global mutex.
    let t2 = load_target(&bin_b);
    assert_eq!(t2["id"], "t2");

    // Both targets must be listed and independently queryable.
    let stdout = cli_ok(&["target", "list"]);
    let list: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(list["targets"].as_array().unwrap().len(), 2);

    for id in ["t1", "t2"] {
        let stdout = cli_ok(&["-t", id, "functions", "--limit", "5"]);
        let funcs: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let count = funcs["functions"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
        assert!(count > 0, "functions on {} must not be empty", id);
        // The worker must report the router-assigned target ID, proving the
        // query ran against the right per-target process.
        let stdout = cli_ok(&["-t", id, "info"]);
        let info: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(info["target"], id);
    }

    // Duplicate load of an already-loaded input must be refused, not clobber.
    let out = cli(&["target", "load", "-f", &bin_a.display().to_string()]).unwrap();
    assert!(!out.status.success(), "duplicate load must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("already loaded as t1"),
        "unexpected duplicate-load error: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A different raw binary whose --idb-out collides with t1's database
    // must be refused too (database-identity conflict).
    let colliding = dir.join("e2e_a.bin.i64").display().to_string();
    let out = cli(&[
        "target",
        "load",
        "-f",
        &bin_b.display().to_string(),
        "--idb-out",
        &colliding,
    ])
    .unwrap();
    assert!(!out.status.success(), "identity-colliding load must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("already in use by t1"),
        "unexpected identity-conflict error: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Switch + close through the real client path.
    cli_ok(&["target", "switch", "--id", "t2"]);
    cli_ok(&["target", "close", "--id", "t1"]);
    let stdout = cli_ok(&["target", "list"]);
    let list: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(list["targets"].as_array().unwrap().len(), 1);
    assert_eq!(list["active"], "t2");

    // Graceful stop must return promptly (the wedged-daemon case used to hang
    // `daemon stop` forever; the client timeout bounds it now).
    let start = Instant::now();
    cli_ok(&["daemon", "stop"]);
    assert!(
        start.elapsed() < Duration::from_secs(30),
        "daemon stop took too long"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
