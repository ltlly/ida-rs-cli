//! Router process: public Unix socket front-end + one worker per target.
//!
//! The router holds no IDB itself. `target.load` spawns a worker subprocess
//! (`ida-rs-cli daemon worker --sock <path> --id <n>`) which opens the IDB in
//! its own process; analysis requests are forwarded to the target's worker.
//! Because workers are separate processes, a wedged load/analysis can never
//! block the router or other targets (this is what makes multi-target safe
//! with idalib's one-IDB-per-process semantics).

use crate::daemon::protocol::{Request, Response};
use crate::daemon::target::{effective_idb_out, expand_path, TargetInfo};
use crate::daemon::worker::parse_addr;
use crate::daemon::{
    read_line_capped, registry_path, socket_path, worker_socket_path, MAX_LINE_BYTES,
    WORKER_BOOT_TIMEOUT_SECS, WORKER_CONNECT_TIMEOUT_SECS, WORKER_OP_TIMEOUT_SECS,
    WORKER_STOP_TIMEOUT_SECS,
};

use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, Notify};
use tracing::{error, info, warn};

/// A loaded target: its metadata plus the worker subprocess serving it.
struct WorkerEntry {
    info: TargetInfo,
    sock: PathBuf,
    /// Canonical input path (duplicate-load detection).
    canon_path: PathBuf,
    /// Canonical path of the on-disk database this target uses: the IDB
    /// output path for raw binaries, the input itself for existing IDBs.
    /// This is the identity that must stay unique across targets.
    db_identity: PathBuf,
    child: Child,
    /// Serializes in-flight requests to this worker.
    op_lock: Arc<Mutex<()>>,
}

#[derive(Default)]
struct RouterState {
    targets: HashMap<String, WorkerEntry>,
    active: Option<String>,
    next_id: u64,
}

impl RouterState {
    fn new() -> Self {
        Self {
            targets: HashMap::new(),
            active: None,
            next_id: 1,
        }
    }

    fn alloc_id(&mut self) -> String {
        let id = format!("t{}", self.next_id);
        self.next_id += 1;
        id
    }

    /// Resolve a selector to a target ID. Selector may be an exact target ID,
    /// a filename/path substring, or None/"active"/"" for the active target.
    fn resolve(&self, selector: Option<&str>) -> Result<String, String> {
        resolve_selector(
            selector,
            self.active.as_deref(),
            self.targets
                .iter()
                .map(|(id, e)| (id.as_str(), e.info.filename.as_str(), e.info.path.as_str())),
        )
    }
}

/// Pure selector resolution shared semantics with `TargetManager::resolve`.
fn resolve_selector<'a, I>(
    selector: Option<&str>,
    active: Option<&str>,
    entries: I,
) -> Result<String, String>
where
    I: Iterator<Item = (&'a str, &'a str, &'a str)>, // (id, filename, path)
{
    let entries: Vec<_> = entries.collect();
    if entries.is_empty() {
        return Err("No targets loaded. Use 'target load -f <path>' first.".to_string());
    }
    match selector {
        None | Some("active") | Some("") => active
            .map(|s| s.to_string())
            .ok_or_else(|| "No active target".to_string()),
        Some(sel) => {
            if entries.iter().any(|(id, _, _)| *id == sel) {
                return Ok(sel.to_string());
            }
            let matches: Vec<&str> = entries
                .iter()
                .filter(|(_, filename, path)| filename.contains(sel) || path.contains(sel))
                .map(|(id, _, _)| *id)
                .collect();
            match matches.len() {
                0 => Err(format!("No target matching '{}'", sel)),
                1 => Ok(matches[0].to_string()),
                _ => Err(format!(
                    "Ambiguous selector '{}': matches {} targets",
                    sel,
                    matches.len()
                )),
            }
        }
    }
}

/// Lowest-numbered "t<N>" among `ids` (deterministic active fallback).
fn lowest_target_id<'a, I: Iterator<Item = &'a String>>(ids: I) -> Option<String> {
    ids.min_by_key(|id| {
        id.strip_prefix('t')
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(u64::MAX)
    })
    .cloned()
}

/// Canonicalize a path even if it does not exist yet: resolve the parent
/// directory and re-attach the file name. This matters on macOS where
/// $TMPDIR lives under /var (a symlink to /private/var) - without it, the
/// same database file compares unequal depending on which form was passed.
fn canonicalize_lenient(path: &Path) -> PathBuf {
    if let Ok(c) = fs::canonicalize(path) {
        return c;
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name())
        && let Ok(canon_parent) = fs::canonicalize(parent)
    {
        return canon_parent.join(name);
    }
    path.to_path_buf()
}

/// Check a candidate load against existing targets. Returns the conflicting
/// target ID on a duplicate input path or a clashing database identity (the
/// raw-binary `x` and the database `x.i64` derived from it share an identity).
fn find_load_conflict<'a, I>(
    canon_path: &Path,
    db_identity: &Path,
    existing: I,
) -> Option<String>
where
    I: Iterator<Item = (&'a str, &'a Path, &'a Path)>, // (id, canon_path, db_identity)
{
    for (id, other_path, other_identity) in existing {
        if other_path == canon_path {
            return Some(format!("input already loaded as {}", id));
        }
        if other_identity == db_identity {
            return Some(format!(
                "database {} is already in use by {}",
                db_identity.display(),
                id
            ));
        }
    }
    None
}

/// Entry point for `ida-rs-cli daemon start` (foreground).
pub fn run_router() -> anyhow::Result<()> {
    let sock_path = socket_path();
    if let Some(parent) = sock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir_all(crate::daemon::worker_dir())?;

    ensure_single_instance(&sock_path)?;
    sweep_stale_worker_sockets();

    // Bind before writing the registry: a racing second daemon fails here
    // and exits before it can remove the winner's socket/registry files.
    let std_listener = std::os::unix::net::UnixListener::bind(&sock_path)
        .map_err(|e| anyhow::anyhow!("Failed to bind socket {}: {}", sock_path.display(), e))?;
    std_listener.set_nonblocking(true)?;

    write_registry(&sock_path)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()?;

    let result = rt.block_on(run_accept_loop(sock_path.clone(), std_listener));

    // Cleanup on the way out (workers were already shut down).
    let _ = fs::remove_file(&sock_path);
    let _ = fs::remove_file(registry_path());
    info!("Daemon stopped");
    result
}

/// Refuse to start when another live daemon owns the socket; otherwise remove
/// stale socket/registry left behind by a crashed or killed daemon.
fn ensure_single_instance(sock_path: &Path) -> anyhow::Result<()> {
    if !sock_path.exists() {
        return Ok(());
    }
    if ping_socket(sock_path, Duration::from_secs(2)) {
        let pid_hint = std::fs::read_to_string(registry_path())
            .ok()
            .and_then(|c| serde_json::from_str::<Value>(&c).ok())
            .and_then(|v| v.get("pid").and_then(|p| p.as_u64()))
            .map(|p| format!(" (pid {})", p))
            .unwrap_or_default();
        anyhow::bail!(
            "Daemon is already running{}. Use 'ida-rs-cli daemon stop' first.",
            pid_hint
        );
    }
    warn!("Removing stale socket {}", sock_path.display());
    fs::remove_file(sock_path)?;
    let _ = fs::remove_file(registry_path());
    Ok(())
}

/// Remove worker sockets whose owner is gone. Connectable ones belong to
/// orphan workers that are still alive; those exit on their own once they
/// notice the dead router's stdin pipe closing, so leave them alone.
fn sweep_stale_worker_sockets() {
    let dir = crate::daemon::worker_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("sock") {
            continue;
        }
        if !ping_socket(&path, Duration::from_millis(200)) {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Connect to a daemon/worker socket and send a ping; true when it answers.
fn ping_socket(path: &Path, timeout: Duration) -> bool {
    use std::io::{Read, Write};
    let stream = match std::os::unix::net::UnixStream::connect(path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut stream = stream;
    let req = json!({"id": "ping", "op": "ping", "params": {}});
    if stream
        .write_all(format!("{}\n", serde_json::to_string(&req).unwrap()).as_bytes())
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 4096];
    matches!(stream.read(&mut buf), Ok(n) if n > 0)
}

fn write_registry(sock_path: &Path) -> anyhow::Result<()> {
    let reg_path = registry_path();
    if let Some(parent) = reg_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let registry = json!({
        "pid": std::process::id(),
        "socket": sock_path.display().to_string(),
        "started_at": secs,
        "version": env!("CARGO_PKG_VERSION"),
    });
    let mut file = fs::File::create(&reg_path)?;
    use std::io::Write as _;
    file.write_all(serde_json::to_string_pretty(&registry)?.as_bytes())?;
    Ok(())
}

async fn run_accept_loop(
    sock_path: PathBuf,
    std_listener: std::os::unix::net::UnixListener,
) -> anyhow::Result<()> {
    let listener = UnixListener::from_std(std_listener)?;
    info!("Daemon ready. Socket: {}", sock_path.display());

    let state = Arc::new(Mutex::new(RouterState::new()));
    let shutdown = Arc::new(Notify::new());
    // Serializes target.load so duplicate checks stay atomic.
    let load_lock = Arc::new(Mutex::new(()));

    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("Shutdown complete, daemon exiting");
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let st = state.clone();
                        let sd = shutdown.clone();
                        let ll = load_lock.clone();
                        tokio::spawn(async move {
                            handle_connection(stream, st, sd, ll).await;
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_connection(
    stream: UnixStream,
    state: Arc<Mutex<RouterState>>,
    shutdown: Arc<Notify>,
    load_lock: Arc<Mutex<()>>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line_buf: Vec<u8> = Vec::new();

    loop {
        line_buf.clear();
        match read_line_capped(&mut reader, &mut line_buf, MAX_LINE_BYTES).await {
            Ok(0) => break, // clean EOF
            Ok(_) => {}
            Err(e) => {
                let err = Response::error("?".to_string(), format!("Read error: {}", e));
                let _ = write_response(&mut writer, &err).await;
                break;
            }
        }

        let line = String::from_utf8_lossy(&line_buf).trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err = Response::error("?".to_string(), format!("Invalid JSON: {}", e));
                let _ = write_response(&mut writer, &err).await;
                continue;
            }
        };

        let is_shutdown = request.op == "shutdown";
        let response = route_request(&state, &load_lock, request).await;
        if write_response(&mut writer, &response).await.is_err() {
            break;
        }

        if is_shutdown {
            // The client has its ack. Stop accepting, drop the public socket
            // so a new daemon may start, then shut workers down and exit.
            shutdown.notify_one();
            let _ = fs::remove_file(socket_path());
            let _ = fs::remove_file(registry_path());
            shutdown_all_workers(&state).await;
            break;
        }
    }
}

async fn route_request(
    state: &Arc<Mutex<RouterState>>,
    load_lock: &Arc<Mutex<()>>,
    request: Request,
) -> Response {
    let id = request.id.clone();
    match route_inner(state, load_lock, &request).await {
        Ok(result) => Response::success(id, result),
        Err(e) => Response::error(id, e),
    }
}

async fn route_inner(
    state: &Arc<Mutex<RouterState>>,
    load_lock: &Arc<Mutex<()>>,
    req: &Request,
) -> Result<Value, String> {
    let p = &req.params;

    match req.op.as_str() {
        "ping" => {
            let n = state.lock().await.targets.len();
            Ok(json!({"pong": true, "targets": n}))
        }

        "shutdown" => {
            info!("Shutdown requested via socket");
            Ok(json!({"status": "shutting_down"}))
        }

        "int_convert" => {
            let v = p
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing parameter: value".to_string())?;
            let val = parse_addr(v)?;
            Ok(json!({
                "decimal": val,
                "hex": format!("{:#x}", val),
                "octal": format!("{:#o}", val),
                "binary": format!("{:#b}", val),
                "signed": val as i64,
            }))
        }

        "target.load" => handle_target_load(state, load_lock, req).await,

        "target.list" => {
            let st = state.lock().await;
            let mut list: Vec<TargetInfo> = st.targets.values().map(|e| e.info.clone()).collect();
            // Deterministic order: by numeric target id.
            list.sort_by_key(|t| {
                t.id.strip_prefix('t')
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(u64::MAX)
            });
            Ok(json!({"targets": list, "active": st.active}))
        }

        "target.switch" => {
            let sel = param_str(p, "id")?;
            let mut st = state.lock().await;
            let id = st.resolve(Some(sel))?;
            st.active = Some(id.clone());
            Ok(json!({"active": id}))
        }

        "target.close" => {
            let sel = param_str(p, "id")?;
            // Remove the entry first so later ops fail fast, then stop the
            // worker outside the state lock.
            let (id, entry) = {
                let mut st = state.lock().await;
                let id = st.resolve(Some(sel))?;
                let entry = st
                    .targets
                    .remove(&id)
                    .ok_or_else(|| format!("Target not found: {}", id))?;
                if st.active.as_deref() == Some(id.as_str()) {
                    st.active = lowest_target_id(st.targets.keys());
                }
                (id, entry)
            };
            stop_worker(entry).await;
            Ok(json!({"closed": id}))
        }

        // Analysis ops: resolve locally, then forward to the target's worker.
        _ => {
            let (target_id, sock, op_lock) = {
                let st = state.lock().await;
                let id = st.resolve(req.target.as_deref())?;
                let entry = st
                    .targets
                    .get(&id)
                    .ok_or_else(|| format!("Target not found: {}", id))?;
                (id, entry.sock.clone(), entry.op_lock.clone())
            };

            // One in-flight request per worker: its dispatch loop is serial
            // anyway, and this keeps ordering deterministic.
            let _permit = op_lock.lock().await;

            let mut forwarded = req.clone();
            // The worker holds exactly one target carrying the router's ID.
            forwarded.target = None;
            let timeout = op_timeout();
            match forward_to_worker(&sock, &forwarded, timeout).await {
                Ok(resp) if resp.ok => Ok(resp.result.unwrap_or(Value::Null)),
                Ok(resp) => Err(resp.error.unwrap_or_else(|| "worker error".to_string())),
                Err(e) => Err(format!("worker for target {}: {}", target_id, e)),
            }
        }
    }
}

async fn handle_target_load(
    state: &Arc<Mutex<RouterState>>,
    load_lock: &Arc<Mutex<()>>,
    req: &Request,
) -> Result<Value, String> {
    let p = &req.params;
    let path = p
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing parameter: path".to_string())?;
    let auto_analyse = p
        .get("auto_analyse")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let idb_out = p.get("idb_out").and_then(|v| v.as_str());

    let expanded = expand_path(path);
    if !expanded.exists() {
        return Err(format!("File not found: {}", expanded.display()));
    }
    let canon_path = canonicalize_lenient(&expanded);
    // The on-disk database identity: for raw binaries the IDB output file
    // (existing or to-be-created), for IDB inputs the input itself.
    let db_identity = match effective_idb_out(&expanded, idb_out) {
        Some(out) => canonicalize_lenient(&out),
        None => canon_path.clone(),
    };

    let _load_permit = load_lock.lock().await;

    // Duplicate / database-identity conflict checks against existing targets.
    let conflict = {
        let st = state.lock().await;
        find_load_conflict(
            &canon_path,
            &db_identity,
            st.targets.iter().map(|(id, e)| {
                (id.as_str(), e.canon_path.as_path(), e.db_identity.as_path())
            }),
        )
    };
    if let Some(conflict) = conflict {
        return Err(format!("{}: {}", expanded.display(), conflict));
    }

    let id = state.lock().await.alloc_id();

    info!(target_id = %id, path = %expanded.display(), "Spawning worker for target");
    let (child, sock) = spawn_worker(&id).await?;

    // Forward the original load request into the fresh worker.
    let load_req = Request {
        id: req.id.clone(),
        op: "target.load".to_string(),
        params: json!({
            "path": expanded.display().to_string(),
            "auto_analyse": auto_analyse,
            "idb_out": idb_out,
        }),
        target: None,
    };
    let timeout = op_timeout();
    let (child, mut info) = match worker_load_handshake(child, &sock, &load_req, timeout).await {
        Ok(ok) => ok,
        Err(e) => return Err(format!("load failed: {}", e)),
    };
    info.id = id.clone();

    let entry = WorkerEntry {
        info: info.clone(),
        sock,
        canon_path,
        db_identity,
        child,
        op_lock: Arc::new(Mutex::new(())),
    };
    {
        let mut st = state.lock().await;
        if st.active.is_none() {
            st.active = Some(id.clone());
        }
        st.targets.insert(id.clone(), entry);
    }
    serde_json::to_value(&info).map_err(|e| e.to_string())
}

/// Forward the load request into a freshly spawned worker and parse the
/// resulting TargetInfo. On any failure the worker is killed and its socket
/// removed, so a failed load never leaks a subprocess.
async fn worker_load_handshake(
    child: Child,
    sock: &Path,
    load_req: &Request,
    timeout: Duration,
) -> Result<(Child, TargetInfo), String> {
    let result = async {
        let resp = forward_to_worker(sock, load_req, timeout).await?;
        if !resp.ok {
            return Err(resp.error.unwrap_or_else(|| "worker load failed".to_string()));
        }
        let info: TargetInfo = serde_json::from_value(
            resp.result
                .ok_or_else(|| "worker load returned no result".to_string())?,
        )
        .map_err(|e| format!("invalid worker load result: {}", e))?;
        Ok(info)
    }
    .await;
    match result {
        Ok(info) => Ok((child, info)),
        Err(e) => {
            stop_worker_child(child, sock).await;
            Err(e)
        }
    }
}

/// Spawn a worker subprocess and wait for its socket to accept connections.
async fn spawn_worker(id: &str) -> Result<(Child, PathBuf), String> {
    let sock = worker_socket_path(id);
    let _ = fs::remove_file(&sock);

    let exe = std::env::current_exe().map_err(|e| format!("cannot locate own exe: {}", e))?;
    let mut cmd = Command::new(exe);
    cmd.arg("daemon")
        .arg("worker")
        .arg("--sock")
        .arg(&sock)
        .arg("--id")
        .arg(id)
        // stdin doubles as the liveness watchdog channel: the worker exits
        // when this pipe closes (i.e. when the router dies).
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn worker: {}", e))?;

    let deadline = Instant::now() + Duration::from_secs(WORKER_BOOT_TIMEOUT_SECS);
    loop {
        match UnixStream::connect(&sock).await {
            Ok(_) => return Ok((child, sock)),
            Err(_) => {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        return Err(format!("worker exited during boot: {}", status));
                    }
                    Ok(None) => {}
                    Err(e) => return Err(format!("worker wait error: {}", e)),
                }
                if Instant::now() >= deadline {
                    let _ = child.kill().await;
                    return Err(format!(
                        "worker did not come up within {}s",
                        WORKER_BOOT_TIMEOUT_SECS
                    ));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Shut down every loaded worker (router shutdown path).
async fn shutdown_all_workers(state: &Arc<Mutex<RouterState>>) {
    let entries: Vec<WorkerEntry> = {
        let mut st = state.lock().await;
        st.targets.drain().map(|(_, e)| e).collect()
    };
    for entry in entries {
        stop_worker(entry).await;
    }
}

/// Politely stop a worker (shutdown op), escalating to SIGKILL on timeout.
async fn stop_worker(entry: WorkerEntry) {
    let sock = entry.sock.clone();
    let mut child = entry.child;
    let shutdown_req = Request {
        id: "router-shutdown".to_string(),
        op: "shutdown".to_string(),
        params: json!({}),
        target: None,
    };
    let resp = forward_to_worker(&sock, &shutdown_req, Duration::from_secs(WORKER_STOP_TIMEOUT_SECS)).await;
    if let Err(e) = resp {
        warn!("worker shutdown request failed ({}); killing", e);
    }
    wait_child(&mut child, &sock).await;
}

/// Wait for a worker child to exit; SIGKILL after the grace period, then
/// remove its socket file.
async fn wait_child(child: &mut Child, sock: &Path) {
    let wait = tokio::time::timeout(Duration::from_secs(WORKER_STOP_TIMEOUT_SECS), child.wait()).await;
    match wait {
        Ok(Ok(status)) => info!("worker exited: {}", status),
        Ok(Err(e)) => warn!("worker wait error: {}", e),
        Err(_) => {
            warn!("worker did not exit in {}s, killing", WORKER_STOP_TIMEOUT_SECS);
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }
    let _ = fs::remove_file(sock);
}

/// Stop a worker that never finished loading (no entry was recorded).
async fn stop_worker_child(mut child: Child, sock: &Path) {
    let _ = child.kill().await;
    let _ = child.wait().await;
    let _ = fs::remove_file(sock);
}

/// Send a request to a worker socket and read one response, bounded by
/// `timeout` for the whole connect+write+read round trip.
async fn forward_to_worker(
    sock: &Path,
    request: &Request,
    timeout: Duration,
) -> Result<Response, String> {
    let fut = async {
        let mut stream = tokio::time::timeout(
            Duration::from_secs(WORKER_CONNECT_TIMEOUT_SECS),
            UnixStream::connect(sock),
        )
        .await
        .map_err(|_| format!("connect timed out ({}s)", WORKER_CONNECT_TIMEOUT_SECS))?
        .map_err(|e| format!("connect failed: {}", e))?;

        let line = serde_json::to_string(request).map_err(|e| e.to_string())?;
        stream
            .write_all(line.as_bytes())
            .await
            .map_err(|e| format!("write failed: {}", e))?;
        stream
            .write_all(b"\n")
            .await
            .map_err(|e| format!("write failed: {}", e))?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(stream);
        let mut buf = Vec::new();
        read_line_capped(&mut reader, &mut buf, MAX_LINE_BYTES)
            .await
            .map_err(|e| format!("read failed: {}", e))?;
        if buf.is_empty() {
            return Err("worker closed connection without responding".to_string());
        }
        serde_json::from_slice::<Response>(&buf)
            .map_err(|e| format!("invalid worker response: {}", e))
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| format!("operation timed out after {}s", timeout.as_secs()))?
}

fn op_timeout() -> Duration {
    let secs = std::env::var("IDA_CLI_OP_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(WORKER_OP_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

fn param_str<'a>(p: &'a Value, key: &str) -> Result<&'a str, String> {
    p.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Missing parameter: {}", key))
}

async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    response: &Response,
) -> std::io::Result<()> {
    let line = match serde_json::to_string(response) {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to serialize response {}: {}", response.id, e);
            serde_json::to_string(&Response::error(
                response.id.clone(),
                format!("Internal: response serialization failed: {}", e),
            ))
            .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"serialization\"}".to_string())
        }
    };
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries<'a>(v: &'a [(String, String, String)]) -> impl Iterator<Item = (&'a str, &'a str, &'a str)> {
        v.iter()
            .map(|(id, f, p)| (id.as_str(), f.as_str(), p.as_str()))
    }

    #[test]
    fn resolve_selector_exact_substring_active() {
        let v = vec![
            ("t1".to_string(), "libalpha.so".to_string(), "/tmp/libalpha.so".to_string()),
            ("t2".to_string(), "beta.bin".to_string(), "/work/beta.bin".to_string()),
        ];
        assert_eq!(resolve_selector(Some("t2"), Some("t1"), entries(&v)).unwrap(), "t2");
        assert_eq!(resolve_selector(Some("alpha"), Some("t1"), entries(&v)).unwrap(), "t1");
        assert_eq!(resolve_selector(None, Some("t2"), entries(&v)).unwrap(), "t2");
        assert_eq!(resolve_selector(Some("active"), Some("t2"), entries(&v)).unwrap(), "t2");
        assert!(resolve_selector(Some("/"), Some("t1"), entries(&v)).is_err()); // ambiguous
        assert!(resolve_selector(Some("zzz"), Some("t1"), entries(&v)).is_err()); // no match
        assert!(resolve_selector(None, None, entries(&v)).is_err()); // no active
        let empty: Vec<(String, String, String)> = vec![];
        assert!(resolve_selector(None, None, entries(&empty)).is_err());
    }

    #[test]
    fn lowest_target_id_picks_smallest_number() {
        let v: Vec<String> = vec!["t10".into(), "t2".into(), "t3".into()];
        assert_eq!(lowest_target_id(v.iter()).as_deref(), Some("t2"));
        let empty: Vec<String> = vec![];
        assert_eq!(lowest_target_id(empty.iter()), None);
    }

    #[test]
    fn find_load_conflict_detects_same_input_and_shared_database() {
        let existing: Vec<(String, PathBuf, PathBuf)> = vec![
            // t1: raw binary -> derived .i64 identity
            (
                "t1".into(),
                PathBuf::from("/a/x.so"),
                PathBuf::from("/a/x.so.i64"),
            ),
            // t2: IDB input -> identity is the input itself
            ("t2".into(), PathBuf::from("/b/y.i64"), PathBuf::from("/b/y.i64")),
        ];
        let iter = || {
            existing
                .iter()
                .map(|(id, p, i)| (id.as_str(), p.as_path(), i.as_path()))
        };
        // Same raw input again -> conflict with t1.
        assert_eq!(
            find_load_conflict(Path::new("/a/x.so"), Path::new("/a/x.so.i64"), iter()),
            Some("input already loaded as t1".to_string())
        );
        // Loading the derived database directly shares t1's identity.
        assert_eq!(
            find_load_conflict(Path::new("/a/x.so.i64"), Path::new("/a/x.so.i64"), iter()),
            Some("database /a/x.so.i64 is already in use by t1".to_string())
        );
        // A raw binary whose derived output would clobber t2's open database.
        assert_eq!(
            find_load_conflict(Path::new("/b/y"), Path::new("/b/y.i64"), iter()),
            Some("database /b/y.i64 is already in use by t2".to_string())
        );
        // Unrelated load -> no conflict.
        assert_eq!(
            find_load_conflict(Path::new("/c/z.so"), Path::new("/c/z.so.i64"), iter()),
            None
        );
    }

    #[test]
    fn canonicalize_lenient_resolves_symlinked_parents() {
        // Existing file: fully canonicalized.
        let real = std::env::temp_dir().join(format!("ida-canon-test-{}", std::process::id()));
        fs::create_dir_all(&real).unwrap();
        let f = real.join("x.i64");
        fs::write(&f, b"").unwrap();
        assert_eq!(canonicalize_lenient(&f), fs::canonicalize(&f).unwrap());

        // Non-existent file in an existing dir: parent is canonicalized.
        let missing = real.join("not-there-yet.i64");
        assert_eq!(
            canonicalize_lenient(&missing),
            fs::canonicalize(&real).unwrap().join("not-there-yet.i64")
        );

        // Non-existent dir: returned unchanged rather than failing.
        let nowhere = Path::new("/definitely/not/a/real/dir/x.i64");
        assert_eq!(canonicalize_lenient(nowhere), nowhere.to_path_buf());
        let _ = fs::remove_dir_all(&real);
    }

    #[test]
    fn ping_socket_fails_on_missing_file() {
        assert!(!ping_socket(
            Path::new("/nonexistent/ida-rs-cli-test.sock"),
            Duration::from_millis(100)
        ));
    }

    #[test]
    fn pid_alive_smoke() {
        assert!(crate::daemon::pid_alive(std::process::id()));
    }
}
