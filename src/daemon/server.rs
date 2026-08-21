//! Daemon server: Unix socket listener + IDA main-thread dispatch.
//!
//! Architecture:
//! - Main thread: IDA init -> loops receiving (Request, oneshot::Sender<Response>)
//!   from a channel, dispatches on TargetManager, sends Response back.
//! - Tokio thread: Accepts Unix socket connections, reads JSON-line requests,
//!   sends them to main thread via channel, awaits response, writes back.

use crate::daemon::protocol::{Request, Response};
use crate::daemon::target::TargetManager;
use crate::daemon::{registry_path, socket_path};
use crate::ida::handlers;

use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::oneshot;
use tracing::{error, info};

/// Message sent from the socket server to the IDA main thread.
struct WorkItem {
    request: Request,
    reply_tx: oneshot::Sender<Response>,
}

/// Run the daemon (foreground mode). This function blocks forever.
pub fn run_daemon(foreground: bool) -> anyhow::Result<()> {
    let sock_path = socket_path();
    if let Some(parent) = sock_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Remove stale socket
    if sock_path.exists() {
        fs::remove_file(&sock_path)?;
    }

    // Initialize IDA library on main thread
    info!("Initializing IDA library...");
    idalib::init_library()
        .map_err(|e| anyhow::anyhow!("IDA library initialization failed: {e}"))?;
    // Suppress IDA's "Thank you for using IDA" goodbye message on exit
    let _ = idalib::enable_console_messages(false);
    info!("IDA library initialized");

    // Channel: socket thread -> main thread
    let (work_tx, work_rx) = mpsc::sync_channel::<WorkItem>(64);

    // Write registry
    write_registry(&sock_path)?;

    // Spawn tokio thread for socket server
    let sock_path_clone = sock_path.clone();
    let _server_handle = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("Failed to create tokio runtime");

        rt.block_on(async move {
            run_socket_server(&sock_path_clone, work_tx).await;
        });
    });

    info!("Daemon ready. Socket: {}", sock_path.display());
    if !foreground {
        info!("Running in foreground mode (use Ctrl+C to stop)");
    }

    // Main thread: IDA dispatch loop
    let mut target_mgr = TargetManager::new();

    loop {
        match work_rx.recv() {
            Ok(item) => {
                let is_shutdown = item.request.op == "shutdown";
                let response = dispatch_request(&mut target_mgr, item.request);
                let _ = item.reply_tx.send(response);
                if is_shutdown {
                    info!("Shutdown complete, exiting main loop");
                    // Give the socket handler a moment to flush the response
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    break;
                }
            }
            Err(_) => {
                info!("Work channel closed, daemon shutting down");
                break;
            }
        }
    }

    // Cleanup
    let _ = fs::remove_file(&sock_path);
    let _ = fs::remove_file(registry_path());
    info!("Daemon stopped");
    Ok(())
}

fn write_registry(sock_path: &PathBuf) -> anyhow::Result<()> {
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
    file.write_all(serde_json::to_string_pretty(&registry)?.as_bytes())?;
    Ok(())
}

async fn run_socket_server(sock_path: &PathBuf, work_tx: mpsc::SyncSender<WorkItem>) {
    let listener = match UnixListener::bind(sock_path) {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind socket {}: {}", sock_path.display(), e);
            return;
        }
    };

    info!("Socket server listening on {}", sock_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let tx = work_tx.clone();
                tokio::spawn(async move {
                    handle_connection(stream, tx).await;
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
                break;
            }
        }
    }
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    work_tx: mpsc::SyncSender<WorkItem>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
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

        let req_id = request.id.clone();
        let (reply_tx, reply_rx) = oneshot::channel();

        if work_tx.send(WorkItem { request, reply_tx }).is_err() {
            let err = Response::error(req_id, "Daemon shutting down");
            let _ = write_response(&mut writer, &err).await;
            break;
        }

        match reply_rx.await {
            Ok(response) => {
                let _ = write_response(&mut writer, &response).await;
            }
            Err(_) => {
                let err = Response::error(req_id, "Internal: reply dropped");
                let _ = write_response(&mut writer, &err).await;
            }
        }
    }
}

async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    response: &Response,
) -> std::io::Result<()> {
    let line = serde_json::to_string(response).unwrap_or_default();
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Request dispatch (runs on IDA main thread)
// ---------------------------------------------------------------------------

fn dispatch_request(mgr: &mut TargetManager, req: Request) -> Response {
    let id = req.id.clone();
    match dispatch_inner(mgr, &req) {
        Ok(result) => Response::success(id, result),
        Err(e) => Response::error(id, e),
    }
}

fn dispatch_inner(mgr: &mut TargetManager, req: &Request) -> Result<Value, String> {
    let p = &req.params;

    match req.op.as_str() {
        // -- Target management --
        "target.load" => {
            let path = param_str(p, "path")?;
            let auto_analyse = param_bool(p, "auto_analyse", true);
            let idb_out = p.get("idb_out").and_then(|v| v.as_str());
            let info = mgr.load(path, auto_analyse, idb_out)?;
            to_json(&info)
        }

        "target.close" => {
            let id = param_str(p, "id")?;
            mgr.close(id)?;
            Ok(json!({"closed": id}))
        }

        "target.list" => {
            let list = mgr.list();
            let active = mgr.active_id().map(|s| s.to_string());
            Ok(json!({"targets": list, "active": active}))
        }

        "target.switch" => {
            let id = param_str(p, "id")?;
            mgr.set_active(id)?;
            Ok(json!({"active": id}))
        }

        "ping" => Ok(json!({"pong": true, "targets": mgr.list().len()})),

        "shutdown" => {
            info!("Shutdown requested via socket");
            Ok(json!({"status": "shutting_down"}))
        }

        "int_convert" => {
            let v = param_str(p, "value")?;
            let val = parse_addr(v)?;
            Ok(json!({
                "decimal": val,
                "hex": format!("{:#x}", val),
                "octal": format!("{:#o}", val),
                "binary": format!("{:#b}", val),
                "signed": val as i64,
            }))
        }

        // -- Analysis ops (require resolved target) --
        _ => dispatch_analysis(mgr, req),
    }
}

fn dispatch_analysis(mgr: &mut TargetManager, req: &Request) -> Result<Value, String> {
    let target_id = mgr.resolve(req.target.as_deref())?;
    let p = &req.params;

    match req.op.as_str() {
        "info" => {
            let idb = mgr.get_idb(&target_id)?;
            let db = idb.as_ref().ok_or("IDB is None")?;
            let meta = db.meta();
            Ok(json!({
                "target": target_id,
                "file_type": format!("{:?}", meta.filetype()),
                "processor": db.processor().long_name(),
                "bits": if meta.is_64bit() { 64 } else if meta.is_32bit_exactly() { 32 } else { 16 },
                "function_count": db.function_count(),
                "analysis_status": handlers::analysis::build_analysis_status(db),
            }))
        }

        "meta" => {
            let idb = mgr.get_idb(&target_id)?;
            handlers::globals::handle_idb_meta(idb).map_err(te).and_then(to_json_v)
        }

        "analysis_status" => {
            let idb = mgr.get_idb(&target_id)?;
            handlers::analysis::handle_analysis_status(idb).map_err(te).and_then(to_json_v)
        }

        "functions" | "list_functions" => {
            let idb = mgr.get_idb(&target_id)?;
            let offset = param_usize(p, "offset", 0);
            let limit = param_usize(p, "limit", 100);
            let filter = p.get("filter").and_then(|v| v.as_str());
            handlers::functions::handle_list_functions(idb, offset, limit, filter)
                .map_err(te).and_then(to_json_v)
        }

        "resolve_function" => {
            let idb = mgr.get_idb(&target_id)?;
            let name = param_str(p, "name")?;
            handlers::functions::handle_resolve_function(idb, name)
                .map_err(te).and_then(to_json_v)
        }

        "function_at" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            handlers::functions::handle_function_at(idb, addr)
                .map_err(te).and_then(to_json_v)
        }

        "lookup_funcs" => {
            let idb = mgr.get_idb(&target_id)?;
            let queries = param_str_vec(p, "queries");
            handlers::functions::handle_lookup_funcs(idb, &queries).map_err(te)
        }

        "analyze_funcs" => {
            let idb = mgr.get_idb_mut(&target_id)?;
            handlers::functions::handle_analyze_funcs(idb, None, None).map_err(te)
        }

        "disasm" => {
            let idb = mgr.get_idb(&target_id)?;
            let offset = param_usize(p, "offset", 0);
            let count = param_usize(p, "count", 20);
            // Fetch extra lines for offset, then slice
            let total = count + offset;
            if let Some(name) = p.get("name").and_then(|v| v.as_str()) {
                handlers::disasm::handle_disasm_by_name(idb, name, total)
                    .map_err(te)
                    .map(|s| {
                        let text = apply_line_offset(&s, offset);
                        json!({"disasm": text})
                    })
            } else {
                let addr = param_addr(p, "address")?;
                handlers::disasm::handle_disasm(idb, addr, total)
                    .map_err(te)
                    .map(|s| {
                        let text = apply_line_offset(&s, offset);
                        json!({"disasm": text})
                    })
            }
        }

        "disasm_function_at" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            let offset = param_usize(p, "offset", 0);
            let count = param_usize(p, "count", 200);
            let total = count + offset;
            handlers::disasm::handle_disasm_function_at(idb, addr, total)
                .map_err(te)
                .map(|s| {
                    let text = apply_line_offset(&s, offset);
                    json!({"disasm": text, "has_more": false})
                })
        }

        "decompile" => {
            let idb = mgr.get_idb(&target_id)?;
            let max_lines = param_usize(p, "max_lines", 0);
            let addr = if let Some(name) = p.get("name").and_then(|v| v.as_str()) {
                let func = handlers::functions::handle_resolve_function(idb, name).map_err(te)?;
                parse_addr(&func.address)?
            } else {
                param_addr(p, "address")?
            };
            handlers::disasm::handle_decompile(idb, addr)
                .map_err(te)
                .map(|s| {
                    let text = apply_max_lines(&s, max_lines);
                    json!({"pseudocode": text})
                })
        }

        "pseudocode_at" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            let end = p.get("end_address").and_then(|v| v.as_str())
                .map(parse_addr).transpose()?;
            handlers::disasm::handle_pseudocode_at(idb, addr, end).map_err(te)
        }

        "strings" => {
            let idb = mgr.get_idb(&target_id)?;
            let offset = param_usize(p, "offset", 0);
            let limit = param_usize(p, "limit", 100);
            let filter = p.get("filter").and_then(|v| v.as_str());
            handlers::strings::handle_strings(idb, offset, limit, filter)
                .map_err(te).and_then(to_json_v)
        }

        "find_string" => {
            let idb = mgr.get_idb(&target_id)?;
            let query = param_str(p, "query")?;
            let exact = param_bool(p, "exact", false);
            let ci = param_bool(p, "case_insensitive", false);
            let offset = param_usize(p, "offset", 0);
            let limit = param_usize(p, "limit", 100);
            handlers::strings::handle_find_string(idb, query, exact, ci, offset, limit)
                .map_err(te).and_then(to_json_v)
        }

        "get_string" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            let max_len = param_usize(p, "max_len", 1024);
            handlers::strings::handle_get_string(idb, addr, max_len).map_err(te)
        }

        "analyze_strings" => {
            let idb = mgr.get_idb(&target_id)?;
            let query = p.get("query").and_then(|v| v.as_str());
            let offset = param_usize(p, "offset", 0);
            let limit = param_usize(p, "limit", 100);
            handlers::strings::handle_analyze_strings(idb, query, offset, limit).map_err(te)
        }

        "xrefs_to_string" => {
            let idb = mgr.get_idb(&target_id)?;
            let query = param_str(p, "query")?;
            let exact = param_bool(p, "exact", false);
            let ci = param_bool(p, "case_insensitive", false);
            let offset = param_usize(p, "offset", 0);
            let limit = param_usize(p, "limit", 100);
            let max_xrefs = param_usize(p, "max_xrefs", 10);
            handlers::strings::handle_xrefs_to_string(idb, query, exact, ci, offset, limit, max_xrefs)
                .map_err(te).and_then(to_json_v)
        }

        "segments" => {
            let idb = mgr.get_idb(&target_id)?;
            handlers::segments::handle_segments(idb).map_err(te).and_then(to_json_v)
        }

        "imports" => {
            let idb = mgr.get_idb(&target_id)?;
            let offset = param_usize(p, "offset", 0);
            let limit = param_usize(p, "limit", 100);
            handlers::imports::handle_imports(idb, offset, limit).map_err(te).and_then(to_json_v)
        }

        "exports" | "export_funcs" => {
            let idb = mgr.get_idb(&target_id)?;
            let offset = param_usize(p, "offset", 0);
            let limit = param_usize(p, "limit", 100);
            handlers::imports::handle_exports(idb, offset, limit).map_err(te).and_then(to_json_v)
        }

        "entrypoints" => {
            let idb = mgr.get_idb(&target_id)?;
            handlers::imports::handle_entrypoints(idb).map_err(te).and_then(to_json_v)
        }

        "globals" | "list_globals" => {
            let idb = mgr.get_idb(&target_id)?;
            let filter = p.get("filter").and_then(|v| v.as_str());
            let offset = param_usize(p, "offset", 0);
            let limit = param_usize(p, "limit", 100);
            handlers::globals::handle_list_globals(idb, filter, offset, limit).map_err(te)
        }

        "get_global_value" => {
            let idb = mgr.get_idb(&target_id)?;
            let query = param_str(p, "query")?;
            handlers::globals::handle_get_global_value(idb, query).map_err(te)
        }

        "xrefs_to" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            let offset = param_usize(p, "offset", 0);
            let limit = param_usize(p, "limit", 1000).clamp(1, 10000);
            handlers::xrefs::handle_xrefs_to(idb, addr, offset, limit).map_err(te).and_then(to_json_v)
        }

        "xrefs_from" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            let offset = param_usize(p, "offset", 0);
            let limit = param_usize(p, "limit", 1000).clamp(1, 10000);
            handlers::xrefs::handle_xrefs_from(idb, addr, offset, limit).map_err(te).and_then(to_json_v)
        }

        "xref_matrix" => {
            let idb = mgr.get_idb(&target_id)?;
            let addrs = param_addr_vec(p, "addresses")?;
            handlers::xrefs::handle_xref_matrix(idb, &addrs).map_err(te)
        }

        "basic_blocks" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            handlers::controlflow::handle_basic_blocks(idb, addr).map_err(te).and_then(to_json_v)
        }

        "callers" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            handlers::controlflow::handle_callers(idb, addr).map_err(te).and_then(to_json_v)
        }

        "callees" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            handlers::controlflow::handle_callees(idb, addr).map_err(te).and_then(to_json_v)
        }

        "callgraph" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            let max_depth = param_usize(p, "max_depth", 3);
            let max_nodes = param_usize(p, "max_nodes", 100);
            handlers::controlflow::handle_callgraph(idb, addr, max_depth, max_nodes).map_err(te)
        }

        "find_paths" => {
            let idb = mgr.get_idb(&target_id)?;
            let start = param_addr(p, "start")?;
            let end = param_addr(p, "end")?;
            let max_paths = param_usize(p, "max_paths", 5);
            let max_depth = param_usize(p, "max_depth", 10);
            handlers::controlflow::handle_find_paths(idb, start, end, max_paths, max_depth).map_err(te)
        }

        "get_bytes" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            let size = param_usize(p, "size", 64);
            handlers::memory::handle_get_bytes(idb, Some(addr), None, 0, size)
                .map_err(te).and_then(to_json_v)
        }

        "read_int" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            let size = param_usize(p, "size", 4);
            handlers::memory::handle_read_int(idb, addr, size).map_err(te)
        }

        "find_bytes" => {
            let idb = mgr.get_idb(&target_id)?;
            let pattern = param_str(p, "pattern")?;
            let limit = param_usize(p, "limit", 100);
            handlers::search::handle_find_bytes(idb, pattern, limit).map_err(te)
        }

        "search_text" => {
            let idb = mgr.get_idb(&target_id)?;
            let text = param_str(p, "text")?;
            let max = param_usize(p, "max_results", 100);
            handlers::search::handle_search_text(idb, text, max).map_err(te)
        }

        "search_imm" => {
            let idb = mgr.get_idb(&target_id)?;
            let v = param_str(p, "value")?;
            let imm = parse_addr(v)?;
            let max = param_usize(p, "max_results", 100);
            handlers::search::handle_search_imm(idb, imm, max).map_err(te)
        }

        "find_insns" => {
            let idb = mgr.get_idb(&target_id)?;
            let patterns = param_str_vec(p, "patterns");
            let max = param_usize(p, "max_results", 100);
            let ci = param_bool(p, "case_insensitive", false);
            handlers::search::handle_find_insns(idb, &patterns, max, ci).map_err(te)
        }

        "find_insn_operands" => {
            let idb = mgr.get_idb(&target_id)?;
            let patterns = param_str_vec(p, "patterns");
            let max = param_usize(p, "max_results", 100);
            let ci = param_bool(p, "case_insensitive", false);
            handlers::search::handle_find_insn_operands(idb, &patterns, max, ci).map_err(te)
        }

        "addr_info" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            handlers::address::handle_addr_info(idb, addr).map_err(te).and_then(to_json_v)
        }

        "local_types" => {
            let idb = mgr.get_idb(&target_id)?;
            let offset = param_usize(p, "offset", 0);
            let limit = param_usize(p, "limit", 100);
            let filter = p.get("filter").and_then(|v| v.as_str());
            handlers::types::handle_local_types(idb, offset, limit, filter)
                .map_err(te).and_then(to_json_v)
        }

        "declare_type" => {
            let idb = mgr.get_idb(&target_id)?;
            let decl = param_str(p, "decl")?;
            let relaxed = param_bool(p, "relaxed", false);
            let replace = param_bool(p, "replace", false);
            let multi = param_bool(p, "multi", false);
            handlers::types::handle_declare_type(idb, decl, relaxed, replace, multi).map_err(te)
        }

        "apply_types" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = p.get("address").and_then(|v| v.as_str()).map(parse_addr).transpose()?;
            let name = p.get("name").and_then(|v| v.as_str());
            let offset = p.get("offset").and_then(|v| v.as_i64()).unwrap_or(0);
            let stack_offset = p.get("stack_offset").and_then(|v| v.as_i64());
            let stack_name = p.get("stack_name").and_then(|v| v.as_str());
            let decl = p.get("decl").and_then(|v| v.as_str());
            let type_name = p.get("type_name").and_then(|v| v.as_str());
            let relaxed = param_bool(p, "relaxed", false);
            let delay = param_bool(p, "delay", false);
            let strict = param_bool(p, "strict", false);
            handlers::types::handle_apply_types(idb, addr, name, offset, stack_offset, stack_name, decl, type_name, relaxed, delay, strict)
                .map_err(te)
        }

        "infer_types" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = p.get("address").and_then(|v| v.as_str()).map(parse_addr).transpose()?;
            let name = p.get("name").and_then(|v| v.as_str());
            let offset = p.get("offset").and_then(|v| v.as_i64()).unwrap_or(0);
            handlers::types::handle_infer_types(idb, addr, name, offset)
                .map_err(te).and_then(to_json_v)
        }

        "stack_frame" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            handlers::types::handle_stack_frame(idb, addr).map_err(te).and_then(to_json_v)
        }

        "declare_stack" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = p.get("address").and_then(|v| v.as_str()).map(parse_addr).transpose()?;
            let name = p.get("name").and_then(|v| v.as_str());
            let offset = p.get("offset").and_then(|v| v.as_i64()).unwrap_or(0);
            let var_name = p.get("var_name").and_then(|v| v.as_str());
            let decl = param_str(p, "decl")?;
            let relaxed = param_bool(p, "relaxed", false);
            handlers::types::handle_declare_stack(idb, addr, name, offset, var_name, decl, relaxed)
                .map_err(te).and_then(to_json_v)
        }

        "delete_stack" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = p.get("address").and_then(|v| v.as_str()).map(parse_addr).transpose()?;
            let name = p.get("name").and_then(|v| v.as_str());
            let offset = p.get("offset").and_then(|v| v.as_i64());
            let var_name = p.get("var_name").and_then(|v| v.as_str());
            handlers::types::handle_delete_stack(idb, addr, name, offset, var_name)
                .map_err(te).and_then(to_json_v)
        }

        "structs" => {
            let idb = mgr.get_idb(&target_id)?;
            let offset = param_usize(p, "offset", 0);
            let limit = param_usize(p, "limit", 100);
            let filter = p.get("filter").and_then(|v| v.as_str());
            handlers::structs::handle_structs(idb, offset, limit, filter)
                .map_err(te).and_then(to_json_v)
        }

        "struct_info" => {
            let idb = mgr.get_idb(&target_id)?;
            let ordinal = p.get("ordinal").and_then(|v| v.as_u64()).map(|v| v as u32);
            let name = p.get("name").and_then(|v| v.as_str());
            handlers::structs::handle_struct_info(idb, ordinal, name)
                .map_err(te).and_then(to_json_v)
        }

        "read_struct" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = param_addr(p, "address")?;
            let ordinal = p.get("ordinal").and_then(|v| v.as_u64()).map(|v| v as u32);
            let name = p.get("name").and_then(|v| v.as_str());
            handlers::structs::handle_read_struct(idb, addr, ordinal, name)
                .map_err(te).and_then(to_json_v)
        }

        "xrefs_to_field" => {
            let idb = mgr.get_idb(&target_id)?;
            let ordinal = p.get("ordinal").and_then(|v| v.as_u64()).map(|v| v as u32);
            let name = p.get("name").and_then(|v| v.as_str());
            let mi = p.get("member_index").and_then(|v| v.as_u64()).map(|v| v as u32);
            let mn = p.get("member_name").and_then(|v| v.as_str());
            let limit = param_usize(p, "limit", 100);
            handlers::structs::handle_xrefs_to_field(idb, ordinal, name, mi, mn, limit)
                .map_err(te).and_then(to_json_v)
        }

        "set_comment" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = p.get("address").and_then(|v| v.as_str()).map(parse_addr).transpose()?;
            let name = p.get("name").and_then(|v| v.as_str());
            let offset = p.get("offset").and_then(|v| v.as_i64()).unwrap_or(0);
            let comment = param_str(p, "comment")?;
            let repeatable = param_bool(p, "repeatable", false);
            handlers::annotations::handle_set_comments(idb, addr, name, offset, comment, repeatable)
                .map_err(te)
        }

        "rename" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = p.get("address").and_then(|v| v.as_str()).map(parse_addr).transpose()?;
            let current_name = p.get("current_name").and_then(|v| v.as_str());
            let new_name = param_str(p, "name")?;
            let flags = p.get("flags").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            handlers::annotations::handle_rename(idb, addr, current_name, new_name, flags)
                .map_err(te)
        }

        "patch_bytes" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = p.get("address").and_then(|v| v.as_str()).map(parse_addr).transpose()?;
            let name = p.get("name").and_then(|v| v.as_str());
            let offset = p.get("offset").and_then(|v| v.as_i64()).unwrap_or(0);
            let hex = param_str(p, "bytes")?;
            let bytes = parse_hex_bytes(hex)?;
            handlers::memory::handle_patch_bytes(idb, addr, name, offset, &bytes).map_err(te)
        }

        "patch_asm" => {
            let idb = mgr.get_idb(&target_id)?;
            let addr = p.get("address").and_then(|v| v.as_str()).map(parse_addr).transpose()?;
            let name = p.get("name").and_then(|v| v.as_str());
            let offset = p.get("offset").and_then(|v| v.as_i64()).unwrap_or(0);
            let line = param_str(p, "line")?;
            handlers::memory::handle_patch_asm(idb, addr, name, offset, line).map_err(te)
        }

        "run_script" => {
            let idb = mgr.get_idb(&target_id)?;
            let code = param_str(p, "code")?;
            handlers::script::handle_run_script(idb, code, None, None).map_err(te)
        }

        "load_debug_info" => {
            let idb = mgr.get_idb(&target_id)?;
            let path = p.get("path").and_then(|v| v.as_str());
            let verbose = param_bool(p, "verbose", false);
            handlers::database::handle_load_debug_info(idb, path, verbose).map_err(te)
        }

        other => Err(format!("Unknown operation: {}", other)),
    }
}

// ---------------------------------------------------------------------------
// Param helpers
// ---------------------------------------------------------------------------

fn te(e: crate::ToolError) -> String { e.to_string() }

fn to_json<T: serde::Serialize>(v: &T) -> Result<Value, String> {
    serde_json::to_value(v).map_err(|e| e.to_string())
}

fn to_json_v<T: serde::Serialize>(v: T) -> Result<Value, String> {
    serde_json::to_value(v).map_err(|e| e.to_string())
}

fn param_str<'a>(p: &'a Value, key: &str) -> Result<&'a str, String> {
    p.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Missing parameter: {}", key))
}

fn param_usize(p: &Value, key: &str, default: usize) -> usize {
    p.get(key).and_then(|v| v.as_u64()).map(|v| v as usize).unwrap_or(default)
}

fn param_bool(p: &Value, key: &str, default: bool) -> bool {
    p.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

fn param_addr(p: &Value, key: &str) -> Result<u64, String> {
    let s = param_str(p, key)?;
    parse_addr(s)
}

fn param_str_vec(p: &Value, key: &str) -> Vec<String> {
    p.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default()
}

fn param_addr_vec(p: &Value, key: &str) -> Result<Vec<u64>, String> {
    let strs = param_str_vec(p, key);
    strs.iter().map(|s| parse_addr(s)).collect()
}

fn parse_addr(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|_| format!("Invalid address: {}", s))
    } else {
        s.parse::<u64>().map_err(|_| format!("Invalid address: {}", s))
    }
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("Hex bytes string has odd length".to_string());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|_| format!("Invalid hex byte at position {}", i))
        })
        .collect()
}

/// Skip the first `offset` lines from a newline-separated string.
fn apply_line_offset(s: &str, offset: usize) -> String {
    if offset == 0 {
        return s.to_string();
    }
    s.lines().skip(offset).collect::<Vec<_>>().join("\n")
}

/// Truncate output to `max_lines` lines (0 = no truncation).
fn apply_max_lines(s: &str, max_lines: usize) -> String {
    if max_lines == 0 {
        return s.to_string();
    }
    let lines: Vec<&str> = s.lines().take(max_lines).collect();
    let total_lines = s.lines().count();
    let mut result = lines.join("\n");
    if lines.len() < total_lines {
        result.push_str(&format!(
            "\n// ... ({} lines truncated, use --max-lines 0 for full output)",
            total_lines - lines.len()
        ));
    }
    result
}
