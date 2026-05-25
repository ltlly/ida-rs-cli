//! CLI subcommands for direct IDA analysis without MCP server.
//!
//! Each subcommand opens a binary/IDB, performs a specific analysis,
//! and outputs results as JSON to stdout.

use crate::ida::handlers;
use clap::{Args, Subcommand};
use idalib::{IDBOpenOptions, IDB};
use serde_json::json;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tracing::info;

/// Global arguments shared by all analysis subcommands.
#[derive(Args, Debug, Clone)]
pub struct GlobalAnalysisArgs {
    /// Path to the binary or .i64/.idb database
    #[arg(long, short = 'f')]
    pub file: String,
    /// Output .i64 path when opening a raw binary (defaults to <file>.i64)
    #[arg(long)]
    pub idb_out: Option<String>,
    /// Force auto-analysis before running the command
    #[arg(long)]
    pub auto_analyse: bool,
    /// Enable IDA console messages (verbose)
    #[arg(long)]
    pub ida_console: bool,
}

#[derive(Subcommand)]
pub enum AnalysisCommand {
    /// Show database/binary info (file type, processor, bitness, function count)
    Info,
    /// List functions (paginated, filterable)
    Functions(FunctionsArgs),
    /// Disassemble at an address or by function name
    Disasm(DisasmArgs),
    /// Decompile a function (requires Hex-Rays)
    Decompile(DecompileArgs),
    /// List or search strings
    Strings(StringsArgs),
    /// List segments
    Segments,
    /// List imports
    Imports(PaginationArgs),
    /// List exports
    Exports(PaginationArgs),
    /// List entry points
    Entrypoints,
    /// List global variables
    Globals(GlobalsArgs),
    /// Show cross-references to/from an address
    Xrefs(XrefsArgs),
    /// Show basic blocks (CFG) of a function
    BasicBlocks(AddressArgs),
    /// Show callers of a function
    Callers(AddressArgs),
    /// Show callees of a function
    Callees(AddressArgs),
    /// Read raw bytes at an address
    GetBytes(GetBytesArgs),
    /// Search for byte patterns
    FindBytes(FindBytesArgs),
}

#[derive(Args)]
pub struct FunctionsArgs {
    /// Offset for pagination
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Limit results
    #[arg(long, default_value_t = 100)]
    pub limit: usize,
    /// Filter by function name substring
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct DisasmArgs {
    /// Address to disassemble (hex 0x... or decimal)
    #[arg(long)]
    pub address: Option<String>,
    /// Function name to disassemble
    #[arg(long)]
    pub name: Option<String>,
    /// Number of instructions
    #[arg(long, default_value_t = 20)]
    pub count: usize,
}

#[derive(Args)]
pub struct DecompileArgs {
    /// Address to decompile (hex 0x... or decimal)
    #[arg(long)]
    pub address: Option<String>,
    /// Function name to decompile
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Args)]
pub struct StringsArgs {
    /// Offset for pagination
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Limit results
    #[arg(long, default_value_t = 100)]
    pub limit: usize,
    /// Filter/search query
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct PaginationArgs {
    /// Offset for pagination
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Limit results
    #[arg(long, default_value_t = 100)]
    pub limit: usize,
}

#[derive(Args)]
pub struct GlobalsArgs {
    /// Offset for pagination
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Limit results
    #[arg(long, default_value_t = 100)]
    pub limit: usize,
    /// Filter by name substring
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct XrefsArgs {
    /// Target address (hex 0x... or decimal)
    #[arg(long)]
    pub address: String,
    /// Direction: "to" (default) or "from"
    #[arg(long, default_value = "to")]
    pub direction: String,
}

#[derive(Args)]
pub struct AddressArgs {
    /// Target address (hex 0x... or decimal)
    #[arg(long)]
    pub address: String,
}

#[derive(Args)]
pub struct GetBytesArgs {
    /// Address (hex 0x... or decimal)
    #[arg(long)]
    pub address: String,
    /// Number of bytes to read
    #[arg(long, default_value_t = 64)]
    pub size: usize,
}

#[derive(Args)]
pub struct FindBytesArgs {
    /// Hex byte pattern (e.g., "48 89 5C 24" or "48 ?? 5C")
    #[arg(long)]
    pub pattern: String,
    /// Max results
    #[arg(long, default_value_t = 100)]
    pub limit: usize,
}

/// Parse an address string (hex or decimal)
fn parse_address(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16)
            .map_err(|_| anyhow::anyhow!("Invalid address format: {}", s))
    } else {
        s.parse::<u64>()
            .map_err(|_| anyhow::anyhow!("Invalid address format: {}", s))
    }
}

/// Determine the IDB output path for a raw binary.
fn idb_path_for_raw_binary(path: &Path) -> PathBuf {
    let mut raw_idb = OsString::from(path.as_os_str());
    raw_idb.push(".i64");
    PathBuf::from(raw_idb)
}

/// Open a database with progress ticker.
fn open_database(global: &GlobalAnalysisArgs) -> anyhow::Result<IDB> {
    let path = crate::expand_path(&global.file);
    info!("Opening database: {}", path.display());

    let done = Arc::new(AtomicBool::new(false));
    let done_clone = done.clone();
    let path_display = path.display().to_string();
    let ticker = thread::spawn(move || {
        let start = Instant::now();
        loop {
            thread::sleep(Duration::from_secs(10));
            if done_clone.load(Ordering::Relaxed) {
                break;
            }
            eprintln!(
                "[info] Still opening {} ({}s elapsed)...",
                path_display,
                start.elapsed().as_secs()
            );
        }
    });

    let open_start = Instant::now();

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_idb = ext == "i64" || ext == "idb" || ext == "id0";

    let db = if is_idb {
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(global.auto_analyse).save(true);
        opts.arg("-A");
        if global.auto_analyse {
            info!("Opening existing IDB with auto-analysis enabled");
        }
        opts.open(&path)
            .map_err(|e| anyhow::anyhow!("Failed to open database: {}: {}", path.display(), e))?
    } else {
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(true);
        let out_path = if let Some(out) = global.idb_out.as_deref() {
            PathBuf::from(out)
        } else {
            idb_path_for_raw_binary(&path)
        };
        info!(
            "Opening raw binary with auto-analysis (idb_out={})",
            out_path.display()
        );
        opts.arg("-A");
        opts.idb(&out_path)
            .save(true)
            .open(&path)
            .map_err(|e| anyhow::anyhow!("Failed to open binary: {}: {}", path.display(), e))?
    };

    done.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    info!("Database opened in {}s", open_start.elapsed().as_secs());

    Ok(db)
}

/// Run a CLI analysis command.
pub fn run_analysis(global: GlobalAnalysisArgs, cmd: AnalysisCommand) -> anyhow::Result<()> {
    // Initialize IDA library
    idalib::init_library()
        .map_err(|e| anyhow::anyhow!("IDA library initialization failed: {e}"))?;

    if global.ida_console {
        idalib::enable_console_messages(true)
            .map_err(|e| anyhow::anyhow!("failed to enable console messages: {e}"))?;
    }

    // Open the database
    let db = open_database(&global)?;
    let idb: Option<IDB> = Some(db);

    match cmd {
        AnalysisCommand::Info => {
            let db = idb.as_ref().unwrap();
            let meta = db.meta();
            let info = json!({
                "path": global.file,
                "file_type": format!("{:?}", meta.filetype()),
                "processor": db.processor().long_name(),
                "bits": if meta.is_64bit() { 64 } else if meta.is_32bit_exactly() { 32 } else { 16 },
                "function_count": db.function_count(),
                "analysis_status": crate::ida::handlers::analysis::build_analysis_status(db),
            });
            println!("{}", serde_json::to_string_pretty(&info)?);
        }

        AnalysisCommand::Functions(args) => {
            let result = handlers::functions::handle_list_functions(
                &idb,
                args.offset,
                args.limit,
                args.filter.as_deref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        AnalysisCommand::Disasm(args) => {
            if let Some(name) = &args.name {
                let result = handlers::disasm::handle_disasm_by_name(&idb, name, args.count)?;
                println!("{}", result);
            } else if let Some(addr_str) = &args.address {
                let addr = parse_address(addr_str)?;
                let result = handlers::disasm::handle_disasm(&idb, addr, args.count)?;
                println!("{}", result);
            } else {
                return Err(anyhow::anyhow!(
                    "Either --address or --name must be provided"
                ));
            }
        }

        AnalysisCommand::Decompile(args) => {
            let addr = if let Some(name) = &args.name {
                let func = handlers::functions::handle_resolve_function(&idb, name)?;
                parse_address(&func.address)?
            } else if let Some(addr_str) = &args.address {
                parse_address(addr_str)?
            } else {
                return Err(anyhow::anyhow!(
                    "Either --address or --name must be provided"
                ));
            };
            let result = handlers::disasm::handle_decompile(&idb, addr)?;
            println!("{}", result);
        }

        AnalysisCommand::Strings(args) => {
            let result = handlers::strings::handle_strings(
                &idb,
                args.offset,
                args.limit,
                args.filter.as_deref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        AnalysisCommand::Segments => {
            let result = handlers::segments::handle_segments(&idb)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        AnalysisCommand::Imports(args) => {
            let result = handlers::imports::handle_imports(&idb, args.offset, args.limit)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        AnalysisCommand::Exports(args) => {
            let result = handlers::imports::handle_exports(&idb, args.offset, args.limit)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        AnalysisCommand::Entrypoints => {
            let result = handlers::imports::handle_entrypoints(&idb)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        AnalysisCommand::Globals(args) => {
            let result = handlers::globals::handle_list_globals(
                &idb,
                args.filter.as_deref(),
                args.offset,
                args.limit,
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        AnalysisCommand::Xrefs(args) => {
            let addr = parse_address(&args.address)?;
            match args.direction.as_str() {
                "to" => {
                    let result = handlers::xrefs::handle_xrefs_to(&idb, addr)?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
                "from" => {
                    let result = handlers::xrefs::handle_xrefs_from(&idb, addr)?;
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "Invalid direction '{}'. Use 'to' or 'from'.",
                        other
                    ));
                }
            }
        }

        AnalysisCommand::BasicBlocks(args) => {
            let addr = parse_address(&args.address)?;
            let result = handlers::controlflow::handle_basic_blocks(&idb, addr)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        AnalysisCommand::Callers(args) => {
            let addr = parse_address(&args.address)?;
            let result = handlers::controlflow::handle_callers(&idb, addr)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        AnalysisCommand::Callees(args) => {
            let addr = parse_address(&args.address)?;
            let result = handlers::controlflow::handle_callees(&idb, addr)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        AnalysisCommand::GetBytes(args) => {
            let addr = parse_address(&args.address)?;
            let result =
                handlers::memory::handle_get_bytes(&idb, Some(addr), None, 0, args.size)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        AnalysisCommand::FindBytes(args) => {
            let result = handlers::search::handle_find_bytes(&idb, &args.pattern, args.limit)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }

    Ok(())
}
