//! CLI interface for ida-rs-cli.
//!
//! All analysis commands are routed through the daemon process via Unix socket.
//! The daemon holds loaded binaries in memory, enabling fast repeated queries.
//!
//! Usage:
//!   ida-rs-cli daemon start          # Start daemon (foreground)
//!   ida-rs-cli target load -f a.so   # Load a binary
//!   ida-rs-cli functions             # Query the active target
//!   ida-rs-cli -t t2 disasm --address 0x1000  # Query a specific target

use clap::{Args, Parser, Subcommand};
use serde_json::json;

// ─────────────────────────────────────────────────────────────────────────────
// Top-level CLI definition
// ─────────────────────────────────────────────────────────────────────────────

/// Headless IDA Pro CLI - reverse engineering from the command line.
///
/// All commands communicate with a persistent daemon process that holds loaded
/// binaries in memory. Start the daemon first, then load targets and run analysis.
///
/// Quick start:
///   ida-rs-cli daemon start           # Start the daemon
///   ida-rs-cli target load -f app.so  # Load a binary
///   ida-rs-cli functions              # List functions
///   ida-rs-cli decompile --address 0x1234  # Decompile
#[derive(Parser)]
#[command(name = "ida-rs-cli", version)]
pub struct Cli {
    /// Target selector (ID or filename substring) for daemon queries
    #[arg(long, short = 't', global = true)]
    pub target: Option<String>,

    /// Auto-spill token threshold. Outputs exceeding this estimated token count
    /// are written to a temporary file instead of stdout, preventing context
    /// explosion for AI agents. Set to 0 to disable spilling.
    #[arg(long, global = true, default_value_t = crate::spill::DEFAULT_SPILL_TOKEN_LIMIT, env = "IDA_SPILL_THRESHOLD")]
    pub spill_threshold: usize,

    #[command(subcommand)]
    pub command: CliCommand,
}

// ─────────────────────────────────────────────────────────────────────────────
// Subcommand enum
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum CliCommand {
    // ── Daemon Management ────────────────────────────────────────────────
    /// Manage the background daemon process (start/stop/status)
    Daemon(DaemonArgs),
    /// Manage loaded analysis targets (load/list/close/switch)
    Target(TargetArgs),

    // ── Database / Info ──────────────────────────────────────────────────
    /// Show target info (file type, processor, bitness, function count)
    Info,
    /// Show IDB metadata (compiler, ABI, etc.)
    Meta,
    /// Show analysis status (auto_is_ok, auto_state)
    AnalysisStatus,

    // ── Functions ────────────────────────────────────────────────────────
    /// List functions (paginated, filterable)
    Functions(FunctionsArgs),
    /// Resolve a function by name (returns address and size)
    ResolveFunction(ResolveFunctionArgs),
    /// Find the function containing a given address
    FunctionAt(AddressArgs),
    /// Batch lookup functions by name or address
    LookupFuncs(LookupFuncsArgs),
    /// Trigger re-analysis of all functions (mutating)
    AnalyzeFuncs,

    // ── Disassembly / Decompilation ─────────────────────────────────────
    /// Disassemble at an address or by function name
    Disasm(DisasmArgs),
    /// Disassemble the entire function containing an address
    DisasmFunctionAt(DisasmFunctionAtArgs),
    /// Decompile a function to pseudocode (requires Hex-Rays)
    Decompile(DecompileArgs),
    /// Get decompiled pseudocode at an address or address range
    PseudocodeAt(PseudocodeAtArgs),

    // ── Strings ──────────────────────────────────────────────────────────
    /// List or filter strings in the binary
    Strings(StringsArgs),
    /// Find strings matching a query (supports exact/case-insensitive)
    FindString(FindStringArgs),
    /// Read the string value at a specific address
    GetString(GetStringArgs),
    /// List strings with their cross-references
    AnalyzeStrings(AnalyzeStringsArgs),
    /// Find cross-references to strings matching a query
    XrefsToString(XrefsToStringArgs),

    // ── Binary Structure ─────────────────────────────────────────────────
    /// List all segments with permissions and types
    Segments,
    /// List imported symbols (paginated)
    Imports(PaginationArgs),
    /// List exported/public symbols (paginated)
    Exports(PaginationArgs),
    /// List binary entry points
    Entrypoints,
    /// List named global variables (non-function symbols)
    Globals(GlobalsArgs),
    /// Get a global variable's value by name or address
    GetGlobalValue(QueryArgs),

    // ── Cross-References ─────────────────────────────────────────────────
    /// Show cross-references TO an address (paginated)
    XrefsTo(XrefPageArgs),
    /// Show cross-references FROM an address (paginated)
    XrefsFrom(XrefPageArgs),
    /// Build an xref adjacency matrix for multiple addresses
    XrefMatrix(MultiAddressArgs),

    // ── Control/Call Flow ─────────────────────────────────────────────────
    /// Show basic blocks (CFG) for the function at an address
    BasicBlocks(AddressArgs),
    /// Show all callers of a function
    Callers(AddressArgs),
    /// Show all callees of a function
    Callees(AddressArgs),
    /// Build a call graph rooted at a function
    Callgraph(CallgraphArgs),
    /// Find call paths between two addresses
    FindPaths(FindPathsArgs),

    // ── Memory ───────────────────────────────────────────────────────────
    /// Read raw bytes at an address
    GetBytes(GetBytesArgs),
    /// Read an integer value at an address (1/2/4/8 bytes)
    ReadInt(ReadIntArgs),
    /// Search for a byte pattern (supports wildcards)
    FindBytes(FindBytesArgs),

    // ── Search ───────────────────────────────────────────────────────────
    /// Search for text in disassembly listings
    SearchText(SearchTextArgs),
    /// Search for immediate values in instructions
    SearchImm(SearchImmArgs),
    /// Find instructions matching mnemonic patterns
    FindInsns(FindInsnsArgs),
    /// Find instructions by operand patterns
    FindInsnOperands(FindInsnsArgs),

    // ── Address Info ─────────────────────────────────────────────────────
    /// Resolve an address to its segment/function/symbol context
    AddrInfo(AddressArgs),

    // ── Types ────────────────────────────────────────────────────────────
    /// List local types in the database (paginated)
    LocalTypes(LocalTypesArgs),
    /// Declare a new type (C syntax)
    DeclareType(DeclareTypeArgs),
    /// Apply a type to an address or stack variable
    ApplyTypes(ApplyTypesArgs),
    /// Infer/guess types at an address
    InferTypes(InferTypesArgs),
    /// Show stack frame layout for a function
    StackFrame(AddressArgs),
    /// Declare a stack variable type
    DeclareStack(DeclareStackArgs),
    /// Delete a stack variable
    DeleteStack(DeleteStackArgs),

    // ── Structs ──────────────────────────────────────────────────────────
    /// List structs/unions in the database (paginated)
    Structs(StructsArgs),
    /// Show detailed struct information and members
    StructInfo(StructInfoArgs),
    /// Read struct data at a memory address
    ReadStruct(ReadStructArgs),
    /// Find cross-references to a struct field
    XrefsToField(XrefsToFieldArgs),

    // ── Annotations / Modification ───────────────────────────────────────
    /// Set a comment at an address
    SetComment(SetCommentArgs),
    /// Rename a symbol at an address
    Rename(RenameArgs),
    /// Patch raw bytes at an address
    PatchBytes(PatchBytesArgs),
    /// Assemble and patch an instruction at an address
    PatchAsm(PatchAsmArgs),

    // ── Script ───────────────────────────────────────────────────────────
    /// Run an IDAPython script in the database context
    RunScript(RunScriptArgs),

    // ── Debug Info ───────────────────────────────────────────────────────
    /// Load external debug info (dSYM/DWARF) into the database
    LoadDebugInfo(LoadDebugInfoArgs),

    // ── Utility ──────────────────────────────────────────────────────────
    /// Convert an integer between decimal, hex, octal, and binary
    IntConvert(IntConvertArgs),
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument structs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub command: DaemonCommand,
}

/// Daemon lifecycle management.
#[derive(Subcommand)]
pub enum DaemonCommand {
    /// Start the daemon process (blocks in foreground)
    Start {
        /// Run in background (daemonize)
        #[arg(long)]
        background: bool,
    },
    /// Stop the running daemon gracefully
    Stop,
    /// Show daemon status and loaded target count
    Status,
    /// Internal: run a per-target worker subprocess (spawned by the daemon).
    #[command(hide = true)]
    Worker {
        /// This worker's private socket path
        #[arg(long)]
        sock: std::path::PathBuf,
        /// Router-assigned target ID (e.g. "t3")
        #[arg(long)]
        id: String,
    },
}

#[derive(Args)]
pub struct TargetArgs {
    #[command(subcommand)]
    pub command: TargetCommand,
}

/// Target (binary/IDB) management within the daemon.
#[derive(Subcommand)]
pub enum TargetCommand {
    /// Load a new binary or IDB file into the daemon for analysis.
    /// Each target is served by its own worker process. A loaded target only
    /// becomes active if no other target is active; use `target switch`.
    Load {
        /// Path to binary or .i64/.idb database file
        #[arg(long, short = 'f')]
        file: String,
        /// Output .i64 path for raw binaries (defaults to <file>.i64)
        #[arg(long)]
        idb_out: Option<String>,
        /// Skip auto-analysis when loading
        #[arg(long)]
        no_analyse: bool,
    },
    /// List all currently loaded targets
    List,
    /// Close and unload a target by ID or name
    Close {
        /// Target ID (e.g. "t1") or filename substring
        #[arg(long)]
        id: String,
    },
    /// Switch the active target for subsequent commands
    Switch {
        /// Target ID (e.g. "t1") or filename substring
        #[arg(long)]
        id: String,
    },
}

#[derive(Args)]
pub struct FunctionsArgs {
    /// Number of items to skip
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Maximum number of items to return (use --offset to paginate)
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// Filter functions by name substring
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct ResolveFunctionArgs {
    /// Function name (or substring) to search for
    #[arg(long)]
    pub name: String,
}

#[derive(Args)]
pub struct LookupFuncsArgs {
    /// Queries (names or hex addresses) separated by commas
    #[arg(long, value_delimiter = ',')]
    pub queries: Vec<String>,
}

#[derive(Args)]
pub struct DisasmArgs {
    /// Address to disassemble (hex 0x... or decimal, e.g. 0x100001234)
    #[arg(long)]
    pub address: Option<String>,
    /// Function name to disassemble
    #[arg(long)]
    pub name: Option<String>,
    /// Number of instructions to disassemble
    #[arg(long, default_value_t = 20)]
    pub count: usize,
    /// Number of instructions to skip (for pagination)
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
}

#[derive(Args)]
pub struct DisasmFunctionAtArgs {
    /// Address within the function (hex 0x... or decimal, e.g. 0x100001234)
    #[arg(long)]
    pub address: String,
    /// Maximum number of instructions to return
    #[arg(long, default_value_t = 200)]
    pub count: usize,
    /// Number of instructions to skip (for pagination through large functions)
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
}

#[derive(Args)]
pub struct DecompileArgs {
    /// Function address to decompile (hex 0x... or decimal, e.g. 0x100001234)
    #[arg(long)]
    pub address: Option<String>,
    /// Function name to decompile
    #[arg(long)]
    pub name: Option<String>,
    /// Maximum number of pseudocode lines to return (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    pub max_lines: usize,
}

#[derive(Args)]
pub struct PseudocodeAtArgs {
    /// Start address (hex 0x... or decimal)
    #[arg(long)]
    pub address: String,
    /// End address for range decompilation (optional)
    #[arg(long)]
    pub end_address: Option<String>,
}

#[derive(Args)]
pub struct StringsArgs {
    /// Number of items to skip
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Maximum number of items to return (use --offset to paginate)
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// Filter strings by content substring
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct FindStringArgs {
    /// String content to search for
    #[arg(long)]
    pub query: String,
    /// Require exact match (not substring)
    #[arg(long)]
    pub exact: bool,
    /// Case insensitive search
    #[arg(long)]
    pub case_insensitive: bool,
    /// Number of items to skip
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Maximum number of items to return (use --offset to paginate)
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

#[derive(Args)]
pub struct GetStringArgs {
    /// Address of the string (hex 0x... or decimal)
    #[arg(long)]
    pub address: String,
    /// Maximum string length to read
    #[arg(long, default_value_t = 1024)]
    pub max_len: usize,
}

#[derive(Args)]
pub struct AnalyzeStringsArgs {
    /// Optional query to filter strings
    #[arg(long)]
    pub query: Option<String>,
    /// Number of items to skip
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Maximum number of items to return (use --offset to paginate)
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

#[derive(Args)]
pub struct XrefsToStringArgs {
    /// String content to search for
    #[arg(long)]
    pub query: String,
    /// Require exact match
    #[arg(long)]
    pub exact: bool,
    /// Case insensitive search
    #[arg(long)]
    pub case_insensitive: bool,
    /// Number of items to skip
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Maximum number of items to return (use --offset to paginate)
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// Maximum cross-references per string
    #[arg(long, default_value_t = 10)]
    pub max_xrefs: usize,
}

#[derive(Args)]
pub struct PaginationArgs {
    /// Number of items to skip
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Maximum number of items to return (use --offset to paginate)
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

#[derive(Args)]
pub struct GlobalsArgs {
    /// Number of items to skip
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Maximum number of items to return (use --offset to paginate)
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// Filter globals by name substring
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct QueryArgs {
    /// Query string (name or hex address)
    #[arg(long)]
    pub query: String,
}

#[derive(Args)]
pub struct AddressArgs {
    /// Target address (hex 0x... or decimal)
    #[arg(long)]
    pub address: String,
}

#[derive(Args)]
pub struct XrefPageArgs {
    /// Target address (hex 0x... or decimal)
    #[arg(long)]
    pub address: String,
    /// Number of xrefs to skip
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Maximum number of xrefs to return (max 10000)
    #[arg(long, default_value_t = 1000)]
    pub limit: usize,
}

#[derive(Args)]
pub struct MultiAddressArgs {
    /// Addresses (comma-separated, hex or decimal)
    #[arg(long, value_delimiter = ',')]
    pub addresses: Vec<String>,
}

#[derive(Args)]
pub struct CallgraphArgs {
    /// Root function address (hex 0x... or decimal, e.g. 0x100001234)
    #[arg(long)]
    pub address: String,
    /// Maximum call depth to traverse
    #[arg(long, default_value_t = 3)]
    pub max_depth: usize,
    /// Maximum number of nodes in the graph (keep small to avoid truncation)
    #[arg(long, default_value_t = 50)]
    pub max_nodes: usize,
}

#[derive(Args)]
pub struct FindPathsArgs {
    /// Start address (hex 0x... or decimal)
    #[arg(long)]
    pub start: String,
    /// End address (hex 0x... or decimal)
    #[arg(long)]
    pub end: String,
    /// Maximum number of paths to find
    #[arg(long, default_value_t = 5)]
    pub max_paths: usize,
    /// Maximum search depth
    #[arg(long, default_value_t = 10)]
    pub max_depth: usize,
}

#[derive(Args)]
pub struct GetBytesArgs {
    /// Address to read from (hex 0x... or decimal)
    #[arg(long)]
    pub address: String,
    /// Number of bytes to read
    #[arg(long, default_value_t = 64)]
    pub size: usize,
}

#[derive(Args)]
pub struct ReadIntArgs {
    /// Address to read from (hex 0x... or decimal)
    #[arg(long)]
    pub address: String,
    /// Integer size in bytes (1, 2, 4, or 8)
    #[arg(long, default_value_t = 4)]
    pub size: usize,
}

#[derive(Args)]
pub struct FindBytesArgs {
    /// Hex byte pattern with optional wildcards (e.g., "48 89 5C 24" or "48 ?? 5C")
    #[arg(long)]
    pub pattern: String,
    /// Maximum number of results
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

#[derive(Args)]
pub struct SearchTextArgs {
    /// Text to search for in disassembly
    #[arg(long)]
    pub text: String,
    /// Maximum number of results
    #[arg(long, default_value_t = 50)]
    pub max_results: usize,
}

#[derive(Args)]
pub struct SearchImmArgs {
    /// Immediate value to search for (hex 0x... or decimal)
    #[arg(long)]
    pub value: String,
    /// Maximum number of results
    #[arg(long, default_value_t = 50)]
    pub max_results: usize,
}

#[derive(Args)]
pub struct FindInsnsArgs {
    /// Instruction mnemonic/operand patterns (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub patterns: Vec<String>,
    /// Maximum number of results
    #[arg(long, default_value_t = 50)]
    pub max_results: usize,
    /// Case insensitive pattern matching
    #[arg(long)]
    pub case_insensitive: bool,
}

#[derive(Args)]
pub struct LocalTypesArgs {
    /// Number of items to skip
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Maximum number of items to return (use --offset to paginate)
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// Filter types by name substring
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct DeclareTypeArgs {
    /// Type declaration in C syntax (e.g., "struct foo { int x; };")
    #[arg(long)]
    pub decl: String,
    /// Use relaxed parsing (tolerates some errors)
    #[arg(long)]
    pub relaxed: bool,
    /// Replace existing type with same name
    #[arg(long)]
    pub replace: bool,
    /// Allow multiple declarations in one string
    #[arg(long)]
    pub multi: bool,
}

#[derive(Args)]
pub struct ApplyTypesArgs {
    /// Target address (hex 0x... or decimal)
    #[arg(long)]
    pub address: Option<String>,
    /// Symbol name to apply type to
    #[arg(long)]
    pub name: Option<String>,
    /// Offset from address/name
    #[arg(long, default_value_t = 0)]
    pub offset: i64,
    /// Stack variable offset (for stack var typing)
    #[arg(long)]
    pub stack_offset: Option<i64>,
    /// Stack variable name (for stack var typing)
    #[arg(long)]
    pub stack_name: Option<String>,
    /// C type declaration to apply
    #[arg(long)]
    pub decl: Option<String>,
    /// Named type from local types to apply
    #[arg(long)]
    pub type_name: Option<String>,
    /// Use relaxed parsing
    #[arg(long)]
    pub relaxed: bool,
    /// Delay type application
    #[arg(long)]
    pub delay: bool,
    /// Use strict mode
    #[arg(long)]
    pub strict: bool,
}

#[derive(Args)]
pub struct InferTypesArgs {
    /// Target address (hex 0x... or decimal)
    #[arg(long)]
    pub address: Option<String>,
    /// Symbol name
    #[arg(long)]
    pub name: Option<String>,
    /// Offset from address/name
    #[arg(long, default_value_t = 0)]
    pub offset: i64,
}

#[derive(Args)]
pub struct DeclareStackArgs {
    /// Function address (hex 0x... or decimal)
    #[arg(long)]
    pub address: Option<String>,
    /// Function name
    #[arg(long)]
    pub name: Option<String>,
    /// Stack offset for the variable
    #[arg(long, default_value_t = 0)]
    pub offset: i64,
    /// Variable name
    #[arg(long)]
    pub var_name: Option<String>,
    /// Type declaration for the stack variable
    #[arg(long)]
    pub decl: String,
    /// Use relaxed parsing
    #[arg(long)]
    pub relaxed: bool,
}

#[derive(Args)]
pub struct DeleteStackArgs {
    /// Function address (hex 0x... or decimal)
    #[arg(long)]
    pub address: Option<String>,
    /// Function name
    #[arg(long)]
    pub name: Option<String>,
    /// Stack offset of the variable to delete
    #[arg(long)]
    pub offset: Option<i64>,
    /// Name of the variable to delete
    #[arg(long)]
    pub var_name: Option<String>,
}

#[derive(Args)]
pub struct StructsArgs {
    /// Number of items to skip
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
    /// Maximum number of items to return (use --offset to paginate)
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// Filter structs by name substring
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct StructInfoArgs {
    /// Struct ordinal number
    #[arg(long)]
    pub ordinal: Option<u32>,
    /// Struct name
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Args)]
pub struct ReadStructArgs {
    /// Memory address to read struct from (hex 0x... or decimal)
    #[arg(long)]
    pub address: String,
    /// Struct ordinal number
    #[arg(long)]
    pub ordinal: Option<u32>,
    /// Struct name
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Args)]
pub struct XrefsToFieldArgs {
    /// Struct ordinal number
    #[arg(long)]
    pub ordinal: Option<u32>,
    /// Struct name
    #[arg(long)]
    pub name: Option<String>,
    /// Member index within the struct
    #[arg(long)]
    pub member_index: Option<u32>,
    /// Member name within the struct
    #[arg(long)]
    pub member_name: Option<String>,
    /// Maximum number of results
    #[arg(long, default_value_t = 100)]
    pub limit: usize,
}

#[derive(Args)]
pub struct SetCommentArgs {
    /// Address to comment (hex 0x... or decimal)
    #[arg(long)]
    pub address: Option<String>,
    /// Symbol name to comment
    #[arg(long)]
    pub name: Option<String>,
    /// Offset from address/name
    #[arg(long, default_value_t = 0)]
    pub offset: i64,
    /// Comment text
    #[arg(long)]
    pub comment: String,
    /// Make it a repeatable comment
    #[arg(long)]
    pub repeatable: bool,
}

#[derive(Args)]
pub struct RenameArgs {
    /// Address of the symbol (hex 0x... or decimal)
    #[arg(long)]
    pub address: Option<String>,
    /// Current name of the symbol to rename
    #[arg(long)]
    pub current_name: Option<String>,
    /// New name to assign
    #[arg(long)]
    pub name: String,
    /// IDA rename flags (0 = default)
    #[arg(long, default_value_t = 0)]
    pub flags: i32,
}

#[derive(Args)]
pub struct PatchBytesArgs {
    /// Address to patch (hex 0x... or decimal)
    #[arg(long)]
    pub address: Option<String>,
    /// Symbol name to patch at
    #[arg(long)]
    pub name: Option<String>,
    /// Offset from address/name
    #[arg(long, default_value_t = 0)]
    pub offset: i64,
    /// Hex bytes to write (e.g., "90 90 90" or "909090")
    #[arg(long)]
    pub bytes: String,
}

#[derive(Args)]
pub struct PatchAsmArgs {
    /// Address to patch (hex 0x... or decimal)
    #[arg(long)]
    pub address: Option<String>,
    /// Symbol name to patch at
    #[arg(long)]
    pub name: Option<String>,
    /// Offset from address/name
    #[arg(long, default_value_t = 0)]
    pub offset: i64,
    /// Assembly instruction to assemble and patch (e.g., "nop" or "mov x0, #0")
    #[arg(long)]
    pub line: String,
}

#[derive(Args)]
pub struct RunScriptArgs {
    /// IDAPython code to execute
    #[arg(long)]
    pub code: String,
}

#[derive(Args)]
pub struct LoadDebugInfoArgs {
    /// Path to debug info file (dSYM directory or DWARF file)
    #[arg(long)]
    pub path: Option<String>,
    /// Show verbose output during loading
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Args)]
pub struct IntConvertArgs {
    /// Value to convert (hex 0x.., decimal, octal 0o.., binary 0b..)
    #[arg(long)]
    pub value: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Main entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run the CLI: all commands route through the daemon.
pub fn run_cli(cli: Cli) -> anyhow::Result<()> {
    match &cli.command {
        CliCommand::Daemon(args) => run_daemon_command(&args.command),
        CliCommand::Target(args) => run_target_command(&args.command),
        _ => run_via_daemon(&cli),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Daemon command handlers
// ─────────────────────────────────────────────────────────────────────────────

fn run_daemon_command(cmd: &DaemonCommand) -> anyhow::Result<()> {
    use crate::daemon;
    match cmd {
        DaemonCommand::Start { background } => {
            if *background {
                start_daemon_background()
            } else {
                daemon::run_router()
            }
        }
        DaemonCommand::Stop => {
            let response = send_daemon_request(
                "shutdown",
                json!({}),
                None,
                std::time::Duration::from_secs(crate::daemon::CLIENT_STOP_TIMEOUT_SECS),
            );
            match response {
                Ok(resp) if resp.ok => {
                    eprintln!("Daemon stopped.");
                    Ok(())
                }
                Ok(resp) => anyhow::bail!(
                    "Failed to stop daemon: {}",
                    resp.error.unwrap_or_default()
                ),
                Err(e) => anyhow::bail!("Failed to stop daemon: {}", e),
            }
        }
        DaemonCommand::Status => {
            let sock_path = daemon::socket_path();
            let reg_path = daemon::registry_path();
            if !sock_path.exists() {
                eprintln!("Daemon is not running (no socket found).");
                return Ok(());
            }
            // Best-effort registry read; a corrupt file must not break status.
            let registry = std::fs::read_to_string(&reg_path)
                .ok()
                .and_then(|contents| serde_json::from_str::<serde_json::Value>(&contents).ok());
            if registry.is_none() && reg_path.exists() {
                eprintln!("  Warning: could not parse registry file {}", reg_path.display());
            }
            // Ping with a short timeout to verify liveness. Only claim
            // "running" once the daemon actually answers.
            match send_daemon_request(
                "ping",
                json!({}),
                None,
                std::time::Duration::from_secs(crate::daemon::CLIENT_STATUS_TIMEOUT_SECS),
            ) {
                Ok(resp) if resp.ok => {
                    eprintln!("Daemon is running:");
                    if let Some(reg) = &registry {
                        let pid = reg.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                        let alive = if pid > 0 && crate::daemon::pid_alive(pid as u32) {
                            "alive"
                        } else {
                            "not running?"
                        };
                        eprintln!("  PID: {} ({})", pid, alive);
                        eprintln!(
                            "  Socket: {}",
                            reg.get("socket").and_then(|v| v.as_str()).unwrap_or("?")
                        );
                        eprintln!(
                            "  Version: {}",
                            reg.get("version").and_then(|v| v.as_str()).unwrap_or("?")
                        );
                    }
                    if let Some(result) = &resp.result {
                        let targets =
                            result.get("targets").and_then(|v| v.as_u64()).unwrap_or(0);
                        eprintln!("  Targets loaded: {}", targets);
                    }
                    eprintln!("  Status: healthy");
                }
                _ => {
                    eprintln!("  Status: socket exists but daemon not responding");
                }
            }
            Ok(())
        }
        DaemonCommand::Worker { sock, id } => daemon::run_worker(sock.clone(), id),
    }
}

/// Start the daemon detached: re-exec ourselves in a new session with output
/// appended to the daemon log, then wait for the socket to answer pings.
fn start_daemon_background() -> anyhow::Result<()> {
    use std::io::Write as _;

    let sock_path = crate::daemon::socket_path();
    if sock_path.exists()
        && send_daemon_request(
            "ping",
            json!({}),
            None,
            std::time::Duration::from_secs(crate::daemon::CLIENT_STATUS_TIMEOUT_SECS),
        )
        .map(|r| r.ok)
        .unwrap_or(false)
    {
        anyhow::bail!("Daemon is already running. Use 'ida-rs-cli daemon stop' first.");
    }

    let log_path = crate::daemon::log_path();
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon")
        .arg("start")
        .stdin(std::process::Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file);
    // Detach into a new session so the daemon survives terminal hangup.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = cmd.spawn()?;
    let pid = child.id();

    // Wait for the daemon to come up (socket + ping), watching for early exit.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if sock_path.exists()
            && send_daemon_request(
                "ping",
                json!({}),
                None,
                std::time::Duration::from_secs(crate::daemon::CLIENT_STATUS_TIMEOUT_SECS),
            )
            .map(|r| r.ok)
            .unwrap_or(false)
        {
            eprintln!("Daemon started in background (pid {})", pid);
            eprintln!("  Socket: {}", sock_path.display());
            eprintln!("  Log: {}", log_path.display());
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            let tail = std::fs::read_to_string(&log_path).unwrap_or_default();
            let tail: String = tail.lines().rev().take(20).collect::<Vec<_>>().join("\n");
            let _ = writeln!(std::io::stderr(), "Daemon exited during startup: {}", status);
            if !tail.is_empty() {
                let _ = writeln!(std::io::stderr(), "Last log lines:\n{}", tail);
            }
            anyhow::bail!("Background daemon failed to start (see {})", log_path.display());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "Daemon did not become ready within 15s (see {})",
                log_path.display()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Target command handlers
// ─────────────────────────────────────────────────────────────────────────────

fn run_target_command(cmd: &TargetCommand) -> anyhow::Result<()> {
    match cmd {
        TargetCommand::Load {
            file,
            idb_out,
            no_analyse,
        } => {
            let mut params = json!({
                "path": file,
                "auto_analyse": !no_analyse,
            });
            if let Some(out) = idb_out {
                params["idb_out"] = json!(out);
            }
            let response = send_daemon_request("target.load", params, None, client_timeout())?;
            if response.ok {
                output_json(&response.result)?;
            } else {
                anyhow::bail!(
                    "{}",
                    response.error.unwrap_or_else(|| "Unknown error".to_string())
                );
            }
        }
        TargetCommand::List => {
            let response = send_daemon_request("target.list", json!({}), None, client_timeout())?;
            if response.ok {
                output_json(&response.result)?;
            } else {
                anyhow::bail!(
                    "{}",
                    response.error.unwrap_or_else(|| "Unknown error".to_string())
                );
            }
        }
        TargetCommand::Close { id } => {
            let response = send_daemon_request("target.close", json!({"id": id}), None, client_timeout())?;
            if response.ok {
                let closed = response
                    .result
                    .as_ref()
                    .and_then(|r| r.get("closed"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(id);
                eprintln!("Target '{}' closed.", closed);
            } else {
                anyhow::bail!(
                    "{}",
                    response.error.unwrap_or_else(|| "Unknown error".to_string())
                );
            }
        }
        TargetCommand::Switch { id } => {
            let response = send_daemon_request("target.switch", json!({"id": id}), None, client_timeout())?;
            if response.ok {
                let active = response
                    .result
                    .as_ref()
                    .and_then(|r| r.get("active"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(id);
                eprintln!("Switched to target '{}'.", active);
            } else {
                anyhow::bail!(
                    "{}",
                    response.error.unwrap_or_else(|| "Unknown error".to_string())
                );
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Route analysis commands through daemon
// ─────────────────────────────────────────────────────────────────────────────

fn run_via_daemon(cli: &Cli) -> anyhow::Result<()> {
    let (op, params) = cli_command_to_request(&cli.command)?;
    let response = send_daemon_request(&op, params, cli.target.as_deref(), client_timeout())?;
    if response.ok {
        if let Some(result) = &response.result {
            let spill_result = crate::spill::maybe_spill(result, &op, cli.spill_threshold)?;
            println!("{}", spill_result.stdout_output);
        }
    } else {
        anyhow::bail!(
            "{}",
            response.error.unwrap_or_else(|| "Unknown error".to_string())
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Daemon IPC client
// ─────────────────────────────────────────────────────────────────────────────

/// Send a JSON-line request to the daemon via Unix socket and read the response.
///
/// The read is bounded by `timeout` so a wedged daemon cannot hang the CLI
/// forever. Use `client_timeout()` for regular analysis commands.
fn send_daemon_request(
    op: &str,
    params: serde_json::Value,
    target: Option<&str>,
    timeout: std::time::Duration,
) -> anyhow::Result<crate::daemon::Response> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let sock_path = crate::daemon::socket_path();
    if !sock_path.exists() {
        anyhow::bail!(
            "Daemon is not running. Start it with:\n  ida-rs-cli daemon start"
        );
    }

    let mut stream = UnixStream::connect(&sock_path)
        .map_err(|e| anyhow::anyhow!("Failed to connect to daemon: {}", e))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| anyhow::anyhow!("Failed to set socket timeout: {}", e))?;

    let request = crate::daemon::Request {
        id: make_request_id(),
        op: op.to_string(),
        params,
        target: target.map(|s| s.to_string()),
    };

    let line = serde_json::to_string(&request)?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).map_err(|e| {
        if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) {
            anyhow::anyhow!(
                "Daemon did not respond within {}s (op '{}'). It may be busy or wedged; \
                 check 'ida-rs-cli daemon status'.",
                timeout.as_secs(),
                op
            )
        } else {
            anyhow::anyhow!("Failed to read daemon response: {}", e)
        }
    })?;

    let response: crate::daemon::Response = serde_json::from_str(&response_line)
        .map_err(|e| anyhow::anyhow!("Invalid daemon response: {}", e))?;

    Ok(response)
}

/// Default client-side timeout for analysis commands.
/// Overridable via IDA_CLI_TIMEOUT_SECS for very large binaries.
fn client_timeout() -> std::time::Duration {
    let secs = std::env::var("IDA_CLI_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(crate::daemon::CLIENT_DEFAULT_TIMEOUT_SECS);
    std::time::Duration::from_secs(secs)
}

/// Generate a unique request ID.
fn make_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id() as u128;
    format!("{:016x}{:08x}", nanos, pid)
}

/// Output JSON to stdout (pretty-printed).
fn output_json(value: &impl serde::Serialize) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI command -> daemon request conversion
// ─────────────────────────────────────────────────────────────────────────────

fn cli_command_to_request(cmd: &CliCommand) -> anyhow::Result<(String, serde_json::Value)> {
    let (op, params) = match cmd {
        CliCommand::Daemon(_) | CliCommand::Target(_) => unreachable!(),

        CliCommand::Info => ("info", json!({})),
        CliCommand::Meta => ("meta", json!({})),
        CliCommand::AnalysisStatus => ("analysis_status", json!({})),

        CliCommand::Functions(a) => ("functions", json!({
            "offset": a.offset, "limit": a.limit, "filter": a.filter,
        })),
        CliCommand::ResolveFunction(a) => ("resolve_function", json!({"name": a.name})),
        CliCommand::FunctionAt(a) => ("function_at", json!({"address": a.address})),
        CliCommand::LookupFuncs(a) => ("lookup_funcs", json!({"queries": a.queries})),
        CliCommand::AnalyzeFuncs => ("analyze_funcs", json!({})),

        CliCommand::Disasm(a) => ("disasm", json!({
            "address": a.address, "name": a.name, "count": a.count, "offset": a.offset,
        })),
        CliCommand::DisasmFunctionAt(a) => ("disasm_function_at", json!({
            "address": a.address, "count": a.count, "offset": a.offset,
        })),
        CliCommand::Decompile(a) => ("decompile", json!({
            "address": a.address, "name": a.name, "max_lines": a.max_lines,
        })),
        CliCommand::PseudocodeAt(a) => ("pseudocode_at", json!({
            "address": a.address, "end_address": a.end_address,
        })),

        CliCommand::Strings(a) => ("strings", json!({
            "offset": a.offset, "limit": a.limit, "filter": a.filter,
        })),
        CliCommand::FindString(a) => ("find_string", json!({
            "query": a.query, "exact": a.exact, "case_insensitive": a.case_insensitive,
            "offset": a.offset, "limit": a.limit,
        })),
        CliCommand::GetString(a) => ("get_string", json!({
            "address": a.address, "max_len": a.max_len,
        })),
        CliCommand::AnalyzeStrings(a) => ("analyze_strings", json!({
            "query": a.query, "offset": a.offset, "limit": a.limit,
        })),
        CliCommand::XrefsToString(a) => ("xrefs_to_string", json!({
            "query": a.query, "exact": a.exact, "case_insensitive": a.case_insensitive,
            "offset": a.offset, "limit": a.limit, "max_xrefs": a.max_xrefs,
        })),

        CliCommand::Segments => ("segments", json!({})),
        CliCommand::Imports(a) => ("imports", json!({"offset": a.offset, "limit": a.limit})),
        CliCommand::Exports(a) => ("exports", json!({"offset": a.offset, "limit": a.limit})),
        CliCommand::Entrypoints => ("entrypoints", json!({})),
        CliCommand::Globals(a) => ("globals", json!({
            "offset": a.offset, "limit": a.limit, "filter": a.filter,
        })),
        CliCommand::GetGlobalValue(a) => ("get_global_value", json!({"query": a.query})),

        CliCommand::XrefsTo(a) => ("xrefs_to", json!({
            "address": a.address, "offset": a.offset, "limit": a.limit,
        })),
        CliCommand::XrefsFrom(a) => ("xrefs_from", json!({
            "address": a.address, "offset": a.offset, "limit": a.limit,
        })),
        CliCommand::XrefMatrix(a) => ("xref_matrix", json!({"addresses": a.addresses})),

        CliCommand::BasicBlocks(a) => ("basic_blocks", json!({"address": a.address})),
        CliCommand::Callers(a) => ("callers", json!({"address": a.address})),
        CliCommand::Callees(a) => ("callees", json!({"address": a.address})),
        CliCommand::Callgraph(a) => ("callgraph", json!({
            "address": a.address, "max_depth": a.max_depth, "max_nodes": a.max_nodes,
        })),
        CliCommand::FindPaths(a) => ("find_paths", json!({
            "start": a.start, "end": a.end,
            "max_paths": a.max_paths, "max_depth": a.max_depth,
        })),

        CliCommand::GetBytes(a) => ("get_bytes", json!({"address": a.address, "size": a.size})),
        CliCommand::ReadInt(a) => ("read_int", json!({"address": a.address, "size": a.size})),
        CliCommand::FindBytes(a) => ("find_bytes", json!({
            "pattern": a.pattern, "limit": a.limit,
        })),

        CliCommand::SearchText(a) => ("search_text", json!({
            "text": a.text, "max_results": a.max_results,
        })),
        CliCommand::SearchImm(a) => ("search_imm", json!({
            "value": a.value, "max_results": a.max_results,
        })),
        CliCommand::FindInsns(a) => ("find_insns", json!({
            "patterns": a.patterns, "max_results": a.max_results,
            "case_insensitive": a.case_insensitive,
        })),
        CliCommand::FindInsnOperands(a) => ("find_insn_operands", json!({
            "patterns": a.patterns, "max_results": a.max_results,
            "case_insensitive": a.case_insensitive,
        })),

        CliCommand::AddrInfo(a) => ("addr_info", json!({"address": a.address})),

        CliCommand::LocalTypes(a) => ("local_types", json!({
            "offset": a.offset, "limit": a.limit, "filter": a.filter,
        })),
        CliCommand::DeclareType(a) => ("declare_type", json!({
            "decl": a.decl, "relaxed": a.relaxed, "replace": a.replace, "multi": a.multi,
        })),
        CliCommand::ApplyTypes(a) => ("apply_types", json!({
            "address": a.address, "name": a.name, "offset": a.offset,
            "stack_offset": a.stack_offset, "stack_name": a.stack_name,
            "decl": a.decl, "type_name": a.type_name,
            "relaxed": a.relaxed, "delay": a.delay, "strict": a.strict,
        })),
        CliCommand::InferTypes(a) => ("infer_types", json!({
            "address": a.address, "name": a.name, "offset": a.offset,
        })),
        CliCommand::StackFrame(a) => ("stack_frame", json!({"address": a.address})),
        CliCommand::DeclareStack(a) => ("declare_stack", json!({
            "address": a.address, "name": a.name, "offset": a.offset,
            "var_name": a.var_name, "decl": a.decl, "relaxed": a.relaxed,
        })),
        CliCommand::DeleteStack(a) => ("delete_stack", json!({
            "address": a.address, "name": a.name,
            "offset": a.offset, "var_name": a.var_name,
        })),

        CliCommand::Structs(a) => ("structs", json!({
            "offset": a.offset, "limit": a.limit, "filter": a.filter,
        })),
        CliCommand::StructInfo(a) => ("struct_info", json!({
            "ordinal": a.ordinal, "name": a.name,
        })),
        CliCommand::ReadStruct(a) => ("read_struct", json!({
            "address": a.address, "ordinal": a.ordinal, "name": a.name,
        })),
        CliCommand::XrefsToField(a) => ("xrefs_to_field", json!({
            "ordinal": a.ordinal, "name": a.name,
            "member_index": a.member_index, "member_name": a.member_name,
            "limit": a.limit,
        })),

        CliCommand::SetComment(a) => ("set_comment", json!({
            "address": a.address, "name": a.name, "offset": a.offset,
            "comment": a.comment, "repeatable": a.repeatable,
        })),
        CliCommand::Rename(a) => ("rename", json!({
            "address": a.address, "current_name": a.current_name,
            "name": a.name, "flags": a.flags,
        })),
        CliCommand::PatchBytes(a) => ("patch_bytes", json!({
            "address": a.address, "name": a.name, "offset": a.offset, "bytes": a.bytes,
        })),
        CliCommand::PatchAsm(a) => ("patch_asm", json!({
            "address": a.address, "name": a.name, "offset": a.offset, "line": a.line,
        })),

        CliCommand::RunScript(a) => ("run_script", json!({"code": a.code})),
        CliCommand::LoadDebugInfo(a) => ("load_debug_info", json!({
            "path": a.path, "verbose": a.verbose,
        })),
        CliCommand::IntConvert(a) => ("int_convert", json!({"value": a.value})),
    };
    Ok((op.to_string(), params))
}
