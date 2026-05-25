<p align="center">
  <!--<a href="https://github.com/blacktop/ida-mcp-rs"><img alt="Logo" src="https://raw.githubusercontent.com/blacktop/ida-mcp-rs/refs/heads/main/docs/logo.svg" height="400"/></a>-->
  <h1 align="center">ida-mcp-rs</h1>
  <h4><p align="center">Headless IDA Pro MCP server & CLI for AI-powered reverse engineering.</p></h4>
  <p align="center">
    <a href="https://github.com/blacktop/ida-mcp-rs/actions" alt="Actions">
          <img src="https://github.com/blacktop/ida-mcp-rs/actions/workflows/build.yml/badge.svg" /></a>
    <a href="https://github.com/blacktop/ida-mcp-rs/releases/latest" alt="Downloads">
          <img src="https://img.shields.io/github/downloads/blacktop/ida-mcp-rs/total.svg" /></a>
    <a href="https://github.com/blacktop/ida-mcp-rs/releases" alt="GitHub Release">
          <img src="https://img.shields.io/github/v/release/blacktop/ida-mcp-rs" /></a>
    <a href="http://doge.mit-license.org" alt="LICENSE">
          <img src="https://img.shields.io/:license-mit-blue.svg" /></a>
</p>
<br>

> **[中文文档](README.zh.md)**

This project builds **two binaries** from a shared codebase:

| Binary | Purpose | Transport |
|--------|---------|-----------|
| `ida-mcp` | MCP server for AI agents (Claude, Codex, Cursor, etc.) | stdio / Streamable HTTP |
| `ida-rs-cli` | Daemon-based CLI for direct terminal use and agent skills | Unix socket IPC |

## Prerequisites

- IDA Pro 9.2+ with valid license (9.3sp1 recommended)

## Getting Started

### Install

**macOS / Linux** (via [Homebrew](https://brew.sh))
```bash
brew install blacktop/tap/ida-mcp        # Latest (IDA 9.3/9.3sp1)
brew install blacktop/tap/ida-mcp@9.2    # IDA 9.2
```

**Windows** (via [Scoop](https://scoop.sh))
```powershell
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket
scoop install blacktop/ida-mcp
```

> **Windows note:** See the [Windows platform setup](#windows) section below for DLL discovery options.

**macOS / Linux** (via [Nix](https://nixos.org))
```bash
nix shell github:blacktop/nur#ida-mcp \
  --extra-experimental-features 'nix-command flakes'
```

**Linux** (via [Snap](https://snapcraft.io/ida-mcp))
```bash
sudo snap install ida-mcp
sudo snap connect ida-mcp:dot-idapro   # grant access to ~/.idapro (license)
```
> Strict confinement. Requires IDA Pro installed under `$HOME` (installer default `~/ida-pro-9.3`). For IDA in `/opt/` or system paths, use Homebrew or Nix.

**Direct download** — grab the archive for your platform from [GitHub Releases](https://github.com/blacktop/ida-mcp-rs/releases).

**Build from source**

```bash
cargo build --release    # builds both ida-mcp and ida-rs-cli
```

See [docs/BUILDING.md](docs/BUILDING.md) for details.

> ida-mcp versions mirror IDA Pro versions (`v9.3.x` for IDA 9.3, `v9.2.x` for IDA 9.2). A version mismatch is detected at startup with a clear error message. Scoop and NUR publish the latest version. For older IDA versions, use the matching [GitHub Release](https://github.com/blacktop/ida-mcp-rs/releases) or the versioned Homebrew cask.

### Platform Setup

#### macOS

Standard IDA installations in `/Applications` work automatically:
```bash
claude mcp add ida -- ida-mcp
```

If you see `Library not loaded: @rpath/libida.dylib`, set `DYLD_LIBRARY_PATH` to your IDA path:
```bash
claude mcp add ida -e DYLD_LIBRARY_PATH='/path/to/IDA.app/Contents/MacOS' -- ida-mcp
```

Supported paths (auto-detected):
- `/Applications/IDA Professional 9.3.app/Contents/MacOS`
- `/Applications/IDA Home 9.3.app/Contents/MacOS`
- `/Applications/IDA Essential 9.3.app/Contents/MacOS`
- `/Applications/IDA Professional 9.2.app/Contents/MacOS`

#### Linux

The IDA installer defaults to `~/ida-pro-9.3` — the launcher script auto-detects this:
```bash
claude mcp add ida -- ida-mcp
```

For non-default install locations, set `IDADIR`:
```bash
claude mcp add ida -e IDADIR='/path/to/ida' -- ida-mcp
```

Resolution order: `$IDADIR` → `~/ida-pro-9.3` → `/opt/ida-pro-9.3` and other RUNPATH fallbacks.

#### Windows

**Option A** — Install `ida-mcp.exe` into your IDA directory (simplest, no env setup needed):
```powershell
# Copy the binary next to ida.dll / idalib.dll
copy ida-mcp.exe "C:\Program Files\IDA Professional 9.3\"
claude mcp add ida -- "C:\Program Files\IDA Professional 9.3\ida-mcp.exe"
```

**Option B** — Install via [Scoop](https://scoop.sh) (auto-detects IDA and sets `IDADIR`):
```powershell
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket
scoop install blacktop/ida-mcp
claude mcp add ida -- ida-mcp
```

**Option C** — Set `IDADIR` manually:
```powershell
# Persistent (survives reboots)
setx IDADIR "C:\Program Files\IDA Professional 9.3"
# Then restart your terminal
claude mcp add ida -- ida-mcp
```

Windows requires `ida.dll` and `idalib.dll` to be discoverable at startup. Placing `ida-mcp.exe` in the IDA directory is the easiest approach. Otherwise, the IDA directory must be on `PATH` or pointed to by `IDADIR`.

Common IDA paths:
- `C:\Program Files\IDA Professional 9.3`
- `C:\Program Files\IDA Pro 9.3`
- `C:\Program Files\IDA Home 9.3`

### Runtime Requirements

The binary links against IDA's libraries at runtime. Standard installation paths are auto-detected via baked RPATHs. For non-standard paths:

| Platform | Library | Fallback Configuration |
|----------|---------|------------------------|
| macOS | `libida.dylib` | `DYLD_LIBRARY_PATH` |
| Linux | `libida.so` | `IDADIR` (launcher reads it) or `LD_LIBRARY_PATH` |
| Windows | `ida.dll` | Place exe in IDA dir, set `IDADIR`, or add IDA dir to `PATH` |

---

## MCP Server (`ida-mcp`)

### Configure your AI agent

#### [Claude Code](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/overview)
```bash
claude mcp add ida -- ida-mcp
```

#### [Codex CLI](https://github.com/openai/codex)
```bash
codex mcp add ida -- ida-mcp
```

#### [Gemini CLI](https://github.com/google-gemini/gemini-cli)
```bash
gemini mcp add ida -- ida-mcp
```

#### [Cursor](https://cursor.com)
Add to `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "ida": { "command": "ida-mcp" }
  }
}
```

### MCP Usage

Once configured, you can analyze binaries through your AI agent:

```
# Open a binary (returns quickly — analysis runs separately)
open_idb(path: "~/samples/malware")

# These work immediately, no analysis needed
list_functions(limit: 20)
disasm_by_name(name: "main", count: 20)
strings(limit: 10)

# For xrefs/decompile on large binaries, run analysis in background
analyze_funcs(background: true)   # returns task_id
task_status(task_id: "analyze-1") # poll progress

# Decompile (requires Hex-Rays + completed analysis)
decompile(address: "0x100000f00")

# Discover more tools
tool_catalog(query: "find callers")
```

#### HTTP/SSE worker pool

`serve-http` keeps the existing single in-process IDA worker by default. For
stateful multi-client HTTP/SSE usage, set `--max-workers` above `1` to route
sessions through child `ida-mcp worker` processes:

```bash
ida-mcp serve-http --bind 127.0.0.1:8765 --max-workers 4 --min-workers 1
```

Without `--max-workers N`, HTTP sessions still share one IDA context; a second
client opening another binary waits behind the first and then gets the normal
`A database is already open` error. Pooled startup logs include
`Starting pooled HTTP router` and `MCP pooled HTTP server listening`.

Each opened HTTP session leases one child worker until `close_idb`, HTTP
`DELETE`, session timeout, or server shutdown. `close_idb` releases the lease
immediately, but the child process may stay alive idle for reuse until
`--worker-idle-timeout-secs` elapses. If all workers are leased, new
`open_idb`/`open_dsc` calls fail with `Worker pool exhausted` so clients can
retry later. Pooled mode requires stateful HTTP sessions; `--max-workers > 1`
is rejected with `--stateless`.

If an SSE-capable client exits without sending `close_idb` or HTTP `DELETE`,
pooled mode closes the session after its standalone SSE stream disconnects and
the `--worker-disconnect-grace-secs` reconnect grace elapses.
POST-only clients do not always leave a stream for the server to observe, so
their orphaned sessions are reclaimed by `--session-keep-alive-secs` (default
1800 seconds). Lower it if you need faster pool reclaim for POST-only clients.

#### `dyld_shared_cache` analysis

`open_dsc` opens a single module from Apple's dyld_shared_cache. On first use it runs `idat` in the background to create the `.i64` (this can take minutes). Subsequent opens are instant.

```
# Open a module from the DSC
open_dsc(path: "/path/to/dyld_shared_cache_arm64e", arch: "arm64e",
         module: "/usr/lib/libobjc.A.dylib")

# If a background task was started, poll until done
task_status(task_id: "dsc-1")

# Load additional frameworks for cross-module references
open_dsc(path: "/path/to/dyld_shared_cache_arm64e", arch: "arm64e",
         module: "/usr/lib/libobjc.A.dylib",
         frameworks: ["/System/Library/Frameworks/Foundation.framework/Foundation"])

# Incrementally load another DSC dylib into an already-open database
dsc_add_dylib(module: "/usr/lib/libSystem.B.dylib")

# Incrementally load a DSC data/GOT/stub region by address
dsc_add_region(address: "0x180116000")

# After dsc_add_dylib/dsc_add_region, confirm analysis readiness
analysis_status()
```

Requirements:
- `idat` binary (from IDA installation) must be available via `$IDADIR` or standard install paths
- The DSC loader and `dscu` plugin (bundled with IDA 9.x)

#### IDAPython scripting

`run_script` executes Python code in the open database via IDA's IDAPython engine. stdout and stderr are captured.

```
# Inline script
run_script(code: "import idautils\nfor f in idautils.Functions():\n    print(hex(f))")

# Run a .py file from disk
run_script(file: "/path/to/analysis_script.py")

# With timeout (default 120s, max 600s)
run_script(code: "import ida_bytes; print(ida_bytes.get_bytes(0x1000, 16).hex())",
           timeout_secs: 30)
```

All `ida_*` modules, `idc`, and `idautils` are available. See the [IDAPython API reference](https://python.docs.hex-rays.com).

### Context Optimization

`ida-mcp` exposes 71 tools (~10k tokens of `tools/list` payload). Frontier models with 1M context don't notice; smaller models and agents without lazy tool loading do. Filter the surface to only what you need:

| Flag | Env var | Effect |
|---|---|---|
| `--toolsets=cat1,cat2` | `IDA_MCP_TOOLSETS` | Replaces "all tools" with the union of selected categories |
| `--tools=t1,t2`        | `IDA_MCP_TOOLS`         | Adds individual tools (additive to `--toolsets`) |
| `--exclude-tools=t1,t2`| `IDA_MCP_EXCLUDE_TOOLS` | Subtracts from the include set; always wins |
| `--read-only`          | `IDA_MCP_READ_ONLY`     | Strips mutating/arbitrary-code tools (`run_script`, `patch*`, `rename`, `set_comments`, type/stack edits, `dsc_add_*`, `analyze_funcs`); keeps lifecycle/discovery |

No flags = all 71 tools (default). Categories: `core`, `functions`, `disassembly`, `decompile`, `xrefs`, `control_flow`, `memory`, `search`, `metadata`, `types`, `editing`, `scripting` (run `tool_catalog` to enumerate). Flags override env vars; unknown names rejected at startup.

#### Recommendations by client

- **Claude Code, Cursor:** no action — both clients already lazy-load MCP tool schemas. Claude Code's MCP Tool Search auto-defers when tools exceed 10% of context (Cursor's Dynamic Context Discovery does similar).
- **Codex CLI, OpenCode:** every session pays the full ~10k tokens. Pick a focused subset:
  ```bash
  ida-mcp --toolsets=core,functions,disassembly,decompile,xrefs
  ```
- **Gemini CLI:** the Gemini API caps at 512 function declarations across all MCP servers. Shrink `ida-mcp` so it fits alongside others:
  ```bash
  ida-mcp --toolsets=core,functions,disassembly,decompile --read-only
  ```
- **Small / local models:** prefer the smallest workable surface. For triage:
  ```bash
  ida-mcp --toolsets=core,functions --tools=decompile,callees,callers --read-only
  ```

#### Configuring through `mcpServers.json`

Most installed MCP configs run `ida-mcp` directly without a subcommand. The env vars apply on that path too:

```json
{
  "mcpServers": {
    "ida-mcp": {
      "command": "ida-mcp",
      "env": {
        "IDA_MCP_TOOLSETS": "core,functions,disassembly,decompile,xrefs",
        "IDA_MCP_READ_ONLY": "true"
      }
    }
  }
}
```

#### Measuring

Run `just measure-tools` to see the per-tool char/token breakdown. Filtering doesn't change the numbers reported there (it acts at the protocol boundary), but the difference shows up in your client's context view (`/context` in Claude Code, equivalents elsewhere).

---

## CLI Tool (`ida-rs-cli`)

`ida-rs-cli` provides a daemon-based CLI for direct terminal interaction and agent skill integration. It shares the same analysis engine as `ida-mcp` but exposes it as Unix commands rather than MCP tools.

### Quick Start

```bash
# Start the daemon (holds binaries in memory)
ida-rs-cli daemon start

# Load a binary
ida-rs-cli target load -f /path/to/binary.so

# Analyze
ida-rs-cli functions --limit 20
ida-rs-cli decompile --name main
ida-rs-cli xrefs-to --address 0x100001234
ida-rs-cli strings --filter "password"
```

### Architecture

```
┌─────────────────┐       Unix Socket        ┌─────────────────────┐
│   ida-rs-cli    │ ──── JSON-line IPC ────▶ │      Daemon          │
│  (stateless)    │ ◀──── JSON response ──── │  (persistent, holds  │
└─────────────────┘                           │   IDBs in memory)    │
                                              └─────────────────────┘
```

The daemon runs on the main thread (required by IDA's library), manages multiple loaded targets via `TargetManager`, and processes requests sequentially. The CLI connects, sends one request, reads one response, then exits.

### Daemon Management

```bash
ida-rs-cli daemon start          # start (foreground)
ida-rs-cli daemon start --background   # (planned)
ida-rs-cli daemon stop           # graceful shutdown
ida-rs-cli daemon status         # health check + loaded target count
```

### Target Management

```bash
ida-rs-cli target load -f app.so                # load binary
ida-rs-cli target load -f app.i64               # open existing IDB
ida-rs-cli target load -f app.so --no-analyse   # skip auto-analysis
ida-rs-cli target list                          # show all loaded targets
ida-rs-cli target switch --id t2                # change active target
ida-rs-cli target close --id t1                 # unload a target
```

### Command Categories

| Category | Commands |
|----------|----------|
| Info | `info`, `meta`, `analysis-status` |
| Functions | `functions`, `resolve-function`, `function-at`, `lookup-funcs`, `analyze-funcs` |
| Disassembly | `disasm`, `disasm-function-at`, `decompile`, `pseudocode-at` |
| Strings | `strings`, `find-string`, `get-string`, `analyze-strings`, `xrefs-to-string` |
| Structure | `segments`, `imports`, `exports`, `entrypoints`, `globals`, `get-global-value` |
| Xrefs | `xrefs-to`, `xrefs-from`, `xref-matrix` |
| Control Flow | `basic-blocks`, `callers`, `callees`, `callgraph`, `find-paths` |
| Memory | `get-bytes`, `read-int`, `find-bytes` |
| Search | `search-text`, `search-imm`, `find-insns`, `find-insn-operands` |
| Types | `local-types`, `declare-type`, `apply-types`, `infer-types`, `stack-frame`, `declare-stack`, `delete-stack` |
| Structs | `structs`, `struct-info`, `read-struct`, `xrefs-to-field` |
| Annotations | `set-comment`, `rename`, `patch-bytes`, `patch-asm` |
| Scripting | `run-script` |
| Utility | `int-convert`, `addr-info`, `load-debug-info` |

### Pagination & Output

All list commands support `--offset` and `--limit` (default 50):

```bash
ida-rs-cli functions --offset 0 --limit 50     # page 1
ida-rs-cli functions --offset 50 --limit 50    # page 2
ida-rs-cli imports --limit 100                 # larger page
```

Output is JSON to stdout. Pipe with `jq` for filtering:

```bash
ida-rs-cli functions | jq '.[].name'
ida-rs-cli decompile --name main | jq -r '.pseudocode'
```

### Multi-Target Usage

When multiple binaries are loaded, use `-t` to select:

```bash
ida-rs-cli -t libfoo functions            # by filename substring
ida-rs-cli -t t2 disasm --address 0x1000  # by target ID
```

### Install Agent Skill

Install the bundled skill definition into Claude Code and/or Codex CLI so the agent knows how to use `ida-rs-cli`:

```bash
./scripts/install-skill.sh                    # both clients (symlink)
./scripts/install-skill.sh --client codex     # Codex only
./scripts/install-skill.sh --client claude-code  # Claude Code only
./scripts/install-skill.sh --mode copy        # copy instead of symlink
./scripts/install-skill.sh --uninstall        # remove
```

Skill directories:
- Claude Code: `~/.claude/skills/ida-rs-cli/`
- Codex CLI: `~/.codex/skills/ida-rs-cli/`

---

## Docs

- [docs/TOOLS.md](docs/TOOLS.md) - Tool catalog and discovery workflow
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) - Stdio vs Streamable HTTP
- [docs/BUILDING.md](docs/BUILDING.md) - Build from source
- [docs/TESTING.md](docs/TESTING.md) - Running tests

## License

MIT Copyright (c) 2026 **blacktop**
