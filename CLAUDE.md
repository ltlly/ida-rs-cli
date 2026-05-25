# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`ida-rs-cli` is an agent-first CLI for headless IDA Pro reverse engineering. It is a Rust project that builds two binaries:

- **`ida-mcp`** (`src/bin/mcp_main.rs`) — the original MCP server that exposes IDA Pro tools to AI agents via the Model Context Protocol (stdio/HTTP/SSE transport).
- **`ida-rs-cli`** (`src/main.rs`) — a daemon-based CLI client for direct terminal use and agent skill integration.

## Architecture

### CLI Daemon (`ida-rs-cli`)

The CLI uses a persistent daemon architecture:

1. **Daemon** (`src/daemon/`) — long-running process started via `ida-rs-cli daemon start`. Binds a Unix socket, manages a `TargetManager` that holds loaded IDA databases in memory.
2. **CLI** (`src/cli.rs`) — stateless client. Parses commands via `clap`, serializes to JSON-line requests, sends over Unix socket, prints JSON response to stdout.
3. **Handlers** (`src/ida/handlers/`) — actual IDA analysis logic. Each handler function processes a request and returns results.

Wire path: CLI → Unix socket → Daemon `dispatch` → Handler → IDA library → Response → CLI stdout.

### MCP Server (`ida-mcp`)

The MCP binary is the upstream project. It runs an MCP server (stdio or streamable HTTP) and uses the same handler code in `src/ida/handlers/`.

**Do NOT modify MCP-related code** (`src/bin/mcp_main.rs`, `src/server/`, MCP transport logic) when working on CLI features. The CLI addition is intended as a non-invasive extension.

## Common Commands

```bash
# Build both binaries
cargo build

# Build only the CLI
cargo build --bin ida-rs-cli

# Build only the MCP server
cargo build --bin ida-mcp

# Run the CLI
cargo run --bin ida-rs-cli -- daemon start
cargo run --bin ida-rs-cli -- functions --limit 10

# Run the MCP server
cargo run --bin ida-mcp

# Install the agent skill into Claude Code and Codex
./scripts/install-skill.sh
```

## Project Layout

```
src/
├── main.rs              # CLI entry point
├── cli.rs               # CLI command definitions + dispatch
├── bin/
│   └── mcp_main.rs     # MCP server entry point
├── daemon/
│   ├── mod.rs           # Daemon startup + socket binding
│   ├── server.rs        # Request dispatch to handlers
│   ├── protocol.rs      # JSON-line request/response types
│   └── target.rs        # TargetManager (multi-binary support)
├── ida/
│   ├── handlers/        # Analysis handlers (shared by MCP + CLI)
│   └── ...              # IDA worker, pool, request types
├── server/              # MCP HTTP/SSE server (DO NOT MODIFY for CLI work)
└── ...
skills/
└── ida-rs-cli/
    ├── SKILL.md         # Agent skill definition
    └── agents/
        └── openai.yaml  # Codex agent descriptor
scripts/
└── install-skill.sh     # Install skill to ~/.claude/skills/ and ~/.codex/skills/
```

## Conventions

- **Address parsing:** addresses are strings like `"0x100001234"` or decimal `"4294971956"`. The daemon handler side parses them.
- **Pagination:** list commands use `--offset` + `--limit`. Default limit is 50.
- **Output:** JSON to stdout, logs/errors to stderr. This keeps the CLI pipe-friendly.
- **Target selection:** `-t <selector>` for multi-target; auto-selects when only one is loaded.
- **No MCP modification:** CLI work should only touch `src/cli.rs`, `src/main.rs`, `src/daemon/`, and handler signatures (with backwards-compatible `0` defaults for MCP callers).
