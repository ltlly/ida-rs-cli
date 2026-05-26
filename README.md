<p align="center">
  <h1 align="center">ida-rs-cli</h1>
  <h4><p align="center">Headless IDA Pro CLI for AI-powered reverse engineering.<br>面向 AI 逆向工程的 Headless IDA Pro 命令行工具。</p></h4>
</p>
<br>

> **Fork Notice / Fork 说明**
>
> This is a personal fork of [blacktop/ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs). I only use and maintain the **`ida-rs-cli`** (daemon-based CLI) portion. The MCP server (`ida-mcp`) code remains in the repo but is **not maintained** in this fork — if you need the MCP server, please use the upstream project.
>
> 本仓库是 [blacktop/ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) 的个人 Fork。我仅使用和维护 **`ida-rs-cli`**（基于守护进程的命令行工具）部分。MCP 服务器（`ida-mcp`）代码仍保留在仓库中，但在本 Fork 中**不再维护**——如需 MCP 服务器，请使用上游项目。

---

## What is `ida-rs-cli` / 这是什么

`ida-rs-cli` is a daemon-based CLI that gives you full access to IDA Pro's analysis engine from the terminal. It's designed for agent-driven and scripted reverse engineering workflows — JSON output to stdout, stateless client, persistent daemon holding IDBs in memory.

`ida-rs-cli` 是一个基于守护进程的命令行工具，让你在终端中完整使用 IDA Pro 的分析引擎。它为 Agent 驱动和脚本化的逆向工程工作流而设计——JSON 输出到 stdout、无状态客户端、持久守护进程驻留 IDB 在内存中。

## Prerequisites / 前置要求

- IDA Pro 9.2+ with valid license (9.3sp1 recommended)
- IDA Pro 9.2+，需有效许可证（推荐 9.3sp1）

## Install / 安装

```bash
git clone https://github.com/ltlly/ida-rs-cli.git
cd ida-rs-cli
cargo build --release --bin ida-rs-cli
```

The built binary will be at `target/release/ida-rs-cli`. See [docs/BUILDING.md](docs/BUILDING.md) for more details.

编译产物位于 `target/release/ida-rs-cli`。更多细节见 [docs/BUILDING.md](docs/BUILDING.md)。

## Quick Start / 快速开始

```bash
# Start the daemon (holds binaries in memory)
# 启动守护进程（持有二进制文件在内存中）
ida-rs-cli daemon start

# Load a target binary
# 加载目标二进制
ida-rs-cli target load -f /path/to/binary.so

# Start analyzing
# 开始分析
ida-rs-cli functions --limit 20
ida-rs-cli decompile --name main
ida-rs-cli xrefs-to --address 0x100001234
ida-rs-cli strings --filter "password"
ida-rs-cli callgraph --address 0x4fe30 --max-depth 3
ida-rs-cli get-bytes --address 0x24ac0 --size 64
```

## Architecture / 架构

```
┌─────────────────┐       Unix Socket        ┌──────────────────────┐
│   ida-rs-cli    │ ──── JSON-line IPC ────▶ │       Daemon          │
│  (stateless     │ ◀──── JSON response ──── │  (persistent process, │
│   client)       │                           │   IDBs held in memory)│
└─────────────────┘                           └──────────────────────┘
```

The daemon runs on the main thread (required by IDA's library), manages multiple loaded targets via `TargetManager`, and processes requests sequentially. The CLI client connects, sends one JSON-line request, reads one response, then exits. This design keeps the CLI stateless and pipe-friendly.

守护进程运行在主线程（IDA 库要求），通过 `TargetManager` 管理多个已加载目标，顺序处理请求。CLI 客户端连接、发送一条 JSON-line 请求、读取一条响应后退出。这种设计使 CLI 保持无状态且对管道友好。

## Daemon Management / 守护进程管理

```bash
ida-rs-cli daemon start          # Start in foreground / 前台启动
ida-rs-cli daemon stop           # Graceful shutdown / 优雅停止
ida-rs-cli daemon status         # Health check + loaded target count / 健康检查
```

## Target Management / 目标管理

```bash
ida-rs-cli target load -f app.so                # Load binary / 加载二进制
ida-rs-cli target load -f app.i64               # Open existing IDB / 打开已有 IDB
ida-rs-cli target load -f app.so --no-analyse   # Skip auto-analysis / 跳过自动分析
ida-rs-cli target list                          # List loaded targets / 查看已加载目标
ida-rs-cli target switch --id t2                # Switch active target / 切换活跃目标
ida-rs-cli target close --id t1                 # Unload a target / 卸载目标
```

## Commands / 命令一览

57 subcommands covering all IDA analysis capabilities:

57 个子命令覆盖所有 IDA 分析能力：

| Category / 分类 | Commands / 命令 |
|-----------------|-----------------|
| Info / 基础信息 | `info`, `meta`, `analysis-status` |
| Functions / 函数 | `functions`, `resolve-function`, `function-at`, `lookup-funcs`, `analyze-funcs` |
| Disassembly / 反汇编 | `disasm`, `disasm-function-at`, `decompile`, `pseudocode-at` |
| Strings / 字符串 | `strings`, `find-string`, `get-string`, `analyze-strings`, `xrefs-to-string` |
| Structure / 二进制结构 | `segments`, `imports`, `exports`, `entrypoints`, `globals`, `get-global-value` |
| Xrefs / 交叉引用 | `xrefs-to`, `xrefs-from`, `xref-matrix` |
| Control Flow / 控制流 | `basic-blocks`, `callers`, `callees`, `callgraph`, `find-paths` |
| Memory / 内存 | `get-bytes`, `read-int`, `find-bytes` |
| Search / 搜索 | `search-text`, `search-imm`, `find-insns`, `find-insn-operands` |
| Types / 类型 | `local-types`, `declare-type`, `apply-types`, `infer-types`, `stack-frame`, `declare-stack`, `delete-stack` |
| Structs / 结构体 | `structs`, `struct-info`, `read-struct`, `xrefs-to-field` |
| Annotations / 标注 | `set-comment`, `rename`, `patch-bytes`, `patch-asm` |
| Scripting / 脚本 | `run-script` |
| Utility / 工具 | `int-convert`, `addr-info`, `load-debug-info` |

## Pagination & Output / 分页与输出

All list commands support `--offset` and `--limit` (default 50). Output is JSON to stdout — designed for piping with `jq`:

所有列表命令支持 `--offset` 和 `--limit`（默认 50）。输出为 JSON 到 stdout，适合与 `jq` 配合使用：

```bash
ida-rs-cli functions --offset 0 --limit 50     # Page 1 / 第 1 页
ida-rs-cli functions --offset 50 --limit 50    # Page 2 / 第 2 页
ida-rs-cli functions | jq '.[].name'
ida-rs-cli decompile --name main | jq -r '.pseudocode'
```

## Multi-Target / 多目标

When multiple binaries are loaded, select with `-t`:

多个二进制加载时用 `-t` 选择：

```bash
ida-rs-cli -t libfoo functions            # By filename substring / 按文件名子串
ida-rs-cli -t t2 disasm --address 0x1000  # By target ID / 按目标 ID
```

## Agent Skill Integration / Agent Skill 集成

Install the bundled skill definition so AI agents (Claude Code, Codex CLI) know how to drive `ida-rs-cli`:

安装打包的 Skill 定义，让 AI Agent（Claude Code、Codex CLI）知道如何使用 `ida-rs-cli`：

```bash
./scripts/install-skill.sh                       # Install to both / 安装到两者
./scripts/install-skill.sh --client codex        # Codex only
./scripts/install-skill.sh --client claude-code  # Claude Code only
./scripts/install-skill.sh --uninstall           # Remove / 卸载
```

## Performance / 性能

Measured on a real reverse engineering session (libdidiwsg.so, 3.5MB ARM64 shared library):

在真实逆向会话中测量（libdidiwsg.so，3.5MB ARM64 共享库）：

| Operation / 操作 | Latency / 延迟 |
|------------------|----------------|
| Simple command (int-convert, info) | ~270ms |
| List commands (functions, exports) | ~335ms |
| Decompile (large function, 3808 bytes) | ~842ms |
| 20 rapid sequential commands | ~6.7s total |

The main bottleneck is CLI process startup (~210ms per invocation), not daemon/IDA processing. For agent-driven workflows this is negligible since the agent's thinking time dominates.

主要瓶颈是 CLI 进程启动（每次调用 ~210ms），而非 daemon/IDA 处理。对于 Agent 驱动的工作流，这可以忽略不计，因为 Agent 的思考时间占主导。

## Platform Setup / 平台配置

The binary links against IDA's libraries at runtime. Standard installation paths are auto-detected.

二进制在运行时链接 IDA 库，标准安装路径会自动检测。

| Platform | Library | Fallback |
|----------|---------|----------|
| macOS | `libida.dylib` | `DYLD_LIBRARY_PATH` |
| Linux | `libida.so` | `IDADIR` or `LD_LIBRARY_PATH` |
| Windows | `ida.dll` | Place exe in IDA dir, or set `IDADIR` |

## About the MCP Server / 关于 MCP 服务器

The `ida-mcp` binary (MCP server for AI agents via stdio/HTTP) still exists in this repo but is **unmaintained in this fork**. For MCP usage, please refer to the upstream: [blacktop/ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs).

`ida-mcp` 二进制（通过 stdio/HTTP 为 AI Agent 提供服务的 MCP 服务器）仍存在于本仓库中，但在本 Fork 中**不维护**。如需 MCP 功能，请参考上游项目：[blacktop/ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs)。

## Docs / 文档

- [docs/BUILDING.md](docs/BUILDING.md) - Build from source / 从源码构建
- [docs/TOOLS.md](docs/TOOLS.md) - Tool catalog (MCP) / 工具目录（MCP）
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) - MCP transports / MCP 传输方式
- [docs/TESTING.md](docs/TESTING.md) - Running tests / 运行测试
- [CLAUDE.md](CLAUDE.md) - AI agent guidance for this codebase / AI Agent 代码库指引

## License / 许可证

MIT — Original work Copyright (c) 2026 [blacktop](https://github.com/blacktop)
