<p align="center">
  <h1 align="center">ida-mcp-rs</h1>
  <h4><p align="center">Headless IDA Pro MCP 服务器 & CLI —— 面向 AI 的逆向工程工具</p></h4>
</p>
<br>

> **[English](README.md)**

本项目从同一代码库构建 **两个二进制文件**：

| 二进制 | 用途 | 传输方式 |
|--------|------|----------|
| `ida-mcp` | 面向 AI Agent 的 MCP 服务器（Claude、Codex、Cursor 等） | stdio / Streamable HTTP |
| `ida-rs-cli` | 基于守护进程的 CLI，用于终端直接使用与 Agent Skill 集成 | Unix socket IPC |

## 前置要求

- IDA Pro 9.2+（推荐 9.3sp1）

## 快速开始

### 安装

**macOS / Linux**（通过 [Homebrew](https://brew.sh)）
```bash
brew install blacktop/tap/ida-mcp        # 最新版 (IDA 9.3/9.3sp1)
brew install blacktop/tap/ida-mcp@9.2    # IDA 9.2
```

**Windows**（通过 [Scoop](https://scoop.sh)）
```powershell
scoop bucket add blacktop https://github.com/blacktop/scoop-bucket
scoop install blacktop/ida-mcp
```

**从源码构建**
```bash
cargo build --release    # 同时构建 ida-mcp 和 ida-rs-cli
```

详细构建说明见 [docs/BUILDING.md](docs/BUILDING.md)。

### 平台配置

#### macOS

标准 IDA 安装路径（`/Applications`）会自动检测：
```bash
claude mcp add ida -- ida-mcp
```

如果出现 `Library not loaded: @rpath/libida.dylib`，设置 `DYLD_LIBRARY_PATH`：
```bash
claude mcp add ida -e DYLD_LIBRARY_PATH='/path/to/IDA.app/Contents/MacOS' -- ida-mcp
```

#### Linux

```bash
claude mcp add ida -- ida-mcp
# 非默认路径：
claude mcp add ida -e IDADIR='/path/to/ida' -- ida-mcp
```

#### Windows

最简单的方式是把 `ida-mcp.exe` 放入 IDA 安装目录：
```powershell
copy ida-mcp.exe "C:\Program Files\IDA Professional 9.3\"
claude mcp add ida -- "C:\Program Files\IDA Professional 9.3\ida-mcp.exe"
```

---

## MCP 服务器（`ida-mcp`）

### 配置 AI Agent

```bash
# Claude Code
claude mcp add ida -- ida-mcp

# Codex CLI
codex mcp add ida -- ida-mcp

# Gemini CLI
gemini mcp add ida -- ida-mcp
```

Cursor 配置（`.cursor/mcp.json`）：
```json
{
  "mcpServers": {
    "ida": { "command": "ida-mcp" }
  }
}
```

### MCP 使用示例

```
open_idb(path: "~/samples/malware")
list_functions(limit: 20)
disasm_by_name(name: "main", count: 20)
decompile(address: "0x100000f00")
tool_catalog(query: "find callers")
```

### 上下文优化

`ida-mcp` 暴露 71 个工具（`tools/list` 约 10k tokens）。可按需裁剪：

```bash
# 仅加载核心类别
ida-mcp --toolsets=core,functions,disassembly,decompile,xrefs

# 只读模式（移除修改类工具）
ida-mcp --read-only

# 组合使用
ida-mcp --toolsets=core,functions --tools=decompile,callees,callers --read-only
```

---

## CLI 工具（`ida-rs-cli`）

`ida-rs-cli` 提供基于守护进程的命令行界面，适合终端直接使用以及 Agent Skill 集成。它与 `ida-mcp` 共享同一分析引擎，但以 Unix 命令形式暴露。

### 快速开始

```bash
# 启动守护进程（持有二进制文件在内存中）
ida-rs-cli daemon start

# 加载目标
ida-rs-cli target load -f /path/to/binary.so

# 分析
ida-rs-cli functions --limit 20
ida-rs-cli decompile --name main
ida-rs-cli xrefs-to --address 0x100001234
ida-rs-cli strings --filter "password"
```

### 架构

```
┌─────────────────┐       Unix Socket        ┌─────────────────────┐
│   ida-rs-cli    │ ──── JSON-line IPC ────▶ │      Daemon          │
│  （无状态客户端）│ ◀──── JSON 响应     ──── │ （持久进程，IDB 驻留  │
└─────────────────┘                           │    内存中）           │
└─────────────────────┘
```

### 守护进程管理

```bash
ida-rs-cli daemon start          # 前台启动
ida-rs-cli daemon stop           # 优雅停止
ida-rs-cli daemon status         # 健康检查 + 已加载目标数
```

### 目标管理

```bash
ida-rs-cli target load -f app.so                # 加载二进制
ida-rs-cli target load -f app.i64               # 打开已有 IDB
ida-rs-cli target load -f app.so --no-analyse   # 跳过自动分析
ida-rs-cli target list                          # 查看所有已加载目标
ida-rs-cli target switch --id t2                # 切换活跃目标
ida-rs-cli target close --id t1                 # 卸载目标
```

### 命令分类

| 分类 | 命令 |
|------|------|
| 基础信息 | `info`, `meta`, `analysis-status` |
| 函数 | `functions`, `resolve-function`, `function-at`, `lookup-funcs`, `analyze-funcs` |
| 反汇编 | `disasm`, `disasm-function-at`, `decompile`, `pseudocode-at` |
| 字符串 | `strings`, `find-string`, `get-string`, `analyze-strings`, `xrefs-to-string` |
| 二进制结构 | `segments`, `imports`, `exports`, `entrypoints`, `globals`, `get-global-value` |
| 交叉引用 | `xrefs-to`, `xrefs-from`, `xref-matrix` |
| 控制流 | `basic-blocks`, `callers`, `callees`, `callgraph`, `find-paths` |
| 内存 | `get-bytes`, `read-int`, `find-bytes` |
| 搜索 | `search-text`, `search-imm`, `find-insns`, `find-insn-operands` |
| 类型 | `local-types`, `declare-type`, `apply-types`, `infer-types`, `stack-frame` |
| 结构体 | `structs`, `struct-info`, `read-struct`, `xrefs-to-field` |
| 标注 | `set-comment`, `rename`, `patch-bytes`, `patch-asm` |
| 脚本 | `run-script` |
| 工具 | `int-convert`, `addr-info`, `load-debug-info` |

### 分页与输出

所有列表命令支持 `--offset` 和 `--limit`（默认 50）：

```bash
ida-rs-cli functions --offset 0 --limit 50     # 第 1 页
ida-rs-cli functions --offset 50 --limit 50    # 第 2 页
```

输出为 JSON 到 stdout，配合 `jq` 过滤：

```bash
ida-rs-cli functions | jq '.[].name'
ida-rs-cli decompile --name main | jq -r '.pseudocode'
```

### 多目标使用

多个二进制加载时，用 `-t` 选择：

```bash
ida-rs-cli -t libfoo functions            # 按文件名子串
ida-rs-cli -t t2 disasm --address 0x1000  # 按目标 ID
```

### 安装 Agent Skill

将打包的 Skill 定义安装到 Claude Code 和/或 Codex CLI，让 Agent 知道如何使用 `ida-rs-cli`：

```bash
./scripts/install-skill.sh                       # 安装到两者（符号链接）
./scripts/install-skill.sh --client codex        # 仅 Codex
./scripts/install-skill.sh --client claude-code  # 仅 Claude Code
./scripts/install-skill.sh --mode copy           # 复制而非符号链接
./scripts/install-skill.sh --uninstall           # 卸载
```

Skill 目录：
- Claude Code: `~/.claude/skills/ida-rs-cli/`
- Codex CLI: `~/.codex/skills/ida-rs-cli/`

---

## 文档

- [docs/TOOLS.md](docs/TOOLS.md) - 工具目录与发现工作流
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) - Stdio vs Streamable HTTP
- [docs/BUILDING.md](docs/BUILDING.md) - 从源码构建
- [docs/TESTING.md](docs/TESTING.md) - 运行测试

## 许可证

MIT Copyright (c) 2026 **blacktop**
