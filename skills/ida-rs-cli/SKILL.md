---
name: ida-rs-cli
description: Use the local ida-rs-cli daemon for headless IDA Pro reverse engineering. Prefer this skill for disassembly, decompilation, function listing, xrefs, callgraph, string search, memory read, type inspection, struct analysis, and IDAPython scripting through the ida-rs-cli daemon bridge.
---

# ida-rs-cli

Use this skill when the user wants reverse-engineering work driven by the local `ida-rs-cli` CLI. The tool communicates with a persistent daemon process that holds loaded IDA databases in memory, enabling fast repeated queries over a Unix socket.

## Architecture

- **Daemon** — long-running process started via `ida-rs-cli daemon start`. Holds loaded binaries/IDBs in memory. Manages multiple targets concurrently.
- **CLI** — stateless client that sends JSON-line requests to the daemon over a Unix socket and prints JSON results to stdout.

## Workflow

1. Start the daemon:

```bash
ida-rs-cli daemon start          # blocks in foreground
ida-rs-cli daemon status         # check if running + health
```

2. Load a target:

```bash
ida-rs-cli target load -f /path/to/binary.so
ida-rs-cli target load -f /path/to/existing.i64   # open existing IDB
ida-rs-cli target load -f app.so --idb-out /tmp/app.i64
ida-rs-cli target list                             # see loaded targets
```

3. Run analysis commands (target auto-selected if only one loaded):

```bash
ida-rs-cli functions --limit 20
ida-rs-cli disasm --address 0x100001234 --count 30
ida-rs-cli decompile --name main
```

4. Multi-target usage:

```bash
ida-rs-cli target switch --id t2
ida-rs-cli -t libfoo.so functions    # target by name substring
```

## Key Commands

### Daemon & Target Management

```bash
ida-rs-cli daemon start [--background]
ida-rs-cli daemon stop
ida-rs-cli daemon status
ida-rs-cli target load -f <path> [--idb-out <path>] [--no-analyse]
ida-rs-cli target list
ida-rs-cli target close --id <id>
ida-rs-cli target switch --id <id>
```

### Database Info

```bash
ida-rs-cli info                    # file type, processor, bitness
ida-rs-cli meta                    # compiler, ABI metadata
ida-rs-cli analysis-status         # auto_is_ok, auto_state
```

### Functions

```bash
ida-rs-cli functions [--offset N] [--limit N] [--filter <name>]
ida-rs-cli resolve-function --name <name>
ida-rs-cli function-at --address 0x1234
ida-rs-cli lookup-funcs --queries func1,0x1000,func2
ida-rs-cli analyze-funcs            # trigger re-analysis (mutating)
```

### Disassembly & Decompilation

```bash
ida-rs-cli disasm --address 0x1000 [--count 20] [--offset 0]
ida-rs-cli disasm --name main --count 50
ida-rs-cli disasm-function-at --address 0x1000 [--count 200] [--offset 0]
ida-rs-cli decompile --address 0x1000 [--max-lines 100]
ida-rs-cli decompile --name targetFunc
ida-rs-cli pseudocode-at --address 0x1000 [--end-address 0x1100]
```

### Strings

```bash
ida-rs-cli strings [--offset 0] [--limit 50] [--filter <text>]
ida-rs-cli find-string --query "password" [--exact] [--case-insensitive]
ida-rs-cli get-string --address 0x2000
ida-rs-cli analyze-strings [--query <text>] [--offset 0] [--limit 50]
ida-rs-cli xrefs-to-string --query "error" [--max-xrefs 10]
```

### Binary Structure

```bash
ida-rs-cli segments
ida-rs-cli imports [--offset 0] [--limit 50]
ida-rs-cli exports [--offset 0] [--limit 50]
ida-rs-cli entrypoints
ida-rs-cli globals [--offset 0] [--limit 50] [--filter <name>]
ida-rs-cli get-global-value --query <name_or_address>
```

### Cross-References

```bash
ida-rs-cli xrefs-to --address 0x1000
ida-rs-cli xrefs-from --address 0x1000
ida-rs-cli xref-matrix --addresses 0x1000,0x2000,0x3000
```

### Control/Call Flow

```bash
ida-rs-cli basic-blocks --address 0x1000
ida-rs-cli callers --address 0x1000
ida-rs-cli callees --address 0x1000
ida-rs-cli callgraph --address 0x1000 [--max-depth 3] [--max-nodes 50]
ida-rs-cli find-paths --start 0x1000 --end 0x2000 [--max-paths 5]
```

### Memory

```bash
ida-rs-cli get-bytes --address 0x1000 --size 64
ida-rs-cli read-int --address 0x1000 [--size 4]
ida-rs-cli find-bytes --pattern "48 89 5C 24" [--limit 50]
```

### Search

```bash
ida-rs-cli search-text --text "malloc" [--max-results 50]
ida-rs-cli search-imm --value 0xDEADBEEF [--max-results 50]
ida-rs-cli find-insns --patterns "BL,MOV" [--case-insensitive]
ida-rs-cli find-insn-operands --patterns "X0,SP"
```

### Types & Structs

```bash
ida-rs-cli local-types [--offset 0] [--limit 50] [--filter <name>]
ida-rs-cli declare-type --decl "struct foo { int x; };"
ida-rs-cli apply-types --address 0x1000 --decl "int (*)(void)"
ida-rs-cli infer-types --address 0x1000
ida-rs-cli stack-frame --address 0x1000
ida-rs-cli structs [--offset 0] [--limit 50] [--filter <name>]
ida-rs-cli struct-info --name MyStruct
ida-rs-cli read-struct --address 0x3000 --name MyStruct
ida-rs-cli xrefs-to-field --name MyStruct --member-name field1
```

### Annotations & Patching (Mutating)

```bash
ida-rs-cli set-comment --address 0x1000 --comment "decryption loop"
ida-rs-cli rename --address 0x1000 --name better_name
ida-rs-cli patch-bytes --address 0x1000 --bytes "90 90 90"
ida-rs-cli patch-asm --address 0x1000 --line "nop"
```

### Scripting

```bash
ida-rs-cli run-script --code "import idautils; print(list(idautils.Functions())[:5])"
```

### Utility

```bash
ida-rs-cli int-convert --value 0xDEAD
ida-rs-cli addr-info --address 0x1000
ida-rs-cli load-debug-info --path /path/to/app.dSYM
```

## Address Format

All `--address` parameters accept:
- Hex: `0x100001234`, `0x1000`
- Decimal: `4294971956`

## Pagination

List commands support `--offset` and `--limit` for pagination. Default limit is 50 for most commands. Use `--offset` to page through large result sets:

```bash
ida-rs-cli functions --offset 0 --limit 50    # first page
ida-rs-cli functions --offset 50 --limit 50   # second page
```

## Output

All commands output JSON to stdout. Errors go to stderr. Use `jq` for filtering:

```bash
ida-rs-cli functions | jq '.[].name'
ida-rs-cli decompile --name main | jq -r '.pseudocode'
```

## Tips

- Start the daemon first; all analysis commands require it.
- Use `-t <selector>` to target a specific binary when multiple are loaded.
- Keep `--limit` values reasonable (≤50) to avoid huge outputs.
- For large functions, paginate disassembly with `--offset`.
- `--max-lines 0` in decompile means unlimited output.
- `decompile` requires Hex-Rays; without it only `disasm` commands work.
