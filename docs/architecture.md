---
doc_id: fusion-executor/architecture-reference
product: fusion-executor
class: platform
entry: service
doc_type: architecture
title: {zh: "fusion-executor 架构参考", en: "fusion-executor Architecture Reference"}
audience: engineer
status: draft
version: 0.2.20
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - docs/architecture.md
  - Cargo.toml
---

# fusion-executor — Architecture Reference

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

