---
doc_id: fusion-executor/api-reference
product: fusion-executor
class: platform
entry: service
doc_type: api-reference
title: {zh: "fusion-executor API 参考", en: "fusion-executor API Reference"}
audience: engineer
status: draft
version: 0.2.20
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - README.md
  - docs/architecture.md
  - python/fusion_executor/
---

# fusion-executor API 参考 / API Reference

fusion-executor exposes one surface in three forms: the PyO3 module `fusion_executor` (in-process), the UDS JSON-RPC 2.0 daemon (`serve()`), and the `fusion-executor` CLI. This page documents the primary methods and result types; the full deep-dive (IPC protocol frames, per-crate API, data schemas) lives in [architecture.md](architecture.md), and the authoritative method signatures are in `python/fusion_executor/` and `crates/fe-pyo3/`.

## Core execution

### FusionSandboxExecutor

```python
from fusion_executor import FusionSandboxExecutor, ExecutionResult

ex = FusionSandboxExecutor()
```

Constructor accepts, among others: `guard_sock` (enable fusion-guard zero-trust checks; default OFF), `guard_tenant` (must match the tenant bound to the executor's OS identity in guard, else every evaluate returns -32001 and the command is fail-closed blocked).

### run / run_async / run_streaming

```python
r = ex.run(command, *, task_id=None, cwd=None, timeout=30.0, env_vars=None,
           enable_rollback_snapshot=True, trace_id=None) -> ExecutionResult
```

`ExecutionResult` fields: `exit_code, stdout, stderr, task_id, command, duration_sec, timed_out, blocked_by_security, security_reason, snapshot_id, diagnostics, auto_rolled_back, trace_id, guard_action_id`.

Exit-code contract: `0` success; `-124` timeout; `-1` blocked by Security Guard or internal error. `guard_action_id` carries guard's `action_id` (UUID) when guard is enabled and the verdict is Block/L3, for caller-side audit / confirm loops; `None` when guard is OFF or Allow/L1/L2. `env_vars=None` clears the environment and baselines host PATH.

`run_async(...)` is the asyncio form (`await ex.run_async("echo hi", task_id="t1", cwd="/tmp", timeout=30.0)`); `run_streaming` yields live stdio frames (v1.2). Server-side deterministic cancel of in-flight streams: `cancel_stream(stream_id, *, sock_path=None) -> bool` (issue #32).

### Background shells (v1.8)

`start_shell` returns `ShellStartResult`; poll via `ShellOutput` / `ShellInfo` APIs — run_in_background parity with a background shell registry, `kill_grace_ms` 4-layer teardown. See `examples/03_streaming.py` and the README "Background Shells" section.

### Per-command sandbox profile (v0.2.8)

`SandboxProfile` customizes the macOS seatbelt profile per command (issue #34). Sensitive filesystem paths are file-write denied by seatbelt (best-effort on Darwin 25 where global `file-write*` is degraded — audit C-16).

## Native file tools (v1.3)

`file_edit` / `glob` / `grep` / `write_file` / `multi_edit` / `notebook_edit` — native implementations with a surgical patch engine (replaces Claude-SDK-style BashTool/FileEdit glue). See `examples/05_file_tools.py`.

## Diagnostics & rollback

- `ExecutionResult.diagnostics` — structured slicer output for failing commands (`error_type`, `raw_trace`, ...): traceback regex + tree-sitter slicing for 8 languages.
- `snap = ex.snapshot_create(cwd=...)` — Git stash create, returns SHA.
- `ex.rollback(snap, cwd=...)` — `git checkout -- . && git stash apply`.
- Auto-rollback (v1.4, FR-04 optional): `RollbackPolicy`; `RollbackOutcome{applied, skipped_reason, wip_sha}` fails loud. `RollbackPolicy.max_consecutive_failures` is a **caller-owned** circuit-breaker threshold (ARCH-7): the stateless executor never reads it.

## GUI / Computer Use

20 `GuiAction` variants over AXUIElement + CoreGraphics + CGEvent synthesis, coordinate-mapping `scale_factor`, display-capability query, batch actions and batch mouse-move path, screenshot with sensitive-region masking. TCC grants required: Accessibility (AX actions) and Screen Recording (screenshots) are probed separately (audit C-11/C-12/C-13).

## IPC service

```python
ex.serve()  # UDS JSON-RPC 2.0; default ~/.fusion-executor/fe.sock
sub = ex.subscribe(["telemetry", "stdio"], interval_ms=100, screenshot_interval_ms=1000)
for params in sub:          # yields params (dict) of executor.event frames
    print(params["channel"], params["data"])
sub.unsubscribe()
```

Channels: `telemetry` (10Hz CPU/mem sampling), `stdio` (cross-connection command stream), `screenshot` (periodic capture). Bidirectional server-push via BroadcastHub (v1.5, issue #14). Protocol details and the TypeScript client sketch: [ipc-client-typescript.md](ipc-client-typescript.md).

## Guard integration (optional, default OFF)

Enable by passing `guard_sock='/tmp/fusion-guard.sock'` (or setting `FUSION_GUARD_SOCK`). Every command is evaluated by the fusion-guard daemon before execution (allow/preview/redact/block, risk L1-L4); a guard RPC failure is a fail-closed block, not a degrade. `FUSION_EXECUTOR_TENANT` sets the tenant implicitly. Wire types are mirrored read-only in `crates/fe-guard` — fusion-executor never modifies fusion-guard.

## Tool selection & agent loop (v0.2.14+, issue #46/#54)

- `LayaToolSelector` — deterministic tool selection, dual backends (`"python"`, `"http"` → `/v1/laya/decide`), deterministic filler-stripping param extraction; AC8 <15ms (HTTP p50=6.2ms, python p50=7.2ms). Misses (confidence < 0.7) degrade to the LLM backend.
- `AgentLoop` — wired into `FusionSandboxExecutor.agent_run()` (production path).

## Batch-task service (v0.2.19, issue #57)

```python
from fusion_executor import TaskManager, RetryPolicy, TaskState
```

`TaskManager` — shared async batch-task service for business apps: `task_id` polling, `queued → running → done | failed | cancelled` state machine, retry with backoff, SQLite persistence across restarts, `TASK_PROGRESS:` live progress protocol, result export/report.

## CLI

```bash
fusion-executor "echo hi" --cwd /tmp --timeout 10
fusion-executor "echo hi" -v     # verbose JSON output
```

## Python package

Package root `fusion_executor`; native extension `fusion_executor._native` (built from `crates/fe-pyo3` via maturin). Runtime deps: `pydantic>=2.0`, `fusion-core>=0.7.0` (config resolution only — the executor delegates inference to the caller).
