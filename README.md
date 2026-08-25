# fusion-executor

> **Language / 语言**: **English** | [中文](README_CN.md)

Controlled execution sandbox + macOS OS-level control hub. Runs shell commands safely (Security Guard + PTY Sandbox), drives native GUI (Computer Use via Accessibility API), and rolls back on failure (Git snapshots). Replaces the Claude SDK BashTool/FileEdit + Docker sandbox, but native — no Docker, macOS process isolation + Git snapshots, init <5ms.

Rust core + PyO3/maturin Python bindings. First maturin/PyO3 project in the Fusion monorepo (the other 23 Python projects use setuptools).

**Status: v0.1.0 released** — security + sandbox + diagnostics slicer + Git rollback + UDS JSON-RPC IPC service + macOS GUI (AXUIElement + CoreGraphics + CGEvent key synthesis + modifier combos + scroll/drag/wait + double_click/right_click/hover + window control close/minimize/zoom/resize) + live stdio streaming (NDJSON chunk/done) + screenshot width/height metadata + native file tools (file_edit/glob/grep — native replacement for Claude SDK FileEdit/Glob/Grep) + surgical patch engine (Unified Diff apply + function-level replace, full-rewrite forbidden) + Data Schema §4.1 backfill (task_id/command/duration_sec) + auto-rollback (FR-04 optional policy, git-status damage detection triggers) + live telemetry (10Hz CPU/mem UDS broadcast, GPU caller-injected) + macOS seatbelt runtime sandbox (sandbox-exec, deny network + 13 dangerous binaries) + cross-node rollback registry (FNV-1a repo identifier) + bidirectional IPC server-push (BroadcastHub three-channel telemetry/stdio/screenshot, per-sub scope isolation) + Pydantic strict schema (extra=forbid). Diagnostics slicer covers 8 languages (Python/TS/Node/Bun/Rust/Go-panic/Swift/Go-compile). 16 GuiAction variants, 0 hand-written unsafe blocks outside the audited fe-gui scope. **223 Rust + 113 Python tests green; clippy `--all-targets -D warnings` clean; fmt/ruff clean; maturin builds.** Two audit passes all defects fixed — defect audit (T1–T9, 68 defects) + commercial-grade integration audit (11 Blockers + 13 MAJOR/MINOR, FAIL → PASS). See `examples/` for runnable demos and `docs/INDEX.md` for the documentation map.

## Architecture

10-crate Cargo workspace (resolver 2), one PyO3 binding crate built by maturin.

```
fusion-executor/
├── Cargo.toml              # workspace root (mirrors fusion-design)
├── pyproject.toml          # maturin build backend, fusion_executor Python package
├── crates/
│   ├── fe-core/            # orchestrator: Executor pipeline, BLOCKING_RT
│   ├── fe-security/        # Security Guard: regex blocklist + tokenizer + whitelist
│   ├── fe-sandbox/         # PTY subprocess, timeout, truncation, OOM cap
│   ├── fe-gui/             # macOS Computer Use: AXUIElement + CoreGraphics (P4)
│   ├── fe-rollback/        # git snapshot/rollback (P2) + auto-rollback guard (v1.4)
│   ├── fe-diagnostics/     # Traceback regex + tree-sitter slicer (P2)
│   ├── fe-ipc/             # UDS JSON-RPC 2.0 server (P3) + bidirectional server-push BroadcastHub (v1.5 #14)
│   ├── fe-tools/           # native file tools: file_edit/glob/grep + patch engine (v1.3)
│   ├── fe-telemetry/       # live telemetry: 10Hz CPU/mem sampling stream (v1.4)
│   └── fe-pyo3/            # PyO3 bindings; maturin target → fusion_executor._native
├── python/
│   └── fusion_executor/    # Pydantic v2 models + FusionSandboxExecutor thin wrapper
└── python/tests/           # pytest
```

Core pipeline (fe-core): `validate(command)` → if blocked return `exit_code=-1` → else `sandbox.run()` → return `ExecutionResult`.

### Key Constraints

- `[workspace.lints.rust] unsafe_code = "deny"` — 7 crates forbid unsafe; fe-gui crate-level `#![allow(unsafe_code)]` (3 audited FFI blocks: AXIsProcessTrusted + AXValueGetValue ×2, forced by rustc 1.96 `unsafe_extern_blocks`).
- `extension-module` is NOT in the workspace default features (otherwise `cargo test` cannot link libpython); maturin injects it via `pyproject features=["pyo3/extension-module"]`.
- PTY merges stdout+stderr → all into stdout (stderr empty); traceback is readable at the tail.
- Exit codes: 0=success, -124=timeout, -1=blocked/internal error.

## Build

```bash
cd /Users/dahai/fusion && source .venv/bin/activate   # shared venv (Python 3.14)
pip install maturin                                     # first time
cd fusion-executor
maturin develop --release          # editable install into shared venv → fusion_executor._native
```

## Test

```bash
cd /Users/dahai/fusion && source .venv/bin/activate && cd fusion-executor

# Rust (workspace — extension-module off by default, cargo test can link libpython)
cargo test --workspace
cargo test -p fe-sandbox                # single crate
cargo test -p fe-security

# Python
pytest python/tests
pytest python/tests/test_executor.py::test_run_echo -v   # single test

# Smoke
python -c "from fusion_executor import FusionSandboxExecutor; print(repr(FusionSandboxExecutor().run('echo hi').stdout))"

# Start UDS server + subscribe broadcast (v1.5 #14)
python -c "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()"   # another terminal
# another terminal: subscribe to telemetry push
python -c "from fusion_executor import FusionSandboxExecutor; s=FusionSandboxExecutor().subscribe(['telemetry'], interval_ms=100); [print(next(s)) for _ in range(3)]; s.unsubscribe()"
```

## Lint

```bash
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
ruff check .          # Python
ruff format .         # Python
```

## CLI Usage

```bash
fusion-executor "echo hi" --cwd /tmp --timeout 10
fusion-executor "echo hi" -v          # verbose JSON output
```

## Python API

```python
from fusion_executor import FusionSandboxExecutor, ExecutionResult

ex = FusionSandboxExecutor()

# Sync execution (simplest for scripts)
r: ExecutionResult = ex.run("echo hi")
assert r.exit_code == 0  # 0=success, -124=timeout, -1=blocked/internal error
assert r.stdout == "hi\n"
assert not r.blocked_by_security

# Security block
r = ex.run("rm -rf /")
assert r.blocked_by_security and r.exit_code == -1

# Timeout
r = ex.run("python3 -c 'while True: pass'", timeout=1.0)
assert r.timed_out and r.exit_code == -124

# Diagnostics slicer — failing commands return structured Diagnostics (when exit_code != 0)
r = ex.run("python3 -c \"raise ValueError('boom')\"")
assert r.diagnostics.error_type == "ValueError"
assert r.diagnostics.raw_trace is not None

# Git snapshot + rollback (caller-driven; executor is stateless)
snap = ex.snapshot_create(cwd="/path/to/repo")  # git stash create → SHA
ex.rollback(snap, cwd="/path/to/repo")  # git checkout -- . && git stash apply <id>

# Async (asyncio callers)
r = await ex.run_async("echo hi", task_id="t1", cwd="/tmp", timeout=30.0)

# Bidirectional server-push subscription (v1.5 #14 — requires a running serve())
# Three channels: telemetry (10Hz CPU/mem) / stdio (cross-connection command stream) / screenshot (periodic capture)
sub = ex.subscribe(["telemetry", "stdio"], interval_ms=100, screenshot_interval_ms=1000)
for params in sub:  # __next__ yields the params (dict) of executor.event frames
    print(params["channel"], params["data"])
sub.unsubscribe()  # or sub.close()
```

`run` signature: `run(command, *, task_id=None, cwd=None, timeout=30.0, env_vars=None, enable_rollback_snapshot=True) -> ExecutionResult`.

`ExecutionResult` fields: `exit_code, stdout, stderr, task_id, command, duration_sec, timed_out, blocked_by_security, security_reason, snapshot_id, diagnostics`.

## Native File Tools + Surgical Patch Engine (v1.3)

Replaces the Claude SDK FileEdit/Glob/Grep — native Rust implementation, guarded by the fe-security path guard (rejects cwd escape / sensitive-dir access), atomic write (`.fe-tmp-{pid}` + rename).

```python
from fusion_executor import FusionSandboxExecutor, EditResult, GlobEntry, GrepMatch

ex = FusionSandboxExecutor()

# file_edit — unique-match exact replace (>1 match rejected, avoids accidental edits)
r: EditResult = ex.file_edit("app.py", "x = 1", "x = 99", cwd="/repo")
assert r.ok and r.matches == 1

# glob — wildcard match, returns paths relative to cwd
entries: list[GlobEntry] = ex.glob("**/*.py", cwd="/repo")

# grep — regex search over files/dirs (recursive, skips binary, 1000-hit cap)
hits: list[GrepMatch] = ex.grep(r"^import\s", ["app.py"], cwd="/repo")

# apply_patch — Unified Diff apply (diffy); full rewrite forbidden (new_range all-delete → reject)
r = ex.apply_patch("--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,2 @@\n-x\n+x\n+y\n", cwd="/repo")

# replace_function — function-level replace (tree-sitter AST locate, py/js/ts/rs); no grammar → regex fallback
r = ex.replace_function("mod.py", "old_fn", "def old_fn():\n    return 99\n", cwd="/repo")
```

`EditResult{ok, path, error, matches}`; `GlobEntry{path, is_dir}`; `GrepMatch{path, line_number, content}`. replace_function not finding the function → `ok=False, error="function not found: ..."`.

## Live stdio Streaming (v1.2)

The `run_streaming` generator yields frame by frame — chunk strings first, the done frame yields an `ExecutionResult` at the end. Wired through 4 layers (fe-sandbox `run_streaming` → fe-core `execute_streaming` → fe-pyo3 `NativeStreamIterator` → Python generator).

```python
from fusion_executor import FusionSandboxExecutor, ExecutionResult

ex = FusionSandboxExecutor()
for frame in ex.run_streaming("echo hi", enable_rollback_snapshot=False):
    if isinstance(frame, ExecutionResult):
        print(f"done exit={frame.exit_code}")
    else:
        print(f"chunk: {frame!r}", end="")
```

Frame format (`ExecutionStreamEvent`, serde tag="type"):
- chunk: `{"type":"chunk","data":"..."}` (line-by-line stdout)
- done: `{"type":"done", exit_code:..., stdout:..., diagnostics:...}` (ExecutionResult fields flattened into the same object, not nested)

Blocked (security violation) → only a single done frame, no chunks. Timeout → done frame `timed_out=True, exit_code=-124`. Failing command → done frame includes `diagnostics`.

## Auto-rollback (v1.4 — FR-04 optional policy)

`run()` / `run_streaming()` accept an optional `auto_rollback: RollbackPolicy`. When enabled, if a command fails (`exit_code != 0`) AND workspace file changes are detected (`git status --porcelain` non-empty), it auto-`rollback(本次快照)`s and marks `result.auto_rolled_back=True`. The Executor stays stateless — the guard lifetime is limited to a single execution and does not accumulate failure counts across requests (consecutive-failure counting belongs to the caller's self-healing loop).

```python
from fusion_executor import FusionSandboxExecutor, RollbackPolicy

ex = FusionSandboxExecutor()
policy = RollbackPolicy(max_consecutive_failures=3, file_damage_check=True)
# command corrupts app.py then fails → auto-rollback restores the git baseline
r = ex.run(
    "python3 -c \"open('app.py','w').write('broken'); raise ValueError(1)\"",
    cwd="/repo",
    auto_rollback=policy,
)
assert r.exit_code != 0 and r.auto_rolled_back
```

`RollbackPolicy{max_consecutive_failures=3 (reserved field), file_damage_check=True}`. No snapshot (`enable_rollback_snapshot=False`) → guard skips. Non-git repo → damage detection failure treated as 0 changes, no rollback.

## Live Telemetry (v1.4 — GPU/CPU UDS broadcast)

The `telemetry_stream()` generator yields `TelemetrySample` frame by frame — 10Hz (adjustable `interval_ms`) process CPU/mem sampling. GPU fields default to None (the executor runs no model, has no GPU handle) and are caller-injected. `max_samples>0` ends the stream when reached; dropping the iterator stops the sampling task automatically (channel closes). The Executor is stateless: each call is an independent stream.

```python
from fusion_executor import FusionSandboxExecutor, TelemetrySample

ex = FusionSandboxExecutor()
for s in ex.telemetry_stream(interval_ms=100, max_samples=50):
    print(f"t={s.ts_ms}ms cpu={s.cpu_pct:.1f}% mem={s.mem_mb:.1f}MB")
    # s.gpu_pct / s.gpu_mem_mb default None (serde skip, caller-injected)
```

`TelemetrySample{ts_ms (milliseconds, caller epoch), cpu_pct (single-core multiples), mem_mb (resident memory MB), gpu_pct?, gpu_mem_mb?, task_id?}`. Underlying fe-telemetry `start_stream(cfg, rt::Handle)` spawns the sysinfo sampling task on `BLOCKING_RT`; 4-layer wiring (fe-telemetry → fe-core → fe-ipc `executor.telemetry_stream` multi-frame → fe-pyo3 `NativeTelemetryIterator` → Python generator).

## Bidirectional server-push subscription (v1.5 #14)

`subscribe()` opens a UDS connection to subscribe to a broadcast channel — one subscription, the server continuously pushes notification frames, and the client can concurrently send other requests on the same connection (duplex). Unlike `telemetry_stream`/`execute_stream` (request-initiated, single stream then stops): subscription is **server-pushed**, multiple connections share the same source (fan-out).

```python
from fusion_executor import FusionSandboxExecutor

ex = FusionSandboxExecutor()
# Three channels: telemetry (10Hz CPU/mem) / stdio (cross-connection command chunk+done) / screenshot (periodic capture)
sub = ex.subscribe(["telemetry", "stdio"], interval_ms=100, screenshot_interval_ms=1000)
print(sub.subscription_id)  # "sub-N"
for params in sub:
    print(params["channel"], params["data"])
    if ...:
        break
sub.unsubscribe()  # or sub.close()
```

The three broadcast sources (fe-ipc `BroadcastHub` lazy start/stop, 0 subscribers self-exit):
- **telemetry** — single `executor.telemetry_stream` fan-out to all telemetry subscribers (10Hz default, `interval_ms` adjustable).
- **stdio** — `execute`/`execute_stream` handlers fan out chunk/done to all stdio subscribers (**cross-connection**: A subscribes, B runs a command, A receives the push).
- **screenshot** — periodic `gui_action(Screenshot)` sampling fan-out (`screenshot_interval_ms` default 1000, slower than telemetry); TCC-untrusted → frame `data.ok=false`/error, no crash (via fe-gui safe wrapper).

Push frame format (server-initiated, **no id** — JSON-RPC notification convention; the client distinguishes response vs push by presence of `id`):
- `{"jsonrpc":"2.0","method":"executor.event","params":{"subscription_id":"sub-1","channel":"telemetry","data":{...}}}`

`Subscription` is a pure-Python UDS client — connects to the running `serve()` socket; `__next__` filters `executor.event` frames matching this sub_id, skips non-event frames; `unsubscribe()` sends unsubscribe + closes the socket. `SUB_CHANNELS = ("telemetry", "stdio", "screenshot")` — unknown channel → `ValueError`. fe-ipc adds 0 new unsafe (screenshot reuses fe-gui safe wrapper); fe-core Executor stays stateless (broadcast fan-out is an IPC-broker concern, not executor state).

## IPC Service (UDS JSON-RPC)

Start a UDS JSON-RPC 2.0 server — for fusion-code (TypeScript) / fusion-studio (Swift) to call over a Unix Domain Socket:

```bash
python -c "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()"
# Socket: /tmp/fusion-executor.sock (override FUSION_EXECUTOR_SOCK)
```

Protocol: newline-delimited JSON-RPC 2.0, error codes -32700/-32600/-32601/-32603 + extensions -32010(security)/-32011(timeout)/-32012(rollback)/-32013(AX). Methods: `executor.health`/`execute`/`execute_stream`/`snapshot_create`/`rollback`/`diagnostics`/`gui_action`/`file_edit`/`glob`/`grep`/`apply_patch`/`replace_function`/`telemetry_stream`/`subscribe`/`unsubscribe`/`shutdown`.

`executor.execute_stream` streaming: multi-frame (chunk/done) sharing one id, newline-delimited frame by frame —
- chunk: `{"jsonrpc":"2.0","id":id,"result":{"type":"chunk","data":"..."}}`
- done: `{"jsonrpc":"2.0","id":id,"result":{"type":"done","result":{...ExecutionResult}}}` (the UDS path nests done under `result.result`, DIFFERENT shape from the flattened PyO3 path — the two paths are deliberately separate, each consumer reads its own shape)

`executor.telemetry_stream` streaming: multi-frame sample sharing one id, newline-delimited frame by frame —
- sample: `{"jsonrpc":"2.0","id":id,"result":{"type":"sample","sample":{...TelemetrySample}}}` (params `interval_ms` (default 100) / `max_samples` (default 0 = infinite); GPU fields omitted via serde skip when None)

`executor.subscribe` / `executor.unsubscribe` (v1.5 #14 bidirectional server-push) — see the "Bidirectional server-push subscription" section above. subscribe response `{ok:true, subscription_id:"sub-N"}`, then the server continuously pushes notification frames (no id, `method:"executor.event"`); the connection is duplex, other requests can be sent concurrently. params `channels` (`["telemetry","stdio","screenshot"]`) / `interval_ms` (default 100) / `screenshot_interval_ms` (default 1000).

The fusion-code TS client sketch is in `docs/ipc-client-typescript.md`; fusion-studio uses the existing `IPCClient.swift udsCall` pointed at the same socket.

## Status

- **P1 — Skeleton + Security + Sandbox** ✅ complete
  - fe-security: regex blocklist + tokenizer chain-bypass defense + whitelist (38 unit tests)
  - fe-sandbox: PTY exec + timeout kill + truncation + OOM ring buffer (9 unit tests)
  - fe-core: validate → sandbox → return pipeline
  - fe-pyo3: `execute_sync` binding; `maturin develop` works; `FusionSandboxExecutor.run("echo hi")` works
  - Exit gate: real exec of echo/python; blocks `rm -rf /`/sudo chain/ncat; 1s timeout kills infinite loop (exit -124)
- **P2 — Diagnostics + Rollback** ✅ complete
  - fe-diagnostics: 8 languages (Python/TS/Node/Bun/Rust/Go/Swift/Go-compile) traceback regex extraction + ±20-line code slice, error line marked `>` (12 unit tests)
  - fe-rollback: git CLI snapshot/rollback — `snapshot_create` (stash create/HEAD) + `rollback` (checkout + stash apply) + `rollback_file` single-file (3 unit tests)
  - fe-core: pipeline adds snapshot (pre-exec, non-fatal) + diagnostics slice (when exit_code!=0) + public `snapshot_create_async`/`rollback_async`
  - fe-pyo3: `NativeDiagnostics` + `diagnostics` field + `snapshot_create`/`rollback` methods; env_vars/enable_rollback_snapshot passed through
  - Exit gate: `run("python3 -c 'raise ValueError'")` → `diagnostics.error_type == "ValueError"`; rollback round-trip restores a corrupted file
- **P3 — IPC Service** ✅ complete
  - fe-ipc: UDS JSON-RPC 2.0 server — `tokio::net::UnixListener` + newline-delimited + per-connection spawn; socket `/tmp/fusion-executor.sock` (override `FUSION_EXECUTOR_SOCK`), unlink stale sock + chmod 0o666
  - Methods: `executor.health`/`execute`/`snapshot_create`/`rollback`/`diagnostics`/`gui_action`(P4 stub)/`shutdown`; error codes -32700/-32600/-32601/-32603 + extensions -32010..-32013
  - fe-pyo3: `NativeExecutor.serve(sock_path=None)` binding; `FusionSandboxExecutor.serve()` wrapper runs forever
  - 4 Rust unit tests (health/unknown -32601/malformed -32700/UDS execute) + 5 Python IPC tests (health/execute/diagnostics/unknown/snapshot+rollback round-trip)
  - Exit gate: external raw-socket client calls `executor.execute` echo over UDS → `exit_code=0 stdout="hi\n"`; fusion-code-style TS client sketch in `docs/ipc-client-typescript.md`; fusion-studio uses existing `IPCClient.swift udsCall` pointed at `/tmp/fusion-executor.sock`
- **P4 — macOS GUI** ✅ complete
  - fe-gui: `accessibility` 0.2 safe wrapper (AXUIElement tree/focus/click/type/inspect) + 3 audited unsafe FFI blocks (AXIsProcessTrusted + AXValueGetValue ×2); CoreGraphics `CGDisplay::screenshot` → PNG base64 (Layer B vision fallback)
  - GuiAction (tag=kind, snake_case): `focus_app`/`click`/`type_text`/`key_press`/`screenshot`/`inspect_tree`; GuiResult{ok, node_tree, screenshot_png_b64, error}
  - fe-core: `gui: GuiController` field + `gui_action()` method; fe-ipc `executor.gui_action` live (not stub); fe-pyo3 `NativeGuiResult` + `gui_action(action)` (json.dumps → serde deserialize)
  - Python: `GuiResult` Pydantic + `FusionSandboxExecutor.gui_action(action: dict) -> GuiResult`
  - 6 Rust unit tests + 6 Python tests (model roundtrip/key_press degrade/bad-kind degrade/screenshot TCC-skip/UDS roundtrip/bad-kind UDS -32600)
  - Exit gate: trusted machine `gui_action({"kind":"screenshot"})` → 3.2MB PNG; `gui_action({"kind":"key_press","key":"Tab"})` → ok=False unsupported (v1, fixed in v1.1). GUI tests are TCC-manual (AX Accessibility + Screen Recording)
- **P5 — Hardening** ✅ complete
  - criterion benches: `Executor::new` = 735µs (<5ms NFR ✓); `truncate_output` ~1.75GB/s (100K=3.9µs / 1M=412µs / 10M=5.7ms); `validate` 10k compound command = 317ns (regex fast-path blocks rm -rf)
  - `truncate_output` made pub for bench; `ClickCandidate` type alias fixes clippy `type_complexity`; fe-gui redundant `as u32` conversions removed
  - Python coverage 95% (>80% NFR ✓): cli.py 96% (in-process `main()` tests) / executor.py 90% / models.py 100% / __init__.py 100%; 32 Python tests (+6 CLI +1 async +1 rollback-no-cwd)
  - clippy `--all-targets -D warnings` clean (only upstream block v0.1.6 future-incompat notice, not fe code); `cargo fmt --check` + `ruff check/format` clean; `maturin develop --release` builds
  - Exit gate: 67 Rust + 32 Python tests green; all NFRs met
- **v1 complete** ✅
- **v1.1 — KeyPress support** ✅ complete
  - fe-gui `key_press`: CGEvent synthesis keydown + keyup, post `CGEventTapLocation::HID`; `resolve_keycode` maps key names (case-insensitive + aliases: enter=return, esc=escape, up=up_arrow, cmd=command...) → `core_graphics::event::KeyCode` constants (40+ keys: Return/Tab/Space/Delete/Forward_delete/Escape/arrows/Home/End/PageUp-Down/Help/F1-F20/Command/Shift/Option/Control/Function/Caps_lock/Mute/Volume)
  - core-graphics 0.24 safe wrapper encapsulates the unsafe FFI (CGEventSource::new / CGEvent::new_keyboard_event / post) — zero hand-written unsafe blocks in this function, reuses the fe-gui crate-level `#![allow(unsafe_code)]` scope
  - Unknown key name → `ok:false` + `unknown-key: ...` error listing known key names (no panic, trusted-independent)
  - +2 Rust unit tests (resolve_keycode mapping / unknown key None) + KeyPress degrade test rewritten; +1 Python test (keypress_when_trusted, TCC-skip)
  - Exit gate: trusted machine `gui_action({"kind":"key_press","key":"Tab"})` → ok=True (keydown+keyup posted); `{"key":"return"}` → ok=True; unknown key → ok=False unknown-key. 69 Rust + 33 Python tests green
- **v1.2 — Streaming + Modifiers + Screenshot dimensions** ✅ complete
  - Live stdio streaming (4 layers): fe-sandbox `run_streaming` (mpsc `StreamEvent::Chunk{data}`/`Done(SandboxResult)`) → fe-core `execute_streaming` async (validate→snapshot→`run_streaming`→spawn task forwards chunks, on Done runs diagnostics slice and maps to ExecutionResult; `ExecutionStreamEvent` serde tag="type") → fe-ipc `executor.execute_stream` (multi-frame NDJSON, id reused, chunk `{type,data}`/done `{type,result:{ExecutionResult}}`) → fe-pyo3 `NativeStreamIterator` (`__iter__`/`__next__` via `py.detach` + BLOCKING_RT receives frames + serde→json.loads) → Python `run_streaming` generator
  - Modifier combos (KeyPress): `key` single key name + `modifiers` array (cmd/ctrl/alt/shift/fn); sequential synthesis — keydown modifiers→keydown key→keyup key→keyup modifiers (CGEvent flags); single key only, no chord
  - Screenshot dimension metadata: `GuiResult` adds `screenshot_width`/`screenshot_height` (u32, PNG pixels); fe-gui fills from `CGImageRef` width/height
  - +12 Rust tests (fe-core execute_streaming 4: echo/blocked/timeout/diagnostics; fe-ipc 2: stream chunks/done over UDS, blocked single frame) + 5 Python tests (streaming echo/blocked/timeout/diagnostics, UDS stream)
  - Exit gate: 81 Rust + 40 Python tests green; clippy/fmt/ruff clean; maturin builds
- **v1.3 — Data Schema backfill + Native File Tools + Surgical Patch Engine** ✅ complete
  - Data Schema §4.1 backfill (Gap #1): `ExecutionResult` adds `task_id`/`command`/`duration_sec` fields, threaded through 4 layers (fe-core serde struct → fe-pyo3 `NativeExecutionResult` → Python `ExecutionResult` Pydantic → fe-ipc done frame backfill). `blocked_with` carries task_id/command; blocked result `duration_sec=0.0`
  - fe-tools new crate (Gap #2): `file_edit` (unique-match exact replace, >1 rejected, atomic write) / `glob` (wildcard, relative-to-cwd paths, canonicalized-base fix for the relative-path bug) / `grep` (regex, recursive walkdir, skips binary, 1000 cap). Depends on fe-security `validate_cwd` path guard (rejects cwd escape / sensitive dirs)
  - Surgical Patch Engine (Gap #3, fe-tools): `apply_patch` (diffy Unified Diff apply; full-rewrite heuristic `new_range.start==0 && end==0` → reject; target taken from `patch.modified()`/`original()` with `a/`/`b/` prefix stripped) + `replace_function` (tree-sitter AST locates function node — stack-based preorder traversal fixes the tree-sitter 0.25 `Node::children(&mut cursor)` borrow issue, no `descendants()`; py/js/ts/tsx/rs grammars, regex fallback otherwise; byte-slice replace `[..span.start]+new_body+[span.end..]`)
  - 4-layer wiring: fe-core `tools: Tools` field + 5 wrapper methods (`file_edit`/`glob`/`grep`/`apply_patch`/`replace_function`); fe-ipc `executor.file_edit`/`glob`/`grep`/`apply_patch`/`replace_function` 5 arms; fe-pyo3 `NativeEditResult`/`NativeGlobEntry`/`NativeGrepMatch` pyclasses + 5 `#[pymethods]`; Python `EditResult`/`GlobEntry`/`GrepMatch` Pydantic + `FusionSandboxExecutor` 5 methods
  - clippy fix `ExecutionStreamEvent::Done(ExecutionResult)` → `Done(Box<ExecutionResult>)` (large_enum_variant, Done 264B vs Chunk 24B; serde transparent over Box, serialization unchanged)
  - +13 fe-tools Rust unit tests (file_edit unique/no-match/ambiguous/not-found, glob, grep hit/recursive, apply_patch simple/not-found, replace_function python/not-found/rust, guard_path escape) + 12 Python tests (file_edit unique/ambiguous, glob, grep, apply_patch, replace_function python/not-found, file_edit/glob UDS round-trip subprocess pattern)
  - Exit gate: 94 Rust + 52 Python tests green; clippy `--all-targets -D warnings` clean (only upstream block v0.1.6 future-incompat); fmt/ruff clean; maturin builds
- **v1.4 — Auto-rollback + Live Telemetry + GUI scroll/drag/wait** ✅ complete
  - Auto-rollback (FR-04 optional policy, fe-core `AutoRollbackGuard` + fe-rollback): `RollbackPolicy{max_consecutive_failures (reserved field), file_damage_check}`; command failure + `git status --porcelain` non-empty → `rollback(本次快照)` + `result.auto_rolled_back=True`; guard limited to a single execution (Executor stateless, consecutive-failure counting belongs to caller); 4-layer wiring (fe-core `execute_async`/`execute_streaming` construct guard → fe-pyo3 `auto_rollback_policy` dict→serde → Python `RollbackPolicy` Pydantic + `run()`/`run_streaming()` kwargs); fe-rollback HEAD-baseline bug fix (when stash SHA != HEAD → stash apply; when equal → skip)
  - Live telemetry (fe-telemetry new crate): `TelemetrySample{ts_ms,cpu_pct,mem_mb,gpu_pct?,gpu_mem_mb?,task_id?}` + `TelemetryConfig{interval_ms=100(10Hz),max_samples=0(infinite)}`; `start_stream(cfg, rt::Handle)` spawns sysinfo sampling task on `BLOCKING_RT` (`refresh_processes_specifics(pid, mem+cpu)`, first frame sleeps then samples); channel close / max_samples reached → stop; GPU defaults None (caller-injected), serde `skip_serializing_if`; 4-layer wiring (fe-core `telemetry_stream(cfg)` → fe-ipc `executor.telemetry_stream` multi-frame sample → fe-pyo3 `NativeTelemetryIterator` `__next__` block_on(rx.recv) → Python `telemetry_stream()` generator yields `TelemetrySample`); never-type fallback fix (explicit `TelemetrySample` type annotation)
  - GUI scroll/drag/wait (fe-gui CGEvent synthesis): `scroll` (dx/dy pixels, CGEvent scrollWheel unit axis) / `drag` (from x,y → to x,y, mouseMove+leftMouseDown+move+leftMouseUp) / `wait` (seconds sleep, test helper); +14 Rust unit tests + 14 Python GUI tests
  - +3 fe-telemetry Rust unit tests (stream produces samples / channel close stops / serialize) +1 fe-core +1 fe-ipc (UDS telemetry 3 frames) +5 Python auto-rollback tests +3 Python telemetry tests (native iter/wrapper/UDS)
  - Exit gate: 105 Rust + 60 Python tests green; clippy `--all-targets -D warnings` clean (only upstream block v0.1.6 future-incompat); fmt/ruff clean; maturin builds
- **v1.5 complete**
  - **#12 — Diagnostics-slicer language expansion (TS/Go)** ✅ complete
    - fe-diagnostics `Slicer` regexes 4→9 covering 8 languages: added `ts_re` (tsc paren form `file.ts(l,c): error TSxxxx:`) / `ts_dash_re` (tsc watch `file.ts:l:c - error TSxxxx:`) / `bun_re` (Bun lowercase `error:` + bare `at`) / `go_panic_re` (`(?s)` cross-line `panic: ... goroutine ... \tfile.go:line`, takes last stack frame) / `go_compile_re` (`file.go:l:c: msg` no `error:` keyword). Added `extract_ts`/`extract_bun`/`extract_go_panic`/`extract_go_compile` methods; `slice()` ordering ts→python→node→bun→rust→go_panic→swift→go_compile (isolated by extension/keyword, no conflicts). Zero new deps (pure-text line slicing)
    - fe-security whitelist +`go` +`tsc` (otherwise real `go build`/`tsc --noEmit` blocked by Stage-2, no E2E)
    - +5 fe-diagnostics unit tests +1 whitelist test. Real toolchain E2E: tsc 7.0.2 `TS2322`/`bad.ts`/line 2 ✓; `go build` `compile error`/`main.go`/line 6 ✓; `go run` panic `panic.go`/line 7 ✓. Diagnostics flow automatically through execute→ExecutionResult.diagnostics (when exit_code!=0), no 4-layer wiring
  - **#13 — More GUI actions** ✅ complete
    - fe-gui `GuiAction` 9→16 variants: added `double_click` (ax_label/ax_position, CGEvent 2× LeftMouseDown/Up, second click `EventField::MOUSE_EVENT_CLICK_STATE=2`) / `right_click` (ax_label/ax_position, CGEvent RightMouseDown/Up + `CGMouseButton::Right`) / `hover` (ax_position, CGEvent MouseMoved no button) / `window_close` / `window_minimize` / `window_zoom` (bundle_id, AX button attrs `kAXCloseButtonAttribute`/`kAXMinimizeButtonAttribute`/`kAXZoomButtonAttribute` → `press()`) / `window_resize` (bundle_id + width/height, drag the bottom-right resize handle — read AXPosition+AXSize to compute coords, reuse `drag()` CGEvent; not AXValueCreate set AXSize, avoids a new unsafe block, stays within the 3 audited unsafe scopes)
    - `resolve_click_position` helper shared by click/double_click/right_click (ax_position first; otherwise ax_label→AX tree locate reads AXPosition; neither present → error)
    - **4-layer auto-flow**: fe-core/fe-ipc/fe-pyo3 dispatch after deserializing the GuiAction enum — new variants flow through with zero wiring (only fe-gui changes enum+execute+methods+tests); Python `gui_action(action: dict)` is generic with no per-variant logic
    - **0 new unsafe**: all via accessibility 0.2 safe wrapper (attribute/press) + core-graphics 0.24 safe wrapper (CGEvent/set_integer_value_field); reuses fe-gui crate-level `#![allow(unsafe_code)]` scope
    - +5 fe-gui Rust unit tests (serde roundtrip/snake_case/window degrade/pointer degrade/no-target) +2 Python tests (new_variants_degrade CI path / pointer_variants_when_trusted TCC path; `_ax_access_trusted()` probe separates the TCC Accessibility and Screen Recording permissions)
    - Exit gate: trusted machine hover/double_click/right_click with coords → `ok=True` (CGEvent posted); window_* needs a real GUI session (AX window tree) and degrades in-sandbox. 116 Rust + 62 Python tests green; clippy `--all-targets -D warnings` clean (only upstream block v0.1.6); fmt/ruff clean; maturin builds
  - **#14 — Bidirectional IPC server-push (subscribe/broadcast)** ✅ complete
    - fe-ipc `BroadcastHub` (Arc-shared) — an IPC-broker concern, **fe-core Executor stays stateless** (broadcast fan-out does not enter the executor). registry: sub_id → Subscriber{conn_id, channels, tx}; conn/sub counters AtomicU64; telemetry_task/screenshot_task `Mutex<Option<JoinHandle>>` lazy start/stop (0 subscribers self-exit, next subscribe restarts; source methods take `&self` not `self: Arc<Self>` — avoids use-after-move on `.take()`)
    - Connection DUPLEX: `handle_conn` split into read_task (dispatch requests) + push_task (write server-push frames) sharing `Arc<AsyncMutex<OwnedWriteHalf>>` (lock for atomic line writes); per-connection `mpsc::channel<Value>(128)` push frames + oneshot close
    - Three broadcast sources: **telemetry** (single `executor.telemetry_stream` fan-out, 10Hz default `interval_ms=100`) / **stdio** (execute/execute_stream handlers call `hub.broadcast_stdio()` to fan out chunk/done — **cross-connection** A subscribes, B runs a command, A receives the push) / **screenshot** (periodic `gui_action(Screenshot)` sampling via `spawn_blocking`, `screenshot_interval_ms=1000` slower than telemetry; TCC-untrusted → frame data.ok=false, no crash, reuses fe-gui safe wrapper)
    - Push frame format: `{"jsonrpc":"2.0","method":"executor.event","params":{"subscription_id":"sub-N","channel":..,"data":..}}` — **no id** (notification convention), client distinguishes response vs push by presence of id. `collect_targets(channel)` try_send outside the lock (snapshot sub_id+tx then release the lock)
    - fe-ipc **0 new unsafe** (screenshot reuses fe-gui safe wrapper, crate keeps `unsafe_code="deny"`). fe-pyo3 unchanged — server-push needs a running server, pure-Python UDS client `Subscription` connects to the `serve()` socket
    - Python `Subscription` pure-Python UDS client: `_open()` connects+sends subscribe+reads response sets `_sub_id`; `__next__` filters `executor.event` frames matching sub_id, skips non-event frames; `unsubscribe()` sends unsubscribe+closes socket; `SUB_CHANNELS=("telemetry","stdio","screenshot")` unknown channel → `ValueError`. `FusionSandboxExecutor.subscribe(channels, *, sock_path, interval_ms, screenshot_interval_ms) -> Subscription`
    - +7 fe-ipc Rust unit tests (subscribe telemetry push frames/missing channels -32600/unsubscribe stops push/stdio cross-connection broadcast + existing health/unknown/malformed/execute/stream) +3 Python tests (subscribe telemetry push frames/stdio cross-connection broadcast/unknown channel ValueError); tests use `UnixStream::into_split()` → `(OwnedReadHalf, OwnedWriteHalf)` to avoid borrow-after-move
    - Exit gate: 120 Rust + 70 Python (6 skip TCC) tests green; clippy `--all-targets -D warnings` clean (only upstream block v0.1.6); fmt/ruff clean; maturin builds
- **v1.5 complete** (#12 diagnostics-slicer language expansion + #13 more GUI actions + #14 bidirectional IPC server-push) — 120 Rust + 70 Python (6 skip TCC) tests green; 10 crates; clippy `--all-targets -D warnings` clean (only upstream block v0.1.6 future-incompat); `cargo fmt --check` + `ruff check/format` clean; `maturin develop --release` builds. Zero new unsafe (#13/#14 both use safe wrappers). Next: v1.6 or as needed.
- **Audit T1–T9 — defect audit (2026-08-24/25)** ✅ complete
  - 68 defects across fe-security/fe-sandbox/fe-ipc/fe-tools/fe-rollback/fe-core/fe-pyo3+fe-telemetry/Python layer/fe-diagnostics. All fixed: kill escalation + killpg + deadlock/OOM guards, socket 0o600 + capped-line + semaphore, atomic NamedTempFile write + full-rewrite reject + glob per-hit validate + grep 64MB cap, git `reset --hard` single-step + tag-prefixed snapshot_id + `is_valid_ref`, pre/post git-status diff (no false rollback) + streaming abort+timeout + worker_threads(1), wall-clock ts_ms + Drop abort + `py.detach` GIL release + fail-loud PyRuntimeError + serve signal/cleanup, Subscription GC + stream-test race hardening, tail_lines preserving traceback segment headers + python_re greedy deepest-frame + swift_re extension guard. Commit `36e8790`.
- **Audit 0825 — commercial-grade integration audit (2026-08-25)** ✅ complete — **FAIL → PASS**
  - 10 CRITICAL / 23 MAJOR / 4 MINOR. 11 Blockers landed for commercial-grade integration (commit `0341ccb`): B1 macOS seatbelt runtime sandbox (sandbox-exec deny network + 13 dangerous binaries), B2 read-path `validate_argv` + diagnostics-enrich guard, B3 `guard_path` canonicalize + `..` always-reject, B4 rollback path → fe-security, B5 BLOCKING_RT worker_threads(1)→(N), B6 `run_streaming` cancellable + kill child, B7 `read_capped_line` chunked + in-loop cap, B8 file tools size cap (64MB) + flock atomic write, B9 rollback registry + FNV-1a repo identifier snapshot_id, B10 stdio per-sub scope filter (cross-tenant isolation), B11 Pydantic `extra="forbid"` + Rust serde schema sync.
  - 13 MAJOR/MINOR swept (#45): GUI wait GIL release, kill grace 50ms→500ms, truncate byte-offset, partial stdout preserved, exec semaphore, request multiplexing, glob cap+ignore, grep cap(2000)+max_depth(20)+ignore, apply_patch multi-file split + aggregated full-rewrite reject, diagnostics reads stdout (PTY merge), telemetry strict `model_validate`, `replace_function` no-grammar fail-loud `Err`, `Subscription` configurable `idle_timeout`, `serve(path)` resolved-path + version sync.
  - Exit gate: **223 Rust + 113 Python (6 skip TCC) tests green**; clippy `--all-targets -D warnings` clean; `cargo fmt --check` + `ruff check/format` clean; `maturin develop --release` builds.
- **v0.1.0 released** ✅ — tagged `v0.1.0` (annotated), pushed to `origin`. First stable release. See `examples/` for runnable demos (Python API 01–07 + TypeScript UDS client) and `docs/INDEX.md` for the documentation map.
