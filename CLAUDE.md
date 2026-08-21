# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

**fusion-executor is being built — Rust+PyO3 core via maturin.** P4 (fe-gui macOS GUI) **COMPLETE**: `fe-gui` (`accessibility` 0.2 safe wrapper for AXUIElement tree/focus/click/type/inspect + 3 audited unsafe FFI blocks `AXIsProcessTrusted` + `AXValueGetValue` ×2; CoreGraphics `CGDisplay::screenshot` → PNG base64 Layer-B fallback; crate-level `#![allow(unsafe_code)]` override — rustc 1.96 `unsafe_extern_blocks` makes `AXIsProcessTrusted()`/`AXValueGetValue()` unsafe-to-call, no crate choice avoids it; other 7 crates keep `unsafe_code="deny"`; user-approved scoped exception); `GuiAction` (serde tag=`kind`, rename_all=`snake_case`: `focus_app`/`click`/`type_text`/`key_press`/`screenshot`/`inspect_tree`) + `GuiResult{ok,node_tree,screenshot_png_b64,error}`; 6 Rust unit tests) wired into `fe-core` (`gui: GuiController` field + `gui_action()` method, re-exported `fe_core::gui`) → `fe-ipc` (`executor.gui_action` live, not stub — `-32013` AX-not-trusted, `-32600` bad-action deserialize) → `fe-pyo3` (`NativeGuiResult` pyclass + `gui_action(action: &PyAny)` via `py.import("json").dumps` → `serde_json::from_str`) → Python (`GuiResult` Pydantic model + `FusionSandboxExecutor.gui_action(action: dict) -> GuiResult`); 6 Python GUI tests (model roundtrip / key_press wire-name unsupported / bad-kind degrade / screenshot TCC-skip guard / UDS roundtrip / bad-kind UDS `-32600`). 67 Rust + 26 Python tests green, clippy/fmt/ruff clean, `maturin develop` builds. Smoke: trusted machine `gui_action({"kind":"screenshot"})` → valid 3.2MB PNG, `gui_action({"kind":"key_press","key":"Tab"})` → `ok=False` unsupported. Next: P5 (Hardening — criterion benches <5ms init + <3% truncation CPU, pytest --cov >80%, final docs). **P5 COMPLETE**: criterion benches — `Executor::new` 735µs (<5ms ✓), `truncate_output` ~1.75GB/s, `validate` 10k-compound 317ns; Python coverage 95% (cli 96% / executor 90% / models 100%) via in-process `cli.main()` tests; clippy `--all-targets -D warnings` clean (only upstream `block v0.1.6` future-incompat notice), fmt/ruff clean; `truncate_output`→pub, `ClickCandidate` type alias, `as u32` removed for clippy. 67 Rust + 32 Python tests green, maturin builds. **v1 COMPLETE (P1–P5).** **v1.1 COMPLETE (KeyPress):** `fe-gui::key_press` — CGEvent synthesis (`CGEventSource::new(CombinedSessionState)` → `CGEvent::new_keyboard_event(src, code, keydown)` + keyup → `.post(CGEventTapLocation::HID)`), core-graphics 0.24 safe wrapper encapsulates the unsafe FFI (zero hand-written unsafe blocks; reuses fe-gui crate-level `#![allow(unsafe_code)]` scope). `resolve_keycode` maps 40+ case-insensitive key names + aliases (enter=return, esc=escape, up=up_arrow, cmd=command...) → `core_graphics::event::KeyCode` constants (Return/Tab/Space/Delete/Forward_delete/Escape/arrows/Home/End/PageUp-Down/Help/F1-F20/Command/Shift/Option/Control/Function/Caps_lock/Mute/Volume). Unknown key → `ok:false` + `unknown-key: ...` (no panic, trusted-independent). +2 Rust unit tests (keycode mapping / unknown None) + KeyPress degrade test rewritten; +1 Python test (`keypress_when_trusted`, TCC-skip). Smoke: trusted `gui_action({"kind":"key_press","key":"Tab"})` → `ok=True`, `{"key":"return"}` → `ok=True`, unknown → `ok=False` unknown-key. 69 Rust + 33 Python tests green, clippy/fmt/ruff clean, `maturin develop` builds. See `~/.claude/plans/nifty-foraging-lark.md` for the approved design + build phases (P1–P5). Verify against real files before relying on any structure here. **v1.2 COMPLETE (Streaming + Modifiers + Screenshot dimensions):** (1) Live stdio streaming wired through 4 layers — fe-sandbox `run_streaming` (mpsc `StreamEvent::Chunk{data}`/`Done(SandboxResult)`) → fe-core `execute_streaming(req) async -> Result<(mpsc::Receiver<ExecutionStreamEvent>, JoinHandle<()>)>` (validates; blocked→single Done frame; snapshot; run_streaming; spawned task forwards chunks + on Done applies diagnostics slice + maps to `ExecutionResult`; `ExecutionStreamEvent` enum `#[serde(tag="type", rename_all="snake_case")]` `Chunk{data}`/`Done(ExecutionResult)` — serde FLATTENS Done into `{"type":"done", exit_code:..., ...}` not nested) → fe-ipc `executor.execute_stream` (multi-frame NDJSON, id reused: chunk `{jsonrpc,id,result:{type:chunk,data}}` + done `{jsonrpc,id,result:{type:done,result:{ExecutionResult}}}` — UDS path nests done under `result.result`, DIFFERENT shape from fe-pyo3 flatten, deliberately separate) → fe-pyo3 `NativeStreamIterator` pyclass (`__iter__(slf: Py<Self>)->Py<Self>` + `__next__` via `py.detach(|| ...)` + `BLOCKING_RT.block_on(rx.recv())` + `serde_json::to_string`→`py.import("json").loads`) → Python `run_streaming` generator (yields chunk strings then `ExecutionResult` at done; `_native_result(frame)` passes frame DIRECTLY since serde flatten). (2) KeyPress modifier combos — `key` single key name + `modifiers` array (cmd/ctrl/alt/shift/fn); CGEvent flag synthesis, single-key only no chord. (3) `GuiResult` adds `screenshot_width`/`screenshot_height` (u32, PNG pixels) from `CGImageRef`. pyo3 0.29 API: `allow_threads` REMOVED → `py.detach(|| ...)` (closure 0 args); `PyObject` REMOVED → `Py<PyAny>`; `py.import("json").call_method1("loads",(s,))?.unbind()`. `BLOCKING_RT` = `LazyLock<tokio::runtime::Runtime>` (multi-thread); streaming `execute_streaming` is async, PyO3 `block_on` to get (rx,handle), `__next__` `block_on(rx.recv())` same runtime no nesting panic. +4 fe-core tests (echo chunk/done, blocked single frame, timeout -124, diagnostics ValueError) +2 fe-ipc tests (stream chunks/done over UDS, blocked single frame) +5 Python tests (streaming echo/blocked/timeout/diagnostics + UDS stream). 81 Rust + 40 Python tests green, clippy/fmt/ruff clean, maturin builds. **v1.3 COMPLETE (Data Schema §4.1 + Native File Tools + Surgical Patch Engine):** PRD gap analysis found 3 missing work categories — all landed. (Gap #1) `ExecutionResult` gains `task_id`/`command`/`duration_sec` (PRD §4.1) across 4 layers (fe-core serde struct → fe-pyo3 `NativeExecutionResult` → Python Pydantic → fe-ipc done frame); `blocked_with(reason, task_id, command)` backfills request-side identity on security-block (duration 0.0). (Gap #2) NEW crate `fe-tools` — `file_edit` (unique-match exact replace via `content.matches(old_string)`: 0→NoMatch, >1→Ambiguous reject, ==1→`replacen`+atomic write `.fe-tmp-{pid}`+rename); `glob` (`glob::glob` with `cwd_abs = canonicalize(base)` computed BEFORE pattern build — the fix for relative-path bug where canonicalized macOS temp-dir symlink results failed `strip_prefix`; returns relative paths); `grep` (`Regex` + walkdir recursion skipping dotfiles + binary `\0` detection + 1000-hit cap). All reuse `fe-security::SecurityGuard::validate_cwd` via `guard_path` (expand_tilde, join cwd if relative, reject `..` escape via canonicalize starts_with, validate parent dir). (Gap #3) Surgical Patch Engine in `fe-tools`: `apply_patch` (diffy 0.4.2 `Patch::from_str` → loop `patch.hunks()` counting via `count_hunk_lines` matching `diffy::Line::Insert`/`Delete`/`Context` variants — Line is an enum NOT `.starts_with()`; full-rewrite heuristic `pf.new_range().start()==0 && end()==0` → `FullRewriteForbidden`; target = `patch.modified().or(original())` with `strip_prefix("b/")`/`("a/")`; `diffy::apply(base, &patch)`); `replace_function` (`parser_for_ext` + `function_node_kind` for py/js/ts|tsx/rs + **stack-based preorder traversal** — tree-sitter 0.25.10 has NO `descendants()`, and `Node::children(&mut cursor)` borrows the cursor mutably so recursive shared-`&mut cursor` fails with lifetime/borrow errors; fix = iterative `stack.push(root)`, per-node local `cursor` + `node.children(&mut cursor).collect()` into Vec, drop cursor, push children reversed; `child_by_field_name("name")` for function name; byte-slice replace `[..span.start]+new_body+[span.end..]`; no grammar → `locate_function_regex` fallback). 4-layer wiring: fe-core `tools: Tools` field + 5 wrapper methods → fe-ipc 5 arms (`executor.file_edit/glob/grep/apply_patch/replace_function`, cwd optional, paths as `Vec<String>`) → fe-pyo3 `NativeEditResult`/`NativeGlobEntry`/`NativeGrepMatch` pyclasses (From<RsX>) + 5 `#[pymethods]` → Python `EditResult`/`GlobEntry`/`GrepMatch` Pydantic + 5 `FusionSandboxExecutor` methods. clippy fix: `ExecutionStreamEvent::Done(ExecutionResult)` → `Done(Box<ExecutionResult>)` (clippy `large_enum_variant` — Done 264B vs Chunk 24B; serde transparent over Box, wire format unchanged; 3 construction sites wrapped `Box::new`, match sites unchanged via deref). +13 fe-tools Rust unit tests + 12 Python tests (incl. file_edit/glob UDS roundtrip using subprocess `server` fixture pattern — NOT in-process `serve()` which blocks forever on a daemon thread and hangs pytest). 94 Rust + 52 Python tests green, clippy `--all-targets -D warnings` clean (only upstream `block v0.1.6` future-incompat), fmt/ruff clean, maturin builds.

## What fusion-executor Is

Controlled execution sandbox + macOS OS-level control hub for the Fusion ecosystem. Connects the inference engine (fusion-mlx) to system-side actions. The "hands" of fusion-code / fusion-agent — runs shell commands safely, drives native GUI via Accessibility API, and rolls back on failure.

Dual-mode controlled execution engine (CLI + Native GUI) for Apple Silicon / macOS. Sits at the **L4 generic-tool layer** of the monorepo. The architecture audit (`audit/fusion-ar-audit.md` P2-7) designates it as the home for the code-sandbox capability currently embedded in fusion-science (PythonExecutor/JupyterKernel/RExecutor) — that execution engine should be extracted here, not rebuilt per-vertical.

## Four Core Subsystems

1. **Security Guard Engine** — two-stage: static regex pattern match (fast filter for `rm -rf`, `sudo`, format, remote pipe) then shlex-style Lexer/AST tokenizer that splits compound shell commands (`&&`, `||`, `;`, `|`) and validates each binary against a whitelist (python, node, pytest, cargo, swift...). Intercept rate target: 100%.
2. **Subprocess / PTY Sandbox** — PTY or stdio subprocess to capture ANSI color codes + full Traceback; heartbeat timer enforces timeout (SIGINT graceful → SIGKILL forceful within 50ms, cleans whole child process tree); stdio truncation keeps head context + tail stack trace, folds the middle past `max_output_chars`.
3. **macOS Computer Use Adaptor** — `AXUIElement` to extract foreground-window UI node tree (button/textfield coords + Accessibility Label); falls back to `CGWindowListCreateImage` framebuffer capture for vision grounding (mlx-vlm / fusion-design) when nodes lack Accessibility info. Click/keystroke latency target <30ms.
4. **Task Rollback Manager** — Git HEAD snapshot before any file-mutating command; lightweight `snapshot_create()` / `rollback()` hooks supporting single-file `git checkout` (avoid clobbering unaffected modules); auto-rollback after N consecutive failures or detected file damage.

## Data Schema (Pydantic)

The wire contract — `ExecutionRequest` in, `ExecutionResult` out. `ExecutionResult` carries: `exit_code` (0 ok / -124 timeout / -1 blocked-or-internal-error), truncated `stdout`/`stderr`, `task_id`/`command`/`duration_sec` (PRD §4.1, v1.3 — request-side identity + wall-clock), `timed_out`, `blocked_by_security` + `security_reason`, `snapshot_id` for rollback. Diagnostics Slicer runs when `exit_code != 0`: regex-extract Traceback/Error/Exception lines → Tree-sitter AST to locate offending file:line → emit compact JSON (`error_type`, `file_path`, `line_number`, `code_snippet`, `raw_trace`) sized for a prompt.

v1.3 adds native file-tool wire models (fe-tools, replaces Claude SDK FileEdit/Glob/Grep): `EditResult{ok, path, error, matches}` (file_edit unique-match replace + apply_patch + replace_function all return this), `GlobEntry{path, is_dir}`, `GrepMatch{path, line_number, content}`. Surgical Patch Engine: `apply_patch` (diffy Unified Diff, full-rewrite forbidden) + `replace_function` (tree-sitter AST function-level replace, no full-file rewrite).

See `architecture/fusion-executor-prd.md` §4 for the full `ExecutionRequest` / `ExecutionResult` field list and the Diagnostics Slicer algorithm.

## Build / Test / Lint

Rust core + Python bindings via **maturin/PyO3** (first such project in the monorepo — deliberate divergence from setuptools). Shared venv is Python 3.14 → requires pyo3 ≥0.29.

```bash
cd /Users/dahai/fusion
source .venv/bin/activate          # shared venv at repo root — REQUIRED first
cd fusion-executor

# Build & install native extension (editable) into shared venv
maturin develop --release

# Rust
cargo check --workspace
cargo test --workspace                  # e.g. cargo test -p fe-security
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check

# Python
pytest python/tests                     # asyncio_mode=auto, testpaths=["python/tests"]
pytest python/tests/test_executor.py::test_run_echo -v   # single test
ruff check . && ruff format .           # py311, line-length 120

# Smoke
python -c "from fusion_executor import FusionSandboxExecutor; print(FusionSandboxExecutor().run('echo hi').exit_code)"

# Start UDS JSON-RPC server (P3)
python -c "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()"
# Socket: /tmp/fusion-executor.sock (override FUSION_EXECUTOR_SOCK)
```

Python ≥3.11 (venv is 3.14). Runtime dep `pydantic>=2.0`. Test deps `pytest`/`pytest-asyncio`/`pytest-cov`. No httpx, no hard fusion-core — executor is an L4 OS tool, delegates inference to caller. Package root is `fusion_executor` (import as `from fusion_executor import FusionSandboxExecutor, ExecutionResult`). Native extension is `fusion_executor._native` (built from `crates/fe-pyo3`).

## Integration With Ecosystem

- **fusion-code → fusion-executor**: fusion-code drops generated patch to disk, calls `executor.run("pytest tests/")`, receives structured diagnostics, enters next self-healing loop iteration. Refactor plan (PRD §"重构"): fusion-code strips its own subprocess/file-IO into an `ExecutorDriver` interface — all command validation, timeout, stdio capture delegated here.
- **fusion-executor → fusion-studio**: live stdio stream, screenshot sampling, GPU/CPU telemetry broadcast over Unix Domain Socket to the studio dashboard (zero-copy, high-frame-rate render).
- **fusion-executor ↔ fusion-mlx / fusion-gateway**: UDS comms (not HTTP/gRPC) — terminal Traceback-to-model-prompt transfer latency target <2ms.
- **Replaces**: Claude SDK's BashTool/FileEdit/Glob/Grep + Docker sandbox, and DeepSeek Harness's SWE-bench container — but native (no Docker): macOS process isolation + Git snapshots, sandbox init overhead target <5ms.

## Key Design Constraints (NFRs / SLA)

- CLI sandbox init overhead <5ms; log-truncation + regex parse CPU <3% under high throughput.
- Guard against chain-assembly bypass — full token-level parse over `&&`, `||`, `;`, `|`.
- Cap memory on infinite-print death-loops — prevent OOM.
- Exit-code convention must stay stable: `0` success, `-124` timeout, `-1` blocked/security/internal.

## Monorepo Conventions (apply here)

- Indentation: multiples of 4 spaces. No docstrings. Always include logging.
- Domain apps use MLXClient dependency injection + `_parse_json()` for LLM output — but this is an execution tool, not a domain app; it calls OS, not the model. If it ever needs inference, go through `fusion_core.mlx_client.FusionMLXClient` (never raw `httpx` to fusion-mlx — P1-8 violation pattern).
- IPC to fusion-studio uses JSON-RPC 2.0 over Unix Domain Socket.
- Build backend: **maturin** (PyO3) — `crates/fe-pyo3` produces `fusion_executor._native`. NOT setuptools; the only PyO3 project in the monorepo.
- GUI (fe-gui) tests are **manual** — AXUIElement/CoreGraphics need TCC Accessibility + Screen Recording permission; CI skips GUI when `!AXIsProcessTrusted()`.
- `ExecutionResult.diagnostics` field is additive over PRD §4.1 (approved) — delivers PRD §4.2 Slicer output. Live stdio streaming (PRD §5) deferred to v1.1; v1 returns full `ExecutionResult` post-completion. Rollback is **caller-driven** (executor exposes `snapshot_create`/`rollback`, stays stateless per-task).
- Upstream problems (fusion-mlx, fusion-gateway, fusion-core): file issue first, then PR, follow up with code — don't patch other projects in-tree.

## Key Paths

- `architecture/fusion-executor-prd.md` — full PRD, architecture diagram, data schema, diagnostics algorithm, fusion-code refactor plan, Claude-SDK/DeepSeek-Harness capability comparison.
- `audit/fusion-ar-audit.md` (P2-7) — rationale for extracting fusion-science's code sandbox here.
- `/Users/dahai/fusion/CLAUDE.md` — monorepo overview, shared `.venv`, fusion-mlx lifecycle (`~/claude-home/fusion-mlx/start.sh start|stop|status`).
