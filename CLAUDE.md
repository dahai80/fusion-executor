# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

**v0.2.12 released** (tag `v0.2.12`, GitHub release live). Rust+PyO3 core via maturin — the first maturin/PyO3 project in the Fusion monorepo (deliberate divergence from setuptools; the other Python projects use setuptools). 12-crate Cargo workspace (resolver 2). **Issue #46 (laya-mlx deterministic tool selection) landed** — `LayaToolSelector` (pure-Python, calls `laya_mlx.Agent.system_one()` directly) replaces LLM-generated tool-call JSON with the `choice` primitive; `answer_confidence` (max prob) gates LLM fallback, `decide()` adds `extract_params()` (noul/score + regex, Rule 5 deterministic). No Rust changes — laya-mlx is a Python dependency.

- `fe-core` — orchestrator: `Executor` pipeline, `BLOCKING_RT` (LazyLock multi-thread tokio runtime). **Stateless per-task** (M-ARCH-1 — registries live in IPC/PyO3 layer, not `Executor`).
- `fe-security` — Security Guard: regex blocklist + shlex tokenizer + whitelist + resolved-path guard (ARCH-2, trusted-bin-dirs) + inline-interpreter gateway (D3-1, blocks `python -c`/`node -e` default). `ArcSwap` whitelist for SIGHUP reload.
- `fe-sandbox` — PTY/stdio subprocess, timeout (SIGINT→500ms→SIGKILL killpg + ppid-tree), stdio truncation, RSS OOM watchdog, macOS seatbelt profile.
- `fe-gui` — macOS Computer Use: AXUIElement + CoreGraphics + CGEvent synthesis. **Crate-level `#![allow(unsafe_code)]`** for 3 audited FFI blocks (`AXIsProcessTrusted` + `AXValueGetValue` ×2, forced by rustc 1.96 `unsafe_extern_blocks`). Other 11 crates keep `unsafe_code="deny"`. Adding unsafe anywhere requires explicit re-approval.
- `fe-rollback` — git snapshot/rollback + `AutoRollbackGuard` (per-execute, caller-driven).
- `fe-diagnostics` — Traceback regex slicer, 8 languages (Py/TS/Node/Bun/Rust/Go-panic/Swift/Go-compile). Pure-text line extraction (tree-sitter grammars are a reserved dead path).
- `fe-ipc` — UDS JSON-RPC server + `BroadcastHub` (server-push: telemetry/stdio/screenshot) + `ShellRegistry`/`StreamRegistry` + Prometheus metrics (UDS text, no HTTP) + structured logging (tracing-appender rolling) + SIGHUP hot-reload.
- `fe-tools` — file_edit/glob/grep/write_file/multi_edit/notebook_edit + surgical patch engine (apply_patch + replace_function). gitignore-aware glob (`ignore` crate).
- `fe-telemetry` — CPU/mem sampling, 10Hz default, GPU caller-injected.
- `fe-shell` — background shell registry, poll-model (run_in_background/BashOutput/KillShell parity).
- `fe-guard` — fusion-guard wire mirror (Phase 3, default OFF).
- `fe-pyo3` — PyO3 bindings → `fusion_executor._native`.

**Current state**: 528 Rust + 238 Python (8 skip) tests green; clippy `--all-targets -D warnings` clean (only upstream `block v0.1.6` future-incompat); fmt/ruff clean; maturin builds. Four audit passes (0824/0825/0826/0827 + product-0827) — all defects fixed. `GuiAction` = 20 variants. `LayaToolSelector` (Issue #46) = pure-Python, optional `laya-mlx` dep.

**Per-version history**: `git log`, `.remember/` (recent.md / archive.md), and `docs/INDEX.md`. Do not rely on commit-message-level narrative for code structure — verify against real files before trusting any layout claim.

## What fusion-executor Is

Controlled execution sandbox + macOS OS-level control hub for the Fusion ecosystem. Connects the inference engine (fusion-mlx) to system-side actions. The "hands" of fusion-code / fusion-agent — runs shell commands safely, drives native GUI via Accessibility API, and rolls back on failure.

Dual-mode controlled execution engine (CLI + Native GUI) for Apple Silicon / macOS. Sits at the **L4 generic-tool layer** of the monorepo. The architecture audit (`../audit/fusion-ar-audit.md` P2-7) designates it as the home for the code-sandbox capability currently embedded in fusion-science (PythonExecutor/JupyterKernel/RExecutor) — that execution engine should be extracted here, not rebuilt per-vertical.

## Four Core Subsystems

1. **Security Guard Engine** — two-stage: static regex pattern match (fast filter for `rm -rf`, `sudo`, format, remote pipe) then shlex-style Lexer/AST tokenizer that splits compound shell commands (`&&`, `||`, `;`, `|`) and validates each binary against a whitelist (python, node, pytest, cargo, swift...). Intercept rate target: 100%.
2. **Subprocess / PTY Sandbox** — PTY or stdio subprocess to capture ANSI color codes + full Traceback; heartbeat timer enforces timeout (SIGINT graceful → 500ms grace → SIGKILL forceful, cleans whole child process tree via `killpg`; Issue #8: `timeout_sec == 0` is bounded to `DEFAULT_TIMEOUT_CAP_SEC` 120s, never truly unbounded); stdio truncation keeps head context + tail stack trace, folds the middle past `max_output_chars`.
3. **macOS Computer Use Adaptor** — `AXUIElement` to extract foreground-window UI node tree (button/textfield coords + Accessibility Label); falls back to `CGWindowListCreateImage` framebuffer capture for vision grounding (mlx-vlm / fusion-design) when nodes lack Accessibility info. Click/keystroke latency target <30ms.
4. **Task Rollback Manager** — Git HEAD snapshot before any file-mutating command; lightweight `snapshot_create()` / `rollback()` hooks supporting single-file `git checkout` (avoid clobbering unaffected modules); auto-rollback on detected file damage within a single execute (caller-driven: consecutive-failure counting stays with the caller's self-healing loop — Executor is stateless, `RollbackPolicy.max_consecutive_failures` is a reserved/deferred-by-design field, accepted on the wire but never read).

## Data Schema (Pydantic)

The wire contract — `ExecutionRequest` in, `ExecutionResult` out. `ExecutionResult` carries: `exit_code` (0 ok / -124 timeout / -1 blocked-or-internal-error), truncated `stdout`/`stderr`, `task_id`/`command`/`duration_sec` (PRD §4.1), `timed_out`, `blocked_by_security` + `security_reason`, `snapshot_id` for rollback, `cancelled` (Issue #32 — server-side deterministic cancel: `executor.cancel {id}` over UDS → fe-sandbox `kill_process_group_async` SIGINT→SIGKILL killpg + ppid-tree descendant walk; Done frame `exit_code -1` + `cancelled true`; cooperative stop is NOT the cancel path). Diagnostics Slicer runs when `exit_code != 0`: regex-extract Traceback/Error/Exception lines → Tree-sitter AST to locate offending file:line → emit compact JSON (`error_type`, `file_path`, `line_number`, `code_snippet`, `raw_trace`) sized for a prompt.

Native file-tool wire models (fe-tools, replaces Claude SDK FileEdit/Glob/Grep): `EditResult{ok, path, error, matches}` (file_edit unique-match replace + apply_patch + replace_function + write_file + multi_edit + notebook_edit all return this), `GlobEntry{path, is_dir}`, `GrepMatch{path, line_number, content}`. Additional wire models: `RollbackPolicy{max_consecutive_failures (reserved — caller-owned circuit-breaker per ARCH-7), file_damage_check}`; `TelemetrySample{ts_ms, cpu_pct, mem_mb, gpu_pct?, gpu_mem_mb?, task_id?}` + `TelemetryConfig{interval_ms=100, max_samples=0}`; `SandboxProfile{network, filesystem, excluded_commands, fail_if_unavailable}` (Issue #34, per-command seatbelt, default-off / opt-in, `None` = byte-identical to fixed profile); `GuiResult{ok, node_tree, screenshot_png_b64, screenshot_width, screenshot_height, error}`. `ExecutionResult.guard_action_id: str | None` (fusion-guard Phase 3, default OFF — guard Block/L3 carries the guard `action_id` for caller audit).

See `../architecture/fusion-executor-prd.md` §4 for the full `ExecutionRequest` / `ExecutionResult` field list and the Diagnostics Slicer algorithm.

## Build / Test / Lint

Rust core + Python bindings via **maturin/PyO3** (first such project in the monorepo — deliberate divergence from setuptools). 12-crate Cargo workspace (crate map in `docs/architecture.md` §2). Shared venv is Python 3.14 → requires pyo3 ≥0.29.

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
# Socket: ~/.fusion-executor/fe.sock (HOME-private 0o700; override FUSION_EXECUTOR_SOCK)
```

Python ≥3.11 (venv is 3.14). Runtime dep `pydantic>=2.0`. Test deps `pytest`/`pytest-asyncio`/`pytest-cov`. No httpx, no hard fusion-core — executor is an L4 OS tool, delegates inference to caller. Package root is `fusion_executor` (import as `from fusion_executor import FusionSandboxExecutor, ExecutionResult`). Native extension is `fusion_executor._native` (built from `crates/fe-pyo3`).

## Integration With Ecosystem

- **fusion-code → fusion-executor**: fusion-code drops generated patch to disk, calls `executor.run("pytest tests/")`, receives structured diagnostics, enters next self-healing loop iteration. Refactor plan (PRD §"重构"): fusion-code strips its own subprocess/file-IO into an `ExecutorDriver` interface — all command validation, timeout, stdio capture delegated here. **ARCH-7 caller-circuit contract (audit 0827)**: `RollbackPolicy.max_consecutive_failures` is a reserved field the stateless `Executor` never reads — the **caller** (fusion-code self-healing loop) owns the consecutive-failure count and reads that field as its circuit-breaker threshold; auto-rollback is per-execute, not per-loop. Reference skeleton: `examples/08_integrate_fusion_code.py` (consumes the executor API only, does not import fusion-code; one-way issue opened on fusion-code for the `ExecutorDriver` refactor).
- **fusion-executor → fusion-studio**: live stdio stream, screenshot sampling, GPU/CPU telemetry broadcast over Unix Domain Socket to the studio dashboard (zero-copy, high-frame-rate render).
- **fusion-executor ↔ fusion-mlx / fusion-gateway**: UDS comms (not HTTP/gRPC) — terminal Traceback-to-model-prompt transfer latency target <2ms.
- **Replaces**: Claude SDK's BashTool/FileEdit/Glob/Grep + Docker sandbox, and DeepSeek Harness's SWE-bench container — but native (no Docker): macOS process isolation + Git snapshots, sandbox init overhead target <5ms.

## fusion-guard 集成 (Phase 3, Issue #23)

`fusion-executor` 是 fusion-guard 零信任动作授权 daemon 的**执行侧消费方**。guard (per-host UDS
JSON-RPC daemon, Phase 0-2 已落地 14 fg-* crate) 在每条命令执行前裁决 allow/preview/redact/block
+ 风险等级 L1-L4, executor 据此决定执行/拒绝/传递 `guard_action_id` 供调用方审计。

**跨工程约束**: fusion-guard 是 READ-ONLY 跨工程 — 本工程只消费 guard UDS wire 契约 (`/tmp/fusion-guard.sock`
换行分隔 JSON), **不**改 fusion-guard 源码、**不**提 guard PR。本地镜像 wire 类型在 `crates/fe-guard`,
保持 executor 构建独立于 fusion-guard。

**默认 OFF (向后兼容)**: `FusionSandboxExecutor()` 不传 `guard_sock` → guard 关闭, 行为同 v0.2.5 (静态
blocklist regex + 白名单栅栏)。开启: 显式传 `guard_sock='/tmp/fusion-guard.sock'` 或设环境变量
`FUSION_GUARD_SOCK`。

- `FusionSandboxExecutor(guard_sock=..., guard_tenant=...)` → 4 层 plumbing: Python `__init__` →
  fe-pyo3 `PyExecutor::new` → fe-core `Executor::with_guard` → fe-security `SecurityGuard::with_guard`
  (建 `GuardClient` + `ping` 探活 + `rules_dump` 种子缓存 epoch)。
- `FUSION_GUARD_SOCK` / `FUSION_EXECUTOR_TENANT` 环境变量 = 隐式开启。`guard_tenant` 须匹配 guard 配置中
  executor OS 身份 (UID) 绑定的 tenant, 否则每次 evaluate 返 -32001 (鉴权失败) → fail-closed block (非降级,
  降级可能开门)。
- `ExecutionResult.guard_action_id: str | None` — guard 判 Block/L3 时携带 guard 的 `action_id` (uuid),
  供调用方审计/人工 confirm 回路; guard OFF 或 Allow/L1/L2 时 None。4 层 wire auto-flow (fe-core
  serde → fe-pyo3 `#[pyo3(get)]` → Python Pydantic `_STRICT` → fe-ipc done frame serde-flatten)。

**裁决映射** (`SecurityVerdict` ↔ `GuardVerdict`, fe-security 编排): `action==Block` OR `risk_level==L4`
→ block (带 `risk_level`/`action_id`/`seatbelt_required`); `risk_level==L3` (requires_approval) → block
(executor 无人工审批回路, L3 视同拒, 产 `action_id`); `action==Redact` → block (executor 整命令执行,
不支持半 redact); `action==Preview` → allow 但 `requires_approval=true` 透传; `action==Allow` + L1/L2
→ allow, 透传 `risk_level`/`seatbelt_required`。

**Seatbelt 门控 (E7)**: guard 判 `seatbelt_required=true` + 调用方 `req.seatbelt != true` → fe-core
`execute_async`/`execute_streaming` 入口拒绝 (exit -1, 不 spawn)。防降级到非沙箱执行高风险命令。

**Pre-exec 路径复检 (H4 TOCTOU)**: fe-core 在 `validate()` 后、`sandbox.run` 前调
`fe-security::recheck_binary(first_token)` — 复用 `resolve_binary_path` (同一套 `trusted_bin_dirs`,
ARCH-2) + `std::fs::symlink_metadata` (safe Rust, 无 libc/unsafe) 拒执行前窗口新现 symlink。
homebrew `/opt/homebrew/bin/x` → Cellar 是 by-design 不拒 (resolve 期非 symlink); 仅拒 validate 后变 symlink。
SANDBOX_HARDENED_PATH (fe-sandbox spawn 期 PATH) 是另一道独立栅栏, 无需改 fe-sandbox。

**降级 fail-closed (guard 宕机, 验收 #7)**: guard 调用失败 (`GuardError::Unavailable`/超时) → 不 fail-open:
1. `run_cached_rules(command)` 命中 regex block 模式 → block;
2. 未命中 → 交回现有 `validate()` 白名单栅栏 (非白名单 binary 即 block);
3. `allow_inline_interpreter==true` + 缓存空/不可用 → 直接 block 内联形式 (无 guard 无法评估风险, fail-closed);
4. 白名单 binary → allow 但 `warn!` "guard 宕机降级, 风险等级未知" (严于 guard 活时不放宽)。
降级**无法**本地复现 guard 完整裁决 (tokenizer/AST/semantic 在 guard 内), 仅 regex-stage; 故降级 = **更严**。

**R4 冲突消解 (编译期静态兜底)**: Issue #23 R4 原文 "retain `DANGEROUS_BINS` compile-time static fallback"
与 0827 A-12 有意删除该 const 冲突。消解: 现有 fe-security 静态 `build_blocklist()` regex 危险模式 +
`WHITELIST` 白名单即编译期 fail-closed 兜底栅栏; guard 宕机降级时, 这两套静态规则 + 缓存 regex 规则共同构成
兜底, 满足 R4 安全意图。**不**重新引入已删除的 `DANGEROUS_BINS` const (违背 0827 A-12)。

**guard start**: `cd /Users/dahai/fusion/fusion-guard && ./start.sh start|stop|status|doctor`
(需先 `cargo build --release` 产 `target/release/fusion-guard`; sock `/tmp/fusion-guard.sock`)。

## Issue #32 — Server-Side Deterministic Cancel (in-flight executeStream)

Cancel an in-flight `execute_stream` from the server side with a **deterministic** process-tree kill (not a cooperative stop request). Designed for the fusion-code client to abort a runaway long-running command without leaving orphans.

**Cancel semantics** — cancel = local deterministic kill via SIGINT→SIGKILL of the whole process group, NOT a cooperative "please stop" request. The `executor.cancel` UDS method resolves the in-flight stream by its JSON-RPC request id, fires a `oneshot::channel` that fe-sandbox's `run_streaming` `tokio::select!` (biased) is waiting on, then `kill_process_group_async(pid)` runs: `killpg(-pgid, SIGINT)` → `KILL_GRACE_MS` (500ms) grace → `killpg(-pgid, SIGKILL)` → ppid-tree descendant walk (`collect_descendants` + `kill_descendants_ppid`, RUN-9 setsid-orphan fallback). The Done frame returns `exit_code: -1` + `cancelled: true`.

**4-layer wiring**:
1. **fe-sandbox** `run_streaming(cfg, cancel_rx: Option<oneshot::Receiver<()>>)` — `tokio::select!` (biased) over exit_fut / cancel_fut (Box::pin, Receiver !Unpin) / outer_tx.closed() / inner_rx.recv(). Cancel branch → `kill_process_group_async(pid)` → `cancelled=true`, break. PTY path uses portable-pty `setsid` (child = group leader); stdio path uses `CommandExt::process_group(0)` so `killpg(-child_pid)` reaches the whole group.
2. **fe-core** `execute_streaming(&self, req, cancel_rx: Option<Receiver<()>>)` — threads `Some(cancel_rx)` to `self.sandbox.run_streaming`; `ExecutionResult` gains `cancelled: bool` (`#[serde(default, skip_serializing_if="is_false")]`); Done frame backfills `cancelled: sb.cancelled`. In-process `execute_streaming(req, None)` path is never cancellable (no serve() running → no registry).
3. **fe-ipc** `StreamRegistry = Mutex<HashMap<String, oneshot::Sender<()>>>` keyed by stringified JSON-RPC id — lives in the IPC layer (like `ShellRegistry`/`BroadcastHub`, M-ARCH-1 — **Executor stays stateless**). `handle_execute_stream` creates `(tx, rx) = oneshot::channel()`, stores tx under `id.to_string()`, passes `Some(rx)` to execute_streaming, deregisters after done/drop. New UDS arm `executor.cancel {id}` → `registry.cancel(id)` → `sender.send(())` → response `{ok, cancelled}`. Cancel works **cross-connection**: `dispatch_request` spawns a tokio task per request, so read_task keeps reading while a stream runs — a cancel on a second connection reaches the shared registry while the stream is in-flight.
4. **fe-pyo3** `PyExecutionResult.cancelled` (`#[pyo3(get)]` + From). **Python** `ExecutionResult.cancelled` Pydantic field (`_STRICT` extra=forbid) + `FusionSandboxExecutor.cancel_stream(stream_id, *, sock_path=None) -> bool` — opens a fresh UDS connection, sends `executor.cancel {id}`, returns `bool(result.cancelled)`, raises on JSON-RPC error. `stream_id` = the JSON-RPC request id of the `execute_stream` call.

**Client contract** (fusion-code, READ-ONLY): sends `executor.cancel` RPC with `{id}` = JSON-RPC request id of the execute_stream call. Best-effort fail-soft — unknown id → `{ok:false, cancelled:false}`, no exception. The client keeps the execute_stream connection open to read the terminal Done frame (`exit_code -1`, `cancelled true`).

**0 new unsafe** — reuses fe-sandbox `kill_process_group_async` (nix `killpg`/`kill`, all safe). Acceptance (Issue #32): cancel `sleep 1000` (or `python3 -c "while True: pass"`) → child + descendants exit within `KILL_GRACE_MS` + SIGKILL; no orphans under load (ppid-tree walk catches setsid escapees); cancel semantics documented here.

## Issue #34 — Per-command Seatbelt/Sandbox Profile (sandbox-independence for fusion-code G2)

Enable seatbelt/sandbox for the detached executor subprocess with a **per-command** configurable profile. Each `ExecutionRequest` carries an optional `sandbox: SandboxProfile` (`#[serde(default)]`) that tunes the macOS `sandbox-exec` profile for that single command. **Default-off / opt-in**: a `None` profile preserves the existing fixed profile byte-for-byte (default deny network-outbound + directed `SENSITIVE_FS_PATHS` file-write deny), so existing deployments behave identically — no byte drift.

**SandboxProfile wire model** (fe-sandbox `seatbelt.rs`, matches fusion-code `SandboxSettings`):
- `network: Option<SandboxNetworkMode>` — `Allow` omits the network deny; `Deny` (default) keeps `deny network-outbound`. None does not override the default.
- `filesystem: Option<SandboxFsMode>` — `Allow` omits FS deny; `DenyWrite` (default) keeps directed sensitive-path file-write deny; `Deny` adds a global `file-write*` deny (Darwin 25 NO-OP noted).
- `excluded_commands: Vec<String>` — command names injected as `(deny process-exec (literal "<name>"))`. Strings sanitized (`sanitize_profile_string` strips `"`, `\`, control chars) to prevent profile-syntax injection; empty-after-sanitize entries skipped.
- `fail_if_unavailable: bool` — `true` = fail-closed when `sandbox-exec` is not on PATH (`seatbelt_available()` probes via `which::which`): `execute_async`/`execute_streaming` reject with `exit_code -1`, no spawn. `false` (default) = silently degrade to running without seatbelt.

**4-layer wiring** (additive field, auto-flow):
1. **fe-sandbox** `SandboxConfig.sandbox_profile: Option<seatbelt::SandboxProfile>` (last field, `#[serde(default)]`); `build_command`/`build_std_command` accept `sandbox_profile: Option<&SandboxProfile>` — `Some` → `build_profile_from` (parameterized), `None` → cached `profile()` (fixed, byte-identical to v0.2.7). `SandboxNetworkMode`/`SandboxFsMode` enums (`#[serde(rename_all="snake_case")]`, `#[default]` Deny/DenyWrite); `SandboxProfile` struct (`#[serde(rename_all="snake_case", deny_unknown_fields)]`, all `#[serde(default)]`).
2. **fe-core** `ExecutionRequest.sandbox: Option<fe_sandbox::seatbelt::SandboxProfile>` (`#[serde(default)]`); `execute_async`/`execute_streaming` fail-closed gate (`fail_if_unavailable=true` + `!seatbelt_available()` → `blocked_with` exit -1, no spawn) + pass `sandbox_profile: req.sandbox.clone()` into `sb_cfg`.
3. **fe-ipc** auto-flow — `executor.execute`/`execute_stream` parse `ExecutionRequest` via `serde_json::from_value(params)`; additive `sandbox` field requires no method-level wiring.
4. **fe-pyo3** `execute_sync`/`execute_streaming` accept `sandbox: Option<Bound<'_, PyAny>>`; PyAny→serde via `py.import("json").call_method1("dumps", (&obj,))` → `serde_json::from_str`. **Python** `SandboxProfile` Pydantic (`_STRICT` extra=forbid) + `ExecutionRequest.sandbox: SandboxProfile | None` + `run()`/`run_streaming()` `sandbox: SandboxProfile | None = None` kwarg (passes `sandbox.model_dump()` as last native arg; None → native None).

**0 new unsafe** — reuses fe-sandbox safe wrappers + `which` crate (v7) PATH probe. `build_profile_from(None)` equals fixed `build_profile()` (byte-identical assertion in unit test). Baseline preserved: `sandbox=None` is byte-identical to v0.2.7. Acceptance (Issue #34): per-command profile reaches seatbelt; `excluded_commands` denies the named binary via seatbelt (not security guard — non-zero exit, not `blocked_by_security`); `fail_if_unavailable=true` fails closed when sandbox-exec absent; default-off preserves existing behavior.

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
- `ExecutionResult.diagnostics` field is additive over PRD §4.1 (approved) — delivers PRD §4.2 Slicer output. Live stdio streaming (PRD §5) landed — `run_streaming()` yields chunk strings then `ExecutionResult`; fe-sandbox `run_streaming` → fe-core `execute_streaming` (mpsc `ExecutionStreamEvent` `Chunk`/`Done`) → fe-ipc `executor.execute_stream` (NDJSON multi-frame) → fe-pyo3 `NativeStreamIterator` → Python generator. Rollback is **caller-driven by default** (executor exposes `snapshot_create`/`rollback`, stays stateless per-task); optional `auto_rollback=RollbackPolicy{...}` kwarg on `run()`/`run_streaming()` — executor auto-rolls-back to the pre-exec snapshot on `exit_code!=0` + git-status-detected file damage, sets `result.auto_rolled_back=True`, but still does NOT track consecutive-failure counts (that stays with the caller's self-healing loop).
- Upstream problems (fusion-mlx, fusion-gateway, fusion-core): file issue first, then PR, follow up with code — don't patch other projects in-tree.

## Key Paths

**In-repo docs** (authoritative for architecture/API/protocol):
- `docs/architecture.md` — crate map (12 crates), execution pipeline, full Python API surface, IPC protocol (UDS JSON-RPC 2.0 method table + error codes), security guard, diagnostics slicer, fe-gui.
- `docs/PRODUCTION_RUNBOOK.md` — ops runbook (logging, metrics, SIGHUP reload, soak/stability harnesses, degraded-mode smoke).
- `docs/INDEX.md` — documentation map.
- `examples/` — 8 runnable Python examples (`01_run_echo` … `08_integrate_fusion_code`) + `regcheck.rs` + `uds_client_typescript.ts`.
- `scripts/` — `long_stability.py`, `soak_stress.py`, `smoke_degraded_mode.py`.

**Monorepo-root docs** (one level up, not in-project):
- `../architecture/fusion-executor-prd.md` — full PRD, architecture diagram, data schema §4, diagnostics algorithm, fusion-code refactor plan, Claude-SDK/DeepSeek-Harness capability comparison.
- `../audit/fusion-ar-audit.md` (P2-7) — rationale for extracting fusion-science's code sandbox here.
- `../audit/fusion-executor-audit-*.md` — audit reports (0824/0825/0826/0827 + product-0827).
- `/Users/dahai/fusion/CLAUDE.md` — monorepo overview, shared `.venv`, fusion-mlx lifecycle (`~/fusion/fusion-mlx/start.sh start|stop|status`).
