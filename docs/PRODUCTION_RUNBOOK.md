# Production Runbook — fusion-executor

> Enterprise deployment, operations, incident, and API-stability guide.
> Applies to **v0.2.8+**. Verify against your installed version (`fusion_executor.__version__`).

## 1. Platform & System Requirements

| Requirement | Value |
|---|---|
| **OS** | macOS 13+ (Apple Silicon; Intel untested) |
| **Architecture** | arm64 (Apple Silicon). x86_64 not validated. |
| **Python** | ≥3.11 (shared venv uses 3.14) |
| **Rust** | rustc 1.96+ (edition 2021; workspace `unsafe_code="deny"` except fe-gui crate-level allow) |
| **Build backend** | maturin + PyO3 0.29 (the only PyO3 project in the Fusion monorepo) |
| **Runtime dep** | `pydantic>=2.0` |
| **macOS GUI** | TCC **Accessibility** + **Screen Recording** permissions required for `gui_action` (see §8) |
| **seatbelt** | `sandbox-exec` (ships with macOS; probed via PATH at runtime) |

**Product boundary — single platform.** fusion-executor is macOS-only by design (CoreGraphics + Accessibility + sandbox-exec are macOS APIs). There is **no Linux port and none planned** in this release line. Enterprise deployments on Linux must run executor on a dedicated macOS host/VM and reach it over UDS or wrap it behind a gateway. See §13.

**No Docker.** Sandboxing is native macOS (sandbox-exec profile + process-tree kill + git snapshots), not a container. This is deliberate — eliminates container init overhead (init <5ms SLA) and preserves macOS API access for GUI actions.

## 2. Installation

```bash
# 1. Shared monorepo venv (REQUIRED before any Python work)
cd /Users/dahai/fusion
source .venv/bin/activate          # Python 3.14

# 2. Build & install the native extension (editable) into the shared venv
cd fusion-executor
maturin develop --release          # produces fusion_executor._native

# 3. Verify
python -c "from fusion_executor import FusionSandboxExecutor; print(FusionSandboxExecutor().run('echo hi').exit_code)"
# expect: 0
python -c "import fusion_executor; print(fusion_executor.__version__)"
# expect: 0.2.8
```

The package root is `fusion_executor` (import as `from fusion_executor import FusionSandboxExecutor, ExecutionResult`). The native extension is `fusion_executor._native` (built from `crates/fe-pyo3`).

CLI entry point: `fusion-executor` (registered in `pyproject.toml [project.scripts]`).

## 3. Deployment Patterns

### 3.1 Standalone UDS server (primary)

The server is a long-lived process listening on a Unix Domain Socket (HOME-private, `0o700` dir + `0o600` socket). Clients send JSON-RPC 2.0 over UDS.

```bash
fusion-executor --serve                    # default socket ~/.fusion-executor/fe.sock
fusion-executor --serve --sock /run/fe.sock  # custom socket
```

**Concurrency limits** (hard-coded, see `fe-ipc/src/lib.rs`):

| Limit | Value | Constant |
|---|---|---|
| Max connections | 64 | `MAX_CONNECTIONS` |
| Max concurrent non-streaming executes | 16 | `MAX_CONCURRENT_EXECS` |
| Max concurrent streaming executes | 64 | `MAX_CONCURRENT_STREAMS` |
| Default timeout cap | 120s | `DEFAULT_TIMEOUT_CAP_SEC` |
| SIGINT→SIGKILL grace | 500ms | `KILL_GRACE_MS` |

> **Why exec/stream split (RUN-3):** streaming executes hold a permit across the whole chunk→done lifecycle. If they shared the exec semaphore (16), 16 long-running streams would starve short `execute` commands. Separate semaphores prevent starvation. The gauge `fe_exec_sem_available` exposes remaining exec permits for LB/saturation detection.

### 3.2 In-process library (no server)

Callers that don't need cross-process IPC can use the executor directly:

```python
from fusion_executor import FusionSandboxExecutor

ex = FusionSandboxExecutor()
result = ex.run("pytest tests/")
```

**Note:** in-process `run()`/`run_async()` bypass the IPC layer and are **not** counted by Prometheus metrics (only `executor.execute` over UDS + shell lifecycle + rollback are tracked). See §6.

### 3.3 Detached subprocess (fusion-code integration)

fusion-code spawns the executor as a detached subprocess with a per-command sandbox profile (Issue #34). The client owns the consecutive-failure count (self-healing loop circuit-breaker); the executor stays **stateless per-task** (M-ARCH-1). Reference skeleton: `examples/08_integrate_fusion_code.py`.

## 4. Configuration Reference

### 4.1 Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `FUSION_EXECUTOR_SOCK` | `~/.fusion-executor/fe.sock` | UDS socket path (HOME-private `0o700` dir) |
| `FUSION_EXECUTOR_PIDFILE` | (none) | PID file path for service managers |
| `FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS` | `10` | Graceful drain timeout on SIGINT/SIGTERM/`executor.shutdown` (range 1..=300, out-of-range falls back to 10) |
| `FUSION_EXECUTOR_EXTRA_WHITELIST` | (none) | Comma-separated extra command whitelist (hot-reloadable via SIGHUP, e.g. `jq,gh`). Baseline whitelist always present; reload **replaces** extras, never accumulates. Dangerous interpreters (`sh`/`bash`/`zsh`/`sudo`/...) rejected. |
| `FUSION_EXECUTOR_TENANT` | (none) | Guard tenant ID (implicit guard enable; must match guard config binding to executor UID) |
| `FUSION_GUARD_SOCK` | (none) | fusion-guard UDS socket path (implicit guard enable) |
| `FE_LOG_DIR` | `~/.fusion-executor/logs` | Log directory (daily-rolling `fe.log.YYYY-MM-DD`). Unwritable → stderr-only, never crashes. |
| `RUST_LOG` | `info` | Tracing log level (hot-reloadable via SIGHUP) |

### 4.2 ExecutionRequest key fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `command` | `str` | (required) | Shell command |
| `cwd` | `str \| None` | cwd | Working directory |
| `timeout_sec` | `float` | `30.0` | `0` bounded to 120s cap (never unbounded) |
| `seatbelt` | `bool` | `True` | macOS sandbox-exec isolation (default-on, ARCH-1) |
| `env_vars` | `dict \| None` | None | If None: env cleared + host PATH baseline. `inherit_env=True` opt-in. |
| `sandbox` | `SandboxProfile \| None` | None | Per-command seatbelt profile (Issue #34, default-off) |
| `auto_rollback` | `RollbackPolicy \| None` | None | Auto-rollback to pre-exec snapshot on failure + file damage |
| `trace_id` | `str \| None` | auto uuid v4 | Cross-layer trace correlation |
| `task_id` | `str \| None` | None | Caller-side identity (PRD §4.1) |

### 4.3 Exit-code convention (stable contract)

| Code | Meaning |
|---|---|
| `0` | success |
| `-124` | timeout |
| `-1` | blocked / security / internal error |

**Never change.** Callers depend on this. CLI maps `-124`→`124`, `-1`→`1`.

## 5. Security Model

Defense in depth — **4 stages**, fail-closed at every layer:

1. **Stage 1 — static regex blocklist** (`fe-security::build_blocklist`). Fast filter for `rm -rf`, `sudo`, format strings, remote pipes.
2. **Stage 2 — shlex tokenizer + compound-splitter + whitelist**. Splits `&&`/`||`/`;`/`|` and validates each binary against a whitelist (python, node, pytest, cargo, swift, go, tsc, jq, gh, make...). Full token-level parse prevents chain-assembly bypass.
3. **Stage 3 — argv gateway** (D3-1). Default **blocks** inline interpreters (`python -c`/`node -e`/`ruby -e`/`perl -e`) at the binary+flag level — payload content irrelevant. `allow_inline_interpreter=True` opt-in for trusted callers. Prevents agent-driven one-liner bypass of regex dangerous-word enumeration.
4. **Stage 4 — resolved-path whitelist** (ARCH-2). Binary basename in whitelist **AND** absolute path under `trusted_bin_dirs` (`/usr/bin`/`/usr/local/bin`/`/opt/homebrew/bin` + venv bin auto-registered). `/tmp/python3` name-poisoning rejected (fail-closed).

**TOCTOU recheck (H4):** after `validate()`, before `sandbox.run`, `recheck_binary(first_token)` re-resolves the path via `resolve_binary_path` + `std::fs::symlink_metadata` — rejects a binary that became a symlink in the validate→spawn window. Homebrew `/opt/homebrew/bin/x`→Cellar symlinks are by-design (not rejected); only newly-appeared symlinks are.

**Seatbelt (macOS sandbox-exec):** default-on (ARCH-1). Profile denies network-outbound + directed `SENSITIVE_FS_PATHS` file-write. Per-command `SandboxProfile` (Issue #34) can tune network/filesystem/excluded-commands per request; `fail_if_unavailable=True` fails closed when `sandbox-exec` absent.

**Guard (optional, default-off):** fusion-guard zero-trust authorization. Verdict mapping: Block/L4/L3 → block (with `guard_action_id` for audit); Preview → allow + `requires_approval`; Allow/L1/L2 → allow. Degraded fail-closed on guard outage (never fail-open — see §9). **Seatbelt gate (E7):** guard `seatbelt_required=True` + caller `seatbelt≠True` → reject (exit -1, no spawn).

**Process isolation:** PTY/stdio subprocess via `setsid` (child = group leader); `killpg` + ppid-tree descendant walk for setsid orphans (RUN-9). RSS watchdog kills OOM (exit -124, `oom_killed=true`). rlimit NOFILE(1024)/NPROC(512).

## 6. Observability (Logging / Metrics)

### 6.1 Structured logging

JSON `tracing` output (`with_target(true)`), **teed** to a daily-rolling file (`fe.log.YYYY-MM-DD` under `FE_LOG_DIR`, default `~/.fusion-executor/logs/`) **and** stderr. One `fmt` layer + one reloadable `EnvFilter`.

- Default level `info`; `RUST_LOG` overrides.
- Unwritable log dir → stderr-only (never crashes).
- Idempotent via `OnceLock`; `WorkerGuard` held in a static so the non-blocking file buffer flushes on exit.
- Cross-layer `trace_id` (auto uuid v4 or caller-supplied) on every `execute`/`execute_stream` span (m-OPS-06).

### 6.2 Prometheus metrics

Pulled over **UDS** (no HTTP port — preserves M-SEC-01). Method: `executor.metrics_prometheus` → text format. The caller feeds its own exporter. Python wrapper: `FusionSandboxExecutor.metrics_prometheus()`.

| Metric | Type | Meaning |
|---|---|---|
| `fe_exec_total` | counter | Total execute calls (UDS only) |
| `fe_exec_success` | counter | exit_code 0 |
| `fe_exec_blocked` | counter | blocked_by_security |
| `fe_exec_timeout` | counter | exit -124 |
| `fe_exec_failed` | counter | other failures |
| `fe_exec_duration_seconds` | histogram | wall-clock per execute |
| `fe_exec_sem_available` | gauge | remaining exec semaphore permits (0 = saturated, LB signal) |
| `fe_rollback_total` / `fe_rollback_failed` | counter | rollback attempts / failures |
| `fe_shell_active` | gauge | active (not finished) background shells |
| `fe_connections` | gauge | active UDS connections |

**Scope caveat:** in-process `run()`/`run_async()` bypass the IPC layer and are **not** counted. Only `executor.execute` over UDS + `shell_start`/`kill_shell` + `snapshot_create`/`rollback` are tracked. To populate counters in a smoke test, use raw UDS `executor.execute` (not `ex.run()`).

### 6.3 Health probe

`executor.health` over UDS → depth-probed status (socket bound, executor reachable, sandbox available). Use before routing traffic.

## 7. Hot-Reload (SIGHUP)

Send `SIGHUP` to the running server to reload **log level** + **whitelist extras** without restart:

```bash
kill -HUP $(cat $FUSION_EXECUTOR_PIDFILE)
```

- **Log level:** reads `RUST_LOG` (unset/empty → `info`). Bad directive → fail-loud, current level unchanged.
- **Whitelist extras:** reads `FUSION_EXECUTOR_EXTRA_WHITELIST` (comma-split, trim, drop-empty). **Replaces** prior extras from the baseline (never accumulates); dangerous interpreters rejected.

```bash
# Example: allow jq + gh, then reload
FUSION_EXECUTOR_EXTRA_WHITELIST=jq,gh kill -HUP <pid>
# jq --version now allowed (was blocked)
```

SIGHUP is reload-only — it **never** triggers shutdown. SIGINT/SIGTERM trigger graceful drain (timeout `FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS`, default 10s).

## 8. GUI / macOS Accessibility Constraints

`gui_action` drives native macOS UI via the **Accessibility API** (`AXUIElement`) + **CoreGraphics** (CGEvent synthesis, framebuffer screenshot). Two **independent** TCC permissions gate different actions:

| TCC permission | Gates | How to grant |
|---|---|---|
| **Accessibility** | `focus_app`, `click`, `type_text`, `key_press`, `inspect_tree`, `double_click`, `right_click`, `hover`, `window_*`, `drag`, `scroll` | System Settings → Privacy & Security → Accessibility → add the executor host process (Terminal / `fusion-executor` / launcher) |
| **Screen Recording** | `screenshot` (framebuffer capture) | System Settings → Privacy & Security → Screen Recording → add the host process |

**Permission separation matters:** a host may have Accessibility but not Screen Recording (or vice versa). `gui_action` probes the relevant permission per action and **degrades gracefully** (`ok: false`, `error: "accessibility-permission-required"` or screenshot-TCC error) — it never crashes on a missing permission. Screenshot is gated on Screen Recording **before** the AX gate (so a Screen-Recording-trusted + Accessibility-untrusted host can still screenshot).

**Headless / SSH / launchd deployments:**

- `gui_action` actions requiring an AX UI tree (`window_*`, `inspect_tree`, `focus_app` with no window) **degrade** when no GUI session is attached (`kAXErrorCannotComplete` / element-not-found → `ok: false`). This is expected on headless hosts — it is not a bug.
- CGEvent pointer synthesis (`click`/`hover`/`scroll`/`drag`/`key_press`) posts to the HID event tap; on a real GUI session with Accessibility granted it works, on a headless session it is a no-op (no crash).
- **Recommendation:** run GUI-driving workloads on a host with an active GUI session (logged-in user, display attached or `screen sharing`/VNC). For pure command-execution / file-tool / streaming workloads, headless is fully supported — `gui_action` simply returns degraded results.

**CI / test behavior:** Python GUI tests are marked TCC-skip when `!AXIsProcessTrusted()` (6 tests skip on CI). They run fully only on a trusted interactive host. This is by design — CI must not require TCC grants.

**Bundle allowlist (RUN-12):** `GuiConfig::default()` ships a non-empty safe bundle set (Terminal/TextEdit/Finder). `gui_action` with `focus_app` targeting a bundle outside this set degrades unless `disable_bundle_allowlist` is opted in. This prevents an agent from driving arbitrary apps without explicit operator allowance.

## 9. Fusion-Guard Integration (Optional Zero-Trust)

fusion-guard is a per-host zero-trust action-authorization daemon (UDS JSON-RPC). The executor is its **execution-side consumer** — it asks guard to rule (allow/preview/redact/block + risk L1-L4) on each command before running.

**Default OFF (backward-compatible).** `FusionSandboxExecutor()` without `guard_sock` → guard disabled, behavior identical to v0.2.5+ (static blocklist regex + whitelist fence). Enable explicitly:

```python
# explicit
ex = FusionSandboxExecutor(guard_sock="/tmp/fusion-guard.sock", guard_tenant="host-42")
# OR implicit via env
#   FUSION_GUARD_SOCK=/tmp/fusion-guard.sock
#   FUSION_EXECUTOR_TENANT=host-42
```

`guard_tenant` **must** match the tenant bound to the executor's OS identity (UID) in guard config. A mismatch → every `evaluate` returns `-32001` (auth failure) → the executor treats this as **fail-closed block** (not degraded allow — an auth failure is a misconfiguration, and degrading could open a door).

### Verdict mapping

| Guard verdict | Executor action | `guard_action_id` |
|---|---|---|
| `Allow` + L1/L2 | allow | None |
| `Preview` | allow + `requires_approval=true` surfaced | None |
| `Block` **or** `L4` | block (exit -1) | set (uuid, for audit) |
| `L3` (requires_approval) | block (executor has no human-approval loop; L3 = denied) | set |
| `Redact` | block (executor runs whole commands, cannot half-redact) | set |

**Seatbelt gate (E7):** if guard returns `seatbelt_required=true` **and** the caller's `req.seatbelt != true`, the executor rejects with exit -1, no spawn. This prevents downgrading a high-risk command to unsandboxed execution.

### Degraded fail-closed (guard outage)

When guard is unreachable (`GuardError::Unavailable` / timeout), the executor **never fails open**. It degrades to a **stricter** posture:

1. `run_cached_rules(command)` — cached regex-stage rules (from the last successful `guard.rules.dump`) are matched; a hit → block.
2. No cache hit → falls back to the existing `validate()` whitelist fence (non-whitelisted binary → block).
3. `allow_inline_interpreter=true` + empty/unavailable cache → **directly block** inline forms (`python -c`/`node -e`...) — no guard means no risk assessment, so fail-closed.
4. Whitelisted binary → allow **but warn** `"guard 宕机降级, 风险等级未知"` (stricter than when guard is alive — risk level unknown).

**Honest limitation:** the cached rules are **regex-stage only** (guard's tokenizer/AST/semantic stages live inside guard). Degraded mode cannot reproduce guard's full verdict — so it is deliberately **more conservative**, not a faithful replica.

### Cross-project constraint

fusion-guard is **READ-ONLY** cross-project for this repo. The executor consumes guard's UDS wire contract only; it does **not** modify guard source, does **not** file guard PRs. Wire types are mirrored locally in `crates/fe-guard` to keep the executor build independent of guard. Upstream guard problems follow the monorepo flow: file issue first, then PR, then code.

### Guard lifecycle

```bash
cd /Users/dahai/fusion/fusion-guard && ./start.sh start|stop|status|doctor
# socket: /tmp/fusion-guard.sock (requires cargo build --release first)
```

## 10. Incident Response Procedures

### 10.1 Server won't start / socket bind fails

```bash
# 1. Check stale socket from a crashed prior run
ls -la ~/.fusion-executor/fe.sock
# If present but no live server, remove it
rm ~/.fusion-executor/fe.sock

# 2. Check for an already-running server (PID file)
cat ~/.fusion-executor/fe.pid 2>/dev/null && ps -p $(cat ~/.fusion-executor/fe.pid)
# Kill a zombie, then retry

# 3. Permission on the socket dir (must be 0o700, HOME-private)
ls -ld ~/.fusion-executor
chmod 700 ~/.fusion-executor
```

### 10.2 Commands hanging / not returning

- A non-streaming `execute` with `timeout_sec=0` is bounded to the **120s cap** (`DEFAULT_TIMEOUT_CAP_SEC`) — it can never run truly unbounded. If a command appears to hang past 120s, the cap is not reaching it → check that the request didn't set an explicit large `timeout_sec`.
- For a genuinely stuck long-running stream, use **server-side cancel** (Issue #32): `FusionSandboxExecutor.cancel_stream(stream_id)` sends `executor.cancel {id}` → deterministic `killpg` (SIGINT→500ms grace→SIGKILL) of the whole process group. The Done frame returns `exit_code: -1`, `cancelled: true`. No orphans.
- If the whole server is wedged, `SIGTERM` triggers graceful drain (timeout `FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS`, default 10s); in-flight executes are killed via the process-tree walker.

### 10.3 OOM / runaway output

- The **RSS watchdog** (D3-4) kills a child process tree exceeding the RSS threshold → `exit_code: -124`, `oom_killed: true`. No host OOM.
- **stdio truncation** keeps head context + tail stack trace, folding the middle past `max_output_chars`. Infinite-print death-loops are capped, not OOM'd.
- **write_file** caps content at 64MB (`WRITE_FILE_MAX_BYTES`); background shell tail is capped at `TAIL_CAP=100_000` chars.

### 10.4 Security block investigation

A `blocked_by_security: true` result with `exit_code: -1` means Stage 1-4 rejected the command. Inspect `security_reason`:

| Reason shape | Stage | Cause |
|---|---|---|
| regex blocklist hit (e.g. `rm -rf`) | 1 | static dangerous pattern |
| `binary not in whitelist: X` | 2 | non-whitelisted binary |
| `inline interpreter blocked: X -c/-e` | 3 (D3-1) | `python -c`/`node -e` default-blocked |
| `resolved path not under trusted_bin_dirs` | 4 (ARCH-2) | name-poisoning / untrusted path |
| `TOCTOU: binary path changed before spawn` | H4 | binary became a symlink in the validate→spawn window |

To allow a new tool: set `FUSION_EXECUTOR_EXTRA_WHITELIST=tool1,tool2` and `kill -HUP <pid>` (SIGHUP hot-reload, §7). For inline interpreters, the caller must opt in `allow_inline_interpreter=True` (trusted caller only).

### 10.5 Guard-down / degraded mode

If guard is enabled but unreachable, the server logs `"guard 宕机降级, 风险等级未知"` per allowed command and blocks non-whitelisted binaries + inline forms fail-closed (§9). This is **expected** behavior, not a bug. To verify guard health:

```bash
cd /Users/dahai/fusion/fusion-guard && ./start.sh status
```

### 10.5 Rollback / file damage

`auto_rollback=RollbackPolicy{...}` on `run()`/`run_streaming()` rolls back to the pre-exec git snapshot when `exit_code != 0` **and** `git status --porcelain` detects file damage. `result.auto_rolled_back: true` signals it fired. Inspect the snapshot via `git stash list` (snapshots are stash-prefixed). If rollback itself fails, `fe_rollback_failed` counter increments — check logs under `FE_LOG_DIR`.

## 11. Upgrade & Migration Guide

### 11.1 In-place upgrade (within v0.2.x)

The wire contract (`ExecutionRequest`/`ExecutionResult` and tool models) is **additive only** — new fields carry defaults, existing fields keep names and semantics. An in-place upgrade is safe:

```bash
cd /Users/dahai/fusion && source .venv/bin/activate
cd fusion-executor
git pull origin main
maturin develop --release        # rebuild native extension
python -c "import fusion_executor; print(fusion_executor.__version__)"
# Restart any long-running server
```

The server socket path (`FUSION_EXECUTOR_SOCK`) and PID file are stable across releases. Existing clients reconnect after restart.

### 11.2 Breaking-change guardrails

- **Exit codes are a stable contract** (§4.3): `0`/`-124`/`-1`. Never remap.
- **Pydantic models use `extra="forbid"`** (`_STRICT`). A client sending an unknown field gets a `ValidationError` at the boundary — this is intentional (fail-loud on schema drift). When upgrading the executor, upgrade clients in lockstep if the wire model gained a required field (none have been made required post-v0.2.0; all additions are optional-with-default).
- **`deny_unknown_fields`** on Rust serde structs mirrors this. The 4-layer field set (Rust serde ↔ fe-pyo3 `From` ↔ Python Pydantic ↔ fe-ipc done frame) is kept in sync by the `test_models_reject_extra_fields` / `test_models_reject_missing_required_fields` drift-lock tests.

### 11.3 Version SSOT

Three points hold the canonical version (must move together on release):
1. `Cargo.toml` — `workspace.package.version`
2. `pyproject.toml` — `[project].version`
3. `python/fusion_executor/__init__.py` — `__version__`

`maturin` reads `pyproject.toml` (not `Cargo.toml`) for the Python package version, but both must agree. A release bumps all three and tags `vX.Y.Z`.

### 11.4 Rollback to a prior release

```bash
git checkout v0.2.7        # or any prior tag
maturin develop --release
# restart server
```

Git-tagged releases are immutable. Because the wire model is additive-only, a newer client can usually talk to an older server (unknown fields are ignored by older serde) — but an older client talking to a newer server is the supported direction.

## 12. API Stability Policy

**Stability tier: additive-only, no breaking changes within v0.2.x.**

### 12.1 Wire contract (stable)

`ExecutionRequest` / `ExecutionResult` / tool models (`EditResult`, `GlobEntry`, `GrepMatch`, `GrepOutput`, `SandboxProfile`, `RollbackPolicy`, `TelemetrySample`, `GuiResult`) are the cross-process wire contract. Policy:

- **Fields are added, never removed or renamed** within v0.2.x.
- **New fields carry a default** (Rust `#[serde(default)]`, Pydantic `= None` / `= False`), so an older client/server is not broken.
- **Field semantics do not flip** (e.g. `seatbelt` default changed False→True once at ARCH-1; that was a one-time hardening, now stable at `True`).
- **Exit codes are frozen** (§4.3).

### 12.2 UDS JSON-RPC methods (stable)

Method names (`executor.execute`, `executor.execute_stream`, `executor.cancel`, `executor.health`, `executor.shutdown`, `executor.shell_start`/`shell_output`/`kill_shell`/`list_shells`, `executor.file_edit`/`glob`/`grep`/`grep_with_opts`/`apply_patch`/`replace_function`/`write_file`/`multi_edit`/`notebook_edit`, `executor.gui_action`, `executor.telemetry_stream`, `executor.subscribe`/`unsubscribe`, `executor.metrics_prometheus`, `executor.snapshot_create`/`rollback`) are stable. New methods may be added; existing ones keep their param shape (additive optional params only).

### 12.3 Python API (stable)

`FusionSandboxExecutor` public methods (`run`, `run_streaming`, `shell_start`, `shell_output`, `kill_shell`, `list_shells`, `gui_action`, `file_edit`, `glob`, `grep`, `grep_with_opts`, `apply_patch`, `replace_function`, `write_file`, `multi_edit`, `notebook_edit`, `telemetry_stream`, `subscribe`, `metrics_prometheus`, `snapshot_create`, `rollback`, `cancel_stream`, `serve`) keep their signatures. New keyword-only params (with defaults) may be added.

### 12.4 What is NOT stable (internal)

Rust crate APIs (`fe-core`, `fe-sandbox`, `fe-security`, `fe-ipc`, `fe-pyo3`, `fe-tools`, `fe-gui`, `fe-diagnostics`, `fe-rollback`, `fe-telemetry`, `fe-shell`, `fe-guard`) are **internal** — no cross-crate stability guarantee. Consumers must go through the Python or UDS wire layer, not link Rust crates directly.

### 12.5 Breaking changes (v1.0)

A future v1.0 may rename/retire fields. It will be gated by a major-version bump and a migration guide; v0.2.x clients will get a deprecation window. Until then, treat the v0.2.x surface as frozen.

## 13. Known Limitations & Boundaries

These are **explicit product boundaries**, not defects. They define what the executor is and is not.

### 13.1 Single platform — macOS only

fusion-executor is **macOS-only** (Apple Silicon, arm64). It depends on macOS-only APIs: CoreGraphics (CGEvent, framebuffer screenshot), Accessibility (`AXUIElement`), and `sandbox-exec` (seatbelt). **There is no Linux port, and none is planned** in the v0.2.x release line. Linux deployments must run the executor on a dedicated macOS host/VM and reach it over UDS, or place it behind a gateway. Intel x86_64 macOS is not validated.

### 13.2 No Docker / no containers

Sandboxing is native macOS (`sandbox-exec` profile + process-tree kill + git snapshots). This is deliberate — it eliminates container init overhead (init <5ms SLA) and preserves macOS API access for `gui_action`. The executor does not produce or consume container images.

### 13.3 GUI requires an active GUI session

`gui_action` AX-tree actions (`window_*`, `inspect_tree`, `focus_app`) degrade on a headless host with no GUI session (expected, §8). CGEvent pointer synthesis is a no-op headless (no crash). GUI-driving workloads need a logged-in user with a display (or VNC/screen-sharing). Pure command/file/streaming workloads are fully headless-supported.

### 13.4 No inline interpreter by default

`python -c` / `node -e` / `ruby -e` / `perl -e` are blocked by default (D3-1) — an agent-driven one-liner can bypass regex dangerous-word enumeration. Trusted callers opt in via `allow_inline_interpreter=True`. This is a security boundary, not a usability bug.

### 13.5 No human-approval loop for guard L3

When fusion-guard returns `L3` (requires_approval), the executor **blocks** (treats L3 as denied). The executor has no interactive human-confirmation channel; `guard_action_id` is surfaced for an out-of-band audit/confirm flow owned by the caller. A future caller-side confirm loop is out of v0.2.x scope.

### 13.6 Degraded mode is regex-stage only

When guard is down, the executor's cached rules cover only guard's **regex stage** — not tokenizer/AST/semantic verdicts. Degraded mode is deliberately stricter (fail-closed), not a faithful reproduction of guard's full verdict. This is an honest limitation of the optional guard integration.

### 13.7 In-process calls bypass metrics

`run()`/`run_async()` via the native extension directly (in-process, no `serve()`) bypass the IPC layer and are **not** counted by Prometheus counters. Only `executor.execute` over UDS + shell/rollback lifecycle are tracked. To populate metrics in a smoke test, use raw UDS `executor.execute` (not `ex.run()`).

### 13.8 Concurrency is bounded, not elastic

`MAX_CONNECTIONS=64`, `MAX_CONCURRENT_EXECS=16`, `MAX_CONCURRENT_STREAMS=64` are hard-coded. The executor is a single-host tool; horizontal scaling is the caller's responsibility (run multiple executor instances behind a gateway). The `fe_exec_sem_available` gauge exposes saturation for load-balancing decisions.

### 13.9 Rollback is git-snapshot-based

Auto-rollback restores a pre-exec git snapshot on failure + detected file damage. It is **not** a full filesystem snapshot — untracked files outside git awareness are not rolled back. The executor assumes git-tracked working trees for rollback-protected commands.

### 13.10 Seatbelt profile filesystem `Deny` is a best-effort on Darwin 25

The `SandboxProfile.filesystem="deny"` adds a global `file-write*` deny, but on Darwin 25 this is a documented **no-op** (Apple deprecates global file-write deny in this seatbelt dialect). `DenyWrite` (directed sensitive-path deny) is the effective default and is enforced. Operators should not rely on `filesystem="deny"` as a hard write-block on Darwin 25+.

## 14. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ImportError: fusion_executor._native` | native extension not built / venv not activated | `source .venv/bin/activate && maturin develop --release` |
| `exit_code: -1`, `blocked_by_security: true` | security guard rejected command (§5) | inspect `security_reason`; allow via `FUSION_EXECUTOR_EXTRA_WHITELIST` + SIGHUP |
| `exit_code: -124`, `timed_out: true` | timeout (explicit or 120s cap) | raise `timeout_sec` (bounded to 120s cap) or optimize the command |
| `exit_code: -124`, `oom_killed: true` | RSS watchdog killed the child tree | reduce output size / memory footprint; the watchdog protects the host |
| `gui_action` returns `ok: false`, `accessibility-permission-required` | TCC Accessibility not granted (§8) | System Settings → Privacy & Security → Accessibility → add host process |
| `gui_action` screenshot returns TCC error | Screen Recording TCC not granted (§8) | grant Screen Recording to the host process |
| `gui_action` degrades on SSH/launchd | no GUI session (§8, §13.3) | run on a host with an active display; headless GUI is unsupported |
| Server won't bind socket | stale socket from crash (§10.1) | `rm ~/.fusion-executor/fe.sock` |
| `guard 宕机降级` warnings, commands blocked | guard down (§9, §10.5) | `cd fusion-guard && ./start.sh status`; degraded mode is fail-closed by design |
| `auto_rolled_back: true` unexpectedly | command failed + git-status saw file damage | inspect `git stash list` for the snapshot; review the command |
| Metrics counters stay 0 | using in-process `ex.run()` (§6.2, §13.7) | use raw UDS `executor.execute` to populate counters |
| `ValidationError: extra inputs not permitted` | client sent a field the wire model doesn't know (§11.2) | upgrade the client to match the executor version |
| `cancel_stream` returns `False` | unknown/cancelled stream id (Issue #32) | best-effort; the id must be the execute_stream JSON-RPC request id |
| Build fails on `pyo3` / Python version mismatch | wrong venv Python (needs ≥3.11, venv is 3.14) | `source /Users/dahai/fusion/.venv/bin/activate` first |
| `clippy` fails on `block v0.1.6` | upstream future-incompat notice (known, not ours) | ignore — it is an upstream transitive dep notice, not our code |

### Logs

```bash
ls -la ~/.fusion-executor/logs/          # FE_LOG_DIR, daily-rolling fe.log.YYYY-MM-DD
tail -f ~/.fusion-executor/logs/fe.log.$(date +%Y-%m-%d)
grep '"trace_id":"<id>"' ~/.fusion-executor/logs/fe.log.*   # cross-layer trace
RUST_LOG=debug kill -HUP $(cat ~/.fusion-executor/fe.pid)   # bump to debug without restart (§7)
```

### Health check

```python
from fusion_executor import FusionSandboxExecutor

ex = FusionSandboxExecutor()  # or sock_path=...
# UDS health probe
import socket, json

s = socket.socket(socket.AF_UNIX)
s.connect(ex._sock_path())
s.sendall((json.dumps({"jsonrpc": "2.0", "id": 1, "method": "executor.health"}) + "\n").encode())
print(s.recv(4096).decode())
```

### Reproducible bug report

When filing an issue, include: executor version (`fusion_executor.__version__`), macOS version, the `ExecutionRequest` (redact secrets), the `ExecutionResult` (exit code + `security_reason` + `diagnostics`), the relevant `trace_id`, and the log lines under `FE_LOG_DIR` for that `trace_id`.
