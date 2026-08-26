# fe-shell — Background Task Execution API (Issue #1)

Date: 2026-08-26
Status: Approved (LOCKED via brainstorming Q&A)
Issue: #1 ([P0] background task API)

## Problem

`executor.execute` blocks to completion; `executor.execute_stream` streams to `Done`. No shell registry, no shell IDs, no `kill_shell` / `list_shells`, no deferred output poll. Blocks fusion-code BashTool integration (`run_in_background`, `KillShell`, `BashOutput`).

## Locked Decisions (from brainstorming)

1. **New `fe-shell` crate** — shell registry isolated in its own crate, not in `fe-sandbox` or `fe-core`. fe-sandbox stays the one-shot PTY executor; fe-shell owns persistent shells.
2. **Poll-only now** — `shell_output` returns a snapshot of the ring buffer. Live-tail via `BroadcastHub` (defer to follow-up issue). No server-push in this PR.

## Design

### fe-shell crate

**`ShellRegistry`** = `Arc<Mutex<HashMap<String, ShellHandle>>>` (std `Mutex`, std `HashMap`). Registry is sync — no tokio runtime owned by fe-shell (keeps it runtime-agnostic; fe-core owns `BLOCKING_RT`).

```rust
pub struct ShellRegistry {
    shells: std::sync::Mutex<HashMap<String, ShellHandle>>,
    counter: AtomicU64,            // shell_id = "sh-{N}"
}

pub struct ShellHandle {
    pid: Option<u32>,
    output: Arc<Mutex<RingBuffer>>,   // reader thread appends; shell_output snapshots
    exit: Arc<OnceLock<i32>>,         // set when child reaped
    task_id: Option<String>,
    command: String,
    cwd: Option<String>,
    started_at_ms: u128,              // SystemTime since epoch (no Date.now in workflow; this is lib code, fine)
    finished: bool,
    exit_code: Option<i32>,
}
```

**`RingBuffer`** — bounded `VecDeque<String>` chunks, cap `DEFAULT_MAX_OUTPUT` (100k chars via `truncate`-style tail keep). Reader thread pushes decoded chunks; `shell_output` drains-to-snapshot (returns new output since last poll + accumulates a running tail). Simpler: ring buffer holds a running **tail String** (last N chars) + a `new_output` since-last-poll String that `shell_output` drains. Poll model = "give me everything new since last poll, plus current tail snapshot".

Actually cleanest poll model (Claude Code `BashOutput`): `shell_output(id) -> {output: String, running: bool, exit_code: Option<i32>}` where `output` = **cumulative tail snapshot** (not incremental). Caller dedups if needed. Tail capped at `max_output_chars`. Simple, stateless per-poll.

### Methods

- `shell_start(command, cwd, env, task_id, max_output_chars, seatbelt, inherit_env, max_nproc, max_cpu_sec) -> Result<String>` — spawn via reused fe-sandbox PTY spawn helper; spawn background **std::thread** reader → appends to ring buffer tail; spawn background **std::thread** waiter → `child.wait()` → set `exit_code` + `finished`. Return `shell_id`.
- `shell_output(id) -> Result<ShellOutput{output, running, exit_code}>` — snapshot tail + finished/exit_code.
- `kill_shell(id) -> Result<bool>` — reuse `fe_sandbox::kill_tree(pid)`; mark finished; reap.
- `list_shells() -> Vec<ShellInfo{shell_id, pid, task_id, command, started_at_ms, finished, exit_code}>`.

### fe-sandbox refactor (minimal, surgical)

Extract the PTY spawn path (openpty + `seatbelt::build_command` + `cwd` + `configure_env` + `spawn_command` + reader thread start) into a pub helper:

```rust
pub struct SpawnedPty {
    pub pid: Option<u32>,
    pub reader_rx: mpsc::Receiver<ReaderMsg>,   // or expose master reader handle
    pub master_writer: PtyWriter,
    pub wait_handle: ChildHandle,                // for wait()
}
pub fn spawn_pty(cfg: &SandboxConfig) -> Result<SpawnedPty>
```

`ReaderMsg` must be pub. fe-shell uses `spawn_pty` to get the reader channel; fe-shell's own reader loop drains it into its ring buffer. This reuses ALL proven env/seatbelt/PTY/truncation logic — zero duplication.

**Risk**: refactor touches fe-sandbox hot path. Mitigation: `run_streaming` stays the production path; `spawn_pty` is an extraction that `run_streaming` can optionally reuse OR be a parallel helper. To keep blast radius small: `spawn_pty` is a NEW pub fn that duplicates ONLY the spawn setup (openpty+build_command+configure_env+spawn), NOT the reader/timeout/exit coordination (those stay in run_streaming untouched). fe-shell owns its own reader thread reading `pair.master.try_clone_reader()` directly. → **spawn_pty returns `(pid, master_reader, master_writer, child)`**; fe-shell threads the reader + wait itself.

### 4-layer wiring

1. **fe-core** — `Executor` gains `shell: ShellRegistry` field (`ShellRegistry::new()` in `Executor::new`). Wrapper methods `shell_start`/`shell_output`/`kill_shell`/`list_shells` that delegate to `self.shell` (security validate happens HERE in `shell_start` via `self.security.validate(command)` — fail-closed, blocked → `ShellStartResult{ok:false, blocked:true, security_reason}`). Re-export `fe_shell as shell` + wire models.
2. **fe-ipc** — 4 new arms: `executor.shell_start` / `executor.shell_output` / `executor.kill_shell` / `executor.list_shells`. Manual `param_str` extraction (matches existing file-tool arms). `shell_start` params: command/cwd?/env_vars?/task_id?/timeout_sec?/seatbelt?/inherit_env?/max_nproc?/max_cpu_sec?.
3. **fe-pyo3** — `NativeShellOutput`/`NativeShellInfo` pyclasses + 4 `#[pymethods]`. Simple args use `#[pyo3(signature)]`; `env_vars` dict via `py.import("json").dumps` → serde.
4. **Python** — `ShellOutput`/`ShellInfo` Pydantic (`_STRICT` extra=forbid) + `FusionSandboxExecutor.shell_start`/`shell_output`/`kill_shell`/`list_shells`.

### Wire models

```rust
pub struct ShellStartResult { pub ok: bool, pub shell_id: Option<String>, pub blocked_by_security: bool, pub security_reason: Option<String>, pub error: Option<String> }
pub struct ShellOutput { pub shell_id: String, pub output: String, pub running: bool, pub exit_code: Option<i32> }
pub struct ShellInfo { pub shell_id: String, pub pid: Option<u32>, pub task_id: Option<String>, pub command: String, pub started_at_ms: u128, pub finished: bool, pub exit_code: Option<i32> }
```

### Tests

- **fe-shell Rust unit**: shell_start echo-sleep → shell_id; shell_output while running → running=true, output has early output; kill_shell → finished, exit_code; list_shells. security-blocked (rm -rf /) → shell_start ok=false blocked. Reuse tempdir for cwd.
- **fe-ipc Rust**: UDS shell_start/shell_output/kill_shell/list_shells roundtrip.
- **Python**: native shell_start+poll+kill; UDS roundtrip; blocked command.

### NFR / constraints

- 0 new unsafe (fe-shell `unsafe_code="deny"`; reuses fe-sandbox safe wrappers + portable-pty).
- fe-shell owns no tokio runtime (std threads + std Mutex). fe-core may call from sync or async context.
- Ring buffer tail cap = `max_output_chars` (default 100k) — same OOM guard as sandbox.
- started_at_ms via `SystemTime::now().duration_since(UNIX_EPOCH)` (lib code, not workflow JS — allowed).
- Poll-only: no BroadcastHub changes in this PR.

## Files

- NEW `crates/fe-shell/Cargo.toml` + `src/lib.rs`
- MODIFY `crates/fe-sandbox/src/lib.rs` (pub `spawn_pty` + pub `ReaderMsg` if needed) — minimal extraction
- MODIFY `Cargo.toml` (workspace members += fe-shell)
- MODIFY `crates/fe-core/src/lib.rs` (shell field + 4 wrappers + re-export)
- MODIFY `crates/fe-ipc/src/lib.rs` (4 arms)
- MODIFY `crates/fe-pyo3/src/lib.rs` (pyclasses + 4 pymethods)
- MODIFY `python/fusion_executor/executor.py` (4 methods)
- MODIFY `python/fusion_executor/models.py` (ShellOutput/ShellInfo Pydantic)
- MODIFY `python/tests/test_executor.py` (tests)
