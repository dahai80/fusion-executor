// fe-core — Executor orchestrator (P1 minimal pipeline)
//
// Pipeline: validate → spawn → return
// Heavy components (tree-sitter / git handles) lazily loaded, new() <5ms (NFR)

use std::panic::AssertUnwindSafe;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::Result;
use futures::future::FutureExt;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

#[cfg(feature = "diagnostics")]
use fe_diagnostics::Slicer;
#[cfg(feature = "gui")]
use fe_gui::{GuiAction, GuiConfig, GuiController, GuiResult};
use fe_rollback::RollbackManager;
use fe_sandbox::{Sandbox, SandboxConfig};
use fe_security::{SecurityGuard, SecurityVerdict};
use fe_shell::{ShellInfo, ShellOutput, ShellRegistry, ShellStartParams, ShellStartResult};
#[cfg(feature = "telemetry")]
use fe_telemetry::{start_stream as start_telemetry, TelemetryConfig, TelemetrySample};
use fe_tools::{
    EditResult, GlobEntry, GrepMatch, GrepOptions, GrepOutput, MultiEditItem, NotebookEditMode,
    Tools,
};

#[cfg(feature = "diagnostics")]
pub use fe_diagnostics as diagnostics;
#[cfg(feature = "gui")]
pub use fe_gui as gui;
pub use fe_rollback as rollback;
pub use fe_sandbox as sandbox;
pub use fe_security as security;
pub use fe_shell as shell;
#[cfg(feature = "telemetry")]
pub use fe_telemetry as telemetry;
#[cfg(feature = "telemetry")]
pub use fe_telemetry::{
    TelemetryConfig as TelemetryStreamConfig, TelemetrySample as TelemetryFrame,
};
pub use fe_tools as tools;
pub use fe_tools::{
    EditResult as ToolsEditResult, GlobEntry as ToolsGlobEntry, GrepMatch as ToolsGrepMatch,
    GrepOptions as ToolsGrepOptions, GrepOutput as ToolsGrepOutput,
    GrepOutputMode as ToolsGrepOutputMode, MultiEditItem as ToolsMultiEditItem,
    NotebookEditMode as ToolsNotebookEditMode,
};

// BLOCKING_RT — multi-threaded N workers (CPU core count, floor 2), concurrently running
// sandbox/telemetry/IPC tasks
// Audit Blocker 5 / 1.2: the old worker_threads(1) was globally serial → execute + telemetry
// + IPC requests blocked each other
// Fix: worker_threads(N) raises parallelism. Still a single global runtime (LazyLock), no
// nested-runtime panic
// (asyncio callers live on the Python side, this runtime is independent; raising N only grows
// the thread pool, no nesting issue)
// Pattern taken from fusion-design/crates/fd-ai-adapter/src/lib.rs
//
// A-5: a LazyLock init panic is unrecoverable (poisoned OnceLock — any later Runtime access
// in this process panics). Construction failure = process permanently unusable, no retry.
// So the panic message must include the build failure reason so caller logs can locate the
// root cause; documented convention: first run() panic = process needs a restart, no Result
// to catch and no fallback (sandbox/telemetry are all async).
pub static BLOCKING_RT: LazyLock<Runtime> = LazyLock::new(|| {
    // D4-12: cap workers at 8 — a CLI/OS-tool does not need all 32 cores open (spawning 32
    // workers on a 32-core machine purely wastes thread stacks).
    // Floor 2 keeps execute/telemetry/IPC parallel; cap 8 covers high-concurrency UDS, the
    // rest is throttled by the exec_sem semaphore.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    let workers = workers.clamp(2, 8);
    info!(
        workers,
        "BLOCKING_RT initializing multi-thread runtime (D4-12 cap 8)"
    );
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            panic!(
                "BLOCKING_RT init failed: tokio runtime build failed — {e}. \
                 This panic is unrecoverable (poisoned LazyLock), the process must be restarted. worker_threads={workers}"
            )
        })
});

// IPC_RT — dedicated multi-thread runtime for IPC server fan-out (serve_blocking entry).
// Audit gap #5 (soak_stress.py deadlock): the old serve_blocking ran on the shared
// BLOCKING_RT (cap 8 workers); 64 connections = ~128 long tasks (push_task + read_loop) +
// 64 dispatch tasks all squeezed into 8 workers → dispatch starvation, response frames
// could not be written → client recv 30s timeout. Fix: a dedicated IPC_RT with workers
// widened for IPC fan-out (clamp 4-16), isolated from BLOCKING_RT (the in-process
// execute_sync path). fe-core execute_async/execute_streaming use bare tokio::spawn
// (landing on the caller runtime = IPC_RT), so the IPC task graph is cleanly isolated and
// BLOCKING_RT keeps only the run() path.
// spawn_blocking lands on the per-runtime blocking pool (512 threads), far above
// MAX_CONCURRENT_EXECS=16, never saturated.
pub static IPC_RT: LazyLock<Runtime> = LazyLock::new(|| {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let workers = workers.clamp(4, 16);
    info!(
        workers,
        "IPC_RT initializing multi-thread runtime (dedicated to IPC fan-out, 4-16 workers)"
    );
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            panic!(
                "IPC_RT init failed: tokio runtime build failed — {e}. \
                 This panic is unrecoverable (poisoned LazyLock), the process must be restarted. worker_threads={workers}"
            )
        })
});

/// Exit code convention: 0=success, -124=timeout, -1=blocked/internal error
pub const EXIT_OK: i32 = 0;
pub const EXIT_TIMEOUT: i32 = -124;
pub const EXIT_BLOCKED: i32 = -1;

/// D3-5/D3-10 (audit 0827 product): command log redaction — the command field goes straight
/// into tracing JSON logs (~/.fusion-executor/logs/fe.log); in agent-driven scenarios the
/// model may generate inline commands containing secrets
/// (curl -H "Authorization: Bearer sk-ant-xxx" / export API_KEY=... / -u user:pass).
/// Without redaction → tokens written to disk in plaintext, readable by same-UID processes,
/// an enterprise-compliance violation (PCI-DSS/HIPAA).
///
/// Log-side filtering only (does not modify ExecutionResult.command — the caller needs the
/// original command for replay/audit);
/// not token extraction (not a vault) — only masks suspected secret fragments, conservatively
/// masking more rather than leaking.
/// Red line: redaction applies only to log spans/info, never breaks validate (validate sees
/// the raw req.command).
fn redact_command(cmd: &str) -> String {
    use regex::Regex;
    use std::sync::LazyLock;
    // (?:...) non-capturing groups avoid shifting replace backreference numbering.
    // case-insensitive (?i).
    static RE_BEARER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\bBearer\s+\S+").unwrap());
    static RE_SK: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\bsk-[A-Za-z0-9_-]+").unwrap());
    // KEY=VAL form: key hits the sensitive set → mask VAL (VAL holds no whitespace; if
    // quoted, mask the whole quoted span)
    // e.g. export PASSWORD=hunter2 / API_KEY="abc def" / --password=secret
    static RE_KV: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?i)((?:password|passwd|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|credential|authorization)\s*=\s*)("[^"]*"|\S+)"#,
        )
        .unwrap()
    });
    // curl basic auth: -u user:pass / --user user:pass (pass is the whole segment after the colon)
    static RE_BASIC: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)(\B-u\b|--user)\s+(\S+):(\S+)").unwrap());
    // -H/--header "Name: val" where Name hits the sensitive set → mask the whole quoted value
    static RE_HEADER: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?i)(-H|--header)\s+"((?:authorization|x-api-key|api-key|cookie|set-cookie)[^"]*)""#,
        )
        .unwrap()
    });
    let mut out = cmd.to_string();
    out = RE_BEARER
        .replace_all(&out, "Bearer [REDACTED]")
        .into_owned();
    out = RE_SK.replace_all(&out, "sk-[REDACTED]").into_owned();
    out = RE_KV.replace_all(&out, "${1}[REDACTED]").into_owned();
    out = RE_BASIC
        .replace_all(&out, "${1} ${2}:[REDACTED]")
        .into_owned();
    out = RE_HEADER
        .replace_all(&out, r#"${1} "[REDACTED]""#)
        .into_owned();
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    pub command: String,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_sec: f64,
    #[serde(default)]
    pub env_vars: Option<std::collections::HashMap<String, String>>,
    /// D5-2: default false — snapshot creation is opt-in (each execute costs 2 git spawns on
    /// the hot path, D4-11). When auto_rollback_policy.is_some(), fe-core force-enables the
    /// snapshot internally (rollback needs a snapshot; the caller should not set both flags).
    /// Default off = bare run("echo") never triggers git, no surprise latency.
    #[serde(default = "default_false")]
    pub enable_rollback_snapshot: bool,
    #[serde(default)]
    pub auto_rollback_policy: Option<RollbackPolicy>,
    /// Blocker 1 / 1.1: macOS seatbelt runtime isolation — sandbox-exec wraps the child
    /// process (network deny + execve deny for dangerous binaries).
    /// Default true — commercially safe default (audit ARCH-1); passes through to
    /// SandboxConfig.seatbelt. Callers may explicitly pass false to disable isolation
    /// (trusted local opt-out, escape risk must be documented).
    #[serde(default = "default_true")]
    pub seatbelt: bool,
    /// Issue #9: environment isolation. Default false → child gets env_clear + a minimal
    /// baseline (PATH/TMPDIR/SHELL) + env_vars, never leaking host secrets
    /// (AWS_SECRET_ACCESS_KEY/ANTHROPIC_API_KEY etc.).
    /// true → inherit the full host env (explicit opt-in for trusted local scenarios,
    /// leak risk documented).
    #[serde(default)]
    pub inherit_env: bool,
    /// Issue #4: capture backend. true (default)=PTY (ANSI/Traceback fidelity, stdout+stderr
    /// merged); false=stdio separate pipes (FR-03 duplex stdout/stderr split, Slicer eats
    /// stderr). With PTY merging, stderr is always empty.
    #[serde(default = "default_use_pty")]
    pub use_pty: bool,
    /// Issue #3: process count cap (RLIMIT_NPROC, injected via ulimit -u). Default 1024 —
    /// blocks fork-bomb concurrent spread, enough for toolchain chained spawns. 0=unlimited
    /// (trusted opt-out). Verified effective on Darwin.
    #[serde(default = "default_nproc")]
    pub max_nproc: u32,
    /// Issue #3: CPU seconds cap (RLIMIT_CPU, injected via ulimit -t). Default 0=unlimited
    /// (relies on the timeout_sec watchdog). >0 hits SIGXCPU at the cap (CPU death-loop
    /// defense). Verified effective on Darwin.
    #[serde(default)]
    pub max_cpu_sec: u32,
    /// RUN-10 (audit 0827): file descriptor cap (RLIMIT_NOFILE, injected via ulimit -n).
    /// Default 1024 — blocks FD-exhaustion attacks (mass-opened fds killing the host).
    /// 0=unlimited (trusted opt-out). Verified effective on Darwin (errno 24 EMFILE).
    #[serde(default = "default_nofile")]
    pub max_nofile: u32,
    /// D3-4 (audit 0827 product): per-task RSS cap (MB). Darwin RLIMIT_AS/RLIMIT_DATA are
    /// ineffective on this platform, so sysinfo polls the child process tree RSS instead and
    /// kills the tree over the limit (exit_code -124, oom_killed=true).
    /// Default 2048 — blocks memory bombs from killing the host. 0=watchdog disabled
    /// (trusted opt-out).
    #[serde(default = "default_rss_limit")]
    pub rss_limit_mb: u32,
    /// M-OPS-06: cross-layer correlation id. When None, the execute entry auto-generates a
    /// uuid v4 that flows through logs/IPC/result.
    #[serde(default)]
    pub trace_id: Option<String>,
    /// Issue #34: per-command configurable seatbelt/sandbox profile (network/filesystem/
    /// excluded commands). None → existing fixed profile (default network deny + sensitive-path
    /// file-write deny), behavior identical to v0.2.7 (default off, opt-in).
    /// Some → build_profile_from generates the seatbelt policy from the profile; with
    /// fail_if_unavailable=true and sandbox-exec unavailable → fail-closed block (exit -1,
    /// no spawn). Matches fusion-code SandboxSettings.
    #[serde(default)]
    pub sandbox: Option<fe_sandbox::seatbelt::SandboxProfile>,
}

fn default_use_pty() -> bool {
    true
}

fn default_nproc() -> u32 {
    1024
}

fn default_nofile() -> u32 {
    1024
}

fn default_rss_limit() -> u32 {
    2048
}

fn default_timeout() -> f64 {
    30.0
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostics {
    pub error_type: Option<String>,
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
    pub code_snippet: Option<String>,
    pub raw_trace: Option<String>,
}

/// Auto-rollback policy (FR-04 — extension of the caller-driven locked decision: the caller
/// may optionally enable the automatic policy). The Executor stays stateless — the guard is
/// constructed within a single execute_async, never accumulating counts across requests.
/// max_consecutive_failures: consecutive-failure cap (triggers rollback at this value);
/// file_damage_check: detect file damage to trigger rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackPolicy {
    /// Issue #12.3 / A4: this field is accepted on the wire (the caller expresses policy
    /// intent) but Rust never reads it — consecutive-failure counting belongs to the caller's
    /// self-healing loop (Executor is stateless, per PRD §refactor; wiring it up would need
    /// cross-request state, violating the NFR).
    /// DEFERRED-BY-DESIGN: kept for a future stateful extension, do not treat it as effective.
    /// Python side marks deprecated=True.
    #[serde(default = "default_max_failures")]
    pub max_consecutive_failures: u32,
    #[serde(default = "default_true")]
    pub file_damage_check: bool,
}

impl Default for RollbackPolicy {
    fn default() -> Self {
        Self {
            max_consecutive_failures: 3,
            file_damage_check: true,
        }
    }
}

fn default_max_failures() -> u32 {
    3
}

impl From<fe_diagnostics::Diagnostics> for Diagnostics {
    fn from(d: fe_diagnostics::Diagnostics) -> Self {
        Self {
            error_type: d.error_type,
            file_path: d.file_path,
            line_number: d.line_number,
            code_snippet: d.code_snippet,
            raw_trace: d.raw_trace,
        }
    }
}

/// L-2: serde skip_serializing_if helper — do not serialize rollback_unavailable when false
/// (saves wire space).
fn is_false(b: &bool) -> bool {
    !b
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub duration_sec: f64,
    pub timed_out: bool,
    pub blocked_by_security: bool,
    pub security_reason: Option<String>,
    pub snapshot_id: Option<String>,
    pub diagnostics: Option<Diagnostics>,
    #[serde(default)]
    pub auto_rolled_back: bool,
    /// L-2: rollback-safety-lost marker — set true when guard construction/snapshot/detection
    /// errors occur, visible to the caller (fail-loud, never silent).
    /// Complementary to auto_rolled_back: the latter means "rolled back", this field means
    /// "should have rolled back but the safety net was unavailable".
    #[serde(default, skip_serializing_if = "is_false")]
    pub rollback_unavailable: bool,
    /// L-1 (audit 0827): rollback skip reason — filled when rollback() was attempted but
    /// skipped (stale snapshot/parse failure/non-git repo/repo identity mismatch), so the
    /// caller can fail-loud distinguish "not rolled back (not needed)" from "not rolled back
    /// (stale snapshot)".
    /// Complementary to auto_rolled_back/rollback_unavailable, three independent axes:
    ///   auto_rolled_back=true        rolled back
    ///   rollback_unavailable=true    rollback safety net unavailable (guard error)
    ///   rollback_skipped_reason=Some rollback attempted but skipped (rollback's internal judgment)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_skipped_reason: Option<String>,
    /// M-OPS-06: cross-layer correlation id — echoes the request-side trace_id (auto-generated
    /// at entry when None).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// D3-4 (audit 0827 product): RSS watchdog trigger marker — child process tree RSS exceeded
    /// rss_limit_mb and was killed. Default false omitted (skip_serializing_if is_false);
    /// exit_code accompanies -124 (kill convention).
    #[serde(default, skip_serializing_if = "is_false")]
    pub oom_killed: bool,
    /// RUN-11: sandbox child PID — backfilled from SandboxResult.pid; the caller passes it to
    /// telemetry_stream to sample the real task process (not the executor itself). The stdio
    /// path has a pid; blocked/timeout paths have none → None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Issue #23 (guard Phase 3): verdict action_id when guard blocks — the caller uses it to
    /// send a confirm approval round to guard
    /// (the executor itself never sends confirm, pass-through only). Filled only when guard is
    /// engaged and rules block/preview; guard OFF or allow → None.
    /// Additive wire field (skip_serializing_if None), 4-layer auto-flow (fe-pyo3 From +
    /// Pydantic + fe-ipc done serde-flatten).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_action_id: Option<String>,
    /// Issue #32: server-side cancel triggers a deterministic process-tree kill. true → the
    /// caller sent executor.cancel, fe-sandbox received the oneshot and ran kill_process_group
    /// (SIGINT→grace→SIGKILL + ppid tree), exit_code=-1.
    /// false → normal completion/timeout/OOM/consumer disconnect/security block. Additive wire
    /// (skip_serializing_if is_false).
    #[serde(default, skip_serializing_if = "is_false")]
    pub cancelled: bool,
}

impl ExecutionResult {
    pub fn blocked(reason: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_BLOCKED,
            blocked_by_security: true,
            security_reason: Some(reason.into()),
            ..Default::default()
        }
    }

    /// Blocked result with task_id/command/trace_id (PRD §4.1 — result echoes request-side
    /// identifiers; M-OPS-06 trace_id)
    pub fn blocked_with(
        reason: impl Into<String>,
        task_id: Option<String>,
        command: Option<String>,
        trace_id: Option<String>,
    ) -> Self {
        Self {
            exit_code: EXIT_BLOCKED,
            blocked_by_security: true,
            security_reason: Some(reason.into()),
            task_id,
            command,
            trace_id,
            ..Default::default()
        }
    }

    /// Issue #23 (guard Phase 3): blocked result when guard rules block — carries the guard
    /// action_id for the caller's confirm round.
    /// Signature matches blocked_with plus action_id (fix #5: no blocked_with call-site
    /// changes, separate constructor).
    pub fn blocked_by_guard(
        reason: impl Into<String>,
        action_id: Option<String>,
        task_id: Option<String>,
        command: Option<String>,
        trace_id: Option<String>,
    ) -> Self {
        Self {
            exit_code: EXIT_BLOCKED,
            blocked_by_security: true,
            security_reason: Some(reason.into()),
            task_id,
            command,
            trace_id,
            guard_action_id: action_id,
            ..Default::default()
        }
    }
}

/// ARCH-4: observability for the in-process execution path (fe-pyo3 execute_sync calls fe-core
/// directly, bypassing fe-ipc). Mirrors the metrics::counter branch of fe-ipc
/// BroadcastHub::record_exec, recording only the Prometheus global counters
/// (AtomicU64 snapshots belong to the fe-ipc hub, untouched here — the in-process path has no
/// hub, only the Prometheus side is filled in).
/// fe-ipc record_exec keeps its own AtomicU64 + calls this helper (deduplicated, avoiding double
/// counting); fe-pyo3 execute_sync calls this helper.
pub fn record_exec_outcome(r: &ExecutionResult) {
    metrics::counter!("fe_exec_total").increment(1);
    if r.blocked_by_security {
        metrics::counter!("fe_exec_blocked").increment(1);
    } else if r.timed_out || r.exit_code == -124 {
        metrics::counter!("fe_exec_timeout").increment(1);
    } else if r.exit_code == 0 {
        metrics::counter!("fe_exec_success").increment(1);
    } else {
        metrics::counter!("fe_exec_failed").increment(1);
    }
}

/// Stream events — Chunk (real-time stdio chunks) / Done (final ExecutionResult, with
/// diagnostics). Mirrors fe-sandbox::StreamEvent, but Done carries the full ExecutionResult
/// (post diagnostics slicing + snapshot id)
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecutionStreamEvent {
    Chunk { data: String },
    Done(Box<ExecutionResult>),
}

/// Auto-rollback guard (FR-04) — detects file damage within a single execution, triggers
/// rollback at the threshold. Lifecycle is bounded to a single execute_async: nothing
/// accumulates across requests (Executor's stateless locked decision).
/// The real consecutive-failure count belongs to the caller (fusion-code's self-healing loop
/// owns the retry count, per PRD §refactor).
/// C-2: decides whether a porcelain status code is a tracked-file mutation (counted as damage).
/// Each `git status --porcelain` line = 2-char XY status code + space + path.
/// - X = staged status, Y = worktree status.
/// - `??` = untracked (intentionally created by the command, not damage) → false.
/// - `A`/` ` + `A` = additions only (staged/worktree adds, no old tracked baseline) → not
///   damage → false.
/// - `M`/`D`/`R`/`C`/`T` in either X or Y = tracked file modified/deleted/renamed/copied/
///   type-changed → damage → true.
///
/// Lines shorter than 2 chars (anomaly) → conservatively false (not damage, avoids false
/// rollbacks).
fn is_tracked_mutation(entry: &str) -> bool {
    let bytes = entry.as_bytes();
    if bytes.len() < 2 {
        return false;
    }
    let x = bytes[0] as char;
    let y = bytes[1] as char;
    const MUTATION_CODES: &[char] = &['M', 'D', 'R', 'C', 'T'];
    // `??` means the whole entry is untracked → never a tracked-file mutation.
    if x == '?' && y == '?' {
        return false;
    }
    // Count when X or Y is a mutation code (covers ` M` worktree modify, `M ` staged modify,
    // `MM` both, `R ` rename, etc.).
    MUTATION_CODES.contains(&x) || MUTATION_CODES.contains(&y)
}

/// max_consecutive_failures is a reserved field for a future stateful extension (A4: currently
/// a dead field, documented rather than deleted).
///
/// C-CORE-01: the old version treated any non-empty `git status --porcelain` as damage —
/// untracked `__pycache__`/WIP/concurrent edits all counted → falsely triggered rollback,
/// losing unrelated changes. Fix: capture `pre_status` (porcelain snapshot) before the command,
/// capture `post_status` after, and only diff out entries **added by the command** before
/// judging damage. Untracked files already in pre don't count (dirty before the command).
/// This way WIP/`__pycache__` and other pre-existing dirty state no longer falsely trigger.
///
/// C-2: C-CORE-01 only excludes pre-existing dirt, but still miscounts entries **intentionally
/// created** by the command (untracked/staged adds) as damage. `detect_damage` further uses
/// `is_tracked_mutation` to count only tracked-file mutations (`M`/`D`/`R`/`C`/`T`), excluding
/// `??`/`A` (untracked/staged adds) — a failed `mkdir -p build && pytest` no longer falsely
/// rolls back legitimate artifacts.
pub struct AutoRollbackGuard {
    policy: RollbackPolicy,
    snapshot_id: String,
    cwd: String,
    rollback: RollbackManager,
    pre_status: std::collections::HashSet<String>,
    // D5-1: whether record_result has been called. If not called by Drop time → a mid-execution
    // panic/abort dropped the guard early; warn! explicitly surfaces the snapshot_id so the
    // caller can recover manually (Drop cannot .await; a real rollback must be caller-initiated).
    // AtomicBool (not Cell<bool>) — the guard is moved across tokio::spawn and must be Send;
    // Cell does not impl Sync.
    recorded: std::sync::atomic::AtomicBool,
}

impl Drop for AutoRollbackGuard {
    fn drop(&mut self) {
        // D5-1: guard dropped without a normal record_result = mid-execution panic/abort/early
        // return. Cannot .await a rollback inside Drop (async-in-Drop is unsound); only a loud
        // warn + exposing the snapshot_id, so the caller can manually rollback(snapshot_id, cwd)
        // after seeing the log (Rule 12 fail-visible, honest path).
        if !self.recorded.load(std::sync::atomic::Ordering::Acquire) {
            warn!(
                snapshot = %self.snapshot_id,
                cwd = %self.cwd,
                "AutoRollbackGuard dropped without record_result — mid-execution panic/early drop; \
                 caller must manually rollback(snapshot_id) to recover (Drop cannot rollback async)"
            );
        }
    }
}

impl AutoRollbackGuard {
    /// Construct — holds the snapshot id created before this execution + cwd + the pre-command
    /// git status snapshot. `pre_status` is captured by `capture_status` before the command;
    /// on capture failure it is an empty set (fail-loud at detect time).
    pub fn new(
        policy: RollbackPolicy,
        snapshot_id: String,
        cwd: String,
        pre_status: std::collections::HashSet<String>,
    ) -> Self {
        Self {
            policy,
            snapshot_id,
            cwd,
            rollback: RollbackManager::new(),
            pre_status,
            recorded: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Collect the git status --porcelain line set (drop blank lines). Captured once before and
    /// once after the command, diffed to find command-added changes.
    /// L-CORE-02: git failure is fail-loud (returns Err), no longer `.unwrap_or(0)` silently
    /// skipping rollback.
    /// D5-4: git status wrapped in tokio::time::timeout(10s) — an NFS/hung git cannot block
    /// execution indefinitely; timeout returns Err (status unknown), detect_damage/caller
    /// handle fail-loud (rollback may be imprecise, but never hangs).
    async fn capture_status(cwd: &str) -> Result<std::collections::HashSet<String>> {
        let fut = tokio::process::Command::new("git")
            .arg("-C")
            .arg(cwd)
            .args(["status", "--porcelain"])
            .output();
        let out = match tokio::time::timeout(std::time::Duration::from_secs(10), fut).await {
            Ok(o) => o.map_err(|e| anyhow::anyhow!("git status failed to start: {e}"))?,
            Err(_) => {
                anyhow::bail!("git status timed out (>10s) — cwd={cwd}, status unknown (D5-4)")
            }
        };
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            anyhow::bail!("git status failed (exit {}): {}", out.status, stderr);
        }
        let s = String::from_utf8_lossy(&out.stdout);
        Ok(s.lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// Detect file damage caused by the command — diff the post-command state against the
    /// pre-command snapshot, counting only entries **added by the command** that are
    /// **tracked-file mutations**. Returns the count.
    ///
    /// C-2: C-CORE-01 only excludes pre-existing dirty files, without distinguishing entries
    /// **intentionally created** by the command (untracked/staged adds) from **corruption**.
    /// A failed `mkdir -p build && pytest` → `build/`/`__pycache__`/`.pytest_cache` present in
    /// post but not pre → misjudged as damage → rollback loses legitimate artifacts. Fix: count
    /// only porcelain XY codes representing tracked-file deletion/modification (`M`/`D`/`R`/`C`/`T`
    /// in either position); `??` (untracked add) and `A` (staged add only, no old tracked
    /// baseline) don't count. git failure is fail-loud (L-CORE-02).
    async fn detect_damage(&self) -> Result<usize> {
        let post = Self::capture_status(&self.cwd).await?;
        let new_entries: Vec<&String> = post
            .iter()
            .filter(|entry| !self.pre_status.contains(*entry))
            .filter(|entry| is_tracked_mutation(entry))
            .collect();
        if !new_entries.is_empty() {
            info!(new = ?new_entries, "command added tracked-file mutation entries (command-caused, counted as damage)");
        } else {
            let skipped: Vec<&String> = post
                .iter()
                .filter(|entry| !self.pre_status.contains(*entry))
                .filter(|entry| !is_tracked_mutation(entry))
                .collect();
            if !skipped.is_empty() {
                info!(
                    skipped = ?skipped,
                    "command-added entries are untracked/staged adds (??/A), not counted as damage — legitimate artifact creation"
                );
            }
        }
        Ok(new_entries.len())
    }

    /// Record the result — exit_code==0 does nothing; !=0 with detected command-caused damage →
    /// rollback and set auto_rolled_back. Modifies result.auto_rolled_back in place. Non-git
    /// repo → detect fails (fail-loud), logged by the caller.
    /// L-CORE-02: detect_damage failure is no longer silent (the old .unwrap_or(0) skipped
    /// rollback); now it propagates Err, already warn!-logged by the callers
    /// (execute_async/execute_streaming).
    pub async fn record_result(&self, result: &mut ExecutionResult) -> Result<()> {
        // D5-1: entering record_result means the guard has been normally consumed (even an early
        // return is a legitimate "no rollback needed"). Drop uses this to distinguish "consumed"
        // vs "mid-execution panic/early drop, unconsumed". Set at entry, covering all return paths.
        self.recorded
            .store(true, std::sync::atomic::Ordering::Release);
        if result.exit_code == 0 {
            return Ok(());
        }
        if !self.policy.file_damage_check {
            return Ok(());
        }
        let damaged = self.detect_damage().await?;
        if damaged == 0 {
            info!(
                exit_code = result.exit_code,
                "failed but no command-added changes, not rolling back"
            );
            return Ok(());
        }
        info!(
            damaged,
            exit_code = result.exit_code,
            "command-caused file changes detected, triggering auto-rollback"
        );
        // L-1 (audit 0827): rollback() now returns RollbackOutcome{applied, skipped_reason, wip_sha}.
        // applied=true → auto_rolled_back=true (rolled back); applied=false + skipped_reason=Some →
        // fill rollback_skipped_reason so the caller can fail-loud distinguish "not rolled back
        // (not needed)" from "not rolled back (stale snapshot)".
        let outcome = self.rollback.rollback(&self.snapshot_id, &self.cwd).await?;
        if outcome.applied {
            result.auto_rolled_back = true;
            if let Some(wip) = &outcome.wip_sha {
                info!(snapshot = %self.snapshot_id, wip = %wip, "auto-rollback succeeded — tracked WIP captured (C-7)");
            } else {
                info!(snapshot = %self.snapshot_id, "auto-rollback succeeded");
            }
        } else if let Some(reason) = &outcome.skipped_reason {
            // L-1: a skip has a reason — surface it to the caller (fail-loud), never silent false.
            result.rollback_skipped_reason = Some(reason.clone());
            warn!(
                snapshot = %self.snapshot_id,
                reason = %reason,
                "auto-rollback skipped (rollback's judgment) — rollback_skipped_reason set (L-1)"
            );
        } else {
            // applied=false with no reason — theoretically unreachable (skipped always carries a
            // reason), defensive warn.
            warn!(snapshot = %self.snapshot_id, "auto-rollback did not take effect (rollback returned applied=false without a reason)");
        }
        Ok(())
    }
}

/// Executor — orchestrator for validation + sandboxed execution
pub struct Executor {
    security: SecurityGuard,
    sandbox: Sandbox,
    #[cfg(feature = "diagnostics")]
    slicer: Slicer,
    rollback: RollbackManager,
    #[cfg(feature = "gui")]
    gui: GuiController,
    tools: Tools,
    // M-ARCH-1: ShellRegistry no longer belongs to the Executor — moved to IpcServer/PyExecutor
    // (alongside BroadcastHub). The Executor stays per-task stateless: restarting the Executor at
    // the IPC layer does not lose background shell handles; the serve-path and in-process path
    // share the same registry. Security validation stays at this layer (self.security), the
    // registry is passed in by the caller.
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

impl Executor {
    pub fn new() -> Self {
        info!("Executor::new() — initializing SecurityGuard + Sandbox + Slicer + Rollback + Gui + Tools");
        // ARCH-2: the SecurityGuard baseline TRUSTED_BIN_DIRS only holds system dirs (/usr/bin
        // etc.). A local venv interpreter (/Users/.../.venv/bin/python3) is not among them →
        // after the basename hit, the resolved-path check fail-closed rejects it and normal
        // python3 commands get blocked. Here we auto-register the venv bin (VIRTUAL_ENV env) +
        // the current executable's parent dir (where the PyO3 extension lives), so local
        // interpreter paths land in the trusted set.
        let mut trusted: Vec<String> = Vec::new();
        if let Ok(venv) = std::env::var("VIRTUAL_ENV") {
            let venv_bin = std::path::Path::new(&venv).join("bin");
            if let Some(s) = venv_bin.to_str() {
                trusted.push(s.to_string());
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                if let Some(s) = parent.to_str() {
                    trusted.push(s.to_string());
                }
            }
        }
        // ARCH-2: rustup's standard install location ($HOME/.cargo/bin) — cargo/rustc live here.
        // Not attacker-controllable (home directory; writing via rustup already requires machine
        // execution rights), does not violate the ARCH-2 /tmp poisoning + PATH-prefix threat
        // model. Registering it lets rustup-only machines (CI macos-14 runner) pass
        // `cargo build/test` — on homebrew machines cargo is already baseline-trusted in
        // /opt/homebrew/bin, unaffected. Trusted at the same level as VIRTUAL_ENV/bin.
        if let Ok(home) = std::env::var("HOME") {
            let cargo_bin = std::path::Path::new(&home).join(".cargo").join("bin");
            if let Some(s) = cargo_bin.to_str() {
                trusted.push(s.to_string());
            }
        }
        let trusted_refs: Vec<&str> = trusted.iter().map(String::as_str).collect();
        let security = if trusted_refs.is_empty() {
            SecurityGuard::new()
        } else {
            info!(dirs = ?trusted_refs, "Executor registered venv/exe trusted binary dirs (ARCH-2)");
            SecurityGuard::new().with_trusted_bin_dirs(&trusted_refs)
        };
        Self {
            security,
            sandbox: Sandbox::new(),
            #[cfg(feature = "diagnostics")]
            slicer: Slicer::new(),
            rollback: RollbackManager::new(),
            #[cfg(feature = "gui")]
            gui: GuiController::new(),
            tools: Tools::new(),
        }
    }

    /// Extend the allowlist — Issue #10: project-level binary pass-through (with the dangerous
    /// interpreter rejection guard)
    pub fn with_extra_whitelist(mut self, extras: &[&str]) -> Self {
        info!(
            count = extras.len(),
            "Executor extended allowlist (project-level pass-through)"
        );
        self.security = self.security.with_extra_whitelist(extras);
        self
    }

    /// ARCH-2 trusted binary dirs pass-through — register project bin dirs (venv/exe dirs are
    /// auto-registered by new(); this builder registers additional project tool dirs, mostly for
    /// tests and multi-bin-path deployments). Passes through to SecurityGuard.
    pub fn with_trusted_bin_dirs(mut self, dirs: &[&str]) -> Self {
        info!(
            count = dirs.len(),
            "Executor registered additional trusted binary dirs (ARCH-2)"
        );
        self.security = self.security.with_trusted_bin_dirs(dirs);
        self
    }

    /// D3-1 (audit 0827 product): inline interpreter gateway pass-through. true=allow python -c /
    /// node -e / ruby -e / perl -e (preserving trusted-caller inline execution); default false
    /// (enterprise hardening rejects inline code, preventing agent-driven arbitrary payloads from
    /// bypassing allowlist semantics). Passes through to
    /// SecurityGuard.with_allow_inline_interpreter.
    pub fn with_allow_inline_interpreter(mut self, allow: bool) -> Self {
        self.security = self.security.with_allow_inline_interpreter(allow);
        self
    }

    /// Issue #23 (fusion-guard Phase 3): enable guard authorization orchestration. Passes through
    /// to SecurityGuard.with_guard (builds GuardClient + RulesCache, liveness probe + seed
    /// cache). Guard is OFF by default (back-compat); the caller must explicitly pass
    /// guard_sock/guard_tenant (or env FUSION_GUARD_SOCK/FUSION_EXECUTOR_TENANT) to enable it.
    /// Once on, validate() goes through guard orchestration: after local validation passes, call
    /// guard.evaluate, map GuardVerdict, degrade fail-closed when guard is down (cached regex +
    /// allowlist fence, never fail-open).
    pub fn with_guard(mut self, sock: &str, tenant: &str) -> Self {
        info!(
            sock,
            tenant, "Executor enabled guard authorization orchestration (Issue #23 Phase 3)"
        );
        self.security = self.security.with_guard(sock, tenant);
        self
    }

    /// m-OPS-02: SIGHUP runtime allowlist hot-reload — rebuilt from baseline + extras (not
    /// additive). &self (Executor's stateless convention, only forwards to
    /// SecurityGuard.reload_extras' ArcSwap store).
    /// The fe-ipc SIGHUP handler reads the FUSION_EXECUTOR_EXTRA_WHITELIST env → splits on
    /// commas → calls this.
    pub fn reload_whitelist(&self, extras: &[&str]) {
        info!(
            count = extras.len(),
            "SIGHUP allowlist hot-reload (baseline rebuild)"
        );
        self.security.reload_extras(extras);
    }

    /// M-SEC-04: GUI security config (bundle allowlist + secure text-field type_text guard).
    /// Default Executor::new() with no config = unrestricted (trusted local caller, audit log
    /// only); enterprise/multi-user scenarios use this constructor to set allowlist +
    /// allow_type_into_secure opt-in.
    #[cfg(feature = "gui")]
    pub fn with_gui_config(mut self, config: GuiConfig) -> Self {
        info!("Executor set GUI security config (M-SEC-04)");
        self.gui = GuiController::new_with_config(config);
        self
    }

    /// GUI action (P4 FR-05) — sync entry point, called by fe-pyo3/fe-ipc
    #[cfg(feature = "gui")]
    pub fn gui_action(&self, action: GuiAction) -> Result<GuiResult> {
        self.gui.execute(action)
    }

    /// #39: batch GUI action pipeline — executes multiple actions in order, collecting each
    /// step's result.
    #[cfg(feature = "gui")]
    pub fn gui_action_batch(&self, actions: Vec<GuiAction>) -> Result<Vec<GuiResult>> {
        self.gui.gui_action_batch(actions)
    }

    /// Native file tool — file_edit (PRD FileEdit localization, #6 replace_all)
    pub fn file_edit(
        &self,
        path: &str,
        old_string: &str,
        new_string: &str,
        cwd: Option<&str>,
        replace_all: bool,
    ) -> Result<EditResult> {
        self.tools
            .file_edit(path, old_string, new_string, cwd, replace_all)
    }

    /// Native file tool — write_file whole-file create/overwrite + parent dir creation (#2,
    /// Claude Code Write parity)
    pub fn write_file(&self, path: &str, content: &str, cwd: Option<&str>) -> Result<EditResult> {
        self.tools.write_file(path, content, cwd)
    }

    /// Background shell — start a persistent shell (#1, Claude Code run_in_background parity)
    /// Security validation at this layer (fail-closed): blocked →
    /// ShellStartResult{ok:false, blocked_by_security:true}
    /// M-ARCH-1: the registry is passed in by the caller (Executor stateless; the registry
    /// belongs to IpcServer/PyExecutor).
    pub fn shell_start(&self, registry: &ShellRegistry, p: ShellStartParams) -> ShellStartResult {
        let v = self.security.validate(&p.command);
        if !v.allowed {
            warn!(command = %p.command, reason = ?v.reason, "shell_start blocked by security guard");
            return ShellStartResult {
                ok: false,
                shell_id: None,
                blocked_by_security: true,
                security_reason: v.reason,
                error: None,
            };
        }
        registry.shell_start(p)
    }

    /// Background shell — poll tail snapshot + run/exit status (#1)
    /// M-ARCH-1: the registry is passed in by the caller.
    pub fn shell_output(registry: &ShellRegistry, shell_id: &str) -> Result<ShellOutput> {
        registry.shell_output(shell_id)
    }

    /// Background shell — kill the process tree (#1, Claude Code KillShell parity)
    /// M-ARCH-1: the registry is passed in by the caller.
    pub fn kill_shell(registry: &ShellRegistry, shell_id: &str) -> Result<bool> {
        registry.kill_shell(shell_id)
    }

    /// Background shell — list all shells (#1)
    /// M-ARCH-1: the registry is passed in by the caller.
    pub fn list_shells(registry: &ShellRegistry) -> Vec<ShellInfo> {
        registry.list_shells()
    }

    /// Native file tool — multi_edit atomic batch edit of one file (#6)
    pub fn multi_edit(
        &self,
        path: &str,
        edits: &[MultiEditItem],
        cwd: Option<&str>,
    ) -> Result<EditResult> {
        self.tools.multi_edit(path, edits, cwd)
    }

    /// Native file tool — notebook_edit Jupyter .ipynb cell editing (#6)
    pub fn notebook_edit(
        &self,
        path: &str,
        cell_id: Option<&str>,
        cell_number: Option<i64>,
        new_source: &str,
        edit_mode: NotebookEditMode,
        cwd: Option<&str>,
    ) -> Result<EditResult> {
        self.tools
            .notebook_edit(path, cell_id, cell_number, new_source, edit_mode, cwd)
    }

    /// Native file tool — glob (PRD GlobTool localization)
    pub fn glob(&self, pattern: &str, cwd: Option<&str>) -> Result<Vec<GlobEntry>> {
        self.tools.glob(pattern, cwd)
    }

    /// Native file tool — grep (PRD GrepTool localization)
    pub fn grep(
        &self,
        pattern: &str,
        paths: &[String],
        cwd: Option<&str>,
    ) -> Result<Vec<GrepMatch>> {
        self.tools.grep(pattern, paths, cwd)
    }

    /// #7 ripgrep parity — grep with options: output mode / context / multiline / glob filter
    pub fn grep_with_opts(
        &self,
        pattern: &str,
        paths: &[String],
        cwd: Option<&str>,
        opts: &GrepOptions,
    ) -> Result<GrepOutput> {
        self.tools.grep_with_opts(pattern, paths, cwd, opts)
    }

    /// Surgical patch engine — apply_patch (PRD §DeepSeek Unified Diff application)
    pub fn apply_patch(&self, diff: &str, cwd: Option<&str>) -> Result<EditResult> {
        self.tools.apply_patch(diff, cwd)
    }

    /// Surgical patch engine — replace_function (PRD §DeepSeek function-level replacement,
    /// whole-file rewrite forbidden)
    pub fn replace_function(
        &self,
        path: &str,
        fn_name: &str,
        new_body: &str,
        cwd: Option<&str>,
    ) -> Result<EditResult> {
        self.tools.replace_function(path, fn_name, new_body, cwd)
    }

    /// Snapshot — exposed for direct fe-pyo3 calls
    pub async fn snapshot_create_async(&self, cwd: &str) -> Result<String> {
        self.rollback.snapshot_create(cwd).await
    }

    /// D6-03 (audit 0827 product): snapshot inventory — exposed for direct fe-pyo3/fe-ipc calls.
    /// Stateless (M-ARCH-1): reads only the on-disk index for the cwd; the Executor holds no
    /// snapshot state.
    pub async fn list_snapshots_async(&self, cwd: &str) -> Result<Vec<fe_rollback::SnapshotInfo>> {
        fe_rollback::RollbackManager::list_snapshots(cwd)
    }

    /// Rollback — exposed for direct fe-pyo3 calls.
    /// L-1 (audit 0827): rollback() internally returns RollbackOutcome; this wrapper maps
    /// .applied → bool to keep the IPC/PyO3/Python-side bool contract unchanged
    /// (skipped_reason detail flows through ExecutionResult across 4 layers).
    pub async fn rollback_async(&self, snapshot_id: &str, cwd: &str) -> Result<bool> {
        self.rollback
            .rollback(snapshot_id, cwd)
            .await
            .map(|o| o.applied)
    }

    /// Validate a command — exposed for direct fe-ipc/fe-pyo3 calls
    pub fn validate(&self, command: &str) -> SecurityVerdict {
        self.security.validate(command)
    }

    /// Async execute — validate → sandbox run → return
    pub async fn execute_async(&self, req: ExecutionRequest) -> Result<ExecutionResult> {
        // M-OPS-06/m-OPS-03: resolve trace_id at entry (None auto uuid v4), the span wraps the
        // whole request chain — logs carry span context
        let trace_id = req
            .trace_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let span = tracing::span!(
            tracing::Level::INFO,
            "execute",
            trace_id = %trace_id,
            command = %redact_command(&req.command)
        );
        let _enter = span.enter();
        info!(command = %redact_command(&req.command), "execute_async — validating");
        let start = Instant::now();
        let verdict = self.security.validate(&req.command);
        if !verdict.allowed {
            let reason = verdict
                .reason
                .unwrap_or_else(|| "unknown reason".to_string());
            info!(%reason, "blocked by security validation");
            // Issue #23: guard blocks carry action_id passed through (caller confirm round);
            // non-guard blocks have action_id=None, same as blocked_with.
            return Ok(ExecutionResult::blocked_by_guard(
                reason,
                verdict.action_id.clone(),
                req.task_id.clone(),
                Some(req.command.clone()),
                Some(trace_id),
            ));
        }
        // Issue #23 acceptance #3 (seatbelt gating E7): guard flags high risk requiring seatbelt
        // but the caller has not enabled it → refuse to execute
        // (prevents degrading to non-sandboxed execution of high-risk commands). With guard OFF,
        // seatbelt_required=false, never triggered.
        if verdict.seatbelt_required && !req.seatbelt {
            let reason = "guard requires seatbelt isolation but the caller has not enabled it (E7 seatbelt gating)";
            warn!(%reason, action_id = ?verdict.action_id, "blocked by seatbelt gating");
            return Ok(ExecutionResult::blocked_by_guard(
                reason,
                verdict.action_id.clone(),
                req.task_id.clone(),
                Some(req.command.clone()),
                Some(trace_id),
            ));
        }
        // Issue #34: per-command sandbox profile fail-closed — the caller requested a custom
        // profile with fail_if_unavailable=true, but sandbox-exec is not on PATH → refuse to
        // execute (prevents silently degrading to no seatbelt). Not triggered when
        // req.seatbelt=false (the caller explicitly opted out of the sandbox; the profile field
        // is meaningless for a bare command, consumed only on the seatbelt path).
        if let Some(sp) = &req.sandbox {
            if sp.fail_if_unavailable && !fe_sandbox::seatbelt::seatbelt_available() {
                let reason =
                    "sandbox profile requested but sandbox-exec unavailable (fail_if_unavailable fail-closed)";
                warn!(%reason, command = %redact_command(&req.command), "blocked by sandbox profile gating");
                return Ok(ExecutionResult::blocked_with(
                    reason.to_string(),
                    req.task_id.clone(),
                    Some(req.command.clone()),
                    Some(trace_id),
                ));
            }
        }
        // cwd validation
        if let Some(cwd) = &req.cwd {
            let cwd_v = self.security.validate_cwd(cwd);
            if !cwd_v.allowed {
                let reason = cwd_v.reason.unwrap_or_else(|| "invalid cwd".to_string());
                info!(%reason, "blocked by cwd validation");
                return Ok(ExecutionResult::blocked_with(
                    reason,
                    req.task_id.clone(),
                    Some(req.command.clone()),
                    Some(trace_id),
                ));
            }
        }

        // Issue #23 acceptance #4 (H4 TOCTOU recheck): after validate resolves the binary path,
        // recheck before spawn — reject symlinks newly appearing in the pre-exec window
        // (not a symlink at validate time, a symlink at recheck time → reject); a vanished path
        // is also rejected. Safe Rust (symlink_metadata, no libc/unsafe). homebrew Cellar
        // symlinks are by-design not rejected (they are symlinks at validate time, not
        // newly-appeared in the pre-exec window). Only the allowlisted binary's first token can
        // be resolved → non-allowlisted ones were already blocked above.
        let first_token = req.command.split_whitespace().next().unwrap_or("");
        if !first_token.is_empty() {
            if let Err(reason) = self.security.recheck_binary(first_token) {
                warn!(%reason, first_token, "blocked by TOCTOU recheck — binary path changed before execution");
                return Ok(ExecutionResult::blocked_with(
                    reason,
                    req.task_id.clone(),
                    Some(req.command.clone()),
                    Some(trace_id),
                ));
            }
        }

        // Snapshot + pre-command git status snapshot.
        // D5-2: default opt-in — want_snapshot = explicit enable_rollback_snapshot ||
        //   auto_rollback_policy.is_some() (rollback needs a snapshot; passing a policy implies
        //   wanting a snapshot, the caller should not set both flags). Bare run("echo") does not
        //   run git by default.
        // D5-2 fail-loud: snapshot_create failure is no longer a "non-fatal" info! swallowed and
        //   continued — now warn! explicitly surfaced; and if the caller passed
        //   auto_rollback_policy but the snapshot cannot be created → rollback safety net lost,
        //   marked rollback_unavailable.
        // C-CORE-01: pre_status is the pre-command worktree state, used by the guard to diff the
        //   post-command state and find command-added changes (the old version judged any
        //   non-empty status as damage, falsely triggering on __pycache__/WIP). pre_status is
        //   captured at the same time as the snapshot (pre-command).
        let want_snapshot = req.enable_rollback_snapshot || req.auto_rollback_policy.is_some();
        let mut snapshot_create_err: Option<anyhow::Error> = None;
        let (snapshot_id, pre_status) = if want_snapshot {
            if let Some(cwd) = &req.cwd {
                let snap = self.rollback.snapshot_create(cwd).await;
                let pre = AutoRollbackGuard::capture_status(cwd).await;
                match (snap, pre) {
                    (Ok(id), Ok(st)) => {
                        if id.is_empty() {
                            // D5-6: want_snapshot=true but empty snapshot id (non-git repo cwd) —
                            // rollback has no anchor; if the caller passed a policy the safety net
                            // is lost, warn! surfaced explicitly (not a silent empty id).
                            if req.auto_rollback_policy.is_some() {
                                warn!(cwd, "empty snapshot id (non-git repo) but caller passed auto_rollback — rollback has no anchor, safety net lost");
                            } else {
                                info!(
                                    cwd,
                                    "empty snapshot id (non-git repo) — no rollback anchor, pre_status capture only"
                                );
                            }
                        } else {
                            info!(%id, "snapshot created");
                        }
                        (Some(id), st)
                    }
                    (Ok(id), Err(e)) => {
                        // Pre-command status capture failed — non-git repo or git anomaly (D5-4
                        // may time out). pre_status empty set; at detect time, a non-empty post
                        // counts entirely as command-added (conservative: attribute all to the
                        // command).
                        warn!(error = %e, cwd, "pre-command git status capture failed, pre_status set to empty");
                        if !id.is_empty() {
                            info!(%id, "snapshot created");
                        }
                        (Some(id), std::collections::HashSet::new())
                    }
                    (Err(e), _) => {
                        // D5-2 fail-loud: snapshot cannot be created → warn! (upgraded info!→warn!).
                        // When the caller passed a policy, mark rollback_unavailable (set after the
                        // result is constructed; the err is recorded here to carry over).
                        warn!(error = %e, cwd, "snapshot creation failed — rollback safety net unavailable (D5-2 fail-loud)");
                        snapshot_create_err = Some(e);
                        (None, std::collections::HashSet::new())
                    }
                }
            } else {
                (None, std::collections::HashSet::new())
            }
        } else {
            (None, std::collections::HashSet::new())
        };

        let env = req.env_vars.unwrap_or_default();
        let sb_cfg = SandboxConfig {
            command: req.command.clone(),
            cwd: req.cwd.clone(),
            env,
            timeout_sec: req.timeout_sec,
            max_output_chars: 100_000,
            seatbelt: req.seatbelt,
            inherit_env: req.inherit_env,
            use_pty: req.use_pty,
            max_nproc: req.max_nproc,
            max_cpu_sec: req.max_cpu_sec,
            max_nofile: req.max_nofile,
            rss_limit_mb: req.rss_limit_mb,
            sandbox_profile: req.sandbox.clone(),
        };
        info!(
            seatbelt = req.seatbelt,
            use_pty = req.use_pty,
            "execute_async — sandbox execution"
        );
        let sb = self.sandbox.run(sb_cfg).await?;

        // Diagnostics slicing — filled when exit_code != 0 and not blocked/timeout (PRD §4.2)
        // Issue #4: with use_pty=false, stderr is independent → Slicer prefers stderr (error
        // channel); in PTY mode stderr is always empty → falls back to stdout (traceback in tail)
        #[cfg(feature = "diagnostics")]
        let diag = if sb.exit_code != 0 && !sb.timed_out {
            let cwd_ref = req.cwd.as_deref();
            let diag_src = if !sb.stderr.is_empty() {
                &sb.stderr
            } else {
                &sb.stdout
            };
            Some(Diagnostics::from(self.slicer.slice(diag_src, cwd_ref)))
        } else {
            None
        };
        #[cfg(not(feature = "diagnostics"))]
        let diag: Option<Diagnostics> = None;

        let sid_filtered = snapshot_id.as_ref().filter(|s| !s.is_empty()).cloned();
        let mut result = ExecutionResult {
            exit_code: sb.exit_code,
            stdout: sb.stdout,
            stderr: sb.stderr,
            task_id: req.task_id.clone(),
            command: Some(req.command.clone()),
            duration_sec: start.elapsed().as_secs_f64(),
            timed_out: sb.timed_out,
            snapshot_id: sid_filtered.clone(),
            diagnostics: diag,
            trace_id: Some(trace_id),
            oom_killed: sb.oom_killed, // D3-4: RSS watchdog trigger backfill
            pid: sb.pid, // RUN-11: backfill sandbox child PID for telemetry to sample the real task
            ..Default::default()
        };

        // D5-2 fail-loud: snapshot cannot be created and the caller passed a policy → rollback has
        // no anchor, the guard is never constructed, and the caller has no signal that the safety
        // net is lost. Mark rollback_unavailable=true (snapshot_create_err was warn!-logged above).
        if snapshot_create_err.is_some() && req.auto_rollback_policy.is_some() {
            result.rollback_unavailable = true;
        }

        // Auto-rollback (FR-04) — when the caller passed a policy and snapshot+cwd exist, the
        // guard judges within the single execution. pre_status was captured pre-command and is
        // passed to the guard for detect_damage diffing (C-CORE-01)
        if let (Some(policy), Some(cwd), Some(sid)) = (
            req.auto_rollback_policy.clone(),
            req.cwd.clone(),
            sid_filtered.as_ref(),
        ) {
            if !sid.is_empty() {
                let guard = AutoRollbackGuard::new(policy, sid.clone(), cwd, pre_status.clone());
                if let Err(e) = guard.record_result(&mut result).await {
                    // L-2: fail-loud — the old version warn!-degraded then silently continued, the
                    // caller had no signal that the rollback safety net was lost.
                    // Mark rollback_unavailable=true so the caller sees it, still warn!-logged
                    // (dual-channel visibility).
                    warn!(error = %e, "auto-rollback guard error — rollback_unavailable set");
                    result.rollback_unavailable = true;
                }
            }
        }

        Ok(result)
    }

    /// Sync execute — via BLOCKING_RT, for the PyO3 sync entry
    pub fn execute(&self, req: ExecutionRequest) -> Result<ExecutionResult> {
        BLOCKING_RT.block_on(self.execute_async(req))
    }

    /// Streaming execute — validate → snapshot → sandbox.run_streaming → forward Chunks, fill
    /// diagnostics at Done. Security-blocked → single Done(blocked) frame; everything else goes
    /// through run_streaming's real-time chunking.
    /// Non-breaking: coexists with execute_async; the Done frame's ExecutionResult is logically
    /// equivalent (diagnostics slicing happens at Done time).
    pub async fn execute_streaming(
        &self,
        req: ExecutionRequest,
        cancel_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> Result<(mpsc::Receiver<ExecutionStreamEvent>, JoinHandle<()>)> {
        // M-OPS-06/m-OPS-03: resolve trace_id + span at entry (same as execute_async)
        let trace_id = req
            .trace_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let span = tracing::span!(
            tracing::Level::INFO,
            "execute_stream",
            trace_id = %trace_id,
            command = %redact_command(&req.command)
        );
        let _enter = span.enter();
        info!(command = %redact_command(&req.command), "execute_streaming — validating");
        let start = Instant::now();
        let verdict = self.security.validate(&req.command);
        if !verdict.allowed {
            let reason = verdict
                .reason
                .unwrap_or_else(|| "unknown reason".to_string());
            info!(%reason, "blocked by security validation (streaming)");
            let action_id = verdict.action_id.clone();
            let (tx, rx) = mpsc::channel(8);
            let handle = tokio::spawn(async move {
                let _ = tx
                    .send(ExecutionStreamEvent::Done(Box::new(
                        ExecutionResult::blocked_by_guard(
                            reason,
                            action_id,
                            req.task_id.clone(),
                            Some(req.command.clone()),
                            Some(trace_id),
                        ),
                    )))
                    .await;
            });
            return Ok((rx, handle));
        }
        // Issue #23 acceptance #3 (seatbelt gating E7, streaming sync path): guard requires
        // seatbelt but the caller has not enabled it → refuse.
        if verdict.seatbelt_required && !req.seatbelt {
            let reason = "guard requires seatbelt isolation but the caller has not enabled it (E7 seatbelt gating, streaming)";
            warn!(%reason, action_id = ?verdict.action_id, "blocked by seatbelt gating (streaming)");
            let action_id = verdict.action_id.clone();
            let (tx, rx) = mpsc::channel(8);
            let handle = tokio::spawn(async move {
                let _ = tx
                    .send(ExecutionStreamEvent::Done(Box::new(
                        ExecutionResult::blocked_by_guard(
                            reason,
                            action_id,
                            req.task_id.clone(),
                            Some(req.command.clone()),
                            Some(trace_id),
                        ),
                    )))
                    .await;
            });
            return Ok((rx, handle));
        }
        // Issue #34: sandbox profile fail-closed (streaming sync path).
        if let Some(sp) = &req.sandbox {
            if sp.fail_if_unavailable && !fe_sandbox::seatbelt::seatbelt_available() {
                let reason = "sandbox profile requested but sandbox-exec unavailable (fail_if_unavailable fail-closed, streaming)";
                warn!(%reason, command = %redact_command(&req.command), "blocked by sandbox profile gating (streaming)");
                let (tx, rx) = mpsc::channel(8);
                let handle = tokio::spawn(async move {
                    let _ = tx
                        .send(ExecutionStreamEvent::Done(Box::new(
                            ExecutionResult::blocked_with(
                                reason.to_string(),
                                req.task_id.clone(),
                                Some(req.command.clone()),
                                Some(trace_id),
                            ),
                        )))
                        .await;
                });
                return Ok((rx, handle));
            }
        }
        if let Some(cwd) = &req.cwd {
            let cwd_v = self.security.validate_cwd(cwd);
            if !cwd_v.allowed {
                let reason = cwd_v.reason.unwrap_or_else(|| "invalid cwd".to_string());
                info!(%reason, "blocked by cwd validation (streaming)");
                let (tx, rx) = mpsc::channel(8);
                let handle = tokio::spawn(async move {
                    let _ = tx
                        .send(ExecutionStreamEvent::Done(Box::new(
                            ExecutionResult::blocked_with(
                                reason,
                                req.task_id.clone(),
                                Some(req.command.clone()),
                                Some(trace_id),
                            ),
                        )))
                        .await;
                });
                return Ok((rx, handle));
            }
        }

        // Issue #23 acceptance #4 (H4 TOCTOU recheck, streaming sync path): recheck before spawn
        // that the binary path has no newly-appeared symlink / has not vanished.
        let first_token = req.command.split_whitespace().next().unwrap_or("");
        if !first_token.is_empty() {
            if let Err(reason) = self.security.recheck_binary(first_token) {
                warn!(%reason, first_token, "blocked by TOCTOU recheck (streaming) — binary path changed before execution");
                let (tx, rx) = mpsc::channel(8);
                let handle = tokio::spawn(async move {
                    let _ = tx
                        .send(ExecutionStreamEvent::Done(Box::new(
                            ExecutionResult::blocked_with(
                                reason,
                                req.task_id.clone(),
                                Some(req.command.clone()),
                                Some(trace_id),
                            ),
                        )))
                        .await;
                });
                return Ok((rx, handle));
            }
        }

        // Snapshot + pre-command git status snapshot (same policy as execute_async; C-CORE-01
        // pre_status diff)
        // D5-2/D5-6: same as execute_async — want_snapshot includes auto_rollback_policy;
        // fail-loud + empty warn.
        let want_snapshot = req.enable_rollback_snapshot || req.auto_rollback_policy.is_some();
        let mut snapshot_create_err: Option<anyhow::Error> = None;
        let (snapshot_id, pre_status) = if want_snapshot {
            if let Some(cwd) = &req.cwd {
                let snap = self.rollback.snapshot_create(cwd).await;
                let pre = AutoRollbackGuard::capture_status(cwd).await;
                match (snap, pre) {
                    (Ok(id), Ok(st)) => {
                        if id.is_empty() {
                            if req.auto_rollback_policy.is_some() {
                                warn!(cwd, "empty snapshot id (non-git repo) but caller passed auto_rollback — rollback has no anchor, safety net lost (streaming)");
                            } else {
                                info!(cwd, "empty snapshot id (non-git repo) — no rollback anchor (streaming)");
                            }
                        } else {
                            info!(%id, "snapshot created (streaming)");
                        }
                        (Some(id), st)
                    }
                    (Ok(id), Err(e)) => {
                        warn!(error = %e, cwd, "pre-command git status capture failed (streaming), pre_status set to empty");
                        if !id.is_empty() {
                            info!(%id, "snapshot created (streaming)");
                        }
                        (Some(id), std::collections::HashSet::new())
                    }
                    (Err(e), _) => {
                        warn!(error = %e, cwd, "snapshot creation failed — rollback safety net unavailable (D5-2 fail-loud, streaming)");
                        snapshot_create_err = Some(e);
                        (None, std::collections::HashSet::new())
                    }
                }
            } else {
                (None, std::collections::HashSet::new())
            }
        } else {
            (None, std::collections::HashSet::new())
        };

        let env = req.env_vars.unwrap_or_default();
        let sb_cfg = fe_sandbox::SandboxConfig {
            command: req.command.clone(),
            cwd: req.cwd.clone(),
            env,
            timeout_sec: req.timeout_sec,
            max_output_chars: 100_000,
            seatbelt: req.seatbelt,
            inherit_env: req.inherit_env,
            use_pty: req.use_pty,
            max_nproc: req.max_nproc,
            max_cpu_sec: req.max_cpu_sec,
            max_nofile: req.max_nofile,
            rss_limit_mb: req.rss_limit_mb,
            sandbox_profile: req.sandbox.clone(),
        };
        info!(
            seatbelt = req.seatbelt,
            "execute_streaming — sandbox streaming execution"
        );
        let (mut sb_rx, sb_handle) = self.sandbox.run_streaming(sb_cfg, cancel_rx)?;

        #[cfg(feature = "diagnostics")]
        let slicer = self.slicer.clone();
        let cwd_for_diag = req.cwd.clone();
        let task_id_for_done = req.task_id.clone();
        let command_for_done = req.command.clone();
        let trace_id_for_done = trace_id.clone();
        let policy_for_done = req.auto_rollback_policy.clone();
        let cwd_for_guard = req.cwd.clone();
        let pre_status_for_guard = pre_status.clone();
        // D5-2: snapshot cannot be created + policy → mark rollback_unavailable (applied inside
        // the closure)
        let snapshot_err_for_done = snapshot_create_err.is_some();
        let policy_present = req.auto_rollback_policy.is_some();

        let (outer_tx, outer_rx) = mpsc::channel::<ExecutionStreamEvent>(64);
        // C-4: the spawn task body is wrapped in catch_unwind — a pathological
        // slicer/guard/unwrap panic does not silently lose the Done frame.
        // outer_tx is cloned for the async inside the catch (moved in); the original outer_tx
        // stays outside the catch so the panic path can send an explicit
        // Done{exit_code:-1, stderr:"internal panic: ..."} (rather than letting outer_rx receive
        // None as a clean EOF).
        let panic_tx = outer_tx.clone();
        let trace_id_for_panic = trace_id.clone();
        let task_id_for_panic = req.task_id.clone();
        let command_for_panic = req.command.clone();
        let handle = tokio::spawn(async move {
            let inner = AssertUnwindSafe(async move {
                while let Some(ev) = sb_rx.recv().await {
                    match ev {
                        fe_sandbox::StreamEvent::Chunk { data } => {
                            if outer_tx
                                .send(ExecutionStreamEvent::Chunk { data })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        fe_sandbox::StreamEvent::Done(sb) => {
                            // Diagnostics slicing — exit_code != 0 and not timeout (PRD §4.2, same
                            // as execute_async)
                            #[cfg(feature = "diagnostics")]
                            let diag = if sb.exit_code != 0 && !sb.timed_out {
                                let cwd_ref = cwd_for_diag.as_deref();
                                // Issue #4: stdio mode has independent stderr → prefer stderr
                                let diag_src = if !sb.stderr.is_empty() {
                                    &sb.stderr
                                } else {
                                    &sb.stdout
                                };
                                Some(Diagnostics::from(slicer.slice(diag_src, cwd_ref)))
                            } else {
                                None
                            };
                            #[cfg(not(feature = "diagnostics"))]
                            let diag: Option<Diagnostics> = None;
                            let sid_filtered =
                                snapshot_id.as_ref().filter(|s| !s.is_empty()).cloned();
                            let mut result = ExecutionResult {
                                exit_code: sb.exit_code,
                                stdout: sb.stdout,
                                stderr: sb.stderr,
                                task_id: task_id_for_done.clone(),
                                command: Some(command_for_done.clone()),
                                duration_sec: start.elapsed().as_secs_f64(),
                                timed_out: sb.timed_out,
                                snapshot_id: sid_filtered.clone(),
                                diagnostics: diag,
                                trace_id: Some(trace_id_for_done.clone()),
                                oom_killed: sb.oom_killed, // D3-4: RSS watchdog trigger backfill
                                pid: sb.pid, // RUN-11: backfill sandbox child PID for telemetry to sample the real task
                                cancelled: sb.cancelled, // Issue #32: server-side cancel pass-through
                                ..Default::default()
                            };
                            // D5-2 fail-loud: snapshot cannot be created and the caller passed a
                            // policy → guard not constructed, mark rollback_unavailable (streaming)
                            if snapshot_err_for_done && policy_present {
                                result.rollback_unavailable = true;
                            }
                            // Auto-rollback (FR-04, same as execute_async; pre_status diff C-CORE-01)
                            if let (Some(policy), Some(cwd), Some(sid)) = (
                                policy_for_done.as_ref(),
                                cwd_for_guard.as_ref(),
                                sid_filtered.as_ref(),
                            ) {
                                if !sid.is_empty() {
                                    let guard = AutoRollbackGuard::new(
                                        policy.clone(),
                                        sid.clone(),
                                        cwd.clone(),
                                        pre_status_for_guard.clone(),
                                    );
                                    if let Err(e) = guard.record_result(&mut result).await {
                                        // L-2: fail-loud — the old version warn!-degraded and
                                        // silently swallowed, the caller had no signal.
                                        // Mark rollback_unavailable=true so the caller sees it
                                        // (same as execute_async).
                                        warn!(
                                            error = %e,
                                            "auto-rollback guard error (streaming) — rollback_unavailable set"
                                        );
                                        result.rollback_unavailable = true;
                                    }
                                }
                            }
                            // L-3: send errors are no longer swallowed with let _ = — the consumer
                            // already dropped (early break/exception); warn! explicitly logs "Done
                            // frame dropped" so channel closure is visible in logs.
                            if outer_tx
                                .send(ExecutionStreamEvent::Done(Box::new(result)))
                                .await
                                .is_err()
                            {
                                warn!(
                                    "execute_streaming Done frame dropped — consumer already exited early (outer_tx.send Err)"
                                );
                            }
                            break;
                        }
                    }
                }
                // L-CORE-01: after break, sb_handle.await may block until the child times out
                // (after the chunk channel disconnects, the sandbox coordinator task still drives
                // the child). abort stops the coordinator first, then a timeout wraps the await
                // as a fallback — the child is managed by the sandbox's internal
                // timeout/supervisor, so the fe-core task never hangs indefinitely.
                sb_handle.abort();
                match tokio::time::timeout(Duration::from_secs(5), sb_handle).await {
                    Ok(_) => debug!("execute_streaming coordinator task finished"),
                    Err(_) => warn!(
                        "execute_streaming coordinator task still running 5s after abort (child may still be reaping its timeout)"
                    ),
                }
            });
            // C-4: catch_unwind captures panics in the task body. Err(payload) → send an explicit
            // Done{exit_code:-1, stderr:"internal panic: ..."} rather than letting outer_rx
            // receive None (the old version silently swallowed the result, appearing successful
            // with no result).
            if let Err(payload) = inner.catch_unwind().await {
                let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
                    s.to_string()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic payload".to_string()
                };
                error!(panic = %msg, "execute_streaming task body panicked — sending explicit error Done frame");
                let panic_result = ExecutionResult {
                    exit_code: EXIT_BLOCKED,
                    stderr: format!("internal panic: {msg}"),
                    task_id: task_id_for_panic,
                    command: Some(command_for_panic),
                    duration_sec: start.elapsed().as_secs_f64(),
                    trace_id: Some(trace_id_for_panic),
                    ..Default::default()
                };
                if panic_tx
                    .send(ExecutionStreamEvent::Done(Box::new(panic_result)))
                    .await
                    .is_err()
                {
                    warn!(
                        "execute_streaming panic Done frame also dropped — consumer already exited early (panic_tx.send Err)"
                    );
                }
            }
        });
        Ok((outer_rx, handle))
    }

    /// Real-time telemetry stream — 10Hz CPU/memory sampling, GPU injected by the caller (the
    /// executor runs no models). Returns (Receiver<TelemetrySample>, JoinHandle). The caller
    /// iterates rx to receive frames; dropping rx automatically stops the sampling task (channel
    /// closed). Executor is stateless: each call yields an independent stream.
    pub fn telemetry_stream(
        &self,
        cfg: TelemetryConfig,
    ) -> (mpsc::Receiver<TelemetrySample>, JoinHandle<()>) {
        info!(
            interval_ms = cfg.interval_ms,
            "telemetry_stream — starting sampling"
        );
        start_telemetry(cfg, BLOCKING_RT.handle().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    // D3-5/D3-10: command log redaction — secret patterns masked, non-secrets preserved
    #[test]
    fn redact_command_bearer_token() {
        let r = redact_command("curl -H 'Authorization: Bearer sk-ant-abc123' https://api");
        assert!(
            !r.contains("sk-ant-abc123"),
            "Bearer token should be redacted: {r}"
        );
        assert!(
            r.contains("[REDACTED]"),
            "should contain the [REDACTED] placeholder: {r}"
        );
    }

    #[test]
    fn redact_command_sk_prefix() {
        let r = redact_command("echo sk-proj-xyz789");
        assert!(
            !r.contains("sk-proj-xyz789"),
            "sk- key should be redacted: {r}"
        );
        assert!(
            r.contains("sk-[REDACTED]"),
            "should contain sk-[REDACTED]: {r}"
        );
    }

    #[test]
    fn redact_command_key_equals_value() {
        let r = redact_command("export PASSWORD=hunter2 && curl https://api");
        assert!(
            !r.contains("hunter2"),
            "PASSWORD value should be redacted: {r}"
        );
        assert!(
            r.contains("PASSWORD=[REDACTED]"),
            "should contain PASSWORD=[REDACTED]: {r}"
        );
    }

    #[test]
    fn redact_command_api_key_quoted() {
        let r = redact_command(r#"cli --api-key="abc def ghi""#);
        assert!(
            !r.contains("abc def ghi"),
            "quoted api_key value should be redacted: {r}"
        );
        assert!(r.contains("[REDACTED]"), "should contain [REDACTED]: {r}");
    }

    #[test]
    fn redact_command_curl_basic_auth() {
        let r = redact_command("curl -u admin:s3cret https://api");
        assert!(
            !r.contains("s3cret"),
            "basic auth password should be redacted: {r}"
        );
        assert!(
            r.contains("admin:[REDACTED]"),
            "should keep user and mask pass: {r}"
        );
    }

    #[test]
    fn redact_command_header_authorization() {
        let r = redact_command(r#"curl -H "Authorization: Bearer xyz" https://api"#);
        assert!(
            !r.contains("Bearer xyz"),
            "Authorization header value should be redacted: {r}"
        );
    }

    #[test]
    fn redact_command_preserves_non_secret() {
        let r = redact_command("pytest tests/ -v --tb=short");
        assert_eq!(
            r, "pytest tests/ -v --tb=short",
            "command without secrets should be preserved verbatim: {r}"
        );
    }

    #[test]
    fn redact_command_case_insensitive() {
        let r = redact_command("curl -H 'authorization: bearer tok' url");
        assert!(
            !r.contains("tok"),
            "lowercase authorization/bearer should be redacted: {r}"
        );
    }

    #[test]
    fn execute_streaming_echo_chunk_then_done() {
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "echo hi".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                trace_id: None,
                sandbox: None,
            };
            let (mut rx, handle) = ex.execute_streaming(req, None).await.unwrap();
            let mut combined = String::new();
            let mut done = None;
            while let Some(ev) = rx.recv().await {
                match ev {
                    ExecutionStreamEvent::Chunk { data } => combined.push_str(&data),
                    ExecutionStreamEvent::Done(r) => done = Some(r),
                }
            }
            handle.await.unwrap();
            let done = done.expect("should receive Done");
            assert_eq!(done.exit_code, 0);
            assert!(!done.timed_out);
            assert!(combined.contains("hi"), "chunks={:?}", combined);
            assert!(done.stdout.contains("hi"), "done.stdout={:?}", done.stdout);
        });
    }

    #[test]
    fn trace_id_auto_generated_on_none() {
        // M-OPS-06: request without trace_id → entry auto-generates a uuid v4, backfilled into
        // the result
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "echo t".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                sandbox: None,
                trace_id: None,
            };
            let r = ex.execute_async(req).await.unwrap();
            assert_eq!(r.exit_code, 0);
            assert!(r.trace_id.is_some(), "trace_id should be auto-generated");
            let tid = r.trace_id.as_ref().unwrap();
            assert_eq!(tid.len(), 36, "uuid v4 length 36, got {tid}");
            assert_eq!(
                tid.matches('-').count(),
                4,
                "uuid v4 has 4 separator segments, got {tid}"
            );
        });
    }

    #[test]
    fn trace_id_forwarded_when_provided() {
        // M-OPS-06: caller passes trace_id → echoed verbatim into the result
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "echo t".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                trace_id: Some("caller-tid-123".to_string()),
                sandbox: None,
            };
            let r = ex.execute_async(req).await.unwrap();
            assert_eq!(r.trace_id.as_deref(), Some("caller-tid-123"));
        });
    }

    #[test]
    fn trace_id_present_on_blocked() {
        // M-OPS-06: blocked results also carry trace_id (forwarded via blocked_with)
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "rm -rf /".to_string(),
                task_id: Some("tk".to_string()),
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                sandbox: None,
                trace_id: Some("blk-tid".to_string()),
            };
            let r = ex.execute_async(req).await.unwrap();
            assert!(r.blocked_by_security);
            assert_eq!(r.trace_id.as_deref(), Some("blk-tid"));
        });
    }

    #[test]
    fn trace_id_streaming_done_carries_it() {
        // M-OPS-06: streaming Done frame carries trace_id
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "echo s".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                sandbox: None,
                rss_limit_mb: default_rss_limit(),
                trace_id: Some("stream-tid".to_string()),
            };
            let (mut rx, handle) = ex.execute_streaming(req, None).await.unwrap();
            let mut done = None;
            while let Some(ev) = rx.recv().await {
                if let ExecutionStreamEvent::Done(r) = ev {
                    done = Some(r);
                }
            }
            handle.await.unwrap();
            let done = done.expect("should receive Done");
            assert_eq!(done.trace_id.as_deref(), Some("stream-tid"));
        });
    }

    #[test]
    fn execute_streaming_blocked_single_done_frame() {
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "rm -rf /".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                sandbox: None,
                rss_limit_mb: default_rss_limit(),
                trace_id: None,
            };
            let (mut rx, handle) = ex.execute_streaming(req, None).await.unwrap();
            let mut frames = 0;
            let mut blocked = false;
            while let Some(ev) = rx.recv().await {
                frames += 1;
                if let ExecutionStreamEvent::Done(r) = ev {
                    assert_eq!(r.exit_code, EXIT_BLOCKED);
                    assert!(r.blocked_by_security);
                    blocked = true;
                }
            }
            handle.await.unwrap();
            assert_eq!(frames, 1, "a block should send exactly one Done frame");
            assert!(blocked);
        });
    }

    #[test]
    fn execute_streaming_timeout_done_frame() {
        rt().block_on(async {
            let ex = Executor::new().with_allow_inline_interpreter(true);
            let req = ExecutionRequest {
                command: "python3 -c \"while True: pass\"".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 1.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                sandbox: None,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                trace_id: None,
            };
            let (mut rx, handle) = ex.execute_streaming(req, None).await.unwrap();
            let mut done = None;
            while let Some(ev) = rx.recv().await {
                if let ExecutionStreamEvent::Done(r) = ev {
                    done = Some(r);
                }
            }
            handle.await.unwrap();
            let done = done.expect("should receive Done");
            assert!(done.timed_out);
            assert_eq!(done.exit_code, EXIT_TIMEOUT);
        });
    }

    #[test]
    fn execute_streaming_diagnostics_on_nonzero_exit() {
        rt().block_on(async {
            let ex = Executor::new().with_allow_inline_interpreter(true);
            let req = ExecutionRequest {
                command: "python3 -c \"raise ValueError('boom')\"".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                sandbox: None,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                trace_id: None,
            };
            let (mut rx, handle) = ex.execute_streaming(req, None).await.unwrap();
            let mut done = None;
            while let Some(ev) = rx.recv().await {
                if let ExecutionStreamEvent::Done(r) = ev {
                    done = Some(r);
                }
            }
            handle.await.unwrap();
            let done = done.unwrap();
            assert_ne!(done.exit_code, 0);
            let diag = done
                .diagnostics
                .expect("non-zero exit should fill diagnostics");
            assert_eq!(diag.error_type.as_deref(), Some("ValueError"));
        });
    }

    #[test]
    fn execute_streaming_cancel_kills_process_tree_issue32() {
        // Issue #32: server-side cancel → execute_streaming receives cancel_rx → kills the
        // process tree → Done frame with exit_code -1, cancelled true, not a timeout. Exits
        // within the cancel timeout.
        rt().block_on(async {
            let ex = Executor::new().with_allow_inline_interpreter(true);
            let req = ExecutionRequest {
                command: "python3 -c \"while True: pass\"".to_string(),
                task_id: Some("cancel-test".to_string()),
                cwd: None,
                timeout_sec: 100.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                sandbox: None,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                trace_id: None,
            };
            let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
            let start = std::time::Instant::now();
            let (mut rx, handle) = ex.execute_streaming(req, Some(cancel_rx)).await.unwrap();
            // send cancel after 500ms — beats the 100s timeout_sec
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let _ = cancel_tx.send(());
            let mut done = None;
            while let Some(ev) = rx.recv().await {
                if let ExecutionStreamEvent::Done(r) = ev {
                    done = Some(r);
                }
            }
            handle.await.unwrap();
            let done = done.expect("should receive a Done frame");
            assert_eq!(
                done.exit_code, -1,
                "Issue #32: cancel should produce exit_code -1 (blocked/internal convention)"
            );
            assert!(
                done.cancelled,
                "Issue #32: cancelled should pass through as true"
            );
            assert!(
                !done.timed_out,
                "Issue #32: cancel is not a timeout — timed_out should not be set"
            );
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "Issue #32: cancel should complete within the cancel timeout, actual {:?}",
                start.elapsed()
            );
        });
    }

    fn make_git_repo(dir: &std::path::Path) {
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .output()
                .expect("git failed")
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        std::fs::write(dir.join("app.py"), "print('ok')\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "init"]);
    }

    #[test]
    fn auto_rollback_triggers_on_failure_with_file_damage() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            // python3 is allowlisted — rewrite app.py then raise (failure + file damage)
            let cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\"";
            let req = ExecutionRequest {
                command: cmd.to_string(),
                task_id: None,
                cwd: Some(cwd.clone()),
                timeout_sec: 15.0,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: Some(RollbackPolicy::default()),
                seatbelt: false,
                inherit_env: false,
                sandbox: None,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                trace_id: None,
            };
            let ex = Executor::new().with_allow_inline_interpreter(true);
            let res = ex.execute_async(req).await.unwrap();
            assert_ne!(res.exit_code, 0, "should fail");
            assert!(res.auto_rolled_back, "should auto-rollback");
            // after rollback app.py is restored to its original content
            let content = std::fs::read_to_string(dir.path().join("app.py")).unwrap();
            assert_eq!(
                content, "print('ok')\n",
                "should be restored after rollback: {content}"
            );
        });
    }

    #[test]
    fn auto_rollback_skipped_when_exit_ok() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            // successful command: worktree clean after commit, should not roll back
            let req = ExecutionRequest {
                command: "echo hi".to_string(),
                task_id: None,
                cwd: Some(cwd),
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: Some(RollbackPolicy::default()),
                seatbelt: false,
                sandbox: None,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                trace_id: None,
            };
            let ex = Executor::new();
            let res = ex.execute_async(req).await.unwrap();
            assert_eq!(res.exit_code, 0);
            assert!(!res.auto_rolled_back, "success should not roll back");
        });
    }

    #[test]
    fn auto_rollback_no_policy_means_no_action() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            // no policy → no rollback even with failure + file changes
            let cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\"";
            let req = ExecutionRequest {
                command: cmd.to_string(),
                task_id: None,
                cwd: Some(cwd.clone()),
                timeout_sec: 15.0,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: None,
                sandbox: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                trace_id: None,
            };
            let ex = Executor::new().with_allow_inline_interpreter(true);
            let res = ex.execute_async(req).await.unwrap();
            assert_ne!(res.exit_code, 0);
            assert!(!res.auto_rolled_back, "no policy should not roll back");
            // file stays damaged (not rolled back)
            let content = std::fs::read_to_string(dir.path().join("app.py")).unwrap();
            assert_eq!(
                content, "broken\n",
                "without policy the file should keep its changes: {content}"
            );
        });
    }

    // Issue #12.3 / A4: max_consecutive_failures is a DEFERRED-BY-DESIGN dead field —
    // Rust never reads it. Setting an extremely high value (99) should not block single-execution
    // file-damage rollback (proves the field is accepted but ignored, stateless).
    #[test]
    fn max_consecutive_failures_ignored_stateless() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            let cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\"";
            let req = ExecutionRequest {
                command: cmd.to_string(),
                task_id: None,
                cwd: Some(cwd.clone()),
                timeout_sec: 15.0,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: Some(RollbackPolicy {
                    max_consecutive_failures: 99,
                    file_damage_check: true,
                }),
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                trace_id: None,
                sandbox: None,
            };
            let ex = Executor::new().with_allow_inline_interpreter(true);
            let res = ex.execute_async(req).await.unwrap();
            assert_ne!(res.exit_code, 0, "should fail");
            // even with max_consecutive_failures=99 (far beyond a single execution), file damage
            // still rolls back immediately — the field does not constrain a single execution
            assert!(
                res.auto_rolled_back,
                "max_consecutive_failures does not affect single-execution rollback (dead field)"
            );
            let content = std::fs::read_to_string(dir.path().join("app.py")).unwrap();
            assert_eq!(
                content, "print('ok')\n",
                "should be restored after rollback: {content}"
            );
        });
    }

    // C-CORE-01: dirty before the command (untracked wip.txt) + command fails but touches no
    // files → no false rollback trigger. The old detect_damage saw a non-empty git status
    // (wip.txt) and judged damage → false rollback (needless reset, losing wip.txt if stashed).
    // New version diffs pre/post: wip.txt is in pre_status, not "command-added" → no rollback.
    #[test]
    fn auto_rollback_no_false_trigger_on_preexisting_dirty() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            // create an untracked file (WIP) before the command — pre_status records it
            std::fs::write(dir.path().join("wip.txt"), "work in progress\n").unwrap();
            // command fails but changes no files (pure raise) — post_status contains wip.txt but
            // pre does too → no additions
            let cmd = "python3 -c \"raise ValueError('boom')\"";
            let req = ExecutionRequest {
                command: cmd.to_string(),
                task_id: None,
                cwd: Some(cwd),
                timeout_sec: 15.0,
                env_vars: None,
                sandbox: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: Some(RollbackPolicy::default()),
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                trace_id: None,
            };
            let ex = Executor::new().with_allow_inline_interpreter(true);
            let res = ex.execute_async(req).await.unwrap();
            assert_ne!(res.exit_code, 0, "should fail");
            assert!(
                !res.auto_rolled_back,
                "command added no changes (wip.txt dirty before the command) → no false rollback"
            );
            // app.py untouched by the command, stays as-is
            let app = std::fs::read_to_string(dir.path().join("app.py")).unwrap();
            assert_eq!(app, "print('ok')\n", "app.py untouched");
            // wip.txt preserved (no rollback, nothing lost)
            let wip = std::fs::read_to_string(dir.path().join("wip.txt")).unwrap();
            assert_eq!(
                wip, "work in progress\n",
                "wip.txt should not be lost to rollback"
            );
        });
    }

    #[test]
    fn telemetry_stream_yields_samples_and_stops() {
        rt().block_on(async {
            let ex = Executor::new();
            let cfg = TelemetryConfig {
                interval_ms: 20,
                max_samples: 4,
                pid: None,
            };
            let (mut rx, handle) = ex.telemetry_stream(cfg);
            let mut samples = Vec::new();
            while let Some(s) = rx.recv().await {
                samples.push(s);
            }
            let _ = handle.await;
            assert_eq!(samples.len(), 4, "expected 4 frames");
            assert!(samples.iter().all(|s| s.mem_mb >= 0.0));
            assert!(
                samples.iter().all(|s| s.gpu_pct.is_none()),
                "GPU not injected by default"
            );
        });
    }

    // ===== 0827 fe-core P0-P3 fix regression tests =====

    /// C-2: is_tracked_mutation porcelain code classification — only tracked-file mutations count
    /// as damage, ?? /A don't.
    #[test]
    fn c2_is_tracked_mutation_classifies_porcelain_codes() {
        // untracked addition (intentionally created by the command) → not damage
        assert!(
            !is_tracked_mutation("?? build/"),
            "?? untracked is not damage"
        );
        assert!(!is_tracked_mutation("?? __pycache__/"));
        // staged addition (no old tracked baseline) → not damage
        assert!(
            !is_tracked_mutation("A  new_file.py"),
            "A staged addition is not damage"
        );
        // worktree addition (A in Y position) → not counted
        assert!(!is_tracked_mutation(" A new_file.py"), " Y=A is not damage");
        // tracked file modified (M in either position) → damage
        assert!(
            is_tracked_mutation(" M app.py"),
            " Y=M worktree modify is damage"
        );
        assert!(
            is_tracked_mutation("M  app.py"),
            "X=M staged modify is damage"
        );
        assert!(
            is_tracked_mutation("MM app.py"),
            "MM both-areas modify is damage"
        );
        // tracked file deleted (D) → damage
        assert!(is_tracked_mutation(" D app.py"), " Y=D delete is damage");
        assert!(
            is_tracked_mutation("D  app.py"),
            "X=D staged delete is damage"
        );
        // rename/copy (R/C) → damage
        assert!(
            is_tracked_mutation("R  old.py -> new.py"),
            "R rename is damage"
        );
        assert!(
            is_tracked_mutation("C  src.py -> dst.py"),
            "C copy is damage"
        );
        // type change (T) → damage
        assert!(
            is_tracked_mutation(" T app.py"),
            " Y=T type change is damage"
        );
        // anomalous short lines → conservatively false (no false rollback)
        assert!(!is_tracked_mutation(""), "empty line is not damage");
        assert!(!is_tracked_mutation("A"), "single-char line is not damage");
    }

    /// C-2: `mkdir -p build && <failing command>` — untracked build/ present in post but not in
    /// pre, should not be misjudged as damage triggering rollback (a big hole C-CORE-01 missed,
    /// typical fusion-code workflow).
    #[test]
    fn c2_untracked_build_dir_not_treated_as_damage() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            // mkdir creates an untracked build/ dir, then python3 raises (allowlisted + exit!=0)
            // build/ is in post (?? build/) but not pre → old version misjudged damage → false
            // rollback. After the C-2 fix: ?? is not counted as damage → damaged=0 → no rollback,
            // auto_rolled_back=false.
            let cmd = "mkdir -p build && python3 -c \"raise ValueError(1)\"";
            let req = ExecutionRequest {
                command: cmd.to_string(),
                task_id: None,
                cwd: Some(cwd.clone()),
                timeout_sec: 15.0,
                sandbox: None,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: Some(RollbackPolicy::default()),
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                trace_id: None,
            };
            let ex = Executor::new().with_allow_inline_interpreter(true);
            let res = ex.execute_async(req).await.unwrap();
            assert_ne!(res.exit_code, 0, "should fail (python raise)");
            assert!(
                !res.auto_rolled_back,
                "C-2: untracked build/ should not trigger rollback, got auto_rolled_back={}",
                res.auto_rolled_back
            );
            // build/ should be preserved (not wiped by rollback)
            assert!(
                dir.path().join("build").exists(),
                "C-2: build/ dir should be preserved (legitimate artifact not falsely rolled back)"
            );
        });
    }

    /// C-2: tracked file broken by the command (M) + exit!=0 → rollback should still trigger
    /// (C-2 does not break the real-damage path).
    #[test]
    fn c2_tracked_modify_still_triggers_rollback() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            // rewrite the tracked file app.py ( M) then raise → real damage → should roll back
            let cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\"";
            let req = ExecutionRequest {
                command: cmd.to_string(),
                task_id: None,
                cwd: Some(cwd),
                sandbox: None,
                timeout_sec: 15.0,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: Some(RollbackPolicy::default()),
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                rss_limit_mb: default_rss_limit(),
                trace_id: None,
            };
            let ex = Executor::new().with_allow_inline_interpreter(true);
            let res = ex.execute_async(req).await.unwrap();
            assert_ne!(res.exit_code, 0, "should fail");
            assert!(
                res.auto_rolled_back,
                "C-2: tracked-file M mutation should trigger rollback, got auto_rolled_back={}",
                res.auto_rolled_back
            );
        });
    }

    /// L-2: rollback_unavailable field defaults to false, omitted on serialization
    /// (skip_serializing_if is_false).
    #[test]
    fn l2_rollback_unavailable_default_and_skip_serialize() {
        let r = ExecutionResult::default();
        assert!(!r.rollback_unavailable, "default false");
        // false → not serialized (saves wire space)
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("rollback_unavailable"),
            "false should be skipped: {json}"
        );
        // true → serialized
        let r2 = ExecutionResult {
            rollback_unavailable: true,
            ..Default::default()
        };
        let json2 = serde_json::to_string(&r2).unwrap();
        assert!(
            json2.contains("rollback_unavailable"),
            "true should be serialized: {json2}"
        );
        // deserialization compatibility (missing field → default false)
        let back: ExecutionResult = serde_json::from_str(
            r#"{"exit_code":0,"stdout":"","stderr":"","timed_out":false,"blocked_by_security":false}"#,
        )
        .unwrap();
        assert!(
            !back.rollback_unavailable,
            "missing field should deserialize to default false"
        );
    }

    /// L-1 (audit 0827): rollback_skipped_reason field defaults to None, omitted on serialization
    /// (skip_serializing_if Option::is_none). Distinguishes "not rolled back (not needed)" (None)
    /// from "not rolled back (stale snapshot)" (Some) — fail-loud.
    #[test]
    fn l1_rollback_skipped_reason_default_and_skip_serialize() {
        let r = ExecutionResult::default();
        assert!(r.rollback_skipped_reason.is_none(), "default None");
        // None → skipped (saves wire space)
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("rollback_skipped_reason"),
            "None should be skipped: {json}"
        );
        // Some → serialized
        let r2 = ExecutionResult {
            rollback_skipped_reason: Some("snapshot_id parse failure".to_string()),
            ..Default::default()
        };
        let json2 = serde_json::to_string(&r2).unwrap();
        assert!(
            json2.contains("rollback_skipped_reason"),
            "Some should be serialized: {json2}"
        );
        assert!(
            json2.contains("snapshot_id parse failure"),
            "reason value should be on the wire: {json2}"
        );
        // deserialization compatibility (missing field → default None)
        let back: ExecutionResult = serde_json::from_str(
            r#"{"exit_code":0,"stdout":"","stderr":"","timed_out":false,"blocked_by_security":false}"#,
        )
        .unwrap();
        assert!(
            back.rollback_skipped_reason.is_none(),
            "missing field should deserialize to default None"
        );
    }

    /// A-5: the BLOCKING_RT panic message includes the build failure reason + unrecoverable hint
    /// (documentation anchor, does not trigger a real panic). Verifies the static is accessible +
    /// the runtime is alive (can run tasks).
    #[test]
    fn a5_blocking_rt_symbol_accessible() {
        // Accessing triggers init (must succeed in a normal environment); verifies the symbol is
        // accessible and the runtime is alive (can spawn tasks).
        let entered: bool = BLOCKING_RT.handle().block_on(async { true });
        assert!(
            entered,
            "BLOCKING_RT should be accessible and able to execute tasks"
        );
    }
}
