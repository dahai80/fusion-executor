from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

# Blocker 11 (schema sync audit): extra="forbid" on all models — a mismatch between the Rust serde struct and
# the Pydantic fields fails loudly (old extra="ignore" silently dropped unknown fields; when Rust renamed a field /
# serde bug, the Pydantic side returned empty fields as fake success). Strict validation breaks silent schema drift.
_STRICT = ConfigDict(extra="forbid")

# ARCH-4 observability boundary: the in-process path (run()/run_async()/run_streaming calling fe-core directly) bypasses the fe-ipc
# layer, so metrics/telemetry/audit counters routed over UDS are not triggered. execute_sync already mirrors key counters
# (fe_exec_total etc.) into the global metrics recorder, but full observability (BroadcastHub pushes / connection counts /
# Prometheus export) is only available on the serve() UDS path. When full metrics are needed, use serve() + executor.execute over UDS;
# do not rely on in-process run() metric coverage.


class Diagnostics(BaseModel):
    model_config = _STRICT
    error_type: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None
    raw_trace: str | None = None


class RollbackPolicy(BaseModel):
    model_config = _STRICT
    # L-PY-03: max_consecutive_failures is a dead field (Rust never reads it; CLAUDE.md states the caller
    # owns the consecutive-failure count). A4 decision: keep it (cross-layer cascade — tests send it, the fe-rollback wire
    # includes it), but mark it deprecated to warn callers not to rely on it. Rule 7: single source of truth, no ambiguity.
    max_consecutive_failures: int = Field(
        default=3,
        deprecated=True,
        description="Consecutive-failure cap (DEPRECATED reserved field, never read by Rust; the caller's self-healing loop owns the count)",
    )
    file_damage_check: bool = Field(
        default=True, description="Check for file damage on failure (git status) to trigger rollback"
    )


class SandboxProfile(BaseModel):
    model_config = _STRICT
    # Issue #34: per-command seatbelt/sandbox profile (matches fusion-code SandboxSettings).
    # None/default off → the existing fixed profile (default network deny + sensitive-path file-write deny), same behavior as v0.2.7.
    network: str | None = Field(
        default=None,
        description="Network policy: allow=permit outbound; deny=network deny (deny network-outbound, current default). None=do not override the default",
    )
    filesystem: str | None = Field(
        default=None,
        description="Filesystem policy: allow=no FS deny injected; deny_write=targeted sensitive-path file-write deny (default); deny=global file-write deny (Darwin 25 NO-OP). None=do not override the default",
    )
    excluded_commands: list[str] = Field(
        default_factory=list,
        description="Command names denied via deny process-exec inside the seatbelt profile (literal path matching)",
    )
    fail_if_unavailable: bool = Field(
        default=False,
        description="Fail-closed block when sandbox-exec is unavailable (exit -1, no spawn); False=silently degrade to running without seatbelt",
    )


class ExecutionRequest(BaseModel):
    model_config = _STRICT
    command: str
    task_id: str | None = None
    cwd: str | None = None
    timeout_sec: float = Field(default=30.0, description="Seconds; timeout exit code -124")
    env_vars: dict[str, str] | None = None
    enable_rollback_snapshot: bool = False
    auto_rollback_policy: RollbackPolicy | None = None
    seatbelt: bool = Field(
        default=True,
        description="macOS seatbelt runtime isolation (sandbox-exec network deny + dangerous-binary execve deny); commercial security default True, aligns with fe-core serde default_true + executor.run/run_async/shell_start defaults",
    )
    inherit_env: bool = Field(
        default=False,
        description="Environment isolation: False(default)=env_clear + minimal baseline PATH/TMPDIR/SHELL + env_vars, no host secret leakage; True=inherit the full host env (trusted local opt-in)",
    )
    use_pty: bool = Field(
        default=True,
        description="I/O backend: True(default)=PTY (merged stdout/stderr preserving ANSI/Traceback, stderr always empty); False=stdio (stdout/stderr captured independently, opt-in for callers that need split streams)",
    )
    max_nproc: int = Field(
        default=1024,
        description="Process count cap (RLIMIT_NPROC, injected via ulimit -u); blocks fork-bomb fan-out while leaving room for toolchain spawn chains; 0=unlimited (trusted opt-out); verified effective on Darwin",
    )
    max_cpu_sec: int = Field(
        default=0,
        description="CPU seconds cap (RLIMIT_CPU, injected via ulimit -t); >0 raises SIGXCPU at the cap (CPU death-loop defense); 0=unlimited (relies on the timeout_sec watchdog); verified effective on Darwin",
    )
    max_nofile: int = Field(
        default=1024,
        description="File descriptor cap (RLIMIT_NOFILE, injected via ulimit -n); blocks FD-exhaustion attacks; 0=unlimited (trusted opt-out); verified effective on Darwin (errno 24 EMFILE)",
    )
    rss_limit_mb: int = Field(
        default=2048,
        description="Per-task RSS cap (MB); Darwin RLIMIT_AS/RLIMIT_DATA are platform-invalid, so a sysinfo poll kills the child tree when RSS exceeds the cap (exit_code -124, oom_killed=true); blocks memory bombs; 0=disable the watchdog (trusted opt-out) (D3-4)",
    )
    trace_id: str | None = Field(
        default=None,
        description="Cross-layer correlation id; auto-generated uuid v4 at the execution entry when None, threading logs/IPC/results (M-OPS-06)",
    )
    sandbox: SandboxProfile | None = Field(
        default=None,
        description="Issue #34: per-command seatbelt/sandbox profile (network/filesystem/excluded commands); "
        "None=existing fixed profile (default network deny + sensitive-path file-write deny), same behavior as v0.2.7; "
        "fail_if_unavailable=true blocks fail-closed when sandbox-exec is unavailable (exit -1)",
    )


class ExecutionResult(BaseModel):
    model_config = _STRICT
    exit_code: int = Field(description="0=success, -124=timeout, -1=blocked/internal error")
    stdout: str = ""
    stderr: str = ""
    task_id: str | None = None
    command: str | None = None
    duration_sec: float = 0.0
    timed_out: bool = False
    blocked_by_security: bool = False
    security_reason: str | None = None
    snapshot_id: str | None = None
    diagnostics: Diagnostics | None = None
    auto_rolled_back: bool = False
    rollback_unavailable: bool = Field(
        default=False,
        description="Rollback-assurance failure marker — set true when guard errors (fail-loud, not silent); complements auto_rolled_back",
    )
    rollback_skipped_reason: str | None = Field(
        default=None,
        description="Rollback skip reason — rollback was attempted but skipped (stale snapshot/parse failure/not a git repo/repo mismatch); "
        "distinguishes 'not rolled back (not needed)' from 'not rolled back (stale snapshot)' (fail-loud); complements auto_rolled_back/rollback_unavailable",
    )
    trace_id: str | None = Field(
        default=None,
        description="Cross-layer correlation id — backfills the request-side trace_id or an entry-generated one (M-OPS-06)",
    )
    oom_killed: bool = Field(
        default=False,
        description="RSS watchdog trigger marker — child tree killed for exceeding rss_limit_mb (D3-4); accompanied by exit_code -124",
    )
    pid: int | None = Field(
        default=None,
        description="Sandbox child PID — the caller uses it to pass telemetry_stream(pid=...) and sample the real task process "
        "(not the executor itself, RUN-11); present on the stdio path, absent on the blocked/timeout path",
    )
    guard_action_id: str | None = Field(
        default=None,
        description="Guard authorization verdict action_id (Issue #23 Phase 3) — returned when guard decides Block/L3, "
        "for caller audit / manual-confirm loops; None when guard is OFF or Allow/L1/L2",
    )
    cancelled: bool = Field(
        default=False,
        description="Server-side deterministic cancel marker (Issue #32) — after executor.cancel, fe-sandbox "
        "SIGINT→SIGKILLs the process group, Done frame exit_code -1 + cancelled true; False on non-cancel paths",
    )


class GuiResult(BaseModel):
    model_config = _STRICT
    ok: bool = False
    node_tree: str | None = None
    screenshot_png_b64: str | None = None
    screenshot_width: int | None = None
    screenshot_height: int | None = None
    # #38: backing scale factor — physical PNG pixels / logical points (Retina=2.0, non-Retina=1.0).
    # Coordinate contract: GuiAction x/y inputs + inspect_tree AXPosition = logical points;
    #           screenshot_width/height = physical pixels. Callers convert (pixel = point * scale).
    scale_factor: float = 1.0
    # #43: display list JSON (filled by the display_info action) — [{id, scale, bounds:{x,y,w,h}, primary}].
    # None=not a display_info result (backward compatible). fusion-osagent reads scale from it, removing the hardcoded 2.0.
    displays: str | None = None
    error: str | None = None


class EditResult(BaseModel):
    model_config = _STRICT
    ok: bool = False
    path: str | None = None
    error: str | None = None
    matches: int = 0


class GlobEntry(BaseModel):
    model_config = _STRICT
    path: str
    is_dir: bool = False


class GrepMatch(BaseModel):
    model_config = _STRICT
    path: str
    line_number: int
    content: str
    context_before: list[str] = Field(default_factory=list, description="Context lines before the match (-B)")
    context_after: list[str] = Field(default_factory=list, description="Context lines after the match (-A)")


class GrepFileCount(BaseModel):
    model_config = _STRICT
    path: str
    count: int


class GrepOptions(BaseModel):
    model_config = _STRICT
    output_mode: str = Field(default="content", description="content | files_with_matches | count")
    after: int = Field(default=0, description="Extra lines after each match (-A)")
    before: int = Field(default=0, description="Extra lines before each match (-B)")
    context: int = Field(
        default=0, description="Lines of context on both sides of each match (-C, equivalent to max(A,B))"
    )
    multiline: bool = Field(default=False, description="Multiline mode (whole-file buffer matching)")
    glob_include: list[str] = Field(default_factory=list, description="Only match files matching these globs (-g)")
    glob_exclude: list[str] = Field(default_factory=list, description="Exclude files matching these globs (-g '!...')")


class GrepOutput(BaseModel):
    model_config = _STRICT
    output_mode: str = Field(default="content")
    matches: list[GrepMatch] = Field(default_factory=list, description="Matches in content mode")
    files: list[str] = Field(default_factory=list, description="Matched files in files_with_matches mode")
    counts: list[GrepFileCount] = Field(default_factory=list, description="Per-file counts in count mode")


class MultiEditItem(BaseModel):
    model_config = _STRICT
    old_string: str
    new_string: str
    replace_all: bool = Field(
        default=False, description="True=replace all matches; False=unique match required (default)"
    )


class TelemetrySample(BaseModel):
    model_config = _STRICT
    ts_ms: int = Field(description="Sample timestamp (milliseconds, caller epoch)")
    cpu_pct: float = Field(description="Process CPU percentage (single-core multiples)")
    mem_mb: float = Field(description="Process resident memory (MB)")
    gpu_pct: float | None = Field(default=None, description="GPU percentage (caller-injected)")
    gpu_mem_mb: float | None = Field(default=None, description="GPU memory usage (MB, caller-injected)")
    task_id: str | None = Field(default=None, description="Associated task id")


class ShellStartResult(BaseModel):
    model_config = _STRICT
    ok: bool = Field(description="Whether the start succeeded")
    shell_id: str | None = Field(
        default=None, description="Background shell id (sh-N); None on failure or when blocked"
    )
    blocked_by_security: bool = Field(default=False, description="Whether blocked by the security guard")
    security_reason: str | None = Field(default=None, description="Block reason")
    error: str | None = Field(default=None, description="Start error")


class ShellOutput(BaseModel):
    model_config = _STRICT
    shell_id: str = Field(description="Background shell id")
    output: str = Field(description="Accumulated tail snapshot (not incremental; callers dedupe themselves)")
    running: bool = Field(description="Whether still running")
    exit_code: int | None = Field(default=None, description="Exit code (None while running)")


class ShellInfo(BaseModel):
    model_config = _STRICT
    shell_id: str = Field(description="Background shell id")
    pid: int | None = Field(default=None, description="Child process pid")
    task_id: str | None = Field(default=None, description="Associated task id")
    command: str = Field(description="Start command")
    started_at_ms: int = Field(description="Start timestamp (millisecond epoch)")
    finished: bool = Field(description="Whether already exited")
    exit_code: int | None = Field(default=None, description="Exit code (None while running)")


# D6-03 (audit 0827 product): snapshot listing entry — mirrors fe_rollback::SnapshotInfo (read back from the on-disk index).
class SnapshotInfo(BaseModel):
    model_config = _STRICT
    id: str = Field(description="Snapshot id (head:<SHA> / stash:<SHA>,base:<HEAD> / repo:<hash> suffix)")
    created_ms: int = Field(description="Snapshot creation timestamp (millisecond epoch)")
    kind: str = Field(description="Snapshot kind (head baseline / stash with changes)")


# Issue #46: laya-mlx deterministic tool calling — ToolDecision return shape.
# answer_confidence (max prob) is the gate metric — laya-mlx confidence.py states explicitly:
# confidence (entropy) is "not calibrated" and does not transfer across option counts; answer_confidence is
# what the min_confidence gate definition uses. Gate comparisons always use answer_confidence.
class ToolDecision(BaseModel):
    model_config = _STRICT
    tool_id: str = Field(
        description="Selected tool id; 'llm_fallback' on low-confidence degradation; 'none' when no tool is needed"
    )
    confidence: float = Field(description="answer_confidence = max(probabilities) — used for gate comparisons")
    probabilities: dict[str, float] = Field(description="Probability distribution over options (tool_id -> prob)")
    params: dict[str, str | int | None] = Field(
        default_factory=dict,
        description="Extracted parameter slots (file_path/search_query/count etc.); empty dict when no parameters",
    )
    fell_back: bool = Field(
        default=False, description="True=confidence below the gate; the caller should fall back to LLM tool selection"
    )
    latency_ms: float = Field(description="Decision latency (milliseconds, perf_counter)")
    model: str = Field(description="laya model id (e.g. convaiinnovations/laya)")
    usage: dict[str, int | bool | list[str]] | None = Field(
        default=None, description="laya usage (input_tokens/state_tokens/truncated etc.); for diagnostics"
    )
