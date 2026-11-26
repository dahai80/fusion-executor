from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
import socket
from collections.abc import Callable, Iterator
from typing import Any

from .models import (
    Diagnostics,
    EditResult,
    ExecutionResult,
    GlobEntry,
    GrepMatch,
    GrepOutput,
    GuiResult,
    MultiEditItem,
    RollbackPolicy,
    SandboxProfile,
    ShellInfo,
    ShellOutput,
    ShellStartResult,
    SnapshotInfo,
    TelemetrySample,
)

logger = logging.getLogger("fusion_executor")

DEFAULT_SOCK = os.path.expanduser(
    "~/.fusion-executor/fe.sock"
)  # IMPL-1: aligns with Rust M-SEC-01 (HOME-private 0o700)
# D6-01: pidfile — written on serve startup, removed on shutdown. Ops can `kill $(cat fe.pid)` / monitor liveness.
# Lives in the same directory as the socket (~/.fusion-executor/, HOME-private 0o700); never exposes the pid to other users.
DEFAULT_PIDFILE = os.path.expanduser("~/.fusion-executor/fe.pid")
SUB_CHANNELS = ("telemetry", "stdio", "screenshot")
# P-2: subscription line-buffer cap — guards against corrupted streams (no newline) / oversized frames; on overflow drop the buffer and treat as end-of-stream
_SUB_BUF_MAX_BYTES = 8 * 1024 * 1024


def ensure_socket_dir(path: str = DEFAULT_SOCK) -> None:
    # IMPL-1: aligns with Rust M-SEC-01 — default socket lives in ~/.fusion-executor/ (HOME-private, 0o700).
    # Ensure the directory exists before serve (the Rust side also mkdirs; doing it here first prevents a missing path before bind; no-op when the parent of a custom path already exists).
    # makedirs mode only applies at creation; an existing directory (e.g. leftover 0o755) must be explicitly chmod'ed to tighten it, otherwise the auth premise is broken.
    sock_dir = os.path.dirname(path) or os.path.expanduser("~/.fusion-executor")
    try:
        os.makedirs(sock_dir, mode=0o700, exist_ok=True)
        if os.path.isdir(sock_dir):
            os.chmod(sock_dir, 0o700)
    except OSError as e:
        logger.warning("ensure_socket_dir failed to create %s: %s", sock_dir, e)


def write_pidfile(path: str = DEFAULT_PIDFILE) -> None:
    # D6-01: write the pidfile on serve startup. The directory is created first by ensure_socket_dir (same dir as the socket).
    # Failure does not block serve (the pidfile is an ops aid, not security-critical) — fail-visible warning, keep serving.
    try:
        pid_dir = os.path.dirname(path)
        if pid_dir:
            os.makedirs(pid_dir, mode=0o700, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
        logger.info("pidfile written to %s (pid=%d)", path, os.getpid())
    except OSError as e:
        logger.warning("pidfile write to %s failed: %s — ops monitoring will be unavailable, serve continues", path, e)


def remove_pidfile(path: str = DEFAULT_PIDFILE) -> None:
    # D6-01: remove the pidfile on serve shutdown. Silently no-op when absent (write failed or already removed); warn without raising on delete failure.
    try:
        if os.path.exists(path):
            os.unlink(path)
            logger.info("pidfile removed %s", path)
    except OSError as e:
        logger.warning("pidfile removal of %s failed: %s", path, e)


class FusionSandboxExecutor:
    def __init__(
        self,
        sock_path: str | None = None,
        *,
        extra_whitelist: list[str] | None = None,
        disable_bundle_allowlist: bool = False,
        allow_inline_interpreter: bool = False,
        trusted_bin_dirs: list[str] | None = None,
        guard_sock: str | None = None,
        guard_tenant: str | None = None,
    ) -> None:
        try:
            from ._native import NativeExecutor
        except ImportError as e:
            raise ImportError(
                "fusion_executor._native not loaded — run `maturin develop` to build the native extension"
            ) from e
        # RUN-12: disable_bundle_allowlist=True disables the GUI foreground-app allowlist (unrestricted opt-in, audit-logged only);
        #         the default False uses the secure default set (Terminal/TextEdit/finder). Pass True when driving arbitrary apps on test machines.
        # D3-1 (audit 0827 product): allow_inline_interpreter=True enables inline interpreters (python -c / node -e
        #   / ruby -e / perl -e); default False (enterprise hardening rejects inline code, preventing agent-driven arbitrary payloads from bypassing allowlist semantics).
        #   Test machines / local interactive scenarios that rely on python3 -c must pass True explicitly to opt in.
        # D3-6 (audit 0827 product 4-layer): trusted_bin_dirs registers directories holding project tools — tools in extra_whitelist
        #   must resolve into a trusted directory to be allowed (fail-closed against /tmp/python3 poisoning). Tests/callers register their project bin dirs.
        # Issue #23 (Phase 3): guard authorization orchestration is OFF by default — pass guard_sock explicitly or set FUSION_GUARD_SOCK to enable,
        #   each command's verdict (allow/preview/redact/block + risk level L1-L4) is queried from the fusion-guard daemon before execution.
        #   Guard-outage degradation is fail-closed (cached regex rules + static allowlist fence, never fail-open).
        #   guard_tenant / FUSION_EXECUTOR_TENANT must match the tenant bound to this host identity in the guard config, otherwise auth fails.
        guard_sock = guard_sock if guard_sock is not None else os.environ.get("FUSION_GUARD_SOCK")
        guard_tenant = guard_tenant if guard_tenant is not None else os.environ.get("FUSION_EXECUTOR_TENANT")
        self._native = NativeExecutor(
            extra_whitelist,
            disable_bundle_allowlist,
            allow_inline_interpreter,
            trusted_bin_dirs,
            guard_sock,
            guard_tenant,
        )
        self._sock_path = sock_path

    def run(
        self,
        command: str,
        *,
        task_id: str | None = None,
        cwd: str | None = None,
        timeout_sec: float = 30.0,
        env_vars: dict[str, str] | None = None,
        enable_rollback_snapshot: bool = False,
        auto_rollback: RollbackPolicy | None = None,
        # ARCH-1: default True — aligns with fe-core serde default_true (commercial security default).
        # Trusted local callers can opt out by passing seatbelt=False explicitly. The old default False was inconsistent
        # with the UDS execute path (serde default true).
        seatbelt: bool = True,
        inherit_env: bool = False,
        use_pty: bool = True,
        max_nproc: int = 1024,
        max_cpu_sec: int = 0,
        max_nofile: int = 1024,
        rss_limit_mb: int = 2048,
        trace_id: str | None = None,
        sandbox: SandboxProfile | None = None,
    ) -> ExecutionResult:
        # M-PY-01: top-level upfront validation, fail early with friendly errors (instead of deferring to PyO3 panic/TypeError)
        if not isinstance(command, str):
            raise TypeError(f"command must be str, got {type(command).__name__}")
        if timeout_sec is not None and timeout_sec <= 0:
            raise ValueError(f"timeout_sec must be positive, got {timeout_sec}")
        if cwd is not None and not isinstance(cwd, str):
            raise TypeError(f"cwd must be str|None, got {type(cwd).__name__}")
        if env_vars is not None:
            if not isinstance(env_vars, dict):
                raise TypeError(f"env_vars must be dict|None, got {type(env_vars).__name__}")
            for k, v in env_vars.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise TypeError(
                        f"env_vars keys and values must both be str, got ({type(k).__name__},{type(v).__name__})"
                    )
        if not isinstance(max_nproc, int) or max_nproc < 0:
            raise ValueError(f"max_nproc must be a non-negative int, got {max_nproc!r}")
        if not isinstance(max_cpu_sec, int) or max_cpu_sec < 0:
            raise ValueError(f"max_cpu_sec must be a non-negative int, got {max_cpu_sec!r}")
        if not isinstance(max_nofile, int) or max_nofile < 0:
            raise ValueError(f"max_nofile must be a non-negative int, got {max_nofile!r}")
        if not isinstance(rss_limit_mb, int) or rss_limit_mb < 0:
            raise ValueError(f"rss_limit_mb must be a non-negative int, got {rss_limit_mb!r}")
        logger.debug(
            "run command=%r timeout_sec=%s cwd=%s task_id=%s inherit_env=%s use_pty=%s max_nproc=%s max_cpu_sec=%s max_nofile=%s rss_limit_mb=%s",
            command,
            timeout_sec,
            cwd,
            task_id,
            inherit_env,
            use_pty,
            max_nproc,
            max_cpu_sec,
            max_nofile,
            rss_limit_mb,
        )
        policy_dict = auto_rollback.model_dump() if auto_rollback is not None else None
        sandbox_dict = sandbox.model_dump() if sandbox is not None else None
        native = self._native.execute_sync(
            command,
            task_id,
            cwd,
            timeout_sec,
            env_vars,
            enable_rollback_snapshot,
            policy_dict,
            seatbelt,
            inherit_env,
            use_pty,
            max_nproc,
            max_cpu_sec,
            max_nofile,
            rss_limit_mb,
            trace_id,
            sandbox_dict,
        )
        diag = None
        if native.diagnostics is not None:
            nd = native.diagnostics
            diag = Diagnostics(
                error_type=nd.error_type,
                file_path=nd.file_path,
                line_number=nd.line_number,
                code_snippet=nd.code_snippet,
                raw_trace=nd.raw_trace,
            )
        result = ExecutionResult(
            exit_code=native.exit_code,
            stdout=native.stdout,
            stderr=native.stderr,
            task_id=native.task_id,
            command=native.command,
            duration_sec=native.duration_sec,
            timed_out=native.timed_out,
            blocked_by_security=native.blocked_by_security,
            security_reason=native.security_reason,
            snapshot_id=native.snapshot_id,
            diagnostics=diag,
            auto_rolled_back=native.auto_rolled_back,
            rollback_unavailable=native.rollback_unavailable,
            rollback_skipped_reason=native.rollback_skipped_reason,
            trace_id=native.trace_id,
            oom_killed=native.oom_killed,
            pid=native.pid,
            guard_action_id=native.guard_action_id,
        )
        logger.info(
            "run done exit=%s blocked=%s timed_out=%s oom=%s diag=%s rolled_back=%s rb_unavail=%s rb_skipped=%s dur=%.3fs",
            result.exit_code,
            result.blocked_by_security,
            result.timed_out,
            result.oom_killed,
            result.diagnostics.error_type if result.diagnostics else None,
            result.auto_rolled_back,
            result.rollback_unavailable,
            result.rollback_skipped_reason,
            result.duration_sec,
        )
        return result

    async def run_async(self, command: str, **kw) -> ExecutionResult:
        # C-PYO3-01: older version did `return self.run(...)` — fake async, synchronous blocking of the event loop
        # (BLOCKING_RT.block_on inside run holds the GIL, stalling the asyncio loop). Now asyncio.to_thread
        # pushes the synchronous run onto a thread pool so the event loop can run other coroutines concurrently.
        return await asyncio.to_thread(self.run, command, **kw)

    def run_streaming(
        self,
        command: str,
        *,
        task_id: str | None = None,
        cwd: str | None = None,
        timeout_sec: float = 30.0,
        env_vars: dict[str, str] | None = None,
        enable_rollback_snapshot: bool = False,
        auto_rollback: RollbackPolicy | None = None,
        # ARCH-1: default True — aligns with fe-core serde default_true + run() (see comment above).
        seatbelt: bool = True,
        inherit_env: bool = False,
        use_pty: bool = True,
        max_nproc: int = 1024,
        max_cpu_sec: int = 0,
        max_nofile: int = 1024,
        rss_limit_mb: int = 2048,
        trace_id: str | None = None,
        sandbox: SandboxProfile | None = None,
    ) -> Iterator[str | ExecutionResult]:
        # M-PY-01: same upfront validation as run()
        if not isinstance(command, str):
            raise TypeError(f"command must be str, got {type(command).__name__}")
        if timeout_sec is not None and timeout_sec <= 0:
            raise ValueError(f"timeout_sec must be positive, got {timeout_sec}")
        if not isinstance(max_nproc, int) or max_nproc < 0:
            raise ValueError(f"max_nproc must be a non-negative int, got {max_nproc!r}")
        if not isinstance(max_cpu_sec, int) or max_cpu_sec < 0:
            raise ValueError(f"max_cpu_sec must be a non-negative int, got {max_cpu_sec!r}")
        if not isinstance(max_nofile, int) or max_nofile < 0:
            raise ValueError(f"max_nofile must be a non-negative int, got {max_nofile!r}")
        if not isinstance(rss_limit_mb, int) or rss_limit_mb < 0:
            raise ValueError(f"rss_limit_mb must be a non-negative int, got {rss_limit_mb!r}")
        # Streaming backend is PTY-only: use_pty=False has no stdio streaming implementation yet (run_streaming goes
        # through portable-pty to keep ANSI/Traceback fidelity — the main point of streaming). For separate stderr use run(use_pty=False).
        if not use_pty:
            raise ValueError(
                "run_streaming does not support use_pty=False yet (no stdio streaming backend; use run() for split streams)"
            )
        logger.debug(
            "run_streaming command=%r timeout_sec=%s cwd=%s task_id=%s inherit_env=%s use_pty=%s max_nproc=%s max_cpu_sec=%s max_nofile=%s rss_limit_mb=%s",
            command,
            timeout_sec,
            cwd,
            task_id,
            inherit_env,
            use_pty,
            max_nproc,
            max_cpu_sec,
            max_nofile,
            rss_limit_mb,
        )
        policy_dict = auto_rollback.model_dump() if auto_rollback is not None else None
        sandbox_dict = sandbox.model_dump() if sandbox is not None else None
        it = self._native.execute_streaming(
            command,
            task_id,
            cwd,
            timeout_sec,
            env_vars,
            enable_rollback_snapshot,
            policy_dict,
            seatbelt,
            inherit_env,
            use_pty,
            max_nproc,
            max_cpu_sec,
            max_nofile,
            rss_limit_mb,
            trace_id,
            sandbox_dict,
        )
        for frame in it:
            # L-PY-02: strict keys (old .get(default) swallowed serde bugs; a missing field silently looked like "blocked")
            ftype = frame["type"]
            if ftype == "chunk":
                data = frame.get("data", "")
                logger.debug("stream chunk len=%s", len(data))
                yield data
            elif ftype == "done":
                # serde tag="type" → Done(ExecutionResult) flattens into {"type":"done", exit_code:..., ...}
                result = self._native_result(frame)
                logger.info(
                    "stream done exit=%s blocked=%s timed_out=%s diag=%s",
                    result.exit_code,
                    result.blocked_by_security,
                    result.timed_out,
                    result.diagnostics.error_type if result.diagnostics else None,
                )
                yield result
                return
            else:
                # M-6: unknown frame type (new frame from protocol evolution / corrupted frame) — don't raise, stay forward-compatible, but log at debug for traceability
                logger.debug("unknown stream frame type=%r, skipping (forward-compatible)", ftype)

    def _native_result(self, payload: dict) -> ExecutionResult:
        # L-PY-02: strict validation (old .get(default) swallowed missing fields; when Rust renamed a field / serde bug,
        # a successful command silently returned exit_code=-1 looking like blocked/internal error). model_validate raises
        # ValidationError fail-loud; diagnostics is optional and built separately.
        diag = None
        nd = payload.get("diagnostics")
        if nd is not None:
            diag = Diagnostics(
                error_type=nd.get("error_type"),
                file_path=nd.get("file_path"),
                line_number=nd.get("line_number"),
                code_snippet=nd.get("code_snippet"),
                raw_trace=nd.get("raw_trace"),
            )
        # type=done frame: serde flattens Done into the outer layer with type/exit_code/..., validated in one model_validate
        # drop the type field before validating (type is a stream marker, not an ExecutionResult field)
        fields = {k: v for k, v in payload.items() if k != "type"}
        fields["diagnostics"] = diag
        return ExecutionResult.model_validate(fields)

    def rollback(self, snapshot_id: str, cwd: str | None = None) -> bool:
        if cwd is None:
            raise ValueError("rollback requires cwd")
        logger.info("rollback snapshot=%s cwd=%s", snapshot_id, cwd)
        return self._native.rollback(snapshot_id, cwd)

    def snapshot_create(self, cwd: str) -> str:
        logger.info("snapshot_create cwd=%s", cwd)
        return self._native.snapshot_create(cwd)

    def list_snapshots(self, cwd: str) -> list[SnapshotInfo]:
        # D6-03 (audit 0827 product): snapshot listing — read back from the on-disk index, for ops audit / live snapshot discovery.
        # Stateless (M-ARCH-1): only reads the index for the given cwd; the executor holds no snapshot state.
        logger.info("list_snapshots cwd=%s", cwd)
        native_list = self._native.list_snapshots(cwd)
        out = [SnapshotInfo.model_validate(s.to_dict()) for s in native_list]
        logger.info("list_snapshots done count=%d cwd=%s", len(out), cwd)
        return out

    def validate(self, command: str) -> dict:
        # Issue #11 / #12.4: pre-execution validation without executing — the caller asks the user for authorization before run
        # (Option A: caller owns gating). The executor only enforces the hard blocklist (never-blocked); interactive confirmation belongs to the caller.
        # Returns {allowed: bool, blocked: bool, reason: str|None, stage: "regex"|"tokenizer"|None}
        if not isinstance(command, str) or not command.strip():
            raise ValueError(f"command must be a non-empty string, got {command!r}")
        result = self._native.validate(command)
        logger.info("validate command=%r allowed=%s blocked=%s", command, result.get("allowed"), result.get("blocked"))
        return result

    def file_edit(
        self,
        path: str,
        old_string: str,
        new_string: str,
        *,
        cwd: str | None = None,
        replace_all: bool = False,
    ) -> EditResult:
        logger.debug("file_edit path=%r cwd=%s replace_all=%s", path, cwd, replace_all)
        native = self._native.file_edit(path, old_string, new_string, cwd, replace_all)
        result = EditResult(
            ok=native.ok,
            path=native.path,
            error=native.error,
            matches=native.matches,
        )
        logger.info("file_edit done ok=%s matches=%s path=%s", result.ok, result.matches, result.path)
        return result

    def write_file(
        self,
        path: str,
        content: str,
        *,
        cwd: str | None = None,
    ) -> EditResult:
        logger.debug("write_file path=%r cwd=%s bytes=%s", path, cwd, len(content))
        native = self._native.write_file(path, content, cwd)
        result = EditResult(
            ok=native.ok,
            path=native.path,
            error=native.error,
            matches=native.matches,
        )
        logger.info("write_file done ok=%s path=%s", result.ok, result.path)
        return result

    def shell_start(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env_vars: dict[str, str] | None = None,
        task_id: str | None = None,
        max_output_chars: int = 100000,
        seatbelt: bool = True,
        inherit_env: bool = False,
        max_nproc: int = 1024,
        max_cpu_sec: int = 0,
        max_nofile: int = 1024,
        max_idle_sec: int = 3600,
        kill_grace_ms: int = 500,
        sandbox: SandboxProfile | None = None,
    ) -> ShellStartResult:
        if not isinstance(max_idle_sec, int) or max_idle_sec < 0:
            raise ValueError(f"max_idle_sec must be a non-negative int, got {max_idle_sec!r}")
        if not isinstance(kill_grace_ms, int) or kill_grace_ms < 0:
            raise ValueError(f"kill_grace_ms must be a non-negative int, got {kill_grace_ms!r}")
        if not isinstance(max_nofile, int) or max_nofile < 0:
            raise ValueError(f"max_nofile must be a non-negative int, got {max_nofile!r}")
        if sandbox is not None and not isinstance(sandbox, SandboxProfile):
            raise TypeError(f"sandbox must be SandboxProfile | None, got {type(sandbox).__name__}")
        sandbox_payload = sandbox.model_dump() if sandbox is not None else None
        logger.debug(
            "shell_start command=%r cwd=%s task_id=%s seatbelt=%s inherit_env=%s max_idle_sec=%s kill_grace_ms=%s max_nofile=%s sandbox=%s",
            command,
            cwd,
            task_id,
            seatbelt,
            inherit_env,
            max_idle_sec,
            kill_grace_ms,
            max_nofile,
            sandbox_payload is not None,
        )
        native = self._native.shell_start(
            command,
            cwd,
            env_vars,
            task_id,
            max_output_chars,
            seatbelt,
            inherit_env,
            max_nproc,
            max_cpu_sec,
            max_nofile,
            max_idle_sec,
            kill_grace_ms,
            sandbox_payload,
        )
        result = ShellStartResult.model_validate(native.to_dict())
        logger.info(
            "shell_start done ok=%s shell_id=%s blocked=%s",
            result.ok,
            result.shell_id,
            result.blocked_by_security,
        )
        return result

    def shell_output(self, shell_id: str) -> ShellOutput:
        logger.debug("shell_output id=%s", shell_id)
        native = self._native.shell_output(shell_id)
        result = ShellOutput.model_validate(native.to_dict())
        logger.info(
            "shell_output done id=%s running=%s exit=%s out_len=%s",
            result.shell_id,
            result.running,
            result.exit_code,
            len(result.output),
        )
        return result

    def kill_shell(self, shell_id: str) -> bool:
        logger.debug("kill_shell id=%s", shell_id)
        ok = self._native.kill_shell(shell_id)
        logger.info("kill_shell done id=%s ok=%s", shell_id, ok)
        return ok

    def list_shells(self) -> list[ShellInfo]:
        logger.debug("list_shells")
        native_list = self._native.list_shells()
        out = [ShellInfo.model_validate(i.to_dict()) for i in native_list]
        logger.info("list_shells done count=%s", len(out))
        return out

    def multi_edit(
        self,
        path: str,
        edits: list[MultiEditItem | dict],
        *,
        cwd: str | None = None,
    ) -> EditResult:
        logger.debug("multi_edit path=%r cwd=%s edits=%s", path, cwd, len(edits))
        items = [e if isinstance(e, MultiEditItem) else MultiEditItem.model_validate(e) for e in edits]
        payload = [item.model_dump() for item in items]
        native = self._native.multi_edit(path, payload, cwd)
        result = EditResult(
            ok=native.ok,
            path=native.path,
            error=native.error,
            matches=native.matches,
        )
        logger.info("multi_edit done ok=%s matches=%s path=%s", result.ok, result.matches, result.path)
        return result

    def notebook_edit(
        self,
        path: str,
        new_source: str,
        *,
        cell_id: str | None = None,
        cell_number: int | None = None,
        edit_mode: str = "replace",
        cwd: str | None = None,
    ) -> EditResult:
        logger.debug(
            "notebook_edit path=%r cell_id=%s cell_number=%s mode=%s cwd=%s",
            path,
            cell_id,
            cell_number,
            edit_mode,
            cwd,
        )
        native = self._native.notebook_edit(path, new_source, cell_id, cell_number, edit_mode, cwd)
        result = EditResult(
            ok=native.ok,
            path=native.path,
            error=native.error,
            matches=native.matches,
        )
        logger.info("notebook_edit done ok=%s mode=%s path=%s", result.ok, edit_mode, result.path)
        return result

    def glob(self, pattern: str, *, cwd: str | None = None) -> list[GlobEntry]:
        logger.debug("glob pattern=%r cwd=%s", pattern, cwd)
        native_entries = self._native.glob(pattern, cwd)
        out = [GlobEntry(path=e.path, is_dir=e.is_dir) for e in native_entries]
        logger.info("glob done count=%s", len(out))
        return out

    def grep(
        self,
        pattern: str,
        paths: list[str],
        *,
        cwd: str | None = None,
    ) -> list[GrepMatch]:
        logger.debug("grep pattern=%r paths=%s cwd=%s", pattern, paths, cwd)
        native_matches = self._native.grep(pattern, paths, cwd)
        out = [
            GrepMatch(
                path=m.path,
                line_number=m.line_number,
                content=m.content,
                context_before=list(m.context_before),
                context_after=list(m.context_after),
            )
            for m in native_matches
        ]
        logger.info("grep done matches=%s", len(out))
        return out

    def grep_with_opts(
        self,
        pattern: str,
        paths: list[str],
        opts: dict,
        *,
        cwd: str | None = None,
    ) -> GrepOutput:
        logger.debug("grep_with_opts pattern=%r paths=%s opts=%s cwd=%s", pattern, paths, opts, cwd)
        native = self._native.grep_with_opts(pattern, paths, opts, cwd)
        data = native.to_dict()
        result = GrepOutput.model_validate(data)
        logger.info(
            "grep_with_opts done mode=%s matches=%s files=%s counts=%s",
            result.output_mode,
            len(result.matches),
            len(result.files),
            len(result.counts),
        )
        return result

    def apply_patch(self, diff: str, *, cwd: str | None = None) -> EditResult:
        logger.debug("apply_patch cwd=%s diff_len=%s", cwd, len(diff))
        native = self._native.apply_patch(diff, cwd)
        result = EditResult(
            ok=native.ok,
            path=native.path,
            error=native.error,
            matches=native.matches,
        )
        logger.info("apply_patch done ok=%s matches=%s path=%s", result.ok, result.matches, result.path)
        return result

    def replace_function(
        self,
        path: str,
        fn_name: str,
        new_body: str,
        *,
        cwd: str | None = None,
    ) -> EditResult:
        logger.debug("replace_function path=%r fn=%s cwd=%s", path, fn_name, cwd)
        native = self._native.replace_function(path, fn_name, new_body, cwd)
        result = EditResult(
            ok=native.ok,
            path=native.path,
            error=native.error,
            matches=native.matches,
        )
        logger.info("replace_function done ok=%s fn=%s", result.ok, fn_name)
        return result

    def gui_action(self, action: dict) -> GuiResult:
        # M-PY-02: pre-validate the dict + kind field (the old version accepted None/"string"/{} and let them all go
        # through the Rust round-trip, returning an error string with no structured fields). Only rejects wrong types + missing kind;
        # unknown kinds pass through so Rust can degrade (ok=false, preserving the test_gui_action_bad_kind_degrades contract).
        if not isinstance(action, dict):
            raise TypeError(f"action must be dict, got {type(action).__name__}")
        if "kind" not in action:
            raise ValueError("action is missing the 'kind' field")
        kind = action["kind"]
        if not isinstance(kind, str):
            raise TypeError(f"action['kind'] must be str, got {type(kind).__name__}")
        logger.debug("gui_action kind=%s action=%s", kind, action)
        native = self._native.gui_action(action)
        result = GuiResult(
            ok=native.ok,
            node_tree=native.node_tree,
            screenshot_png_b64=native.screenshot_png_b64,
            screenshot_width=native.screenshot_width,
            screenshot_height=native.screenshot_height,
            scale_factor=native.scale_factor,
            displays=native.displays,
            error=native.error,
        )
        logger.info(
            "gui_action done ok=%s has_tree=%s has_shot=%s err=%s",
            result.ok,
            result.node_tree is not None,
            result.screenshot_png_b64 is not None,
            result.error,
        )
        return result

    def gui_action_batch(self, actions: list[dict]) -> list[GuiResult]:
        # #39: batched atomic action pipeline — executes multiple actions in order, collecting a GuiResult per step.
        # Not transactional: a step failure does not abort later steps (the caller decides retry/compensation based on each step's ok).
        if not isinstance(actions, list):
            raise TypeError(f"actions must be list, got {type(actions).__name__}")
        for i, a in enumerate(actions):
            if not isinstance(a, dict):
                raise TypeError(f"actions[{i}] must be dict, got {type(a).__name__}")
            if "kind" not in a:
                raise ValueError(f"actions[{i}] is missing the 'kind' field")
            kind = a["kind"]
            if not isinstance(kind, str):
                raise TypeError(f"actions[{i}]['kind'] must be str, got {type(kind).__name__}")
        logger.debug("gui_action_batch count=%d", len(actions))
        natives = self._native.gui_action_batch(actions)
        results = [
            GuiResult(
                ok=n.ok,
                node_tree=n.node_tree,
                screenshot_png_b64=n.screenshot_png_b64,
                screenshot_width=n.screenshot_width,
                screenshot_height=n.screenshot_height,
                scale_factor=n.scale_factor,
                displays=n.displays,
                error=n.error,
            )
            for n in natives
        ]
        logger.info(
            "gui_action_batch done count=%d ok_count=%d",
            len(results),
            sum(1 for r in results if r.ok),
        )
        return results

    def telemetry_stream(
        self,
        *,
        interval_ms: int = 100,
        max_samples: int = 0,
        pid: int | None = None,
    ) -> Iterator[TelemetrySample]:
        logger.debug(
            "telemetry_stream interval_ms=%s max_samples=%s pid=%s",
            interval_ms,
            max_samples,
            pid,
        )
        it = self._native.telemetry_stream(interval_ms, max_samples, pid)
        for count, frame in enumerate(it, start=1):
            # 3.11: strict model_validate (old frame.get("ts_ms", 0) defaulted to 0 — when Rust renamed a field /
            # serde bug, missing fields were silently swallowed and fake ts_ms=0/cpu=0 data entered the pipeline).
            # Blocker 11 _STRICT extra=forbid; missing required ts_ms/cpu_pct/mem_mb → ValidationError fail-loud.
            sample = TelemetrySample.model_validate(frame)
            logger.debug("telemetry sample #%s cpu=%.1f%% mem=%.1fMB", count, sample.cpu_pct, sample.mem_mb)
            yield sample

    def subscribe(
        self,
        channels: list[str],
        *,
        sock_path: str | None = None,
        interval_ms: int | None = None,
        screenshot_interval_ms: int | None = None,
        scope: str | list[str] = "own_conn",
        idle_timeout: float | None = None,
    ) -> Subscription:
        logger.info(
            "subscribe channels=%s sock=%s interval_ms=%s scope=%s idle_timeout=%s",
            channels,
            sock_path,
            interval_ms,
            scope,
            idle_timeout,
        )
        # M-PY-03: reject an empty channel list explicitly (the old bad check found no bad items for an empty list → passed →
        # opened a subscription with no channel interest → never received pushes → __next__ blocked 15s then TimeoutError instead of StopIteration)
        if not channels:
            raise ValueError("channels must not be empty")
        bad = [c for c in channels if c not in SUB_CHANNELS]
        if bad:
            raise ValueError(f"unknown channels: {bad}, options {list(SUB_CHANNELS)}")
        # scope only applies to the stdio channel (Blocker 10, closes the audit §2.9 cross-tenant leak):
        #   "all" → full broadcast; ["id1",..] → task_id allowlist; "own_conn" (default) → only this connection's commands
        if scope not in ("all", "own_conn") and not isinstance(scope, list):
            raise ValueError("scope must be 'all' | 'own_conn' | a list of task_ids")
        # 3.13: idle_timeout None = no timeout (long-stream consumers); a number = recv timeout in seconds (old
        # hardcoded 15s meant slow pushes >15s → spurious StopIteration). The subscription handshake must use a finite
        # timeout; after that switch to idle_timeout.
        path = sock_path or self._sock_path or os.environ.get("FUSION_EXECUTOR_SOCK", DEFAULT_SOCK)
        sub = Subscription(path, channels, interval_ms, screenshot_interval_ms, scope, idle_timeout)
        sub._open()
        return sub

    def metrics(self, sock_path: str | None = None) -> dict:
        # C-OPS-05: ops metrics — calls executor.metrics over UDS to read server runtime counters
        # (exec_total/blocked/timeout/success/failed + duration/stdio aggregates + rollback).
        # Must be called against a running serve() instance (no server → ConnectionRefused).
        path = sock_path or self._sock_path or os.environ.get("FUSION_EXECUTOR_SOCK", DEFAULT_SOCK)
        req = {"jsonrpc": "2.0", "id": 1, "method": "executor.metrics", "params": {}}
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        try:
            sock.connect(path)
            sock.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            line = buf.split(b"\n", 1)[0].decode("utf-8").strip()
            resp = json.loads(line) if line else {}
            if "error" in resp:
                raise RuntimeError(f"metrics failed: {resp['error']}")
            logger.info("metrics ok: %s", resp.get("result"))
            return resp.get("result", {})
        finally:
            sock.close()

    def metrics_prometheus(self, sock_path: str | None = None) -> str:
        # M-OPS-02: Prometheus text format — calls executor.metrics_prometheus over UDS to fetch the
        # scrape text (fe_exec_total/fe_shell_active/fe_connections... + HELP/TYPE headers).
        # No HTTP port is opened (keeps M-SEC-01 UDS-only); the caller feeds its own exporter or dashboard directly.
        # recorder install failure → -32603; the caller degrades to the metrics() JSON.
        path = sock_path or self._sock_path or os.environ.get("FUSION_EXECUTOR_SOCK", DEFAULT_SOCK)
        req = {"jsonrpc": "2.0", "id": 1, "method": "executor.metrics_prometheus", "params": {}}
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        try:
            sock.connect(path)
            sock.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            line = buf.split(b"\n", 1)[0].decode("utf-8").strip()
            resp = json.loads(line) if line else {}
            if "error" in resp:
                raise RuntimeError(f"metrics_prometheus failed: {resp['error']}")
            text = resp.get("result", {}).get("text", "")
            logger.info("metrics_prometheus ok: %d bytes", len(text))
            return text
        finally:
            sock.close()

    def cancel_stream(self, stream_id, *, sock_path: str | None = None) -> bool:
        # Issue #32: server-side deterministic cancel — sends executor.cancel {id} to a running serve(),
        # after which fe-sandbox SIGINT→SIGKILLs the process tree (not a cooperative stop); matches the execute_stream
        # Done frame exit_code -1 + cancelled true. stream_id = the JSON-RPC request id of the execute_stream call
        # (aligned with the fusion-code client contract). Best-effort: finished/unknown id → False, no raise.
        path = sock_path or self._sock_path or os.environ.get("FUSION_EXECUTOR_SOCK", DEFAULT_SOCK)
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "executor.cancel",
            "params": {"id": stream_id},
        }
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        try:
            sock.connect(path)
            sock.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            line = buf.split(b"\n", 1)[0].decode("utf-8").strip()
            resp = json.loads(line) if line else {}
            if "error" in resp:
                raise RuntimeError(f"cancel_stream failed: {resp['error']}")
            ok = bool(resp.get("result", {}).get("cancelled", False))
            logger.info("cancel_stream id=%s cancelled=%s", stream_id, ok)
            return ok
        finally:
            sock.close()

    def agent_run(
        self,
        user_request: str,
        *,
        max_steps: int = 8,
        backend: str = "http",
        mlx_url: str | None = None,
        api_key: str | None = None,
        min_confidence: float = 0.7,
        whitelist: dict[str, str] | None = None,
        extra_handlers: dict[str, Callable[[dict], Any]] | None = None,
        context: str = "",
    ) -> dict[str, Any]:
        # Issue #46 AC7: AgentLoop wired into the executor pipeline — LayaToolSelector picks a tool →
        # this executor runs it (self.run/self.grep/...) → the result is fed back → repeat.
        # Replaces the "LLM generates tool-call JSON" step (deterministic laya choice primitive, not LLM free text).
        #
        # Default backend="http" — the executor is an L4 OS tool and does not load a local laya model;
        # the HTTP backend calls fusion-mlx /v1/laya/decide (production inference path, no laya_mlx dependency).
        # backend="python" calls laya_mlx.Agent.system_one directly (lower latency, requires a local model cache).
        #
        # UDS exposure deferred — fe-ipc is a pure-Rust UDS server (no Python callbacks), laya is a Python dependency;
        # cross-process callers (fusion-code) can call agent_run via the Python API directly, or file a separate UDS agent.run issue later.
        from .agent_loop import AgentLoop
        from .laya_tool_selector import LayaToolSelector

        if not isinstance(user_request, str):
            raise TypeError(f"user_request must be str, got {type(user_request).__name__}")
        if max_steps < 1:
            raise ValueError(f"max_steps must be >= 1, got {max_steps}")
        logger.info(
            "agent_run request=%r backend=%s max_steps=%s min_confidence=%s — wiring AgentLoop",
            user_request[:80],
            backend,
            max_steps,
            min_confidence,
        )
        selector = LayaToolSelector(
            min_confidence=min_confidence,
            backend=backend,
            mlx_url=mlx_url,
            api_key=api_key,
        )
        loop = AgentLoop(
            selector,
            executor=self,
            max_steps=max_steps,
            whitelist=whitelist,
            extra_handlers=extra_handlers,
        )
        result = loop.run(user_request, context=context)
        logger.info(
            "agent_run done: completed=%s final_tool=%s step_count=%s metrics=%s",
            result["completed"],
            result["final_tool"],
            result["step_count"],
            result["metrics"],
        )
        return result

    def serve(self, sock_path: str | None = None) -> None:
        # C-PYO3-02: the old version called bare self._native.serve() — fe-pyo3 serve_blocking has no shutdown
        # handle, so SIGINT/SIGTERM left a stale socket behind. Now signal handling + try/finally cleanup:
        # register SIGINT/SIGTERM → raise KeyboardInterrupt to break out of serve_blocking, finally
        # os.unlink the stale socket. serve_blocking blocks on recv; signals interrupt the main thread.
        # 3.15: resolve the path (env/default) and pass it uniformly to Rust — the old version passed the raw
        # sock_path (possibly None), a different source from the path used for the finally cleanup (env-resolved).
        # Although Rust also resolved the env and they coincidentally matched, passing the path explicitly removes
        # the implicit env dependency so cleanup and listening use exactly the same path.
        path = sock_path or os.environ.get("FUSION_EXECUTOR_SOCK", DEFAULT_SOCK)
        pid_path = os.environ.get("FUSION_EXECUTOR_PIDFILE", DEFAULT_PIDFILE)
        # IMPL-1: ensure the socket parent directory exists before serve (default ~/.fusion-executor/ 0o700, aligns with Rust M-SEC-01).
        ensure_socket_dir(path)
        # D6-01: write the pidfile (for ops monitoring/kill). Same dir as the socket; the directory was created by ensure_socket_dir.
        write_pidfile(pid_path)
        # ARCH-1: seatbelt governance — both execute + shell_start default to true (commercial security default, aligns with fe-core serde default_true).
        # Callers can explicitly pass seatbelt:false to disable isolation (trusted local opt-out).
        logger.info(
            "seatbelt enabled by default (execute + shell_start paths) — macOS sandbox-exec isolation. Trusted local callers can pass seatbelt:false to opt out."
        )
        logger.info("serve sock=%s — starting UDS JSON-RPC server (stoppable by signal)", path)
        old_int = signal.getsignal(signal.SIGINT)
        old_term = signal.getsignal(signal.SIGTERM)
        raised = False
        signal.signal(signal.SIGINT, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
        try:
            self._native.serve(path)
        except KeyboardInterrupt:
            raised = True
            logger.info("serve received shutdown signal, closing server")
        finally:
            signal.signal(signal.SIGINT, old_int)
            signal.signal(signal.SIGTERM, old_term)
            if os.path.exists(path):
                try:
                    os.unlink(path)
                    logger.info("serve cleaned up stale socket %s", path)
                except OSError as e:
                    logger.warning("serve socket cleanup failed %s: %s", path, e)
            # D6-01: remove the pidfile on shutdown (normal + signal + exception paths all go through finally)
            remove_pidfile(pid_path)
            if raised:
                raise KeyboardInterrupt("serve shut down")


class Subscription:
    def __init__(
        self,
        sock_path: str,
        channels: list[str],
        interval_ms: int | None,
        screenshot_interval_ms: int | None,
        scope: str | list[str] = "own_conn",
        idle_timeout: float | None = None,
    ) -> None:
        self._sock_path = sock_path
        self._channels = channels
        self._interval_ms = interval_ms
        self._screenshot_interval_ms = screenshot_interval_ms
        self._scope = scope
        # 3.13: idle_timeout None = no recv timeout during the stream (long-stream consumers are not cut off spuriously); the handshake uses a fixed 15s.
        self._idle_timeout = idle_timeout
        self._sock: socket.socket | None = None
        self._sub_id: str | None = None
        self._buf = b""
        # IMPL-3: crash marker — distinguishes "normal stream end" (local unsubscribe/close, _closed_by_server=True)
        # vs "server crash/disconnect" (socket EOF unexpected, _closed_by_server=False). __next__ uses this:
        # local close → StopIteration (clean stream end); unexpected EOF → ConnectionError (the caller can catch to reconnect/alert).
        self._closed_by_server: bool = False
        # IMPL-3: _read_json sets this True on socket EOF (distinguishing from timeout-None); __next__ checks it for crash detection.
        self._eof_seen: bool = False

    def _open(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Fixed 15s timeout during the handshake (the subscribe response should come back within seconds)
        sock.settimeout(15.0)
        sock.connect(self._sock_path)
        self._sock = sock
        params: dict = {"channels": self._channels}
        if self._interval_ms is not None:
            params["interval_ms"] = self._interval_ms
        if self._screenshot_interval_ms is not None:
            params["screenshot_interval_ms"] = self._screenshot_interval_ms
        # Blocker 10: stdio scope passthrough (all=true / task_ids=[..] / default own_conn)
        if self._scope == "all":
            params["all"] = True
        elif isinstance(self._scope, list):
            params["task_ids"] = self._scope
        req = {"jsonrpc": "2.0", "id": 1, "method": "executor.subscribe", "params": params}
        sock.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
        resp = self._read_json()
        if resp is None or "error" in resp:
            err = resp.get("error") if resp else None
            raise RuntimeError(f"subscribe failed: {err}")
        self._sub_id = resp["result"]["subscription_id"]
        # 3.13: after a successful handshake switch to idle_timeout (None = blocking without timeout, or the user-set seconds)
        sock.settimeout(self._idle_timeout)
        logger.info(
            "subscribe ok sub_id=%s channels=%s idle_timeout=%s", self._sub_id, self._channels, self._idle_timeout
        )

    def _read_json(self) -> dict | None:
        assert self._sock is not None
        while b"\n" not in self._buf:
            # M-PY-04: server stops pushing (telemetry panic / screenshot silently denied by TCC) → recv 15s
            # then socket.timeout. The old version let TimeoutError propagate out of __next__, so the caller's
            # for-loop got TimeoutError instead of StopIteration (mixed semantics). Catch and convert to None →
            # __next__ raises StopIteration, clean stream end.
            try:
                chunk = self._sock.recv(4096)
            except TimeoutError:
                logger.warning("subscription recv timed out, treating as end of stream")
                return None
            if not chunk:
                # IMPL-3: socket EOF — distinguish timeout (branch above, legitimate idle) from a real disconnect (this branch).
                # Mark _eof_seen=True so __next__ can decide: local close → StopIteration;
                # unexpected EOF → ConnectionError.
                self._eof_seen = True
                return None
            self._buf += chunk
            # P-2: unbounded line-buffer growth guard — a corrupted stream (no newline) or an oversized frame would blow up _buf.
            # Truncate, drop the buffer, and warn, treating it as end of stream (better than OOM; the next recv without \n still returns None).
            if len(self._buf) > _SUB_BUF_MAX_BYTES:
                logger.warning(
                    "subscription _buf exceeded %d bytes, dropping (corrupted stream / oversized frame)",
                    _SUB_BUF_MAX_BYTES,
                )
                self._buf = b""
                return None
        line, self._buf = self._buf.split(b"\n", 1)
        text = line.decode("utf-8").strip()
        if not text:
            return None
        return json.loads(text)

    @property
    def subscription_id(self) -> str | None:
        return self._sub_id

    def __iter__(self) -> Iterator[dict]:
        return self

    def __next__(self) -> dict:
        # IMPL-3: already closed locally via close/unsubscribe (_closed_by_server=True, _sock=None) → clean stream end StopIteration.
        # Return early, don't call _read_json again (the sock is closed and its assert self._sock is not None would raise).
        if self._sock is None:
            if self._eof_seen and not self._closed_by_server:
                logger.warning(
                    "subscription disconnected unexpectedly (server EOF without unsubscribe), raising ConnectionError"
                )
                raise ConnectionError("server disconnected unexpectedly")
            raise StopIteration
        while True:
            frame = self._read_json()
            if frame is None:
                # IMPL-3: distinguish end-of-stream causes. _closed_by_server=True = local unsubscribe/close
                # (clean stream end → StopIteration); _eof_seen=True without a local close = server crash/disconnect
                # (→ ConnectionError, the caller can catch to reconnect/alert); pure timeout (both flags False) =
                # legitimate idle, treated as stream end with StopIteration.
                if self._eof_seen and not self._closed_by_server:
                    logger.warning(
                        "subscription disconnected unexpectedly (server EOF without unsubscribe), raising ConnectionError"
                    )
                    raise ConnectionError("server disconnected unexpectedly")
                raise StopIteration
            if "method" in frame and frame.get("method") == "executor.event":
                params = frame.get("params", {})
                if self._sub_id is None or params.get("subscription_id") == self._sub_id:
                    logger.debug("event channel=%s", params.get("channel"))
                    return params
            logger.debug("skipping non-event frame: %s", frame.get("id"))

    def unsubscribe(self) -> bool:
        if self._sock is None or self._sub_id is None:
            return False
        try:
            req = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "executor.unsubscribe",
                "params": {"subscription_id": self._sub_id},
            }
            self._sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
            resp = self._read_json()
            ok = bool(resp and resp.get("result", {}).get("ok"))
            logger.info("unsubscribe sub_id=%s ok=%s", self._sub_id, ok)
            return ok
        except OSError as e:
            logger.warning("unsubscribe send failed: %s", e)
            return False
        finally:
            if self._sock is not None:
                # IMPL-3: local-close marker — a local unsubscribe/close is an expected close, so __next__ getting None should StopIteration, not ConnectionError.
                self._closed_by_server = True
                self._sock.close()
                self._sock = None

    def close(self) -> None:
        if self._sock is not None:
            # IMPL-3: same as unsubscribe — an explicit close is a local close, mark it to avoid a false crash detection.
            self._closed_by_server = True
            self._sock.close()
            self._sock = None

    # C-PYO3-03: GC without unsubscribe = leaked socket FD + leaked server-side subscription entry. Add __del__ best-effort
    # close (unsubscribe success is not guaranteed, only the local socket is closed; the server side exits on its own via the dead tx channel);
    # __enter__/__exit__ support `with executor.subscribe(...) as sub:` for an explicit lifecycle.
    def __enter__(self) -> Subscription:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.unsubscribe()
        except Exception:
            logger.debug("__exit__ unsubscribe raised, degrading to close")
        self.close()

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()
