from __future__ import annotations

import logging
from collections.abc import Iterator

from .models import (
    Diagnostics,
    EditResult,
    ExecutionResult,
    GlobEntry,
    GrepMatch,
    GuiResult,
    RollbackPolicy,
    TelemetrySample,
)

logger = logging.getLogger("fusion_executor")


class FusionSandboxExecutor:
    def __init__(self, sock_path: str | None = None) -> None:
        try:
            from ._native import NativeExecutor
        except ImportError as e:
            raise ImportError("fusion_executor._native 未加载 — 运行 `maturin develop` 编译原生扩展") from e
        self._native = NativeExecutor()
        self._sock_path = sock_path

    def run(
        self,
        command: str,
        *,
        task_id: str | None = None,
        cwd: str | None = None,
        timeout: float = 30.0,
        env_vars: dict[str, str] | None = None,
        enable_rollback_snapshot: bool = True,
        auto_rollback: RollbackPolicy | None = None,
    ) -> ExecutionResult:
        logger.debug("run command=%r timeout=%s cwd=%s task_id=%s", command, timeout, cwd, task_id)
        policy_dict = auto_rollback.model_dump() if auto_rollback is not None else None
        native = self._native.execute_sync(
            command,
            task_id,
            cwd,
            timeout,
            env_vars,
            enable_rollback_snapshot,
            policy_dict,
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
        )
        logger.info(
            "run done exit=%s blocked=%s timed_out=%s diag=%s rolled_back=%s dur=%.3fs",
            result.exit_code,
            result.blocked_by_security,
            result.timed_out,
            result.diagnostics.error_type if result.diagnostics else None,
            result.auto_rolled_back,
            result.duration_sec,
        )
        return result

    async def run_async(self, command: str, **kw) -> ExecutionResult:
        return self.run(command, **kw)

    def run_streaming(
        self,
        command: str,
        *,
        task_id: str | None = None,
        cwd: str | None = None,
        timeout: float = 30.0,
        env_vars: dict[str, str] | None = None,
        enable_rollback_snapshot: bool = True,
        auto_rollback: RollbackPolicy | None = None,
    ) -> Iterator[str | ExecutionResult]:
        logger.debug("run_streaming command=%r timeout=%s cwd=%s task_id=%s", command, timeout, cwd, task_id)
        policy_dict = auto_rollback.model_dump() if auto_rollback is not None else None
        it = self._native.execute_streaming(
            command,
            task_id,
            cwd,
            timeout,
            env_vars,
            enable_rollback_snapshot,
            policy_dict,
        )
        for frame in it:
            ftype = frame.get("type")
            if ftype == "chunk":
                data = frame.get("data", "")
                logger.debug("stream chunk len=%s", len(data))
                yield data
            elif ftype == "done":
                # serde tag="type" → Done(ExecutionResult) 扁平为 {"type":"done", exit_code:..., ...}
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

    def _native_result(self, payload: dict) -> ExecutionResult:
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
        return ExecutionResult(
            exit_code=payload.get("exit_code", -1),
            stdout=payload.get("stdout", ""),
            stderr=payload.get("stderr", ""),
            task_id=payload.get("task_id"),
            command=payload.get("command"),
            duration_sec=payload.get("duration_sec", 0.0),
            timed_out=payload.get("timed_out", False),
            blocked_by_security=payload.get("blocked_by_security", False),
            security_reason=payload.get("security_reason"),
            snapshot_id=payload.get("snapshot_id"),
            diagnostics=diag,
            auto_rolled_back=payload.get("auto_rolled_back", False),
        )

    def rollback(self, snapshot_id: str, cwd: str | None = None) -> bool:
        if cwd is None:
            raise ValueError("rollback 需要 cwd")
        logger.info("rollback snapshot=%s cwd=%s", snapshot_id, cwd)
        return self._native.rollback(snapshot_id, cwd)

    def snapshot_create(self, cwd: str) -> str:
        logger.info("snapshot_create cwd=%s", cwd)
        return self._native.snapshot_create(cwd)

    def file_edit(
        self,
        path: str,
        old_string: str,
        new_string: str,
        *,
        cwd: str | None = None,
    ) -> EditResult:
        logger.debug("file_edit path=%r cwd=%s", path, cwd)
        native = self._native.file_edit(path, old_string, new_string, cwd)
        result = EditResult(
            ok=native.ok,
            path=native.path,
            error=native.error,
            matches=native.matches,
        )
        logger.info("file_edit done ok=%s matches=%s path=%s", result.ok, result.matches, result.path)
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
        out = [GrepMatch(path=m.path, line_number=m.line_number, content=m.content) for m in native_matches]
        logger.info("grep done matches=%s", len(out))
        return out

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
        logger.debug("gui_action action=%s", action)
        native = self._native.gui_action(action)
        result = GuiResult(
            ok=native.ok,
            node_tree=native.node_tree,
            screenshot_png_b64=native.screenshot_png_b64,
            screenshot_width=native.screenshot_width,
            screenshot_height=native.screenshot_height,
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

    def telemetry_stream(
        self,
        *,
        interval_ms: int = 100,
        max_samples: int = 0,
    ) -> Iterator[TelemetrySample]:
        logger.debug("telemetry_stream interval_ms=%s max_samples=%s", interval_ms, max_samples)
        it = self._native.telemetry_stream(interval_ms, max_samples)
        for count, frame in enumerate(it, start=1):
            sample = TelemetrySample(
                ts_ms=frame.get("ts_ms", 0),
                cpu_pct=frame.get("cpu_pct", 0.0),
                mem_mb=frame.get("mem_mb", 0.0),
                gpu_pct=frame.get("gpu_pct"),
                gpu_mem_mb=frame.get("gpu_mem_mb"),
                task_id=frame.get("task_id"),
            )
            logger.debug("telemetry sample #%s cpu=%.1f%% mem=%.1fMB", count, sample.cpu_pct, sample.mem_mb)
            yield sample

    def serve(self, sock_path: str | None = None) -> None:
        logger.info("serve sock=%s — 启动 UDS JSON-RPC 服务器 (永驻)", sock_path)
        self._native.serve(sock_path)
