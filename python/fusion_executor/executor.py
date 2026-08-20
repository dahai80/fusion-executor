from __future__ import annotations

import logging
from collections.abc import Iterator

from .models import Diagnostics, ExecutionResult, GuiResult

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
    ) -> ExecutionResult:
        logger.debug("run command=%r timeout=%s cwd=%s", command, timeout, cwd)
        native = self._native.execute_sync(
            command,
            cwd,
            timeout,
            env_vars,
            enable_rollback_snapshot,
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
            timed_out=native.timed_out,
            blocked_by_security=native.blocked_by_security,
            security_reason=native.security_reason,
            snapshot_id=native.snapshot_id,
            diagnostics=diag,
        )
        logger.info(
            "run done exit=%s blocked=%s timed_out=%s diag=%s",
            result.exit_code,
            result.blocked_by_security,
            result.timed_out,
            result.diagnostics.error_type if result.diagnostics else None,
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
    ) -> Iterator[str | ExecutionResult]:
        logger.debug("run_streaming command=%r timeout=%s cwd=%s", command, timeout, cwd)
        it = self._native.execute_streaming(
            command,
            cwd,
            timeout,
            env_vars,
            enable_rollback_snapshot,
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
            timed_out=payload.get("timed_out", False),
            blocked_by_security=payload.get("blocked_by_security", False),
            security_reason=payload.get("security_reason"),
            snapshot_id=payload.get("snapshot_id"),
            diagnostics=diag,
        )

    def rollback(self, snapshot_id: str, cwd: str | None = None) -> bool:
        if cwd is None:
            raise ValueError("rollback 需要 cwd")
        logger.info("rollback snapshot=%s cwd=%s", snapshot_id, cwd)
        return self._native.rollback(snapshot_id, cwd)

    def snapshot_create(self, cwd: str) -> str:
        logger.info("snapshot_create cwd=%s", cwd)
        return self._native.snapshot_create(cwd)

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

    def serve(self, sock_path: str | None = None) -> None:
        logger.info("serve sock=%s — 启动 UDS JSON-RPC 服务器 (永驻)", sock_path)
        self._native.serve(sock_path)
