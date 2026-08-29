from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
import socket
from collections.abc import Iterator

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
    ShellInfo,
    ShellOutput,
    ShellStartResult,
    SnapshotInfo,
    TelemetrySample,
)

logger = logging.getLogger("fusion_executor")

DEFAULT_SOCK = os.path.expanduser("~/.fusion-executor/fe.sock")  # IMPL-1: 对齐 Rust M-SEC-01 (HOME 私有 0o700)
# D6-01: pidfile — serve 启动写 pid, 停机删。ops 可 `kill $(cat fe.pid)` / 监控存活。
# 与 socket 同目录 (~/.fusion-executor/, HOME 私有 0o700), 不暴露 pid 给其他用户。
DEFAULT_PIDFILE = os.path.expanduser("~/.fusion-executor/fe.pid")
SUB_CHANNELS = ("telemetry", "stdio", "screenshot")
# P-2: subscription 行缓冲上限 — 损坏流 (无 newline) / 超巨帧防护, 超则丢缓冲当流结束
_SUB_BUF_MAX_BYTES = 8 * 1024 * 1024


def ensure_socket_dir(path: str = DEFAULT_SOCK) -> None:
    # IMPL-1: 对齐 Rust M-SEC-01 — 默认 socket 置 ~/.fusion-executor/ (HOME 私有, 0o700)。
    # serve 前确保目录存在 (Rust 侧亦 mkdir, 此处前置防 bind 前路径缺失; 自定义路径父目录已存在则 no-op)。
    # makedirs mode 仅创建时生效; 既存目录 (如旧 0o755 残留) 须显式 chmod 收紧, 否则破坏鉴权前提。
    sock_dir = os.path.dirname(path) or os.path.expanduser("~/.fusion-executor")
    try:
        os.makedirs(sock_dir, mode=0o700, exist_ok=True)
        if os.path.isdir(sock_dir):
            os.chmod(sock_dir, 0o700)
    except OSError as e:
        logger.warning("ensure_socket_dir 创建 %s 失败: %s", sock_dir, e)


def write_pidfile(path: str = DEFAULT_PIDFILE) -> None:
    # D6-01: serve 启动写 pidfile。目录由 ensure_socket_dir (socket 同目录) 先建。
    # 失败不阻断 serve (pidfile 是 ops 辅助, 非安全关键) — fail-visible 警告, 继续服务。
    try:
        pid_dir = os.path.dirname(path)
        if pid_dir:
            os.makedirs(pid_dir, mode=0o700, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
        logger.info("pidfile 写入 %s (pid=%d)", path, os.getpid())
    except OSError as e:
        logger.warning("pidfile 写入 %s 失败: %s — ops 监控将不可用, serve 继续", path, e)


def remove_pidfile(path: str = DEFAULT_PIDFILE) -> None:
    # D6-01: serve 停机删 pidfile。不存在 (写失败或已被删) 静默 no-op; 删失败警告不抛。
    try:
        if os.path.exists(path):
            os.unlink(path)
            logger.info("pidfile 清理 %s", path)
    except OSError as e:
        logger.warning("pidfile 清理 %s 失败: %s", path, e)


class FusionSandboxExecutor:
    def __init__(
        self,
        sock_path: str | None = None,
        *,
        extra_whitelist: list[str] | None = None,
        disable_bundle_allowlist: bool = False,
        allow_inline_interpreter: bool = False,
        trusted_bin_dirs: list[str] | None = None,
    ) -> None:
        try:
            from ._native import NativeExecutor
        except ImportError as e:
            raise ImportError("fusion_executor._native 未加载 — 运行 `maturin develop` 编译原生扩展") from e
        # RUN-12: disable_bundle_allowlist=True 关闭 GUI 焦点 app 白名单 (无限制 opt-in, 仅审计日志);
        #         默认 False 走安全默认集 (Terminal/TextEdit/finder)。测试机 drive 任意 app 时传 True。
        # D3-1 (审计 0827 product): allow_inline_interpreter=True 开启内联解释器 (python -c / node -e
        #   / ruby -e / perl -e); 默认 False (企业硬化拒内联代码, 防 agent-driven 任意 payload 绕白名单语义)。
        #   测试机/本地交互场景依赖 python3 -c, 显式传 True opt-in。
        # D3-6 (审计 0827 product 4-layer): trusted_bin_dirs 登记项目工具所在目录 — extra_whitelist 的工具
        #   须 resolve 到可信目录才放行 (fail-closed 防 /tmp/python3 投毒)。测试/调用方登记项目 bin 目录。
        self._native = NativeExecutor(
            extra_whitelist, disable_bundle_allowlist, allow_inline_interpreter, trusted_bin_dirs
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
        # ARCH-1: 默认 True — 对齐 fe-core serde default_true (商用安全默认)。
        # 受信本地 opt-out 显式传 seatbelt=False。原默认 False 与 UDS execute 路径 (serde 默认 true) 不一致。
        seatbelt: bool = True,
        inherit_env: bool = False,
        use_pty: bool = True,
        max_nproc: int = 1024,
        max_cpu_sec: int = 0,
        max_nofile: int = 1024,
        rss_limit_mb: int = 2048,
        trace_id: str | None = None,
    ) -> ExecutionResult:
        # M-PY-01: 顶前置校验, 早 fail 友好错误 (非延迟到 PyO3 内部 panic/TypeError)
        if not isinstance(command, str):
            raise TypeError(f"command 必须为 str, 得 {type(command).__name__}")
        if timeout_sec is not None and timeout_sec <= 0:
            raise ValueError(f"timeout_sec 必须为正数, 得 {timeout_sec}")
        if cwd is not None and not isinstance(cwd, str):
            raise TypeError(f"cwd 必须为 str|None, 得 {type(cwd).__name__}")
        if env_vars is not None:
            if not isinstance(env_vars, dict):
                raise TypeError(f"env_vars 必须为 dict|None, 得 {type(env_vars).__name__}")
            for k, v in env_vars.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise TypeError(f"env_vars 键值均须 str, 得 ({type(k).__name__},{type(v).__name__})")
        if not isinstance(max_nproc, int) or max_nproc < 0:
            raise ValueError(f"max_nproc 必须为非负 int, 得 {max_nproc!r}")
        if not isinstance(max_cpu_sec, int) or max_cpu_sec < 0:
            raise ValueError(f"max_cpu_sec 必须为非负 int, 得 {max_cpu_sec!r}")
        if not isinstance(max_nofile, int) or max_nofile < 0:
            raise ValueError(f"max_nofile 必须为非负 int, 得 {max_nofile!r}")
        if not isinstance(rss_limit_mb, int) or rss_limit_mb < 0:
            raise ValueError(f"rss_limit_mb 必须为非负 int, 得 {rss_limit_mb!r}")
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
        # C-PYO3-01: 旧版 return self.run(...) — 假异步, 同步阻塞事件循环 (run 内
        # BLOCKING_RT.block_on 持 GIL, asyncio 事件循环卡死)。改 asyncio.to_thread
        # 把同步 run 扔线程池, 事件循环可并发跑其他协程。
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
        # ARCH-1: 默认 True — 对齐 fe-core serde default_true + run() (见上注释)。
        seatbelt: bool = True,
        inherit_env: bool = False,
        use_pty: bool = True,
        max_nproc: int = 1024,
        max_cpu_sec: int = 0,
        max_nofile: int = 1024,
        rss_limit_mb: int = 2048,
        trace_id: str | None = None,
    ) -> Iterator[str | ExecutionResult]:
        # M-PY-01: 同 run() 前置校验
        if not isinstance(command, str):
            raise TypeError(f"command 必须为 str, 得 {type(command).__name__}")
        if timeout_sec is not None and timeout_sec <= 0:
            raise ValueError(f"timeout_sec 必须为正数, 得 {timeout_sec}")
        if not isinstance(max_nproc, int) or max_nproc < 0:
            raise ValueError(f"max_nproc 必须为非负 int, 得 {max_nproc!r}")
        if not isinstance(max_cpu_sec, int) or max_cpu_sec < 0:
            raise ValueError(f"max_cpu_sec 必须为非负 int, 得 {max_cpu_sec!r}")
        if not isinstance(max_nofile, int) or max_nofile < 0:
            raise ValueError(f"max_nofile 必须为非负 int, 得 {max_nofile!r}")
        if not isinstance(rss_limit_mb, int) or rss_limit_mb < 0:
            raise ValueError(f"rss_limit_mb 必须为非负 int, 得 {rss_limit_mb!r}")
        # 流式后端仅 PTY: use_pty=False 暂无 stdio 流式实现 (run_streaming 走 portable-pty,
        # 保 ANSI/Traceback 保真 — 流式主要目的)。需独立 stderr 分流用 run(use_pty=False)。
        if not use_pty:
            raise ValueError("run_streaming 暂不支持 use_pty=False (无 stdio 流式后端; 用 run() 分流)")
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
        )
        for frame in it:
            # L-PY-02: 严格键 (旧 .get(default) 吞 serde bug, 缺字段静默成功看像 blocked)
            ftype = frame["type"]
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
            else:
                # M-6: 未知帧 type (协议演进新帧/损坏帧) — 不抛保向前兼容, 但 debug 记录可追溯
                logger.debug("未知流帧 type=%r, 跳过 (向前兼容)", ftype)

    def _native_result(self, payload: dict) -> ExecutionResult:
        # L-PY-02: 严格校验 (旧 .get(default) 吞缺失字段, Rust 改字段名/serde bug 时
        # 静默返 exit_code=-1 成功命令看像 blocked/内部错误)。model_validate 抛
        # ValidationError fail-loud; diagnostics 可选, 单独 build。
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
        # type=done 帧: serde flatten Done 进外层, 含 type/exit_code/... 一次 model_validate
        # 去掉 type 字段后校验 (type 是流标记非 ExecutionResult 字段)
        fields = {k: v for k, v in payload.items() if k != "type"}
        fields["diagnostics"] = diag
        return ExecutionResult.model_validate(fields)

    def rollback(self, snapshot_id: str, cwd: str | None = None) -> bool:
        if cwd is None:
            raise ValueError("rollback 需要 cwd")
        logger.info("rollback snapshot=%s cwd=%s", snapshot_id, cwd)
        return self._native.rollback(snapshot_id, cwd)

    def snapshot_create(self, cwd: str) -> str:
        logger.info("snapshot_create cwd=%s", cwd)
        return self._native.snapshot_create(cwd)

    def list_snapshots(self, cwd: str) -> list[SnapshotInfo]:
        # D6-03 (审计 0827 product): 快照清单 — on-disk 索引读回, 供运维审计/存活快照发现。
        # 无状态 (M-ARCH-1): 仅读 cwd 对应索引, executor 不持有快照状态。
        logger.info("list_snapshots cwd=%s", cwd)
        native_list = self._native.list_snapshots(cwd)
        out = [SnapshotInfo.model_validate(s.to_dict()) for s in native_list]
        logger.info("list_snapshots done count=%d cwd=%s", len(out), cwd)
        return out

    def validate(self, command: str) -> dict:
        # Issue #11 / #12.4: 非执行预校验 — 调用方先问用户授权再 run (Option A: caller owns gating)。
        # Executor 只强制硬黑名单 (never-blocked); interactive confirmation 归 caller。
        # 返回 {allowed: bool, blocked: bool, reason: str|None, stage: "regex"|"tokenizer"|None}
        if not isinstance(command, str) or not command.strip():
            raise ValueError(f"command 必须非空字符串, 得 {command!r}")
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
    ) -> ShellStartResult:
        if not isinstance(max_idle_sec, int) or max_idle_sec < 0:
            raise ValueError(f"max_idle_sec 必须为非负 int, 得 {max_idle_sec!r}")
        if not isinstance(kill_grace_ms, int) or kill_grace_ms < 0:
            raise ValueError(f"kill_grace_ms 必须为非负 int, 得 {kill_grace_ms!r}")
        if not isinstance(max_nofile, int) or max_nofile < 0:
            raise ValueError(f"max_nofile 必须为非负 int, 得 {max_nofile!r}")
        logger.debug(
            "shell_start command=%r cwd=%s task_id=%s seatbelt=%s inherit_env=%s max_idle_sec=%s kill_grace_ms=%s max_nofile=%s",
            command,
            cwd,
            task_id,
            seatbelt,
            inherit_env,
            max_idle_sec,
            kill_grace_ms,
            max_nofile,
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
        # M-PY-02: 预校验 dict + kind 字段 (旧版接受 None/"string"/{} 全经 Rust 序列化
        # 往返返中文错误串无结构化字段)。仅拒绝类型错 + 缺 kind; 未知 kind 放行让
        # Rust 降级 (ok=false, 保留 test_gui_action_bad_kind_degrades 契约)。
        if not isinstance(action, dict):
            raise TypeError(f"action 必须为 dict, 得 {type(action).__name__}")
        if "kind" not in action:
            raise ValueError("action 缺 'kind' 字段")
        kind = action["kind"]
        if not isinstance(kind, str):
            raise TypeError(f"action['kind'] 必须为 str, 得 {type(kind).__name__}")
        logger.debug("gui_action kind=%s action=%s", kind, action)
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
            # 3.11: 严格 model_validate (旧 frame.get("ts_ms", 0) 默认 0 — Rust 改字段名/
            # serde bug 时静默吞缺失字段, ts_ms=0/cpu=0 假数据进融合)。Blocker 11 _STRICT
            # extra=forbid; 缺必填 ts_ms/cpu_pct/mem_mb → ValidationError fail-loud。
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
        # M-PY-03: 空通道列表显式拒 (旧版 bad 检查空列表无 bad 项 → 过 → 开订阅无通道
        # 兴趣 → 永不收推送 → __next__ 阻塞 15s 后 TimeoutError 非 StopIteration)
        if not channels:
            raise ValueError("channels 不能为空")
        bad = [c for c in channels if c not in SUB_CHANNELS]
        if bad:
            raise ValueError(f"未知通道: {bad}, 可选 {list(SUB_CHANNELS)}")
        # scope 仅对 stdio 通道生效 (Blocker 10, 破审计 §2.9 跨租户泄漏):
        #   "all" → 全广播; ["id1",..] → task_id 白名单; "own_conn" (默认) → 仅本连接命令
        if scope not in ("all", "own_conn") and not isinstance(scope, list):
            raise ValueError("scope 须为 'all' | 'own_conn' | task_id 列表")
        # 3.13: idle_timeout None = 无超时 (长流消费者); 数值 = recv 超时秒数 (旧版硬编 15s,
        # 慢推送 >15s → 误 StopIteration)。订阅握手必用有限超时, 之后再切 idle_timeout。
        path = sock_path or self._sock_path or os.environ.get("FUSION_EXECUTOR_SOCK", DEFAULT_SOCK)
        sub = Subscription(path, channels, interval_ms, screenshot_interval_ms, scope, idle_timeout)
        sub._open()
        return sub

    def metrics(self, sock_path: str | None = None) -> dict:
        # C-OPS-05: 运维指标 — 经 UDS 调 executor.metrics 读服务器运行态计数
        # (exec_total/blocked/timeout/success/failed + duration/stdio 聚合 + rollback)。
        # 须对运行中的 serve() 实例调用 (无 server → ConnectionRefused)。
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
                raise RuntimeError(f"metrics 失败: {resp['error']}")
            logger.info("metrics ok: %s", resp.get("result"))
            return resp.get("result", {})
        finally:
            sock.close()

    def metrics_prometheus(self, sock_path: str | None = None) -> str:
        # M-OPS-02: Prometheus text format — 经 UDS 调 executor.metrics_prometheus 拉
        # scrape 文本 (fe_exec_total/fe_shell_active/fe_connections... + HELP/TYPE 头)。
        # 不开 HTTP 端口 (保 M-SEC-01 UDS-only); 调用方喂自家 exporter 或直接展板。
        # recorder install 失败 → -32603, 调用方降级用 metrics() JSON。
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
                raise RuntimeError(f"metrics_prometheus 失败: {resp['error']}")
            text = resp.get("result", {}).get("text", "")
            logger.info("metrics_prometheus ok: %d bytes", len(text))
            return text
        finally:
            sock.close()

    def serve(self, sock_path: str | None = None) -> None:
        # C-PYO3-02: 旧版裸 self._native.serve() — fe-pyo3 serve_blocking 无 shutdown
        # 句柄, SIGINT/SIGTERM 不解 socket 残留。改信号处理 + try/finally 清理:
        # 注册 SIGINT/SIGTERM → 触发 KeyboardInterrupt 跳出 serve_blocking, finally
        # os.unlink 残留 socket。serve_blocking 阻塞 recv, 信号在主线程中断。
        # 3.15: 解析 path (env/default) 后统一传给 Rust — 旧版传原始 sock_path (可能 None),
        # 与 finally 清理用的 path (env 解析) 不同源, 虽 Rust 亦解析 env 凑巧一致, 但显式
        # 传 path 消除隐式 env 依赖, 清理与监听严格同一路径。
        path = sock_path or os.environ.get("FUSION_EXECUTOR_SOCK", DEFAULT_SOCK)
        pid_path = os.environ.get("FUSION_EXECUTOR_PIDFILE", DEFAULT_PIDFILE)
        # IMPL-1: serve 前确保 socket 父目录存在 (默认 ~/.fusion-executor/ 0o700, 对齐 Rust M-SEC-01)。
        ensure_socket_dir(path)
        # D6-01: 写 pidfile (ops 监控/kill 用)。socket 同目录, 目录已由 ensure_socket_dir 建。
        write_pidfile(pid_path)
        # ARCH-1: seatbelt 治理 — execute + shell_start 均默认 true (商用安全默认, 对齐 fe-core serde default_true)。
        # 调用方显式传 seatbelt:false 关闭隔离 (受信本地 opt-out)。
        logger.info(
            "seatbelt 默认开启 (execute + shell_start 路径) — macOS sandbox-exec 隔离。受信本地可透传 seatbelt:false opt-out。"
        )
        logger.info("serve sock=%s — 启动 UDS JSON-RPC 服务器 (信号可停)", path)
        old_int = signal.getsignal(signal.SIGINT)
        old_term = signal.getsignal(signal.SIGTERM)
        raised = False
        signal.signal(signal.SIGINT, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
        try:
            self._native.serve(path)
        except KeyboardInterrupt:
            raised = True
            logger.info("serve 收到停机信号, 关闭服务器")
        finally:
            signal.signal(signal.SIGINT, old_int)
            signal.signal(signal.SIGTERM, old_term)
            if os.path.exists(path):
                try:
                    os.unlink(path)
                    logger.info("serve 清理残留 socket %s", path)
                except OSError as e:
                    logger.warning("serve 清理 socket 失败 %s: %s", path, e)
            # D6-01: 停机删 pidfile (正常 + 信号 + 异常路径都走 finally)
            remove_pidfile(pid_path)
            if raised:
                raise KeyboardInterrupt("serve 已停机")


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
        # 3.13: idle_timeout None = 流期间无 recv 超时 (长流消费者不误断); 握手用固定 15s。
        self._idle_timeout = idle_timeout
        self._sock: socket.socket | None = None
        self._sub_id: str | None = None
        self._buf = b""
        # IMPL-3: crash 标记 — 区分 "正常流结束" (本端 unsubscribe/close 主动, _closed_by_server=True)
        # vs "server 崩溃/断连" (socket EOF 无预期, _closed_by_server=False)。__next__ 据此区分:
        # 主动关闭 → StopIteration (干净流尾); 非预期 EOF → ConnectionError (调用方可 catch 重连/告警)。
        self._closed_by_server: bool = False
        # IMPL-3: _read_json 在 socket EOF 时置 True (区分超时-None), __next__ 据此判 crash。
        self._eof_seen: bool = False

    def _open(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # 握手阶段固定 15s 超时 (subscribe 响应应秒级回)
        sock.settimeout(15.0)
        sock.connect(self._sock_path)
        self._sock = sock
        params: dict = {"channels": self._channels}
        if self._interval_ms is not None:
            params["interval_ms"] = self._interval_ms
        if self._screenshot_interval_ms is not None:
            params["screenshot_interval_ms"] = self._screenshot_interval_ms
        # Blocker 10: stdio 作用域透传 (all=true / task_ids=[..] / 默认 own_conn)
        if self._scope == "all":
            params["all"] = True
        elif isinstance(self._scope, list):
            params["task_ids"] = self._scope
        req = {"jsonrpc": "2.0", "id": 1, "method": "executor.subscribe", "params": params}
        sock.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
        resp = self._read_json()
        if resp is None or "error" in resp:
            err = resp.get("error") if resp else None
            raise RuntimeError(f"subscribe 失败: {err}")
        self._sub_id = resp["result"]["subscription_id"]
        # 3.13: 握手成功后切到 idle_timeout (None=阻塞无超时, 或用户设的秒数)
        sock.settimeout(self._idle_timeout)
        logger.info(
            "subscribe ok sub_id=%s channels=%s idle_timeout=%s", self._sub_id, self._channels, self._idle_timeout
        )

    def _read_json(self) -> dict | None:
        assert self._sock is not None
        while b"\n" not in self._buf:
            # M-PY-04: 服务端停推 (telemetry panic/screenshot TCC 拒静默) → recv 15s
            # 后 socket.timeout。旧版抛 TimeoutError 穿透 __next__, 调用方 for-loop
            # 得 TimeoutError 非 StopIteration (混合语义)。捕获转 None → __next__ 抛
            # StopIteration, 干净流尾。
            try:
                chunk = self._sock.recv(4096)
            except TimeoutError:
                logger.warning("subscription recv 超时, 当流结束")
                return None
            if not chunk:
                # IMPL-3: socket EOF — 区分超时 (上分支, 合法 idle) vs 真断连 (本分支)。
                # 标记 _eof_seen=True 让 __next__ 据此决定: 主动关闭 → StopIteration;
                # 非预期 EOF → ConnectionError。
                self._eof_seen = True
                return None
            self._buf += chunk
            # P-2: 行缓冲无界增长防护 — 损坏流 (无 newline) 或超巨帧会撑爆 _buf。
            # 截断丢缓冲并 warn, 当流结束 (比 OOM 强; 下次 recv 无 \n 仍 None)。
            if len(self._buf) > _SUB_BUF_MAX_BYTES:
                logger.warning("subscription _buf 超 %d 字节, 丢弃 (损坏流/超巨帧)", _SUB_BUF_MAX_BYTES)
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
        # IMPL-3: 本端已主动 close/unsubscribe (_closed_by_server=True, _sock=None) → 干净流尾 StopIteration。
        # 提前返回, 不再调 _read_json (sock 已关, 其 assert self._sock is not None 会抛)。
        if self._sock is None:
            if self._eof_seen and not self._closed_by_server:
                logger.warning("subscription 非预期断连 (server EOF 无 unsubscribe), 抛 ConnectionError")
                raise ConnectionError("server disconnected unexpectedly")
            raise StopIteration
        while True:
            frame = self._read_json()
            if frame is None:
                # IMPL-3: 区分流尾原因。_closed_by_server=True = 本端主动 unsubscribe/close
                # (干净流尾 → StopIteration); _eof_seen=True 且非主动关 = server 崩溃/断连
                # (→ ConnectionError, 调用方可 catch 重连/告警); 纯超时 (两标志皆 False) =
                # 合法 idle, 当流尾 StopIteration。
                if self._eof_seen and not self._closed_by_server:
                    logger.warning("subscription 非预期断连 (server EOF 无 unsubscribe), 抛 ConnectionError")
                    raise ConnectionError("server disconnected unexpectedly")
                raise StopIteration
            if "method" in frame and frame.get("method") == "executor.event":
                params = frame.get("params", {})
                if self._sub_id is None or params.get("subscription_id") == self._sub_id:
                    logger.debug("event channel=%s", params.get("channel"))
                    return params
            logger.debug("跳过非 event 帧: %s", frame.get("id"))

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
            logger.warning("unsubscribe 发送失败: %s", e)
            return False
        finally:
            if self._sock is not None:
                # IMPL-3: 主动关标记 — 本端 unsubscribe/close 是预期关闭, __next__ 得 None 应 StopIteration 非 ConnectionError。
                self._closed_by_server = True
                self._sock.close()
                self._sock = None

    def close(self) -> None:
        if self._sock is not None:
            # IMPL-3: 同 unsubscribe — 显式 close 属主动关闭, 标记避免误判 crash。
            self._closed_by_server = True
            self._sock.close()
            self._sock = None

    # C-PYO3-03: GC 无 unsubscribe = socket FD + 服务端订阅项泄漏。加 __del__ 尽力
    # close (不保证 unsubscribe 成功, 仅关本地 socket; 服务端侧靠 tx 死通道自退);
    # __enter__/__exit__ 支持 `with executor.subscribe(...) as sub:` 显式生命周期。
    def __enter__(self) -> Subscription:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.unsubscribe()
        except Exception:
            logger.debug("__exit__ unsubscribe 异常, 降级 close")
        self.close()

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()
