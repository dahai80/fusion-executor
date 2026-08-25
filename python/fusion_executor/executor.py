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
    GuiResult,
    RollbackPolicy,
    TelemetrySample,
)

logger = logging.getLogger("fusion_executor")

DEFAULT_SOCK = "/tmp/fusion-executor.sock"
SUB_CHANNELS = ("telemetry", "stdio", "screenshot")


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
        timeout_sec: float = 30.0,
        env_vars: dict[str, str] | None = None,
        enable_rollback_snapshot: bool = True,
        auto_rollback: RollbackPolicy | None = None,
        seatbelt: bool = False,
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
        logger.debug("run command=%r timeout_sec=%s cwd=%s task_id=%s", command, timeout_sec, cwd, task_id)
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
        enable_rollback_snapshot: bool = True,
        auto_rollback: RollbackPolicy | None = None,
        seatbelt: bool = False,
    ) -> Iterator[str | ExecutionResult]:
        # M-PY-01: 同 run() 前置校验
        if not isinstance(command, str):
            raise TypeError(f"command 必须为 str, 得 {type(command).__name__}")
        if timeout_sec is not None and timeout_sec <= 0:
            raise ValueError(f"timeout_sec 必须为正数, 得 {timeout_sec}")
        logger.debug("run_streaming command=%r timeout_sec=%s cwd=%s task_id=%s", command, timeout_sec, cwd, task_id)
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
    ) -> Iterator[TelemetrySample]:
        logger.debug("telemetry_stream interval_ms=%s max_samples=%s", interval_ms, max_samples)
        it = self._native.telemetry_stream(interval_ms, max_samples)
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

    def serve(self, sock_path: str | None = None) -> None:
        # C-PYO3-02: 旧版裸 self._native.serve() — fe-pyo3 serve_blocking 无 shutdown
        # 句柄, SIGINT/SIGTERM 不解 socket 残留。改信号处理 + try/finally 清理:
        # 注册 SIGINT/SIGTERM → 触发 KeyboardInterrupt 跳出 serve_blocking, finally
        # os.unlink 残留 socket。serve_blocking 阻塞 recv, 信号在主线程中断。
        # 3.15: 解析 path (env/default) 后统一传给 Rust — 旧版传原始 sock_path (可能 None),
        # 与 finally 清理用的 path (env 解析) 不同源, 虽 Rust 亦解析 env 凑巧一致, 但显式
        # 传 path 消除隐式 env 依赖, 清理与监听严格同一路径。
        path = sock_path or os.environ.get("FUSION_EXECUTOR_SOCK", DEFAULT_SOCK)
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
                return None
            self._buf += chunk
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
        while True:
            frame = self._read_json()
            if frame is None:
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
                self._sock.close()
                self._sock = None

    def close(self) -> None:
        if self._sock is not None:
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
