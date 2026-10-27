from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import logging
import re
import sqlite3
import time
import uuid
from collections.abc import Awaitable, Callable
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from .executor import FusionSandboxExecutor

logger = logging.getLogger("fusion_executor.task_service")

# Issue #57: 共享异步批量任务服务 — 通用 task_id 轮询 / 状态机 / 重试退避 / 结果导出。
# 各业务应用 (~/fusion/business/*) 不再各自造 SQLite 队列 + worker。
# 设计: 纯 Python 层组件 (同 agent_loop/laya_tool_selector), Executor 保持 stateless (M-ARCH-1);
#       shell 任务复用 executor 后台 shell (shell_start/shell_output/kill_shell) — 继承安全守卫/seatbelt,
#       天然获得运行中取消 + 增量进度解析。

_STRICT = ConfigDict(extra="forbid")

# shell 任务进度协议: 子进程输出一行 "TASK_PROGRESS: 0.42" (0..1) 即上报进度
_PROGRESS_RE = re.compile(r"TASK_PROGRESS:\s*([0-9]*\.?[0-9]+)")

_DEFAULT_TIMEOUT_SEC = 600.0
_FAILURE_REASON_MAX = 2000


class TaskState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RetryPolicy(BaseModel):
    model_config = _STRICT

    max_retries: int = 0
    backoff_initial_sec: float = 1.0
    backoff_max_sec: float = 60.0
    backoff_multiplier: float = 2.0

    def backoff_sec(self, attempts_done: int) -> float:
        if attempts_done < 1:
            return 0.0
        raw = self.backoff_initial_sec * (self.backoff_multiplier ** (attempts_done - 1))
        return min(raw, self.backoff_max_sec)


class TaskStatus(BaseModel):
    model_config = _STRICT

    task_id: str
    kind: str
    name: str | None = None
    state: TaskState
    progress: float = 0.0
    attempts: int = 0
    max_retries: int = 0
    failure_reason: str | None = None
    created_at: float = 0.0
    started_at: float | None = None
    finished_at: float | None = None
    duration_sec: float | None = None
    result: dict[str, Any] | None = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT,
    command TEXT,
    state TEXT NOT NULL,
    progress REAL NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 0,
    next_retry_at REAL,
    failure_reason TEXT,
    result_json TEXT,
    created_at REAL NOT NULL,
    started_at REAL,
    finished_at REAL,
    timeout_sec REAL,
    cwd TEXT,
    retry_json TEXT
)
"""


class TaskManager:
    """共享异步批量任务管理器 (Issue #57)。

    状态机: queued → running → done/failed; 失败且未耗尽重试 → queued (带退避 next_retry_at)。
    持久化: SQLite (data_dir/tasks.db) — 跨进程重启存活 (async 任务闭包除外, 重启后标 failed)。
    信任边界: 进程内组件 — 宿主应用自身做 fusion-identity 鉴权 (业务应用已持有 FUSION_CLIENT_KEY)。
    """

    def __init__(
        self,
        data_dir: str | Path,
        *,
        executor: FusionSandboxExecutor | None = None,
        max_workers: int = 4,
        poll_interval_sec: float = 0.1,
    ) -> None:
        if max_workers < 1:
            raise ValueError(f"max_workers 须 >= 1, 得 {max_workers!r}")
        if poll_interval_sec <= 0:
            raise ValueError(f"poll_interval_sec 须为正数, 得 {poll_interval_sec!r}")
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.executor = executor or FusionSandboxExecutor()
        self.max_workers = max_workers
        self.poll_interval_sec = poll_interval_sec
        self._db = self.data_dir / "tasks.db"
        self._conn = sqlite3.connect(self._db, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._wake: asyncio.Event = asyncio.Event()
        self._workers: list[asyncio.Task] = []
        self._stopped = False
        self._cancel_flags: set[str] = set()
        self._running_tasks: dict[str, asyncio.Task] = {}
        self._async_factories: dict[str, Callable[..., Awaitable[Any]]] = {}
        logger.info("TaskManager init db=%s max_workers=%s poll=%.2fs", self._db, max_workers, poll_interval_sec)

    # ---------- 生命周期 ----------

    async def start(self) -> None:
        if self._workers:
            return
        self._stopped = False
        for i in range(self.max_workers):
            self._workers.append(asyncio.create_task(self._worker_loop(i), name=f"fe-task-worker-{i}"))
        logger.info("TaskManager started workers=%d", self.max_workers)

    async def stop(self, *, wait: bool = True) -> None:
        self._stopped = True
        self._wake.set()
        workers, self._workers = self._workers, []
        for t in list(self._running_tasks.values()):
            t.cancel()
        if wait and workers:
            await asyncio.gather(*workers, return_exceptions=True)
        logger.info("TaskManager stopped workers=%d", len(workers))

    def close(self) -> None:
        self._conn.close()
        logger.info("TaskManager closed db=%s", self._db)

    # ---------- 提交 ----------

    def submit_shell(
        self,
        command: str,
        *,
        name: str | None = None,
        timeout_sec: float = _DEFAULT_TIMEOUT_SEC,
        cwd: str | None = None,
        retry: RetryPolicy | None = None,
    ) -> str:
        if not isinstance(command, str) or not command.strip():
            raise ValueError("command 必须为非空 str")
        if timeout_sec <= 0:
            raise ValueError(f"timeout_sec 须为正数, 得 {timeout_sec!r}")
        rp = retry or RetryPolicy()
        task_id = f"t-{uuid.uuid4().hex[:12]}"
        now = time.time()
        self._conn.execute(
            "INSERT INTO tasks (task_id, kind, name, command, state, attempts, max_retries,"
            " next_retry_at, created_at, timeout_sec, cwd, retry_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                task_id,
                "shell",
                name,
                command,
                TaskState.QUEUED.value,
                0,
                rp.max_retries,
                now,
                now,
                timeout_sec,
                cwd,
                rp.model_dump_json(),
            ),
        )
        self._conn.commit()
        logger.info(
            "task submit shell id=%s name=%s cmd=%r timeout=%s retry=%d",
            task_id,
            name,
            command,
            timeout_sec,
            rp.max_retries,
        )
        self._wake.set()
        return task_id

    def submit_async(
        self,
        factory: Callable[..., Awaitable[Any]],
        *,
        name: str | None = None,
        retry: RetryPolicy | None = None,
    ) -> str:
        if not callable(factory):
            raise TypeError("factory 必须为 callable 返回 Awaitable")
        rp = retry or RetryPolicy()
        task_id = f"t-{uuid.uuid4().hex[:12]}"
        now = time.time()
        self._conn.execute(
            "INSERT INTO tasks (task_id, kind, name, state, attempts, max_retries,"
            " next_retry_at, created_at, retry_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                task_id,
                "async",
                name,
                TaskState.QUEUED.value,
                0,
                rp.max_retries,
                now,
                now,
                rp.model_dump_json(),
            ),
        )
        self._conn.commit()
        self._async_factories[task_id] = factory
        logger.info("task submit async id=%s name=%s retry=%d", task_id, name, rp.max_retries)
        self._wake.set()
        return task_id

    # ---------- 查询 / 导出 ----------

    def status(self, task_id: str) -> TaskStatus:
        row = self._get(task_id)
        return self._to_status(row)

    def list_tasks(self, state: TaskState | None = None) -> list[TaskStatus]:
        if state is None:
            rows = self._conn.execute("SELECT * FROM tasks ORDER BY created_at").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM tasks WHERE state=? ORDER BY created_at", (state.value,)
            ).fetchall()
        return [self._to_status(r) for r in rows]

    def result(self, task_id: str) -> dict[str, Any] | None:
        row = self._get(task_id)
        if not row["result_json"]:
            return None
        return json.loads(row["result_json"])

    def export(self, task_id: str, path: str | Path | None = None) -> Path:
        report = self.status(task_id).model_dump(mode="json")
        out = Path(path) if path else self.data_dir / "exports" / f"{task_id}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("task export id=%s path=%s", task_id, out)
        return out

    def export_report(self, path: str | Path | None = None) -> Path:
        report = {
            "exported_at": time.time(),
            "counts": {s.value: len(self.list_tasks(s)) for s in TaskState},
            "tasks": [t.model_dump(mode="json") for t in self.list_tasks()],
        }
        out = Path(path) if path else self.data_dir / "exports" / f"report-{int(time.time())}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("task report exported path=%s", out)
        return out

    async def cancel(self, task_id: str) -> bool:
        row = self._get(task_id)
        state = row["state"]
        if state == TaskState.QUEUED.value:
            self._async_factories.pop(task_id, None)
            self._conn.execute(
                "UPDATE tasks SET state=?, finished_at=?, failure_reason=? WHERE task_id=?",
                (TaskState.CANCELLED.value, time.time(), "cancelled before start", task_id),
            )
            self._conn.commit()
            logger.info("task cancel (queued) id=%s", task_id)
            return True
        if state == TaskState.RUNNING.value:
            if row["kind"] == "async":
                t = self._running_tasks.get(task_id)
                if t is not None:
                    t.cancel()
            else:
                self._cancel_flags.add(task_id)
            logger.info("task cancel (running) id=%s", task_id)
            return True
        logger.info("task cancel no-op id=%s state=%s", task_id, state)
        return False

    # ---------- 内部 ----------

    def _get(self, task_id: str) -> sqlite3.Row:
        row = self._conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(f"task 不存在: {task_id}")
        return row

    def _to_status(self, row: sqlite3.Row) -> TaskStatus:
        result = json.loads(row["result_json"]) if row["result_json"] else None
        duration = None
        if row["started_at"] and row["finished_at"]:
            duration = round(row["finished_at"] - row["started_at"], 3)
        return TaskStatus(
            task_id=row["task_id"],
            kind=row["kind"],
            name=row["name"],
            state=TaskState(row["state"]),
            progress=round(row["progress"], 4),
            attempts=row["attempts"],
            max_retries=row["max_retries"],
            failure_reason=row["failure_reason"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            duration_sec=duration,
            result=result,
        )

    def _claim_next(self) -> sqlite3.Row | None:
        now = time.time()
        row = self._conn.execute(
            "SELECT * FROM tasks WHERE state=? AND next_retry_at<=? ORDER BY next_retry_at LIMIT 1",
            (TaskState.QUEUED.value, now),
        ).fetchone()
        if row is None:
            return None
        attempts = row["attempts"] + 1
        self._conn.execute(
            "UPDATE tasks SET state=?, attempts=?, started_at=COALESCE(started_at,?), progress=0 WHERE task_id=?",
            (TaskState.RUNNING.value, attempts, now, row["task_id"]),
        )
        self._conn.commit()
        logger.info(
            "task claim id=%s kind=%s attempt=%d/%d", row["task_id"], row["kind"], attempts, row["max_retries"] + 1
        )
        return self._get(row["task_id"])

    async def _worker_loop(self, idx: int) -> None:
        while not self._stopped:
            row = self._claim_next()
            if row is None:
                self._wake.clear()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._wake.wait(), timeout=self.poll_interval_sec)
                continue
            try:
                if row["kind"] == "shell":
                    await self._run_shell(row)
                else:
                    await self._run_async(row)
            except Exception as e:  # worker 兜底 — 单任务异常不杀 worker (Rule 12 log)
                logger.exception("task worker %d crash on id=%s", idx, row["task_id"])
                self._handle_failure(row["task_id"], f"worker internal error: {e!r}")

    async def _run_shell(self, row: sqlite3.Row) -> None:
        task_id = row["task_id"]
        command = row["command"]
        timeout_sec = row["timeout_sec"] or _DEFAULT_TIMEOUT_SEC
        sr = self.executor.shell_start(
            command,
            cwd=row["cwd"],
            task_id=task_id,
            max_idle_sec=max(1, int(timeout_sec)),
        )
        if sr.blocked_by_security or not sr.ok or sr.shell_id is None:
            reason = sr.security_reason or sr.error or "shell_start failed"
            logger.warning("task %s blocked/failed at start: %s", task_id, reason)
            self._handle_failure(task_id, f"blocked: {reason}")
            return
        shell_id = sr.shell_id
        logger.info("task %s shell started shell_id=%s", task_id, shell_id)
        last_len = 0
        deadline = time.time() + timeout_sec
        exit_code: int | None = None
        while True:
            if task_id in self._cancel_flags:
                self._cancel_flags.discard(task_id)
                self.executor.kill_shell(shell_id)
                self._finish(task_id, TaskState.CANCELLED, "cancelled while running")
                return
            so = self.executor.shell_output(shell_id)
            out = so.output or ""
            if len(out) < last_len:  # tail 截断回卷 — 重新解析
                last_len = 0
            new = out[last_len:]
            last_len = len(out)
            m = _PROGRESS_RE.search(new)
            if m:
                try:
                    p = min(max(float(m.group(1)), 0.0), 1.0)
                    self._conn.execute("UPDATE tasks SET progress=? WHERE task_id=?", (p, task_id))
                    self._conn.commit()
                    logger.debug("task %s progress=%.2f", task_id, p)
                except ValueError:
                    pass
            if not so.running:
                exit_code = so.exit_code
                break
            if time.time() > deadline:
                self.executor.kill_shell(shell_id)
                self._handle_failure(task_id, f"timeout after {timeout_sec}s")
                return
            await asyncio.sleep(self.poll_interval_sec)
        if exit_code == 0:
            self._finish(
                task_id,
                TaskState.DONE,
                None,
                result={"exit_code": exit_code, "output": out},
            )
        else:
            self._handle_failure(task_id, f"exit_code={exit_code}; output tail: {out[-500:]!r}")

    async def _run_async(self, row: sqlite3.Row) -> None:
        task_id = row["task_id"]
        factory = self._async_factories.get(task_id)
        if factory is None:
            self._handle_failure(task_id, "async factory lost (process restart)")
            return
        try:
            sig = inspect.signature(factory)
            takes_arg = len(sig.parameters) > 0
        except (TypeError, ValueError):
            takes_arg = False

        def report_progress(p: float) -> None:
            pv = min(max(float(p), 0.0), 1.0)
            self._conn.execute("UPDATE tasks SET progress=? WHERE task_id=?", (pv, task_id))
            self._conn.commit()
            logger.debug("task %s progress=%.2f", task_id, pv)

        coro = factory(report_progress) if takes_arg else factory()
        at = asyncio.create_task(coro)
        self._running_tasks[task_id] = at
        try:
            ret = await at
        except asyncio.CancelledError:
            self._finish(task_id, TaskState.CANCELLED, "cancelled while running")
            return
        except Exception as e:
            self._handle_failure(task_id, f"{type(e).__name__}: {e}")
            return
        finally:
            self._running_tasks.pop(task_id, None)
        try:
            result = json.loads(json.dumps(ret, ensure_ascii=False, default=str))
        except (TypeError, ValueError):
            result = {"repr": repr(ret)}
        if not isinstance(result, dict):
            result = {"value": result}
        self._finish(task_id, TaskState.DONE, None, result=result)

    def _handle_failure(self, task_id: str, reason: str) -> None:
        row = self._get(task_id)
        attempts = row["attempts"]
        reason_short = reason[:_FAILURE_REASON_MAX]
        if attempts <= row["max_retries"]:
            try:
                rp = RetryPolicy.model_validate_json(row["retry_json"] or "{}")
            except Exception:
                rp = RetryPolicy(max_retries=row["max_retries"])
            backoff = rp.backoff_sec(attempts)
            self._conn.execute(
                "UPDATE tasks SET state=?, failure_reason=?, next_retry_at=? WHERE task_id=?",
                (TaskState.QUEUED.value, reason_short, time.time() + backoff, task_id),
            )
            self._conn.commit()
            logger.warning("task %s attempt %d failed, retry in %.2fs: %s", task_id, attempts, backoff, reason_short)
            self._wake.set()
        else:
            self._finish(task_id, TaskState.FAILED, reason_short)

    def _finish(
        self,
        task_id: str,
        state: TaskState,
        failure_reason: str | None,
        result: dict[str, Any] | None = None,
    ) -> None:
        progress = 1.0 if state == TaskState.DONE else None
        self._conn.execute(
            "UPDATE tasks SET state=?, failure_reason=?, result_json=?, finished_at=?,"
            " progress=COALESCE(?, progress) WHERE task_id=?",
            (
                state.value,
                failure_reason,
                json.dumps(result, ensure_ascii=False) if result is not None else None,
                time.time(),
                progress,
                task_id,
            ),
        )
        self._conn.commit()
        self._async_factories.pop(task_id, None)  # 终态才释放 — 重试轮次间保留 factory
        logger.info("task finish id=%s state=%s", task_id, state.value)
