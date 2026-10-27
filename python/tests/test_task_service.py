from __future__ import annotations

import asyncio
import json

import pytest

from fusion_executor import RetryPolicy, TaskManager, TaskState, TaskStatus


@pytest.fixture
async def tm(tmp_path):
    m = TaskManager(tmp_path / "tasks", max_workers=4, poll_interval_sec=0.05)
    await m.start()
    yield m
    await m.stop()
    m.close()


@pytest.fixture
def scripts(tmp_path):
    # 白名单外 binary (sleep/false) 会被安全守卫拦截 — 用 python3 脚本代替
    d = tmp_path / "scripts"
    d.mkdir()
    (d / "sleep.py").write_text("import sys, time\ntime.sleep(float(sys.argv[1]))\n")
    (d / "fail.py").write_text("import sys\nsys.exit(1)\n")
    (d / "fail3.py").write_text("import sys\nsys.exit(3)\n")
    (d / "flag.py").write_text(
        "import sys, pathlib\n"
        "flag = pathlib.Path(sys.argv[1])\n"
        "if flag.exists():\n"
        "    print('ok')\n"
        "else:\n"
        "    flag.touch()\n"
        "    sys.exit(1)\n"
    )
    return d


async def wait_state(m: TaskManager, task_id: str, *states: TaskState, timeout: float = 15.0) -> TaskStatus:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        st = m.status(task_id)
        if st.state in states:
            return st
        await asyncio.sleep(0.02)
    st = m.status(task_id)
    pytest.fail(f"task {task_id} 未达 {states}, 当前 {st.state} reason={st.failure_reason}")


def test_state_machine_constants():
    assert TaskState.QUEUED.value == "queued"
    assert TaskState.RUNNING.value == "running"
    assert TaskState.DONE.value == "done"
    assert TaskState.FAILED.value == "failed"


def test_retry_policy_backoff():
    rp = RetryPolicy(max_retries=3, backoff_initial_sec=0.1, backoff_multiplier=2.0, backoff_max_sec=0.5)
    assert rp.backoff_sec(1) == 0.1
    assert rp.backoff_sec(2) == 0.2
    assert rp.backoff_sec(3) == 0.4
    assert rp.backoff_sec(4) == 0.5  # cap
    assert rp.backoff_sec(0) == 0.0


async def test_invalid_args(tm: TaskManager, tmp_path):
    with pytest.raises(ValueError):
        TaskManager(tmp_path / "bad", max_workers=0)
    with pytest.raises(ValueError):
        tm.submit_shell("")
    with pytest.raises(ValueError):
        tm.submit_shell("echo hi", timeout_sec=0)
    with pytest.raises(TypeError):
        tm.submit_async("not-callable")


async def test_shell_task_done(tm: TaskManager):
    task_id = tm.submit_shell("echo hello-task", name="t1")
    st = await wait_state(tm, task_id, TaskState.DONE)
    assert st.attempts == 1
    assert st.progress == 1.0
    assert st.duration_sec is not None and st.duration_sec >= 0
    res = tm.result(task_id)
    assert res is not None
    assert res["exit_code"] == 0
    assert "hello-task" in res["output"]


async def test_shell_task_fail_no_retry(tm: TaskManager, scripts):
    task_id = tm.submit_shell(f"python3 {scripts / 'fail.py'}")
    st = await wait_state(tm, task_id, TaskState.FAILED)
    assert st.attempts == 1
    assert st.failure_reason and "exit_code" in st.failure_reason


async def test_shell_task_retry_then_done(tm: TaskManager, tmp_path, scripts):
    # 第 1 次失败 (flag 文件不存在), 第 2 次成功 (自建 flag) — 验证重试 + 退避
    flag = tmp_path / "flag"
    task_id = tm.submit_shell(
        f"python3 {scripts / 'flag.py'} {flag}",
        retry=RetryPolicy(max_retries=2, backoff_initial_sec=0.05),
    )
    st = await wait_state(tm, task_id, TaskState.DONE, TaskState.FAILED)
    assert st.state == TaskState.DONE
    assert st.attempts == 2
    assert st.max_retries == 2


async def test_shell_task_retry_exhausted(tm: TaskManager, scripts):
    task_id = tm.submit_shell(
        f"python3 {scripts / 'fail3.py'}",
        retry=RetryPolicy(max_retries=1, backoff_initial_sec=0.05),
    )
    st = await wait_state(tm, task_id, TaskState.FAILED)
    assert st.attempts == 2  # 1 次原始 + 1 次重试
    assert "exit_code=3" in (st.failure_reason or "")


async def test_shell_task_progress(tm: TaskManager, scripts):
    cmd = f"echo 'TASK_PROGRESS: 0.5' && python3 {scripts / 'sleep.py'} 0.3 && echo done-marker"
    task_id = tm.submit_shell(cmd, timeout_sec=30)
    st = await wait_state(tm, task_id, TaskState.DONE)
    # 最终 progress=1.0 (done); 过程中应有 >=0.5 记录 — 靠轮询间隔 0.05s 覆盖 0.3s sleep
    assert st.state == TaskState.DONE
    assert "done-marker" in (tm.result(task_id) or {}).get("output", "")


async def test_shell_task_security_blocked(tm: TaskManager):
    # 危险命令被安全守卫拦截 — 立即 failed 且带 blocked 原因
    task_id = tm.submit_shell("rm -rf /")
    st = await wait_state(tm, task_id, TaskState.FAILED)
    assert st.attempts == 1
    assert "blocked" in (st.failure_reason or "")


async def test_shell_task_timeout(tm: TaskManager, scripts):
    task_id = tm.submit_shell(f"python3 {scripts / 'sleep.py'} 5", timeout_sec=0.3, retry=RetryPolicy(max_retries=0))
    st = await wait_state(tm, task_id, TaskState.FAILED)
    assert "timeout" in (st.failure_reason or "")


async def test_async_task_done(tm: TaskManager):
    async def factory():
        await asyncio.sleep(0.05)
        return {"answer": 42}

    task_id = tm.submit_async(factory, name="a1")
    await wait_state(tm, task_id, TaskState.DONE)
    assert tm.result(task_id) == {"answer": 42}


async def test_async_task_progress_and_retry(tm: TaskManager):
    calls = {"n": 0}

    async def factory(report_progress):
        calls["n"] += 1
        report_progress(0.3)
        if calls["n"] == 1:
            raise RuntimeError("first attempt fails")
        report_progress(0.9)
        return "ok"

    task_id = tm.submit_async(factory, retry=RetryPolicy(max_retries=1, backoff_initial_sec=0.05))
    st = await wait_state(tm, task_id, TaskState.DONE)
    assert st.attempts == 2
    assert st.progress == 1.0
    assert calls["n"] == 2
    assert tm.result(task_id) == {"value": "ok"}


async def test_async_task_failure_reason(tm: TaskManager):
    async def factory():
        raise ValueError("boom")

    task_id = tm.submit_async(factory)
    st = await wait_state(tm, task_id, TaskState.FAILED)
    assert "ValueError: boom" in (st.failure_reason or "")


async def test_cancel_queued(tmp_path, scripts):
    # max_workers=1 — blocker 占住唯一 worker, 第二任务停留 queued 可取消
    m = TaskManager(tmp_path / "q", max_workers=1, poll_interval_sec=0.05)
    await m.start()
    try:
        blocker = m.submit_shell(f"python3 {scripts / 'sleep.py'} 2", timeout_sec=10)
        await asyncio.sleep(0.2)  # 让 worker 抢占 blocker
        assert m.status(blocker).state == TaskState.RUNNING
        task_id = m.submit_shell("echo late", timeout_sec=10)
        assert m.status(task_id).state == TaskState.QUEUED
        assert await m.cancel(task_id) is True
        st = await wait_state(m, task_id, TaskState.CANCELLED)
        assert st.failure_reason == "cancelled before start"
        assert await m.cancel(blocker) is True
        await wait_state(m, blocker, TaskState.CANCELLED)
    finally:
        await m.stop()
        m.close()


async def test_cancel_running_shell(tm: TaskManager, scripts):
    task_id = tm.submit_shell(f"python3 {scripts / 'sleep.py'} 3", timeout_sec=30)
    await asyncio.sleep(0.2)  # running
    assert tm.status(task_id).state == TaskState.RUNNING
    assert await tm.cancel(task_id) is True
    st = await wait_state(tm, task_id, TaskState.CANCELLED)
    assert "cancelled while running" in (st.failure_reason or "")


async def test_cancel_running_async(tm: TaskManager):
    started = asyncio.Event()

    async def factory():
        started.set()
        await asyncio.sleep(10)
        return "never"

    task_id = tm.submit_async(factory)
    await started.wait()
    assert await tm.cancel(task_id) is True
    await wait_state(tm, task_id, TaskState.CANCELLED)


async def test_persistence_across_restart(tmp_path):
    data_dir = tmp_path / "tasks"
    m1 = TaskManager(data_dir)  # 不 start — 任务停留 queued
    task_id = m1.submit_shell("echo persisted", name="p1")
    assert m1.status(task_id).state == TaskState.QUEUED
    m1.close()

    m2 = TaskManager(data_dir, poll_interval_sec=0.05)
    st = m2.status(task_id)  # 跨重启读取
    assert st.state == TaskState.QUEUED
    assert st.name == "p1"
    await m2.start()
    st = await wait_state(m2, task_id, TaskState.DONE)
    m2.close()  # 双 close 由 fixture 外手动


async def test_async_factory_lost_after_restart(tmp_path):
    data_dir = tmp_path / "tasks"
    m1 = TaskManager(data_dir)

    async def factory():
        return 1

    task_id = m1.submit_async(factory)
    m1.close()  # factory 闭包随进程消失

    m2 = TaskManager(data_dir, poll_interval_sec=0.05)
    await m2.start()
    st = await wait_state(m2, task_id, TaskState.FAILED)
    assert "factory lost" in (st.failure_reason or "")
    await m2.stop()
    m2.close()


async def test_export_and_report(tm: TaskManager, tmp_path):
    task_id = tm.submit_shell("echo export-me", timeout_sec=15)
    await wait_state(tm, task_id, TaskState.DONE)
    p = tm.export(task_id)
    assert p.exists()
    data = json.loads(p.read_text())
    assert data["task_id"] == task_id
    assert data["result"]["exit_code"] == 0
    rp = tm.export_report()
    report = json.loads(rp.read_text())
    assert report["counts"]["done"] >= 1
    assert any(t["task_id"] == task_id for t in report["tasks"])


async def test_list_tasks_filter(tm: TaskManager, scripts):
    t1 = tm.submit_shell("echo a", timeout_sec=15)
    t2 = tm.submit_shell(f"python3 {scripts / 'fail.py'}", timeout_sec=15)
    await wait_state(tm, t1, TaskState.DONE)
    await wait_state(tm, t2, TaskState.FAILED)
    done = tm.list_tasks(TaskState.DONE)
    failed = tm.list_tasks(TaskState.FAILED)
    assert any(t.task_id == t1 for t in done)
    assert any(t.task_id == t2 for t in failed)
    assert len(tm.list_tasks()) >= 2


async def test_status_unknown_task(tm: TaskManager):
    with pytest.raises(KeyError):
        tm.status("t-nonexistent")
