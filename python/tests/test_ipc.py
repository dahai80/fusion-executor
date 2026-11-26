from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest


def _sock_path() -> str:
    fd, p = tempfile.mkstemp(suffix=".sock", prefix="fe-ipc-py-")
    os.close(fd)
    os.unlink(p)
    return p


def _wait_sock(path: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise TimeoutError(f"socket did not appear: {path}")


def _rpc(path: str, req: dict) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(15.0)
        s.connect(path)
        s.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf.decode("utf-8").strip())


@pytest.fixture
def server():
    sock = _sock_path()
    env = dict(os.environ, FUSION_EXECUTOR_SOCK=sock)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor(allow_inline_interpreter=True).serve()",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_sock(sock)
        yield sock
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        if os.path.exists(sock):
            os.unlink(sock)


def test_health_over_uds(server: str):
    resp = _rpc(server, {"jsonrpc": "2.0", "id": 1, "method": "executor.health", "params": {}})
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    assert resp["result"]["ok"] is True
    assert resp["result"]["ax_trusted"] is True
    assert resp["result"]["seatbelt_default_on"] is True  # ARCH-1
    assert "version" in resp["result"]


def test_pidfile_write_remove_roundtrip(tmp_path: Path):
    # D6-01: pidfile helpers tested directly (no serve run — serve blocks). write → read-verify pid → delete → no-op after delete.
    from fusion_executor.executor import remove_pidfile, write_pidfile

    pid_path = str(tmp_path / "fe-test.pid")
    assert not os.path.exists(pid_path)
    write_pidfile(pid_path)
    assert os.path.exists(pid_path)
    with open(pid_path, encoding="utf-8") as f:
        pid_str = f.read()
    assert pid_str == str(os.getpid()), "pidfile should contain the current process pid"
    remove_pidfile(pid_path)
    assert not os.path.exists(pid_path), "pidfile should not exist after deletion"
    # deleting a nonexistent file should be a no-op without raising
    remove_pidfile(pid_path)


def test_pidfile_serve_lifecycle(tmp_path: Path):
    # D6-01: serve writes the pidfile on startup and deletes it on shutdown — verified cross-process. Point FUSION_EXECUTOR_PIDFILE at tmp,
    # keeping HOME unpolluted. Start a child serve → wait for the pidfile → read and verify the pid matches → shut down → verify deletion.
    pid_path = str(tmp_path / "fe-lifecycle.pid")
    sock = _sock_path()
    env = dict(os.environ, FUSION_EXECUTOR_SOCK=sock, FUSION_EXECUTOR_PIDFILE=pid_path)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor(allow_inline_interpreter=True).serve()",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_sock(sock)
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if os.path.exists(pid_path):
                break
            time.sleep(0.05)
        assert os.path.exists(pid_path), "serve startup should write the pidfile"
        with open(pid_path, encoding="utf-8") as f:
            written_pid = int(f.read().strip())
        assert written_pid == proc.pid, f"pidfile pid {written_pid} should match the serve child {proc.pid}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        if os.path.exists(sock):
            os.unlink(sock)
    # after shutdown the pidfile should be cleaned up by finally remove_pidfile
    assert not os.path.exists(pid_path), "serve shutdown should delete the pidfile"


def test_execute_echo_over_uds(server: str):
    resp = _rpc(
        server,
        {"jsonrpc": "2.0", "id": 2, "method": "executor.execute", "params": {"command": "echo hi"}},
    )
    r = resp["result"]
    assert r["exit_code"] == 0
    assert r["stdout"] == "hi\n"


def test_execute_diagnostics_over_uds(server: str):
    resp = _rpc(
        server,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "executor.execute",
            "params": {"command": "python3 -c \"raise ValueError('boom')\""},
        },
    )
    r = resp["result"]
    assert r["exit_code"] != 0
    assert r["diagnostics"]["error_type"] == "ValueError"


def test_unknown_method_over_uds(server: str):
    resp = _rpc(server, {"jsonrpc": "2.0", "id": 4, "method": "nope", "params": {}})
    assert resp["error"]["code"] == -32601


def test_metrics_over_uds(server: str):
    # C-OPS-05b: run one successful command to accumulate counts, then read the metrics snapshot
    _rpc(server, {"jsonrpc": "2.0", "id": 2, "method": "executor.execute", "params": {"command": "echo hi"}})
    resp = _rpc(server, {"jsonrpc": "2.0", "id": 3, "method": "executor.metrics", "params": {}})
    m = resp["result"]
    assert m["exec_total"] >= 1
    assert m["exec_success"] >= 1
    assert isinstance(m["execute_duration_sec_avg"], (int, float))
    assert isinstance(m["stdio_bytes_total"], int)
    assert m["exec_blocked"] == 0
    assert m["rollback_total"] == 0


def test_metrics_wrapper_method(server: str):
    # C-OPS-05b: Python FusionSandboxExecutor.metrics() wraps the UDS call
    from fusion_executor import FusionSandboxExecutor

    _rpc(server, {"jsonrpc": "2.0", "id": 2, "method": "executor.execute", "params": {"command": "echo hi"}})
    ex = FusionSandboxExecutor(sock_path=server)
    m = ex.metrics()
    assert m["exec_total"] >= 1
    assert m["exec_success"] >= 1


def test_metrics_prometheus_over_uds(server: str):
    # M-OPS-02: Prometheus text format — after one execute fe_exec_total is present + HELP/TYPE headers
    _rpc(server, {"jsonrpc": "2.0", "id": 2, "method": "executor.execute", "params": {"command": "echo hi"}})
    resp = _rpc(server, {"jsonrpc": "2.0", "id": 3, "method": "executor.metrics_prometheus", "params": {}})
    assert resp["result"]["ok"] is True
    text = resp["result"]["text"]
    assert "# HELP fe_exec_total" in text
    assert "# TYPE fe_exec_total counter" in text
    assert "# TYPE fe_connections gauge" in text
    assert "fe_exec_total" in text


def test_metrics_prometheus_wrapper_method(server: str):
    # M-OPS-02: Python FusionSandboxExecutor.metrics_prometheus() wraps the UDS call
    from fusion_executor import FusionSandboxExecutor

    _rpc(server, {"jsonrpc": "2.0", "id": 2, "method": "executor.execute", "params": {"command": "echo hi"}})
    ex = FusionSandboxExecutor(sock_path=server)
    text = ex.metrics_prometheus()
    assert "# HELP fe_exec_total" in text
    assert "# TYPE fe_exec_total counter" in text


def test_snapshot_rollback_over_uds(server: str, tmp_path: Path):
    d = tmp_path / "repo"
    d.mkdir()

    def g(*a):
        subprocess.run(["git", "-C", str(d), *a], check=True, capture_output=True)

    g("init", "-q")
    g("config", "user.email", "t@t")
    g("config", "user.name", "t")
    (d / "app.py").write_text("print(1)\n")
    g("add", ".")
    g("commit", "-q", "-m", "base")
    (d / "app.py").write_text("BROKEN\n")

    snap = _rpc(
        server,
        {"jsonrpc": "2.0", "id": 5, "method": "executor.snapshot_create", "params": {"cwd": str(d)}},
    )
    sid = snap["result"]["snapshot_id"]
    assert sid, "snapshot id is empty"

    (d / "app.py").write_text("WORSE\n")
    rb = _rpc(
        server,
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "executor.rollback",
            "params": {"snapshot_id": sid, "cwd": str(d)},
        },
    )
    assert rb["result"]["ok"] is True
    assert (d / "app.py").read_text() == "BROKEN\n"


def test_list_snapshots_over_uds(server: str, tmp_path: Path):
    # D6-03 (audit 0827 product): snapshot inventory — snapshot_create writes an on-disk index, list_snapshots reads it back.
    d = tmp_path / "repo"
    d.mkdir()

    def g(*a):
        subprocess.run(["git", "-C", str(d), *a], check=True, capture_output=True)

    g("init", "-q")
    g("config", "user.email", "t@t")
    g("config", "user.name", "t")
    (d / "app.py").write_text("print(1)\n")
    g("add", ".")
    g("commit", "-q", "-m", "base")

    snap = _rpc(
        server,
        {"jsonrpc": "2.0", "id": 5, "method": "executor.snapshot_create", "params": {"cwd": str(d)}},
    )
    sid = snap["result"]["snapshot_id"]
    assert sid, "snapshot id is empty"

    lst = _rpc(
        server,
        {"jsonrpc": "2.0", "id": 6, "method": "executor.list_snapshots", "params": {"cwd": str(d)}},
    )
    snaps = lst["result"]["snapshots"]
    assert len(snaps) >= 1, "inventory should contain at least one snapshot"
    first = snaps[0]
    assert first["id"] == sid, "first inventory entry id should match the snapshot_create return"
    assert first["kind"] == "head", "no-change snapshot kind should be head"
    assert isinstance(first["created_ms"], int), "created_ms should be an integer"


def test_execute_stream_chunks_then_done_over_uds(server: str):
    req = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "executor.execute_stream",
        "params": {"command": "echo hi", "enable_rollback_snapshot": False},
    }
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(15.0)
        s.connect(server)
        s.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
        buf = b""
        frames: list[dict] = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                frame = json.loads(line.decode("utf-8"))
                frames.append(frame)
                if frame.get("result", {}).get("type") == "done":
                    break
            if frames and frames[-1].get("result", {}).get("type") == "done":
                break
    assert frames, "should receive at least one frame"
    types = [f["result"]["type"] for f in frames]
    assert types[-1] == "done"
    assert all(f["id"] == 7 for f in frames), "all frames share the id"
    done = frames[-1]["result"]["result"]
    assert done["exit_code"] == 0


# gap #5 regression: 64 concurrent echoes all complete, no deadlock starvation.
# old bug: serve_blocking ran on the shared BLOCKING_RT (8 worker cap), 64-connection fan-out starved →
# responses could not be written → recv 30s timeout (32/64 hang). Fixed by isolating on the dedicated IPC_RT (clamped 4-16).
def test_concurrent_echo_64_no_hang(server: str):
    n = 64
    results: list[tuple[int, dict | str]] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        try:
            resp = _rpc(
                server,
                {
                    "jsonrpc": "2.0",
                    "id": i + 1,
                    "method": "executor.execute",
                    "params": {"command": f"echo py{i}", "timeout_sec": 15},
                },
            )
            with lock:
                results.append((i, resp))
        except Exception as e:  # record any exception for the assertion
            with lock:
                results.append((i, f"{type(e).__name__}: {e}"))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20.0)
    wall = time.time() - t0

    # all threads must return within 20s (old bug: 32/64 hung until the 30s timeout)
    alive = [t for t in threads if t.is_alive()]
    assert not alive, f"{len(alive)}/{n} threads still hung (old bug deadlock): {[t.name for t in alive]}"
    assert len(results) == n, f"only {len(results)}/{n} returned: {results[:5]}"

    ok = 0
    errs = []
    for i, resp in results:
        if isinstance(resp, str):
            errs.append(f"{i}:{resp}")
            continue
        ec = resp.get("result", {}).get("exit_code")
        if ec == 0:
            ok += 1
        else:
            errs.append(f"{i}:exit{ec}:{resp}")
    assert ok == n, f"only {ok}/{n} exit_code==0, errs={errs[:5]}"
    assert wall < 15.0, f"wall {wall:.1f}s over budget (old bug 30s deadlock)"
