from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
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
    raise TimeoutError(f"socket 未出现: {path}")


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
            "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()",
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
    # D6-01: pidfile helpers 直接测 (不跑 serve — serve 阻塞)。写 → 读校验 pid → 删 → 删后 no-op。
    from fusion_executor.executor import remove_pidfile, write_pidfile

    pid_path = str(tmp_path / "fe-test.pid")
    assert not os.path.exists(pid_path)
    write_pidfile(pid_path)
    assert os.path.exists(pid_path)
    with open(pid_path, encoding="utf-8") as f:
        pid_str = f.read()
    assert pid_str == str(os.getpid()), "pidfile 应写入当前进程 pid"
    remove_pidfile(pid_path)
    assert not os.path.exists(pid_path), "删除后 pidfile 应不存在"
    # 删不存在文件应 no-op 不抛
    remove_pidfile(pid_path)


def test_pidfile_serve_lifecycle(tmp_path: Path):
    # D6-01: serve 启动写 pidfile, 停机删 — 跨进程验证。注入 FUSION_EXECUTOR_PIDFILE 指向 tmp,
    # 不污染 HOME。启动子进程 serve → 等 pidfile 出现 → 读校验 pid 匹配 → 停机 → 验证已删。
    pid_path = str(tmp_path / "fe-lifecycle.pid")
    sock = _sock_path()
    env = dict(os.environ, FUSION_EXECUTOR_SOCK=sock, FUSION_EXECUTOR_PIDFILE=pid_path)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()",
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
        assert os.path.exists(pid_path), "serve 启动应写 pidfile"
        with open(pid_path, encoding="utf-8") as f:
            written_pid = int(f.read().strip())
        assert written_pid == proc.pid, f"pidfile pid {written_pid} 应匹配 serve 子进程 {proc.pid}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        if os.path.exists(sock):
            os.unlink(sock)
    # 停机后 pidfile 应被 finally remove_pidfile 清理
    assert not os.path.exists(pid_path), "serve 停机应删 pidfile"


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
    # C-OPS-05b: 先跑一次成功命令累计数, 再读 metrics 快照
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
    # C-OPS-05b: Python FusionSandboxExecutor.metrics() 包装 UDS 调用
    from fusion_executor import FusionSandboxExecutor

    _rpc(server, {"jsonrpc": "2.0", "id": 2, "method": "executor.execute", "params": {"command": "echo hi"}})
    ex = FusionSandboxExecutor(sock_path=server)
    m = ex.metrics()
    assert m["exec_total"] >= 1
    assert m["exec_success"] >= 1


def test_metrics_prometheus_over_uds(server: str):
    # M-OPS-02: Prometheus text format — execute 一次后 fe_exec_total 命中 + HELP/TYPE 头
    _rpc(server, {"jsonrpc": "2.0", "id": 2, "method": "executor.execute", "params": {"command": "echo hi"}})
    resp = _rpc(server, {"jsonrpc": "2.0", "id": 3, "method": "executor.metrics_prometheus", "params": {}})
    assert resp["result"]["ok"] is True
    text = resp["result"]["text"]
    assert "# HELP fe_exec_total" in text
    assert "# TYPE fe_exec_total counter" in text
    assert "# TYPE fe_connections gauge" in text
    assert "fe_exec_total" in text


def test_metrics_prometheus_wrapper_method(server: str):
    # M-OPS-02: Python FusionSandboxExecutor.metrics_prometheus() 包装 UDS 调用
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
    assert sid, "快照 id 非空"

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
    assert frames, "应至少收到一帧"
    types = [f["result"]["type"] for f in frames]
    assert types[-1] == "done"
    assert all(f["id"] == 7 for f in frames), "所有帧共用 id"
    done = frames[-1]["result"]["result"]
    assert done["exit_code"] == 0
    assert "hi" in done["stdout"]
