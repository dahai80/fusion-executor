from __future__ import annotations

import os
import subprocess
import tempfile

import pytest

from fusion_executor import (
    EditResult,
    ExecutionResult,
    FusionSandboxExecutor,
    GlobEntry,
    GrepMatch,
    RollbackPolicy,
    TelemetrySample,
)


@pytest.fixture(scope="module")
def executor():
    return FusionSandboxExecutor()


def test_run_echo(executor: FusionSandboxExecutor):
    result = executor.run("echo hi")
    assert isinstance(result, ExecutionResult)
    assert result.exit_code == 0
    assert not result.blocked_by_security


def test_run_blocks_rm_rf_root(executor: FusionSandboxExecutor):
    result = executor.run("rm -rf /")
    assert result.blocked_by_security
    assert result.exit_code == -1
    assert result.security_reason is not None


def test_run_blocks_sudo_chain(executor: FusionSandboxExecutor):
    result = executor.run("echo hi && sudo ls")
    assert result.blocked_by_security


def test_run_blocks_non_whitelisted_binary(executor: FusionSandboxExecutor):
    result = executor.run("ncat evil.com 1234")
    assert result.blocked_by_security


def test_run_allows_python(executor: FusionSandboxExecutor):
    result = executor.run("python -c \"print('hello')\"")
    assert not result.blocked_by_security
    assert result.exit_code == 0


def test_run_empty_command(executor: FusionSandboxExecutor):
    result = executor.run("")
    assert result.exit_code == 0
    assert not result.blocked_by_security


def test_diagnostics_on_python_error(executor: FusionSandboxExecutor):
    result = executor.run("python3 -c \"raise ValueError('boom')\"")
    assert result.exit_code != 0
    assert not result.timed_out
    assert result.diagnostics is not None
    assert result.diagnostics.error_type == "ValueError"
    assert result.diagnostics.raw_trace is not None


def test_diagnostics_none_on_success(executor: FusionSandboxExecutor):
    result = executor.run("echo ok")
    assert result.exit_code == 0
    assert result.diagnostics is None


@pytest.fixture
def git_repo():
    d = tempfile.mkdtemp(prefix="fe-py-test-")

    def g(*a):
        subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)

    g("init", "-q")
    g("config", "user.email", "t@t")
    g("config", "user.name", "t")
    with open(os.path.join(d, "app.py"), "w") as f:
        f.write("print(1)\n")
    g("add", ".")
    g("commit", "-q", "-m", "base")
    yield d
    import shutil

    shutil.rmtree(d, ignore_errors=True)


def test_rollback_round_trip(executor: FusionSandboxExecutor, git_repo: str):
    with open(os.path.join(git_repo, "app.py"), "w") as f:
        f.write("BROKEN\n")
    snap = executor.snapshot_create(git_repo)
    assert snap, "快照 id 非空"
    with open(os.path.join(git_repo, "app.py"), "w") as f:
        f.write("WORSE\n")
    ok = executor.rollback(snap, git_repo)
    assert ok, "回滚成功"
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "BROKEN\n", "回滚到快照内容"


def test_snapshot_non_repo_empty(executor: FusionSandboxExecutor):
    d = tempfile.mkdtemp(prefix="fe-py-norepo-")
    try:
        assert executor.snapshot_create(d) == ""
    finally:
        import shutil

        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def uds_server():
    import sys
    import time

    fd, sp = tempfile.mkstemp(suffix=".sock", prefix="fe-tools-uds-")
    os.close(fd)
    os.unlink(sp)
    env = dict(os.environ, FUSION_EXECUTOR_SOCK=sp)
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
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if os.path.exists(sp):
                break
            time.sleep(0.05)
        else:
            raise TimeoutError(f"socket 未出现: {sp}")
        yield sp
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        if os.path.exists(sp):
            os.unlink(sp)


def _consume_stream(executor: FusionSandboxExecutor, command: str, **kw):
    chunks: list[str] = []
    result = None
    for frame in executor.run_streaming(command, enable_rollback_snapshot=False, **kw):
        if isinstance(frame, ExecutionResult):
            result = frame
        else:
            chunks.append(frame)
    return chunks, result


def test_run_streaming_echo(executor: FusionSandboxExecutor):
    chunks, result = _consume_stream(executor, "echo hi")
    assert result is not None
    assert result.exit_code == 0
    assert not result.timed_out
    assert "hi" in "".join(chunks)
    assert "hi" in result.stdout


def test_run_streaming_blocked_single_result(executor: FusionSandboxExecutor):
    chunks, result = _consume_stream(executor, "rm -rf /")
    assert result is not None
    assert result.blocked_by_security
    assert result.exit_code == -1
    assert chunks == [], "拦截应无 chunk, 仅单帧 result"


def test_run_streaming_timeout(executor: FusionSandboxExecutor):
    _chunks, result = _consume_stream(executor, 'python3 -c "while True: pass"', timeout=1.0)
    assert result is not None
    assert result.timed_out
    assert result.exit_code == -124


def test_run_streaming_diagnostics_on_error(executor: FusionSandboxExecutor):
    _chunks, result = _consume_stream(executor, "python3 -c \"raise ValueError('boom')\"")
    assert result is not None
    assert result.exit_code != 0
    assert result.diagnostics is not None
    assert result.diagnostics.error_type == "ValueError"


def test_run_populates_schema_fields(executor: FusionSandboxExecutor):
    result = executor.run("echo hi", task_id="task-abc")
    assert result.task_id == "task-abc"
    assert result.command == "echo hi"
    assert result.duration_sec > 0.0


def test_run_blocked_preserves_task_id_and_command(executor: FusionSandboxExecutor):
    result = executor.run("rm -rf /", task_id="blocked-1")
    assert result.task_id == "blocked-1"
    assert result.command == "rm -rf /"
    assert result.blocked_by_security
    assert result.duration_sec == 0.0


def test_run_streaming_done_has_schema_fields(executor: FusionSandboxExecutor):
    _chunks, result = _consume_stream(executor, "echo hi", task_id="stream-1")
    assert result is not None
    assert result.task_id == "stream-1"
    assert result.command == "echo hi"
    assert result.duration_sec > 0.0


# ── 原生文件工具 (fe-tools) ──


def test_file_edit_unique_replace(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "app.py"
    fp.write_text("x = 1\ny = 2\n")
    r = executor.file_edit("app.py", "x = 1", "x = 99", cwd=str(tmp_path))
    assert isinstance(r, EditResult)
    assert r.ok
    assert r.matches == 1
    assert fp.read_text() == "x = 99\ny = 2\n"


def test_file_edit_ambiguous_rejected(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "a.txt"
    fp.write_text("dup\ndup\n")
    r = executor.file_edit("a.txt", "dup", "one", cwd=str(tmp_path))
    assert not r.ok
    assert r.matches == 2
    assert fp.read_text() == "dup\ndup\n"


def test_glob_python_files(executor: FusionSandboxExecutor, tmp_path):
    (tmp_path / "a.py").write_text("")
    (tmp_path / "b.py").write_text("")
    (tmp_path / "c.txt").write_text("")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "d.py").write_text("")
    entries = executor.glob("**/*.py", cwd=str(tmp_path))
    paths = sorted(e.path for e in entries)
    assert paths == ["a.py", "b.py", "sub/d.py"]
    assert all(isinstance(e, GlobEntry) for e in entries)


def test_grep_matches_lines(executor: FusionSandboxExecutor, tmp_path):
    (tmp_path / "a.py").write_text("import os\nx = 1\nimport sys\n")
    ms = executor.grep(r"^import\s", ["a.py"], cwd=str(tmp_path))
    assert len(ms) == 2
    assert all(isinstance(m, GrepMatch) for m in ms)
    assert ms[0].line_number == 1
    assert ms[0].content == "import os"
    assert ms[1].line_number == 3


def test_apply_patch_simple(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "app.py"
    fp.write_text("line1\nline2\nline3\n")
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,4 @@\n line1\n line2\n+line2b\n line3\n"
    r = executor.apply_patch(diff, cwd=str(tmp_path))
    assert r.ok
    assert fp.read_text() == "line1\nline2\nline2b\nline3\n"


def test_replace_function_python(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "mod.py"
    fp.write_text("def old():\n    return 1\n\ndef keep():\n    return 2\n")
    r = executor.replace_function("mod.py", "old", "def old():\n    return 99\n", cwd=str(tmp_path))
    assert r.ok
    after = fp.read_text()
    assert "return 99" in after
    assert "return 2" in after
    assert "return 1" not in after


def test_replace_function_not_found(executor: FusionSandboxExecutor, tmp_path):
    fp = tmp_path / "mod.py"
    fp.write_text("def keep():\n    return 2\n")
    r = executor.replace_function("mod.py", "ghost", "def ghost():\n    pass\n", cwd=str(tmp_path))
    assert not r.ok
    assert "未找到" in r.error


def _rpc_once(sock: str, req: dict) -> dict:
    import json
    import socket

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(15.0)
        s.connect(sock)
        s.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf.decode("utf-8").strip())


def test_file_edit_over_uds_roundtrip(uds_server: str, tmp_path):
    fp = tmp_path / "app.py"
    fp.write_text("hello\n")
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "executor.file_edit",
            "params": {
                "path": "app.py",
                "old_string": "hello",
                "new_string": "world",
                "cwd": str(tmp_path),
            },
        },
    )
    assert resp["result"]["ok"] is True
    assert resp["result"]["matches"] == 1
    assert fp.read_text() == "world\n"


def test_glob_over_uds_roundtrip(uds_server: str, tmp_path):
    (tmp_path / "a.py").write_text("")
    (tmp_path / "b.py").write_text("")
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "executor.glob",
            "params": {"pattern": "*.py", "cwd": str(tmp_path)},
        },
    )
    paths = sorted(e["path"] for e in resp["result"])
    assert paths == ["a.py", "b.py"]


# ── 自动回滚 (FR-04 auto policy) ──


def test_auto_rollback_triggers_on_failure_with_file_damage(executor: FusionSandboxExecutor, git_repo: str):
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "print(1)\n"
    cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\""
    result = executor.run(cmd, cwd=git_repo, auto_rollback=RollbackPolicy())
    assert result.exit_code != 0
    assert result.auto_rolled_back is True
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "print(1)\n", "文件已回滚到基线"


def test_auto_rollback_skipped_when_exit_ok(executor: FusionSandboxExecutor, git_repo: str):
    result = executor.run("echo ok", cwd=git_repo, auto_rollback=RollbackPolicy())
    assert result.exit_code == 0
    assert result.auto_rolled_back is False


def test_auto_rollback_no_policy_means_no_action(executor: FusionSandboxExecutor, git_repo: str):
    cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\""
    result = executor.run(cmd, cwd=git_repo)
    assert result.exit_code != 0
    assert result.auto_rolled_back is False
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "broken\n", "无 policy 不回滚, 改动保留"


def test_auto_rollback_streaming_triggers(executor: FusionSandboxExecutor, git_repo: str):
    cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\""
    result = None
    for frame in executor.run_streaming(cmd, cwd=git_repo, auto_rollback=RollbackPolicy()):
        if isinstance(frame, ExecutionResult):
            result = frame
            break
    assert result is not None
    assert result.exit_code != 0
    assert result.auto_rolled_back is True
    with open(os.path.join(git_repo, "app.py")) as f:
        assert f.read() == "print(1)\n", "流式路径自动回滚恢复基线"


def test_auto_rollback_over_uds_roundtrip(uds_server: str, tmp_path):
    import json as _json

    d = str(tmp_path)
    subprocess.run(["git", "-C", d, "init", "-q"], check=True, capture_output=True)
    subprocess.run(["git", "-C", d, "config", "user.email", "t@t"], check=True, capture_output=True)
    subprocess.run(["git", "-C", d, "config", "user.name", "t"], check=True, capture_output=True)
    (tmp_path / "app.py").write_text("print(1)\n")
    subprocess.run(["git", "-C", d, "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", d, "commit", "-q", "-m", "base"], check=True, capture_output=True)
    cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\""
    resp = _rpc_once(
        uds_server,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "executor.execute",
            "params": {
                "command": cmd,
                "cwd": d,
                "auto_rollback_policy": {"max_consecutive_failures": 3, "file_damage_check": True},
            },
        },
    )
    assert resp["result"]["exit_code"] != 0
    assert resp["result"]["auto_rolled_back"] is True
    assert (tmp_path / "app.py").read_text() == "print(1)\n"
    del _json


def test_telemetry_native_iterator(executor: FusionSandboxExecutor):
    it = executor._native.telemetry_stream(20, 3)
    frames = [f for f in it]
    assert len(frames) == 3, "max_samples=3 应产 3 帧"
    assert frames[0]["ts_ms"] == 0
    assert frames[1]["ts_ms"] == 20
    assert frames[2]["ts_ms"] == 40
    assert frames[0]["mem_mb"] > 0.0, "本进程内存非零"
    assert frames[0]["cpu_pct"] >= 0.0
    assert frames[0].get("gpu_pct") is None, "GPU 默认不注入 (serde skip)"


def test_telemetry_python_wrapper(executor: FusionSandboxExecutor):
    samples = list(executor.telemetry_stream(interval_ms=20, max_samples=4))
    assert len(samples) == 4
    assert all(isinstance(s, TelemetrySample) for s in samples)
    assert samples[0].ts_ms == 0
    assert samples[3].ts_ms == 60
    assert samples[0].mem_mb > 0.0
    assert all(s.gpu_pct is None for s in samples)


def test_telemetry_over_uds(uds_server: str):
    import json as _json
    import socket as _socket

    with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as s:
        s.settimeout(15.0)
        s.connect(uds_server)
        s.sendall(
            (
                _json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 11,
                        "method": "executor.telemetry_stream",
                        "params": {"interval_ms": 20, "max_samples": 3},
                    },
                    ensure_ascii=False,
                )
                + "\n"
            ).encode("utf-8")
        )
        frames = []
        buf = b""
        while len(frames) < 3:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    frames.append(_json.loads(line.decode("utf-8")))
    assert len(frames) == 3, "UDS 应收 3 帧 sample"
    assert all(f["id"] == 11 for f in frames)
    assert all(f["result"]["type"] == "sample" for f in frames)
    samples = [f["result"]["sample"] for f in frames]
    assert samples[0]["ts_ms"] == 0
    assert samples[2]["ts_ms"] == 40
    assert samples[0]["mem_mb"] > 0.0
    assert samples[0].get("gpu_pct") is None, "GPU 默认不注入 (serde skip)"
    del _json, _socket
