from __future__ import annotations

import os
import subprocess
import tempfile

import pytest

from fusion_executor import ExecutionResult, FusionSandboxExecutor


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
