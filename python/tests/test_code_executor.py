"""Tests for the sandboxed code-mode execution backend (issue #75)."""

import inspect
import subprocess
from typing import Any, Protocol, get_type_hints, runtime_checkable

import pytest

from fusion_executor import (
    CodeExecutionError,
    CodeSandboxProfile,
    FusionSandboxExecutor,
    SandboxedCodeExecutor,
)


@runtime_checkable
class HarnessCodeExecutor(Protocol):
    # mirrors fusion_harness.code_mode.CodeExecutor (fusion-harness#50);
    # stdlib-only copy so tests stay cross-repo dependency free
    def execute(self, script: str, namespace: dict) -> Any: ...


@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=ws, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=ws, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=ws, check=True)
    (ws / "seed.txt").write_text("seed\n")
    subprocess.run(["git", "add", "."], cwd=ws, check=True)
    subprocess.run(["git", "commit", "-qm", "seed"], cwd=ws, check=True)
    return ws


@pytest.fixture
def backend(workspace):
    return SandboxedCodeExecutor(FusionSandboxExecutor(), workspace=str(workspace))


def test_protocol_structural_compat(backend):
    # protocol-compatible with harness CodeExecutor (signature locked in fusion-harness#50)
    assert isinstance(backend, HarnessCodeExecutor)
    sig = inspect.signature(backend.execute)
    params = list(sig.parameters.values())
    assert [p.name for p in params] == ["script", "namespace"]
    hints = get_type_hints(backend.execute)
    assert hints["script"] is str
    assert hints["namespace"] is dict


def test_execute_returns_result_variable(backend):
    ns = {"add": lambda a, b: a + b}
    value = backend.execute("x = add(1, 2)\nresult = x + 1", ns)
    assert value == 4


def test_stub_receives_args_and_kwargs(backend):
    seen = {}

    def tool(*args, **kwargs):
        seen.update(args=args, kwargs=kwargs)
        return {"ok": True}

    value = backend.execute("r = fetch('u1', limit=3)\nresult = r['ok']", {"fetch": tool})
    assert value is True
    assert seen == {"args": ("u1",), "kwargs": {"limit": 3}}


def test_missing_result_variable_returns_none(backend):
    assert backend.execute("x = echo('hi')", {"echo": lambda s: s}) is None


def test_non_json_stub_result_roundtrips_as_repr(backend):
    sentinel = object()

    class Weird:
        def __repr__(self):
            return "<weird-42>"

    ns = {"grab": lambda: (sentinel, Weird())[1]}
    assert backend.execute("result = grab()", ns) == "<weird-42>"


def test_unknown_stub_name_rejected(backend):
    with pytest.raises(CodeExecutionError, match="invalid stub name"):
        backend.execute("result = 1", {"bad name": lambda: None})
    with pytest.raises(CodeExecutionError, match="not callable"):
        backend.execute("result = 1", {"nope": 42})


def test_stub_exception_yields_traceback_payload(backend):
    def boom():
        raise ValueError("boom inside tool")

    with pytest.raises(CodeExecutionError) as ei:
        backend.execute("result = boom()", {"boom": boom})
    msg = str(ei.value)
    # harness error-loop contract: "%s: %s" % (type(exc).__name__, exc) must
    # carry the full child traceback for self-repair
    assert msg.startswith("Traceback (most recent call last):")
    assert "ValueError: boom inside tool" in msg
    assert "CodeExecutionError: Traceback" in f"CodeExecutionError: {msg}"


def test_script_syntax_error_payload(backend):
    with pytest.raises(CodeExecutionError) as ei:
        backend.execute("def broken(:\n    pass", {})
    msg = str(ei.value)
    assert "Traceback (most recent call last):" in msg
    assert "SyntaxError" in msg


def test_script_runtime_error_payload(backend):
    with pytest.raises(CodeExecutionError) as ei:
        backend.execute("result = 1 / 0", {})
    msg = str(ei.value)
    assert "ZeroDivisionError: division by zero" in msg


def test_rollback_on_script_failure(backend, workspace):
    script = "with open('damage.txt', 'w') as f:\n    f.write('side effect')\nresult = undefined_helper(1)\n"
    with pytest.raises(CodeExecutionError):
        backend.execute(script, {})
    assert not (workspace / "damage.txt").exists()
    assert (workspace / "seed.txt").read_text() == "seed\n"


def test_rollback_disabled_keeps_side_effects(workspace):
    backend = SandboxedCodeExecutor(
        FusionSandboxExecutor(),
        workspace=str(workspace),
        profile=CodeSandboxProfile(rollback_on_failure=False),
    )
    script = "with open('keep.txt', 'w') as f:\n    f.write('kept')\nresult = undefined_helper(1)\n"
    with pytest.raises(CodeExecutionError):
        backend.execute(script, {})
    assert (workspace / "keep.txt").exists()


def test_profile_violation_visible_error(backend, monkeypatch):
    def blocked_run(*args, **kwargs):
        from fusion_executor import ExecutionResult

        return ExecutionResult(
            exit_code=-1,
            stdout="",
            stderr="denied",
            blocked_by_security=True,
            security_reason="seatbelt: network-outbound denied",
        )

    monkeypatch.setattr(backend._executor, "run", blocked_run)
    with pytest.raises(CodeExecutionError) as ei:
        backend.execute("result = 1", {})
    msg = str(ei.value)
    assert "SecurityViolation" in msg
    assert "network-outbound denied" in msg


def test_timeout_yields_timeout_payload(workspace):
    backend = SandboxedCodeExecutor(
        FusionSandboxExecutor(),
        workspace=str(workspace),
        profile=CodeSandboxProfile(timeout_sec=3.0),
    )
    with pytest.raises(CodeExecutionError) as ei:
        backend.execute("import time\nresult = time.sleep(30)", {})
    assert "TimeoutError" in str(ei.value)


def test_empty_script_rejected(backend):
    with pytest.raises(CodeExecutionError, match="empty script"):
        backend.execute("   \n", {})
    with pytest.raises(CodeExecutionError, match="empty script"):
        backend.execute(123, {})


def test_executor_type_checked(tmp_path):
    with pytest.raises(TypeError, match="run"):
        SandboxedCodeExecutor(object(), workspace=str(tmp_path))
