from __future__ import annotations

from fusion_executor import Diagnostics, ExecutionRequest, ExecutionResult


def test_execution_request_defaults():
    req = ExecutionRequest(command="echo hi")
    assert req.command == "echo hi"
    assert req.timeout_sec == 30.0
    assert req.enable_rollback_snapshot is True
    assert req.task_id is None
    assert req.env_vars is None


def test_execution_request_round_trip():
    req = ExecutionRequest(command="pytest tests/", cwd="/tmp", timeout_sec=10.0)
    dumped = req.model_dump()
    restored = ExecutionRequest.model_validate(dumped)
    assert restored == req


def test_execution_result_blocked():
    result = ExecutionResult(exit_code=-1, blocked_by_security=True, security_reason="sudo")
    dumped = result.model_dump()
    assert dumped["blocked_by_security"] is True
    restored = ExecutionResult.model_validate(dumped)
    assert restored.security_reason == "sudo"


def test_execution_result_with_diagnostics():
    diag = Diagnostics(
        error_type="ValueError",
        file_path="foo.py",
        line_number=42,
        code_snippet="> raise ValueError('x')",
    )
    result = ExecutionResult(exit_code=1, diagnostics=diag)
    dumped = result.model_dump()
    assert dumped["diagnostics"]["error_type"] == "ValueError"
    restored = ExecutionResult.model_validate(dumped)
    assert restored.diagnostics is not None
    assert restored.diagnostics.line_number == 42


def test_execution_result_timeout_code():
    result = ExecutionResult(exit_code=-124, timed_out=True)
    assert result.timed_out is True
