from __future__ import annotations

import pytest
from pydantic import ValidationError

from fusion_executor import (
    Diagnostics,
    EditResult,
    ExecutionRequest,
    ExecutionResult,
    GlobEntry,
    GrepMatch,
    GuiResult,
    RollbackPolicy,
    TelemetrySample,
)


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


# ── Blocker 11: extra="forbid" — 静默 schema drift 防护 ──
# Rust serde struct ↔ Pydantic 字段失配时 fail-loud (旧 extra="ignore" 吞未知字段,
# Rust 改字段名/serde bug → Pydantic 侧空字段假成功)。每模型断言: 未知字段 → ValidationError,
# 缺必填字段 → ValidationError。


@pytest.mark.parametrize(
    "model,valid_kwargs,extra_field",
    [
        (Diagnostics, {"error_type": "X"}, "nope"),
        (RollbackPolicy, {"max_consecutive_failures": 2}, "nope"),
        (ExecutionRequest, {"command": "echo"}, "nope"),
        (ExecutionResult, {"exit_code": 0}, "nope"),
        (GuiResult, {"ok": True}, "nope"),
        (EditResult, {"ok": True}, "nope"),
        (GlobEntry, {"path": "x"}, "nope"),
        (GrepMatch, {"path": "x", "line_number": 1, "content": "c"}, "nope"),
        (TelemetrySample, {"ts_ms": 1, "cpu_pct": 0.0, "mem_mb": 0.0}, "nope"),
    ],
)
def test_models_reject_extra_fields(model, valid_kwargs, extra_field):
    # extra="forbid" — 未知字段必须 ValidationError, 不能静默吞
    bad = {**valid_kwargs, extra_field: "sneaky"}
    with pytest.raises(ValidationError):
        model.model_validate(bad)


@pytest.mark.parametrize(
    "model,required_kwargs",
    [
        (ExecutionRequest, {"task_id": None}),  # 缺 command
        (GlobEntry, {"is_dir": False}),  # 缺 path
        (GrepMatch, {"path": "x", "line_number": 1}),  # 缺 content
        (TelemetrySample, {"ts_ms": 1, "cpu_pct": 0.0}),  # 缺 mem_mb
    ],
)
def test_models_reject_missing_required_fields(model, required_kwargs):
    # 必填字段缺失必须 ValidationError (非默认填充假成功)
    with pytest.raises(ValidationError):
        model.model_validate(required_kwargs)


def test_diagnostics_partial_none_ok():
    # 全 Optional 模型: 空构造合法 (无必填)
    d = Diagnostics()
    assert d.error_type is None
    assert d.line_number is None
    assert Diagnostics.model_validate({}) == d
