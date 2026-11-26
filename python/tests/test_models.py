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
    SandboxProfile,
    TelemetrySample,
)


def test_execution_request_defaults():
    req = ExecutionRequest(command="echo hi")
    assert req.command == "echo hi"
    assert req.timeout_sec == 30.0
    assert req.enable_rollback_snapshot is False
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


# ── Blocker 11: extra="forbid" — silent schema drift protection ──
# Rust serde struct ↔ Pydantic field mismatch fails loud (old extra="ignore" swallowed unknown fields,
# Rust field rename/serde bug → Pydantic-side empty fields faking success). Each model asserts: unknown field → ValidationError,
# missing required field → ValidationError.


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
        (SandboxProfile, {"network": "allow"}, "nope"),
    ],
)
def test_models_reject_extra_fields(model, valid_kwargs, extra_field):
    # extra="forbid" — unknown field must raise ValidationError, never silently swallowed
    bad = {**valid_kwargs, extra_field: "sneaky"}
    with pytest.raises(ValidationError):
        model.model_validate(bad)


@pytest.mark.parametrize(
    "model,required_kwargs",
    [
        (ExecutionRequest, {"task_id": None}),  # missing command
        (GlobEntry, {"is_dir": False}),  # missing path
        (GrepMatch, {"path": "x", "line_number": 1}),  # missing content
        (TelemetrySample, {"ts_ms": 1, "cpu_pct": 0.0}),  # missing mem_mb
    ],
)
def test_models_reject_missing_required_fields(model, required_kwargs):
    # missing required fields must raise ValidationError (not default-filled fake success)
    with pytest.raises(ValidationError):
        model.model_validate(required_kwargs)


def test_diagnostics_partial_none_ok():
    # all-Optional model: empty construction is legal (no required fields)
    d = Diagnostics()
    assert d.error_type is None
    assert d.line_number is None
    assert Diagnostics.model_validate({}) == d


# ── Issue #34: SandboxProfile Pydantic round-trip ──


def test_sandbox_profile_defaults():
    # defaults: all None/False/empty — behavior identical to v0.2.7 (sandbox=None semantics)
    p = SandboxProfile()
    assert p.network is None
    assert p.filesystem is None
    assert p.excluded_commands == []
    assert p.fail_if_unavailable is False


def test_sandbox_profile_round_trip():
    p = SandboxProfile(
        network="allow",
        filesystem="deny",
        excluded_commands=["rm", "curl"],
        fail_if_unavailable=True,
    )
    dumped = p.model_dump()
    assert dumped["network"] == "allow"
    assert dumped["filesystem"] == "deny"
    assert dumped["excluded_commands"] == ["rm", "curl"]
    assert dumped["fail_if_unavailable"] is True
    restored = SandboxProfile.model_validate(dumped)
    assert restored == p


def test_execution_request_sandbox_field():
    # ExecutionRequest.sandbox additive — None default preserves behavior, Some passes through
    req_default = ExecutionRequest(command="echo hi")
    assert req_default.sandbox is None
    req_sbx = ExecutionRequest(
        command="echo hi",
        sandbox=SandboxProfile(network="allow", excluded_commands=["rm"]),
    )
    assert req_sbx.sandbox is not None
    assert req_sbx.sandbox.network == "allow"
    assert req_sbx.sandbox.excluded_commands == ["rm"]
    # round-trip preserved
    dumped = req_sbx.model_dump()
    restored = ExecutionRequest.model_validate(dumped)
    assert restored.sandbox == req_sbx.sandbox
