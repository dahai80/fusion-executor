from __future__ import annotations

from .agent_loop import AgentLoop, AgentStep
from .code_executor import CodeExecutionError, CodeSandboxProfile, SandboxedCodeExecutor
from .executor import FusionSandboxExecutor, Subscription
from .laya_tool_selector import DEFAULT_TOOL_WHITELIST, LayaToolSelector
from .models import (
    Diagnostics,
    EditResult,
    ExecutionRequest,
    ExecutionResult,
    GlobEntry,
    GrepFileCount,
    GrepMatch,
    GrepOptions,
    GrepOutput,
    GuiResult,
    MultiEditItem,
    RollbackPolicy,
    SandboxProfile,
    ShellInfo,
    ShellOutput,
    ShellStartResult,
    SnapshotInfo,
    TelemetrySample,
    ToolDecision,
)
from .task_service import RetryPolicy, TaskManager, TaskState, TaskStatus

__all__ = [
    "DEFAULT_TOOL_WHITELIST",
    "AgentLoop",
    "AgentStep",
    "CodeExecutionError",
    "CodeSandboxProfile",
    "Diagnostics",
    "EditResult",
    "ExecutionRequest",
    "ExecutionResult",
    "FusionSandboxExecutor",
    "GlobEntry",
    "GrepFileCount",
    "GrepMatch",
    "GrepOptions",
    "GrepOutput",
    "GuiResult",
    "LayaToolSelector",
    "MultiEditItem",
    "RetryPolicy",
    "RollbackPolicy",
    "SandboxProfile",
    "SandboxedCodeExecutor",
    "ShellInfo",
    "ShellOutput",
    "ShellStartResult",
    "SnapshotInfo",
    "Subscription",
    "TaskManager",
    "TaskState",
    "TaskStatus",
    "TelemetrySample",
    "ToolDecision",
]
# C-OPS-06: __version__ reads the build.rs-injected value (via fe-pyo3 version_info), no more hardcoded drift
# M-4: warn on import failure (Rule 12 fail-visible), never silently swallow ABI/link errors
try:
    from ._native import version_info as _version_info

    __version__, _git_sha, _build_time = _version_info()
    __git_sha__ = _git_sha
    __build_time__ = _build_time
except Exception as _e:  # native extension not built/unavailable — fall back but warn, never silent
    import warnings

    warnings.warn(
        f"native extension load failed ({_e!r}); degraded functionality, __version__ falls back to 0.2.16",
        RuntimeWarning,
        stacklevel=2,
    )
    __version__ = "0.2.16"
    __git_sha__ = "unknown"
    __build_time__ = "0"
