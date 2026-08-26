from __future__ import annotations

from .executor import FusionSandboxExecutor, Subscription
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
    GrepOutputMode,
    GuiResult,
    MultiEditItem,
    RollbackPolicy,
    ShellInfo,
    ShellOutput,
    ShellStartResult,
    TelemetrySample,
)

__all__ = [
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
    "GrepOutputMode",
    "GuiResult",
    "MultiEditItem",
    "RollbackPolicy",
    "ShellInfo",
    "ShellOutput",
    "ShellStartResult",
    "Subscription",
    "TelemetrySample",
]
# C-OPS-06: __version__ 读 build.rs 注入值 (经 fe-pyo3 version_info), 不再硬编码漂移
# 导入失败时回退 0.2.0 (与 Cargo.toml workspace.package.version 对齐)
try:
    from ._native import version_info as _version_info

    __version__, _git_sha, _build_time = _version_info()
    __git_sha__ = _git_sha
    __build_time__ = _build_time
except Exception:  # native 扩展未构建/不可用
    __version__ = "0.2.0"
    __git_sha__ = "unknown"
    __build_time__ = "0"
