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
    GuiResult,
    MultiEditItem,
    RollbackPolicy,
    SandboxProfile,
    ShellInfo,
    ShellOutput,
    ShellStartResult,
    SnapshotInfo,
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
    "GuiResult",
    "MultiEditItem",
    "RollbackPolicy",
    "SandboxProfile",
    "ShellInfo",
    "ShellOutput",
    "ShellStartResult",
    "SnapshotInfo",
    "Subscription",
    "TelemetrySample",
]
# C-OPS-06: __version__ 读 build.rs 注入值 (经 fe-pyo3 version_info), 不再硬编码漂移
# M-4: 导入失败 warn (Rule 12 fail-visible), 不静默吞 ABI/链接错误
try:
    from ._native import version_info as _version_info

    __version__, _git_sha, _build_time = _version_info()
    __git_sha__ = _git_sha
    __build_time__ = _build_time
except Exception as _e:  # native 扩展未构建/不可用 — 回退兜底但 warn 不静默
    import warnings

    warnings.warn(f"native 扩展加载失败 ({_e!r}); 功能降级, __version__ 回退 0.2.8", RuntimeWarning, stacklevel=2)
    __version__ = "0.2.8"
    __git_sha__ = "unknown"
    __build_time__ = "0"
