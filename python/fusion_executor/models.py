from __future__ import annotations

from pydantic import BaseModel, Field


class Diagnostics(BaseModel):
    error_type: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None
    raw_trace: str | None = None


class RollbackPolicy(BaseModel):
    max_consecutive_failures: int = Field(default=3, description="连续失败上限 (保留字段, 供 stateful 扩展)")
    file_damage_check: bool = Field(default=True, description="失败时检测文件毁损 (git status) 触发回滚")


class ExecutionRequest(BaseModel):
    command: str
    task_id: str | None = None
    cwd: str | None = None
    timeout_sec: float = Field(default=30.0, description="秒; 超时退出码 -124")
    env_vars: dict[str, str] | None = None
    enable_rollback_snapshot: bool = True
    auto_rollback_policy: RollbackPolicy | None = None


class ExecutionResult(BaseModel):
    exit_code: int = Field(description="0=成功, -124=超时, -1=拦截/内部异常")
    stdout: str = ""
    stderr: str = ""
    task_id: str | None = None
    command: str | None = None
    duration_sec: float = 0.0
    timed_out: bool = False
    blocked_by_security: bool = False
    security_reason: str | None = None
    snapshot_id: str | None = None
    diagnostics: Diagnostics | None = None
    auto_rolled_back: bool = False


class GuiResult(BaseModel):
    ok: bool = False
    node_tree: str | None = None
    screenshot_png_b64: str | None = None
    screenshot_width: int | None = None
    screenshot_height: int | None = None
    error: str | None = None


class EditResult(BaseModel):
    ok: bool = False
    path: str | None = None
    error: str | None = None
    matches: int = 0


class GlobEntry(BaseModel):
    path: str
    is_dir: bool = False


class GrepMatch(BaseModel):
    path: str
    line_number: int
    content: str
