from __future__ import annotations

from pydantic import BaseModel, Field


class Diagnostics(BaseModel):
    error_type: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None
    raw_trace: str | None = None


class ExecutionRequest(BaseModel):
    command: str
    task_id: str | None = None
    cwd: str | None = None
    timeout_sec: float = Field(default=30.0, description="秒; 超时退出码 -124")
    env_vars: dict[str, str] | None = None
    enable_rollback_snapshot: bool = True


class ExecutionResult(BaseModel):
    exit_code: int = Field(description="0=成功, -124=超时, -1=拦截/内部异常")
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    blocked_by_security: bool = False
    security_reason: str | None = None
    snapshot_id: str | None = None
    diagnostics: Diagnostics | None = None


class GuiResult(BaseModel):
    ok: bool = False
    node_tree: str | None = None
    screenshot_png_b64: str | None = None
    screenshot_width: int | None = None
    screenshot_height: int | None = None
    error: str | None = None
