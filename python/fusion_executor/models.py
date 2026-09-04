from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

# Blocker 11 (审计 schema 同步): 全模型 extra="forbid" — Rust serde struct ↔
# Pydantic 字段失配时 fail-loud (旧 extra="ignore" 静默丢未知字段, Rust 改字段名/
# serde bug 时 Pydantic 侧空字段假成功)。严格校验破 silent-schema-drift。
_STRICT = ConfigDict(extra="forbid")

# ARCH-4 可观测性边界: 进程内路径 (run()/run_async()/run_streaming 直调 fe-core) 绕过 fe-ipc
# 层, 故不经 UDS 的 metrics/telemetry/审计计数。execute_sync 已 mirror 关键计数器
# (fe_exec_total 等) 进全局 metrics recorder, 但完整可观测性 (BroadcastHub 推送/连接计数/
# Prometheus export) 仅 serve() UDS 路径具备。需完整指标时用 serve() + executor.execute over UDS,
# 不要依赖进程内 run() 的指标覆盖。


class Diagnostics(BaseModel):
    model_config = _STRICT
    error_type: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None
    raw_trace: str | None = None


class RollbackPolicy(BaseModel):
    model_config = _STRICT
    # L-PY-03: max_consecutive_failures 死字段 (Rust 从不读, CLAUDE.md 明说 caller
    # owns 连续失败计数)。A4 决策: 保留 (跨层级联 — 测试发送它, fe-rollback wire
    # 含它), 但标记 deprecated 告诫调用方勿依赖。Rule 7: 单一真源, 不模糊。
    max_consecutive_failures: int = Field(
        default=3,
        deprecated=True,
        description="连续失败上限 (DEPRECATED 保留字段, Rust 不读; 连续失败计数归调用方自愈循环)",
    )
    file_damage_check: bool = Field(default=True, description="失败时检测文件毁损 (git status) 触发回滚")


class SandboxProfile(BaseModel):
    model_config = _STRICT
    # Issue #34: 每命令 seatbelt/sandbox profile (匹配 fusion-code SandboxSettings)。
    # None/默认关 → 现有固定 profile (默认禁网 + 敏感路径 file-write deny), 行为同 v0.2.7。
    network: str | None = Field(
        default=None,
        description="网络策略: allow=放行出网; deny=禁网 (deny network-outbound, 现有默认). None=不覆盖默认",
    )
    filesystem: str | None = Field(
        default=None,
        description="文件系统策略: allow=不注 FS deny; deny_write=定向敏感路径 file-write deny (默认); deny=全局 file-write deny (Darwin 25 NO-OP). None=不覆盖默认",
    )
    excluded_commands: list[str] = Field(
        default_factory=list,
        description="seatbelt 内 deny process-exec 的命令名列表 (literal 路径匹配)",
    )
    fail_if_unavailable: bool = Field(
        default=False,
        description="sandbox-exec 不可用时 fail-closed 拦截 (exit -1, 不 spawn); False=静默降级到无 seatbelt",
    )


class ExecutionRequest(BaseModel):
    model_config = _STRICT
    command: str
    task_id: str | None = None
    cwd: str | None = None
    timeout_sec: float = Field(default=30.0, description="秒; 超时退出码 -124")
    env_vars: dict[str, str] | None = None
    enable_rollback_snapshot: bool = False
    auto_rollback_policy: RollbackPolicy | None = None
    seatbelt: bool = Field(
        default=True,
        description="macOS seatbelt 运行时隔离 (sandbox-exec 禁网 + 危险二进制 execve deny); 商用安全默认 True, 对齐 fe-core serde default_true + executor.run/run_async/shell_start 默认",
    )
    inherit_env: bool = Field(
        default=False,
        description="环境隔离: False(默认)=env_clear+最小基线 PATH/TMPDIR/SHELL+env_vars, 不泄漏宿主密钥; True=继承宿主全量 env (受信本地 opt-in)",
    )
    use_pty: bool = Field(
        default=True,
        description="I/O 后端: True(默认)=PTY (合流 stdout/stderr 保 ANSI/Traceback, stderr 恒空); False=stdio (stdout/stderr 独立捕获, 需分流的调用方 opt-in)",
    )
    max_nproc: int = Field(
        default=1024,
        description="进程数上限 (RLIMIT_NPROC, 经 ulimit -u 注入); 拦 fork bomb 并发扩散, 够工具链链式 spawn; 0=不限 (受信 opt-out); Darwin 实测生效",
    )
    max_cpu_sec: int = Field(
        default=0,
        description="CPU 秒上限 (RLIMIT_CPU, 经 ulimit -t 注入); >0 到顶 SIGXCPU (CPU 死循环防御); 0=不限 (依赖 timeout_sec watchdog); Darwin 实测生效",
    )
    max_nofile: int = Field(
        default=1024,
        description="文件描述符上限 (RLIMIT_NOFILE, 经 ulimit -n 注入); 拦 FD 耗尽攻击; 0=不限 (受信 opt-out); Darwin 实测生效 (errno 24 EMFILE)",
    )
    rss_limit_mb: int = Field(
        default=2048,
        description="per-task RSS 上限 (MB); Darwin RLIMIT_AS/RLIMIT_DATA 平台无效, 改 sysinfo 轮询子进程树 RSS 超限 kill (exit_code -124, oom_killed=true); 拦内存炸弹; 0=禁用 watchdog (受信 opt-out) (D3-4)",
    )
    trace_id: str | None = Field(
        default=None,
        description="跨层关联 id; None 时执行入口自动生成 uuid v4, 贯穿日志/IPC/结果 (M-OPS-06)",
    )
    sandbox: SandboxProfile | None = Field(
        default=None,
        description="Issue #34: 每命令 seatbelt/sandbox profile (网络/文件系统/排除命令); "
        "None=现有固定 profile (默认禁网+敏感路径 file-write deny), 行为同 v0.2.7; "
        "fail_if_unavailable=true 且 sandbox-exec 不可用时 fail-closed 拦截 (exit -1)",
    )


class ExecutionResult(BaseModel):
    model_config = _STRICT
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
    rollback_unavailable: bool = Field(
        default=False,
        description="回滚保障失效标记 — guard 出错时置 true (fail-loud, 不静默); 与 auto_rolled_back 互补",
    )
    rollback_skipped_reason: str | None = Field(
        default=None,
        description="回滚跳过原因 — rollback 尝试过但跳过 (快照失效/解析失败/非 git/repo 不匹配); "
        "区分 '未回滚(无需)' 与 '未回滚(快照失效)' (fail-loud); 与 auto_rolled_back/rollback_unavailable 互补",
    )
    trace_id: str | None = Field(
        default=None, description="跨层关联 id — 回填请求侧 trace_id 或入口自动生成 (M-OPS-06)"
    )
    oom_killed: bool = Field(
        default=False,
        description="RSS watchdog 触发标记 — 子进程树 RSS 超 rss_limit_mb 被 kill (D3-4); 伴随 exit_code -124",
    )
    pid: int | None = Field(
        default=None,
        description="沙箱子进程 PID — 调用方据此传 telemetry_stream(pid=...) 采样真实任务进程 "
        "(非 executor 自身, RUN-11); stdio 路径有, 拦截/超时路径无",
    )
    guard_action_id: str | None = Field(
        default=None,
        description="guard 授权裁决 action_id (Issue #23 Phase 3) — guard 判 Block/L3 时返, "
        "供调用方审计/人工 confirm 回路; guard OFF 或 Allow/L1/L2 时 None",
    )
    cancelled: bool = Field(
        default=False,
        description="服务端确定性 cancel 标记 (Issue #32) — executor.cancel 下发后 fe-sandbox "
        "SIGINT→SIGKILL 进程组, Done 帧 exit_code -1 + cancelled true; 非 cancel 路径 False",
    )


class GuiResult(BaseModel):
    model_config = _STRICT
    ok: bool = False
    node_tree: str | None = None
    screenshot_png_b64: str | None = None
    screenshot_width: int | None = None
    screenshot_height: int | None = None
    # #38: backing scale factor — 物理 PNG 像素 / 逻辑点 (Retina=2.0, 非 Retina=1.0)。
    # 坐标契约: GuiAction x/y 输入 + inspect_tree AXPosition = 逻辑点;
    #           screenshot_width/height = 物理像素。调用方据此换算 (pixel = point * scale)。
    scale_factor: float = 1.0
    error: str | None = None


class EditResult(BaseModel):
    model_config = _STRICT
    ok: bool = False
    path: str | None = None
    error: str | None = None
    matches: int = 0


class GlobEntry(BaseModel):
    model_config = _STRICT
    path: str
    is_dir: bool = False


class GrepMatch(BaseModel):
    model_config = _STRICT
    path: str
    line_number: int
    content: str
    context_before: list[str] = Field(default_factory=list, description="命中行之前的上下文 (-B)")
    context_after: list[str] = Field(default_factory=list, description="命中行之后的上下文 (-A)")


class GrepFileCount(BaseModel):
    model_config = _STRICT
    path: str
    count: int


class GrepOptions(BaseModel):
    model_config = _STRICT
    output_mode: str = Field(default="content", description="content | files_with_matches | count")
    after: int = Field(default=0, description="命中行后额外行数 (-A)")
    before: int = Field(default=0, description="命中行前额外行数 (-B)")
    context: int = Field(default=0, description="命中行前后均取 (-C, 等价 max(A,B))")
    multiline: bool = Field(default=False, description="多行模式 (整文件 buffer 匹配)")
    glob_include: list[str] = Field(default_factory=list, description="仅匹配这些 glob 的文件 (-g)")
    glob_exclude: list[str] = Field(default_factory=list, description="排除匹配这些 glob 的文件 (-g '!...')")


class GrepOutput(BaseModel):
    model_config = _STRICT
    output_mode: str = Field(default="content")
    matches: list[GrepMatch] = Field(default_factory=list, description="content 模式命中")
    files: list[str] = Field(default_factory=list, description="files_with_matches 模式命中文件")
    counts: list[GrepFileCount] = Field(default_factory=list, description="count 模式每文件计数")


class MultiEditItem(BaseModel):
    model_config = _STRICT
    old_string: str
    new_string: str
    replace_all: bool = Field(default=False, description="True=替换全部匹配; False=唯一匹配 (默认)")


class TelemetrySample(BaseModel):
    model_config = _STRICT
    ts_ms: int = Field(description="采样时间戳 (毫秒, 调用方纪元)")
    cpu_pct: float = Field(description="进程 CPU 占用百分比 (单核倍数)")
    mem_mb: float = Field(description="进程常驻内存 (MB)")
    gpu_pct: float | None = Field(default=None, description="GPU 占用百分比 (调用方注入)")
    gpu_mem_mb: float | None = Field(default=None, description="GPU 显存占用 (MB, 调用方注入)")
    task_id: str | None = Field(default=None, description="关联任务 id")


class ShellStartResult(BaseModel):
    model_config = _STRICT
    ok: bool = Field(description="是否启动成功")
    shell_id: str | None = Field(default=None, description="后台 shell id (sh-N); 失败或被拦截时 None")
    blocked_by_security: bool = Field(default=False, description="是否被安全守卫拦截")
    security_reason: str | None = Field(default=None, description="拦截原因")
    error: str | None = Field(default=None, description="启动错误")


class ShellOutput(BaseModel):
    model_config = _STRICT
    shell_id: str = Field(description="后台 shell id")
    output: str = Field(description="累积 tail 快照 (非增量; 调用方自去重)")
    running: bool = Field(description="是否仍在运行")
    exit_code: int | None = Field(default=None, description="退出码 (运行中为 None)")


class ShellInfo(BaseModel):
    model_config = _STRICT
    shell_id: str = Field(description="后台 shell id")
    pid: int | None = Field(default=None, description="子进程 pid")
    task_id: str | None = Field(default=None, description="关联任务 id")
    command: str = Field(description="启动命令")
    started_at_ms: int = Field(description="启动时间戳 (毫秒纪元)")
    finished: bool = Field(description="是否已退出")
    exit_code: int | None = Field(default=None, description="退出码 (运行中为 None)")


# D6-03 (审计 0827 product): 快照清单条目 — 镜像 fe_rollback::SnapshotInfo (on-disk 索引读回)。
class SnapshotInfo(BaseModel):
    model_config = _STRICT
    id: str = Field(description="快照 id (head:<SHA> / stash:<SHA>,base:<HEAD> / repo:<hash> 后缀)")
    created_ms: int = Field(description="快照创建时间戳 (毫秒纪元)")
    kind: str = Field(description="快照类型 (head 基线 / stash 含改动)")
