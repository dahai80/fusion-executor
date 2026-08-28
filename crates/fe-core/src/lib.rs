// fe-core — Executor orchestrator (P1 minimal pipeline)
//
// Pipeline: validate → spawn → return
// 重型组件 (tree-sitter / git handle) 懒加载，new() <5ms (NFR)

use std::panic::AssertUnwindSafe;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::Result;
use futures::future::FutureExt;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

#[cfg(feature = "diagnostics")]
use fe_diagnostics::Slicer;
#[cfg(feature = "gui")]
use fe_gui::{GuiAction, GuiConfig, GuiController, GuiResult};
use fe_rollback::RollbackManager;
use fe_sandbox::{Sandbox, SandboxConfig};
use fe_security::{SecurityGuard, SecurityVerdict};
use fe_shell::{ShellInfo, ShellOutput, ShellRegistry, ShellStartParams, ShellStartResult};
#[cfg(feature = "telemetry")]
use fe_telemetry::{start_stream as start_telemetry, TelemetryConfig, TelemetrySample};
use fe_tools::{
    EditResult, GlobEntry, GrepMatch, GrepOptions, GrepOutput, MultiEditItem, NotebookEditMode,
    Tools,
};

#[cfg(feature = "diagnostics")]
pub use fe_diagnostics as diagnostics;
#[cfg(feature = "gui")]
pub use fe_gui as gui;
pub use fe_rollback as rollback;
pub use fe_sandbox as sandbox;
pub use fe_security as security;
pub use fe_shell as shell;
#[cfg(feature = "telemetry")]
pub use fe_telemetry as telemetry;
#[cfg(feature = "telemetry")]
pub use fe_telemetry::{
    TelemetryConfig as TelemetryStreamConfig, TelemetrySample as TelemetryFrame,
};
pub use fe_tools as tools;
pub use fe_tools::{
    EditResult as ToolsEditResult, GlobEntry as ToolsGlobEntry, GrepMatch as ToolsGrepMatch,
    GrepOptions as ToolsGrepOptions, GrepOutput as ToolsGrepOutput,
    GrepOutputMode as ToolsGrepOutputMode, MultiEditItem as ToolsMultiEditItem,
    NotebookEditMode as ToolsNotebookEditMode,
};

// BLOCKING_RT — 多线程 N worker (CPU 核心数, 下限 2), 并发执行 sandbox/telemetry/IPC 任务
// 审计 Blocker 5 / 1.2: 原 worker_threads(1) 全局串行 → execute + telemetry + IPC 请求互相阻塞
// 解法: worker_threads(N) 提升并行度。仍是单一全局 runtime (LazyLock), 不会嵌套 runtime panic
// (asyncio 调用方在 Python 侧, 此 runtime 独立; N 提升只增线程池大小, 无嵌套问题)
// 模式源自 fusion-design/crates/fd-ai-adapter/src/lib.rs
//
// A-5: LazyLock init panic 不可恢复 (OnceLock 中毒, 该进程此后任何 Runtime 访问都 panic)。
// 构造失败 = 进程永久不可用, 无重试。故 panic 信息须含构建原因, 让调用方日志能定位根因;
// 文档化约定: 首次 run() panic = 进程需重启, 无 Result 可捕获无降级 (sandbox/telemetry 全 async)。
pub static BLOCKING_RT: LazyLock<Runtime> = LazyLock::new(|| {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    let workers = workers.max(2);
    info!(workers, "BLOCKING_RT 初始化多线程 runtime");
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            panic!(
                "BLOCKING_RT init failed: tokio runtime 构建失败 — {e}. \
                 此 panic 不可恢复 (LazyLock 中毒), 进程需重启。worker_threads={workers}"
            )
        })
});

/// 退出码约定: 0=成功, -124=超时, -1=拦截/内部异常
pub const EXIT_OK: i32 = 0;
pub const EXIT_TIMEOUT: i32 = -124;
pub const EXIT_BLOCKED: i32 = -1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    pub command: String,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_sec: f64,
    #[serde(default)]
    pub env_vars: Option<std::collections::HashMap<String, String>>,
    #[serde(default = "default_true")]
    pub enable_rollback_snapshot: bool,
    #[serde(default)]
    pub auto_rollback_policy: Option<RollbackPolicy>,
    /// Blocker 1 / 1.1: macOS seatbelt 运行时隔离 — sandbox-exec 包装子进程 (禁网 + 危险二进制 execve deny)。
    /// 默认 true — 商用安全默认 (audit ARCH-1); 透传 SandboxConfig.seatbelt。
    /// 调用方显式传 false 关闭隔离 (受信本地 opt-out, 须文档化逃逸风险)。
    #[serde(default = "default_true")]
    pub seatbelt: bool,
    /// Issue #9: 环境隔离。默认 false → 子进程 env_clear + 仅最小基线 (PATH/TMPDIR/SHELL) + env_vars,
    /// 不泄漏宿主密钥 (AWS_SECRET_ACCESS_KEY/ANTHROPIC_API_KEY 等)。
    /// true → 继承宿主全量 env (受信本地场景显式 opt-in, 文档化泄漏风险)。
    #[serde(default)]
    pub inherit_env: bool,
    /// Issue #4: 捕获后端。true(默认)=PTY (ANSI/Traceback 保真, stdout+stderr 合并);
    /// false=stdio 独立管道 (FR-03 双工 stdout/stderr 分离, Slicer 吃 stderr)。PTY 合并时 stderr 恒空。
    #[serde(default = "default_use_pty")]
    pub use_pty: bool,
    /// Issue #3: 进程数上限 (RLIMIT_NPROC, 经 ulimit -u 注入)。默认 1024 — 拦 fork bomb 并发扩散,
    /// 够工具链链式 spawn。0=不限 (受信 opt-out)。Darwin 实测生效。
    #[serde(default = "default_nproc")]
    pub max_nproc: u32,
    /// Issue #3: CPU 秒上限 (RLIMIT_CPU, 经 ulimit -t 注入)。默认 0=不限 (依赖 timeout_sec watchdog)。
    /// >0 到顶 SIGXCPU (CPU 死循环防御)。Darwin 实测生效。
    #[serde(default)]
    pub max_cpu_sec: u32,
    /// RUN-10 (审计 0827): 文件描述符上限 (RLIMIT_NOFILE, 经 ulimit -n 注入)。默认 1024 —
    /// 拦 FD 耗尽攻击 (海量打开 fd 击杀宿主)。0=不限 (受信场景 opt-out)。Darwin 实测生效 (errno 24 EMFILE)。
    #[serde(default = "default_nofile")]
    pub max_nofile: u32,
    /// M-OPS-06: 跨层关联 id。None 时 execute 入口自动生成 uuid v4, 贯穿日志/IPC/结果。
    #[serde(default)]
    pub trace_id: Option<String>,
}

fn default_use_pty() -> bool {
    true
}

fn default_nproc() -> u32 {
    1024
}

fn default_nofile() -> u32 {
    1024
}

fn default_timeout() -> f64 {
    30.0
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostics {
    pub error_type: Option<String>,
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
    pub code_snippet: Option<String>,
    pub raw_trace: Option<String>,
}

/// 自动回滚策略 (FR-04 — caller-driven 锁定决策的扩展: 调用方可选启用自动策略)。
/// Executor 保持无状态 — guard 在单次 execute_async 内构造, 不跨请求累积计数。
/// max_consecutive_failures: 连续失败上限 (达此值触发回滚); file_damage_check: 检测文件毁损触发回滚。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackPolicy {
    /// Issue #12.3 / A4: 此字段在 wire 上接受 (调用方表达策略意图), 但 Rust 永不读 —
    /// 连续失败计数归 caller 自愈循环 (Executor 无状态, PRD §重构 明确; 接入需跨请求状态违反 NFR)。
    /// DEFERRED-BY-DESIGN: 保留供未来 stateful 扩展, 勿当生效字段。Python 侧标 deprecated=True。
    #[serde(default = "default_max_failures")]
    pub max_consecutive_failures: u32,
    #[serde(default = "default_true")]
    pub file_damage_check: bool,
}

impl Default for RollbackPolicy {
    fn default() -> Self {
        Self {
            max_consecutive_failures: 3,
            file_damage_check: true,
        }
    }
}

fn default_max_failures() -> u32 {
    3
}

impl From<fe_diagnostics::Diagnostics> for Diagnostics {
    fn from(d: fe_diagnostics::Diagnostics) -> Self {
        Self {
            error_type: d.error_type,
            file_path: d.file_path,
            line_number: d.line_number,
            code_snippet: d.code_snippet,
            raw_trace: d.raw_trace,
        }
    }
}

/// L-2: serde skip_serializing_if 辅助 — false 时不序列化 rollback_unavailable (wire 省位)。
fn is_false(b: &bool) -> bool {
    !b
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub duration_sec: f64,
    pub timed_out: bool,
    pub blocked_by_security: bool,
    pub security_reason: Option<String>,
    pub snapshot_id: Option<String>,
    pub diagnostics: Option<Diagnostics>,
    #[serde(default)]
    pub auto_rolled_back: bool,
    /// L-2: 回滚保障失效标记 — guard 构造/快照/检测出错时置 true, 调用方可见 (fail-loud, 不静默)。
    /// 与 auto_rolled_back 互补: 后者表 "已回滚", 此字段表 "本应回滚但保障不可用"。
    #[serde(default, skip_serializing_if = "is_false")]
    pub rollback_unavailable: bool,
    /// L-1 (审计 0827): 回滚跳过原因 — rollback() 尝试过但跳过 (快照失效/解析失败/非 git 仓库/
    /// repo 标识不匹配) 时填充, 调用方可 fail-loud 区分 "未回滚 (无需)" 与 "未回滚 (快照失效)"。
    /// 与 auto_rolled_back/rollback_unavailable 互补, 三轴独立:
    ///   auto_rolled_back=true        已回滚
    ///   rollback_unavailable=true    回滚保障不可用 (guard 出错)
    ///   rollback_skipped_reason=Some 回滚尝试过但跳过 (rollback 内部判定)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_skipped_reason: Option<String>,
    /// M-OPS-06: 跨层关联 id — 回填请求侧 trace_id (None 时入口自动生成)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

impl ExecutionResult {
    pub fn blocked(reason: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_BLOCKED,
            blocked_by_security: true,
            security_reason: Some(reason.into()),
            ..Default::default()
        }
    }

    /// 带 task_id/command/trace_id 的拦截结果 (PRD §4.1 — result 回填请求侧标识; M-OPS-06 trace_id)
    pub fn blocked_with(
        reason: impl Into<String>,
        task_id: Option<String>,
        command: Option<String>,
        trace_id: Option<String>,
    ) -> Self {
        Self {
            exit_code: EXIT_BLOCKED,
            blocked_by_security: true,
            security_reason: Some(reason.into()),
            task_id,
            command,
            trace_id,
            ..Default::default()
        }
    }
}

/// ARCH-4: 进程内执行路径 (fe-pyo3 execute_sync 直调 fe-core, 绕过 fe-ipc) 的可观测性补齐。
/// 镜像 fe-ipc BroadcastHub::record_exec 的 metrics::counter 分支, 仅记 Prometheus 全局计数器
/// (AtomicU64 快照归 fe-ipc hub, 此处不碰 — 进程内路径无 hub, 只补 Prometheus 侧)。
/// fe-ipc record_exec 保留自有 AtomicU64 + 调此 helper (去重, 避免双计); fe-pyo3 execute_sync 调此 helper。
pub fn record_exec_outcome(r: &ExecutionResult) {
    metrics::counter!("fe_exec_total").increment(1);
    if r.blocked_by_security {
        metrics::counter!("fe_exec_blocked").increment(1);
    } else if r.timed_out || r.exit_code == -124 {
        metrics::counter!("fe_exec_timeout").increment(1);
    } else if r.exit_code == 0 {
        metrics::counter!("fe_exec_success").increment(1);
    } else {
        metrics::counter!("fe_exec_failed").increment(1);
    }
}

/// 流式事件 — Chunk (实时 stdio 分块) / Done (最终 ExecutionResult, 含 diagnostics)
/// 镜像 fe-sandbox::StreamEvent, 但 Done 携带完整 ExecutionResult (经诊断切片 + 快照 id)
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecutionStreamEvent {
    Chunk { data: String },
    Done(Box<ExecutionResult>),
}

/// 自动回滚守卫 (FR-04) — 单次执行内检测文件毁损, 达阈值触发 rollback。
/// 生命周期限定单次 execute_async: 不跨请求累积 (Executor 无状态锁定决策)。
/// 真正的连续失败计数归 caller (fusion-code 自愈循环 owns retry count, PRD §重构 明确)。
/// C-2: 判 porcelain 行码是否为跟踪文件突变 (计为 damage)。
/// `git status --porcelain` 每行 = 2 字符 XY 状态码 + 空格 + 路径。
/// - X = 暂存区状态, Y = 工作区状态。
/// - `??` = 未跟踪 (命令有意创建, 非 damage) → false。
/// - `A`/` ` + `A` = 仅新增 (暂存/工作区新增, 无旧跟踪基线) → 不计 damage → false。
/// - `M`/`D`/`R`/`C`/`T` 在 X 或 Y 任一位置 = 跟踪文件被修改/删除/重命名/复制/类型变 → damage → true。
///
/// 短于 2 字符的行 (异常) → 保守计 false (不算 damage, 避误回滚)。
fn is_tracked_mutation(entry: &str) -> bool {
    let bytes = entry.as_bytes();
    if bytes.len() < 2 {
        return false;
    }
    let x = bytes[0] as char;
    let y = bytes[1] as char;
    const MUTATION_CODES: &[char] = &['M', 'D', 'R', 'C', 'T'];
    // `??` 整行未跟踪 → 绝非跟踪文件突变。
    if x == '?' && y == '?' {
        return false;
    }
    // X 或 Y 是突变码即计 (含 ` M` 工作区改、`M ` 暂存改、`MM` 两区都改、`R ` 重命名等)。
    MUTATION_CODES.contains(&x) || MUTATION_CODES.contains(&y)
}

/// max_consecutive_failures 保留字段, 供未来 stateful 扩展 (A4: 当前死字段, 文档标注非删除)。
///
/// C-CORE-01: 旧版 `git status --porcelain` 非空即判毁损 — 未跟踪 `__pycache__`/WIP/并发编辑
/// 全算 → 误触发回滚丢无关改动。修: 命令前 capture `pre_status` (porcelain 快照), 命令后
/// 再 capture `post_status`, diff 出**命令新增**的改动条目才判毁损。pre 已记录的未跟踪文件
/// 不算 (命令前就脏)。这样 WIP/`__pycache__` 等命令前已存在的脏状态不误触发。
///
/// C-2: C-CORE-01 仅排除预存脏, 仍把命令**有意创建** (未跟踪/暂存新增) 误算 damage。
/// `detect_damage` 进一步用 `is_tracked_mutation` 只计跟踪文件突变 (`M`/`D`/`R`/`C`/`T`),
/// `??`/`A` (未跟踪/暂存新增) 不计 — `mkdir -p build && pytest` 失败不再误回滚合法产物。
pub struct AutoRollbackGuard {
    policy: RollbackPolicy,
    snapshot_id: String,
    cwd: String,
    rollback: RollbackManager,
    pre_status: std::collections::HashSet<String>,
}

impl AutoRollbackGuard {
    /// 构造 — 持有本次执行前创建的快照 id + cwd + 命令前 git status 快照。
    /// `pre_status` 由 `capture_status` 在命令前采集, 捕获失败则空集 (detect 时 fail-loud)。
    pub fn new(
        policy: RollbackPolicy,
        snapshot_id: String,
        cwd: String,
        pre_status: std::collections::HashSet<String>,
    ) -> Self {
        Self {
            policy,
            snapshot_id,
            cwd,
            rollback: RollbackManager::new(),
            pre_status,
        }
    }

    /// 采集 git status --porcelain 行集 (去空白行)。命令前后各采一次, diff 出命令新增改动。
    /// L-CORE-02: git 失败 fail-loud (返 Err), 不再 `.unwrap_or(0)` 静默跳回滚。
    async fn capture_status(cwd: &str) -> Result<std::collections::HashSet<String>> {
        let out = tokio::process::Command::new("git")
            .arg("-C")
            .arg(cwd)
            .args(["status", "--porcelain"])
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("git status 启动失败: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            anyhow::bail!("git status 失败 (exit {}): {}", out.status, stderr);
        }
        let s = String::from_utf8_lossy(&out.stdout);
        Ok(s.lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// 检测命令导致的文件毁损 — diff 命令后状态与命令前快照, 只算**命令新增**且为
    /// **跟踪文件突变**的条目。返回计数。
    ///
    /// C-2: C-CORE-01 仅排除预存脏文件, 不区分命令**有意创建** (未跟踪/暂存新增) 与**损坏**。
    /// `mkdir -p build && pytest` 失败 → `build/`/`__pycache__`/`.pytest_cache` 在 post 不在 pre
    /// → 误判 damage → 回滚丢合法产物。修: 只计 porcelain XY 行码表示跟踪文件删除/修改的条目
    /// (`M`/`D`/`R`/`C`/`T` 在任一位置), `??` (未跟踪新增) 与 `A` (仅暂存新增, 无旧跟踪) 不计。
    /// git 失败 fail-loud (L-CORE-02)。
    async fn detect_damage(&self) -> Result<usize> {
        let post = Self::capture_status(&self.cwd).await?;
        let new_entries: Vec<&String> = post
            .iter()
            .filter(|entry| !self.pre_status.contains(*entry))
            .filter(|entry| is_tracked_mutation(entry))
            .collect();
        if !new_entries.is_empty() {
            info!(new = ?new_entries, "命令新增跟踪文件突变条目 (命令导致, 计为 damage)");
        } else {
            let skipped: Vec<&String> = post
                .iter()
                .filter(|entry| !self.pre_status.contains(*entry))
                .filter(|entry| !is_tracked_mutation(entry))
                .collect();
            if !skipped.is_empty() {
                info!(
                    skipped = ?skipped,
                    "命令新增条目但为未跟踪/暂存新增 (??/A), 不计 damage — 合法产物创建"
                );
            }
        }
        Ok(new_entries.len())
    }

    /// 记录结果 — exit_code==0 无动作; !=0 且检测命令导致毁损 → rollback, 标记 auto_rolled_back。
    /// 就地修改 result.auto_rolled_back。非 git repo → detect 失败 (fail-loud) 由调用方 log。
    /// L-CORE-02: detect_damage 失败不再静默 (旧 .unwrap_or(0) 跳回滚); 现 propagate Err,
    /// 调用方 (execute_async/execute_streaming) 已 warn! 记录。
    pub async fn record_result(&self, result: &mut ExecutionResult) -> Result<()> {
        if result.exit_code == 0 {
            return Ok(());
        }
        if !self.policy.file_damage_check {
            return Ok(());
        }
        let damaged = self.detect_damage().await?;
        if damaged == 0 {
            info!(exit_code = result.exit_code, "失败但无命令新增改动, 不回滚");
            return Ok(());
        }
        info!(
            damaged,
            exit_code = result.exit_code,
            "检测到命令导致文件改动, 触发自动回滚"
        );
        // L-1 (审计 0827): rollback() 现返 RollbackOutcome{applied, skipped_reason, wip_sha}。
        // applied=true → auto_rolled_back=true (已回滚); applied=false + skipped_reason=Some →
        // 填 rollback_skipped_reason 让调用方 fail-loud 区分 "未回滚(无需)" 与 "未回滚(快照失效)"。
        let outcome = self.rollback.rollback(&self.snapshot_id, &self.cwd).await?;
        if outcome.applied {
            result.auto_rolled_back = true;
            if let Some(wip) = &outcome.wip_sha {
                info!(snapshot = %self.snapshot_id, wip = %wip, "自动回滚成功 — 已捕获 tracked WIP (C-7)");
            } else {
                info!(snapshot = %self.snapshot_id, "自动回滚成功");
            }
        } else if let Some(reason) = &outcome.skipped_reason {
            // L-1: 跳过有原因 — 暴露给调用方 (fail-loud), 不静默 false。
            result.rollback_skipped_reason = Some(reason.clone());
            warn!(
                snapshot = %self.snapshot_id,
                reason = %reason,
                "自动回滚跳过 (rollback 判定) — rollback_skipped_reason 已置位 (L-1)"
            );
        } else {
            // applied=false + 无原因 — 理论上不达 (skipped 必带原因), 防御性 warn。
            warn!(snapshot = %self.snapshot_id, "自动回滚未生效 (rollback 返回 applied=false 无原因)");
        }
        Ok(())
    }
}

/// Executor — 校验 + 沙箱执行的编排器
pub struct Executor {
    security: SecurityGuard,
    sandbox: Sandbox,
    #[cfg(feature = "diagnostics")]
    slicer: Slicer,
    rollback: RollbackManager,
    #[cfg(feature = "gui")]
    gui: GuiController,
    tools: Tools,
    // M-ARCH-1: ShellRegistry 不再属 Executor — 移到 IpcServer/PyExecutor (与 BroadcastHub 并列)。
    // Executor 保持 per-task 无状态: IPC 层重启 Executor 不丢后台 shell 句柄; serve-path 与
    // in-process path 共享同一 registry。安在校验留此层 (self.security), registry 由调用方传引用。
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

impl Executor {
    pub fn new() -> Self {
        info!("Executor::new() — 初始化 SecurityGuard + Sandbox + Slicer + Rollback + Gui + Tools");
        // ARCH-2: SecurityGuard 基线 TRUSTED_BIN_DIRS 仅系统目录 (/usr/bin 等)。本地 venv
        // 解释器 (/Users/.../.venv/bin/python3) 不在内 → basename 命中后 resolved-path 校验
        // fail-closed 拒, 正常 python3 命令被拦。此处自动登记 venv bin (VIRTUAL_ENV env) +
        // 当前可执行父目录 (PyO3 扩展所在), 使本地解释器路径落可信集。
        let mut trusted: Vec<String> = Vec::new();
        if let Ok(venv) = std::env::var("VIRTUAL_ENV") {
            let venv_bin = std::path::Path::new(&venv).join("bin");
            if let Some(s) = venv_bin.to_str() {
                trusted.push(s.to_string());
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                if let Some(s) = parent.to_str() {
                    trusted.push(s.to_string());
                }
            }
        }
        let trusted_refs: Vec<&str> = trusted.iter().map(String::as_str).collect();
        let security = if trusted_refs.is_empty() {
            SecurityGuard::new()
        } else {
            info!(dirs = ?trusted_refs, "Executor 登记 venv/exe 可信二进制目录 (ARCH-2)");
            SecurityGuard::new().with_trusted_bin_dirs(&trusted_refs)
        };
        Self {
            security,
            sandbox: Sandbox::new(),
            #[cfg(feature = "diagnostics")]
            slicer: Slicer::new(),
            rollback: RollbackManager::new(),
            #[cfg(feature = "gui")]
            gui: GuiController::new(),
            tools: Tools::new(),
        }
    }

    /// 扩展白名单 — Issue #10: 项目级二进制放行 (含危险解释器拒绝守卫)
    pub fn with_extra_whitelist(mut self, extras: &[&str]) -> Self {
        info!(count = extras.len(), "Executor 扩展白名单 (项目级放行)");
        self.security = self.security.with_extra_whitelist(extras);
        self
    }

    /// m-OPS-02: SIGHUP 运行时白名单热重载 — 从基线 + extras 重建 (非累加)。
    /// &self (Executor 无状态约定, 仅透传 SecurityGuard.reload_extras 的 ArcSwap store)。
    /// fe-ipc SIGHUP 处理器读 FUSION_EXECUTOR_EXTRA_WHITELIST env → 逗号分割 → 调此。
    pub fn reload_whitelist(&self, extras: &[&str]) {
        info!(count = extras.len(), "SIGHUP 白名单热重载 (基线重建)");
        self.security.reload_extras(extras);
    }

    /// M-SEC-04: GUI 安全配置 (bundle allowlist + 密码框 type_text 守卫)。
    /// 默认 Executor::new() 无配置 = 不限 (本地可信调用方, 仅审计日志);
    /// 企业/多用户场景用此构造器设 allowlist + allow_type_into_secure opt-in。
    #[cfg(feature = "gui")]
    pub fn with_gui_config(mut self, config: GuiConfig) -> Self {
        info!("Executor 设置 GUI 安全配置 (M-SEC-04)");
        self.gui = GuiController::new_with_config(config);
        self
    }

    /// GUI 动作 (P4 FR-05) — 同步入口, 供 fe-pyo3/fe-ipc 调用
    #[cfg(feature = "gui")]
    pub fn gui_action(&self, action: GuiAction) -> Result<GuiResult> {
        self.gui.execute(action)
    }

    /// 原生文件工具 — file_edit (PRD FileEdit 本地化, #6 replace_all)
    pub fn file_edit(
        &self,
        path: &str,
        old_string: &str,
        new_string: &str,
        cwd: Option<&str>,
        replace_all: bool,
    ) -> Result<EditResult> {
        self.tools
            .file_edit(path, old_string, new_string, cwd, replace_all)
    }

    /// 原生文件工具 — write_file 整文件创建/覆盖 + 建父目录 (#2, Claude Code Write parity)
    pub fn write_file(&self, path: &str, content: &str, cwd: Option<&str>) -> Result<EditResult> {
        self.tools.write_file(path, content, cwd)
    }

    /// 后台 shell — 启动持久 shell (#1, Claude Code run_in_background parity)
    /// 安全校验在此层 (fail-closed): blocked → ShellStartResult{ok:false, blocked_by_security:true}
    /// M-ARCH-1: registry 由调用方传引用 (Executor 无状态; registry 归 IpcServer/PyExecutor)。
    pub fn shell_start(&self, registry: &ShellRegistry, p: ShellStartParams) -> ShellStartResult {
        let v = self.security.validate(&p.command);
        if !v.allowed {
            warn!(command = %p.command, reason = ?v.reason, "shell_start 被安全守卫拦截");
            return ShellStartResult {
                ok: false,
                shell_id: None,
                blocked_by_security: true,
                security_reason: v.reason,
                error: None,
            };
        }
        registry.shell_start(p)
    }

    /// 后台 shell — 轮询 tail 快照 + 运行/退出状态 (#1)
    /// M-ARCH-1: registry 由调用方传引用。
    pub fn shell_output(registry: &ShellRegistry, shell_id: &str) -> Result<ShellOutput> {
        registry.shell_output(shell_id)
    }

    /// 后台 shell — kill 进程树 (#1, Claude Code KillShell parity)
    /// M-ARCH-1: registry 由调用方传引用。
    pub fn kill_shell(registry: &ShellRegistry, shell_id: &str) -> Result<bool> {
        registry.kill_shell(shell_id)
    }

    /// 后台 shell — 列出全部 shell (#1)
    /// M-ARCH-1: registry 由调用方传引用。
    pub fn list_shells(registry: &ShellRegistry) -> Vec<ShellInfo> {
        registry.list_shells()
    }

    /// 原生文件工具 — multi_edit 同文件原子批量编辑 (#6)
    pub fn multi_edit(
        &self,
        path: &str,
        edits: &[MultiEditItem],
        cwd: Option<&str>,
    ) -> Result<EditResult> {
        self.tools.multi_edit(path, edits, cwd)
    }

    /// 原生文件工具 — notebook_edit Jupyter .ipynb 单元格编辑 (#6)
    pub fn notebook_edit(
        &self,
        path: &str,
        cell_id: Option<&str>,
        cell_number: Option<i64>,
        new_source: &str,
        edit_mode: NotebookEditMode,
        cwd: Option<&str>,
    ) -> Result<EditResult> {
        self.tools
            .notebook_edit(path, cell_id, cell_number, new_source, edit_mode, cwd)
    }

    /// 原生文件工具 — glob (PRD GlobTool 本地化)
    pub fn glob(&self, pattern: &str, cwd: Option<&str>) -> Result<Vec<GlobEntry>> {
        self.tools.glob(pattern, cwd)
    }

    /// 原生文件工具 — grep (PRD GrepTool 本地化)
    pub fn grep(
        &self,
        pattern: &str,
        paths: &[String],
        cwd: Option<&str>,
    ) -> Result<Vec<GrepMatch>> {
        self.tools.grep(pattern, paths, cwd)
    }

    /// #7 ripgrep parity — grep 带选项: 输出模式 / 上下文 / 多行 / glob 过滤
    pub fn grep_with_opts(
        &self,
        pattern: &str,
        paths: &[String],
        cwd: Option<&str>,
        opts: &GrepOptions,
    ) -> Result<GrepOutput> {
        self.tools.grep_with_opts(pattern, paths, cwd, opts)
    }

    /// 外科补丁引擎 — apply_patch (PRD §DeepSeek Unified Diff 应用)
    pub fn apply_patch(&self, diff: &str, cwd: Option<&str>) -> Result<EditResult> {
        self.tools.apply_patch(diff, cwd)
    }

    /// 外科补丁引擎 — replace_function (PRD §DeepSeek 函数级替换, 禁全文件重写)
    pub fn replace_function(
        &self,
        path: &str,
        fn_name: &str,
        new_body: &str,
        cwd: Option<&str>,
    ) -> Result<EditResult> {
        self.tools.replace_function(path, fn_name, new_body, cwd)
    }

    /// 快照 — 公开供 fe-pyo3 直接调用
    pub async fn snapshot_create_async(&self, cwd: &str) -> Result<String> {
        self.rollback.snapshot_create(cwd).await
    }

    /// 回滚 — 公开供 fe-pyo3 直接调用。
    /// L-1 (审计 0827): rollback() 内部返 RollbackOutcome; 此包装映射 .applied → bool
    /// 保持 IPC/PyO3/Python 侧 bool 契约不变 (skipped_reason 细节经 ExecutionResult 4 层流通)。
    pub async fn rollback_async(&self, snapshot_id: &str, cwd: &str) -> Result<bool> {
        self.rollback
            .rollback(snapshot_id, cwd)
            .await
            .map(|o| o.applied)
    }

    /// 校验命令 — 公开供 fe-ipc/fe-pyo3 直接调用
    pub fn validate(&self, command: &str) -> SecurityVerdict {
        self.security.validate(command)
    }

    /// 异步执行 — 校验 → 沙箱执行 → return
    pub async fn execute_async(&self, req: ExecutionRequest) -> Result<ExecutionResult> {
        // M-OPS-06/m-OPS-03: 入口解析 trace_id (None 自动 uuid v4), span 包整条请求链 — 日志带 span 上下文
        let trace_id = req
            .trace_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let span = tracing::span!(
            tracing::Level::INFO,
            "execute",
            trace_id = %trace_id,
            command = %req.command
        );
        let _enter = span.enter();
        info!(command = %req.command, "execute_async — 校验中");
        let start = Instant::now();
        let verdict = self.security.validate(&req.command);
        if !verdict.allowed {
            let reason = verdict.reason.unwrap_or_else(|| "未知原因".to_string());
            info!(%reason, "安全校验拦截");
            return Ok(ExecutionResult::blocked_with(
                reason,
                req.task_id.clone(),
                Some(req.command.clone()),
                Some(trace_id),
            ));
        }
        // cwd 校验
        if let Some(cwd) = &req.cwd {
            let cwd_v = self.security.validate_cwd(cwd);
            if !cwd_v.allowed {
                let reason = cwd_v.reason.unwrap_or_else(|| "cwd 非法".to_string());
                info!(%reason, "cwd 校验拦截");
                return Ok(ExecutionResult::blocked_with(
                    reason,
                    req.task_id.clone(),
                    Some(req.command.clone()),
                    Some(trace_id),
                ));
            }
        }

        // 快照 + 命令前 git status 快照 (caller-driven 锁定决策: 仅当 enable_rollback_snapshot 且有 cwd)
        // C-CORE-01: pre_status 是命令前工作区状态, 供 guard diff 命令后状态找出命令新增改动
        // (旧版非空即判毁损, __pycache__/WIP 误触发)。pre_status 与 snapshot 同期采集 (命令前)。
        let (snapshot_id, pre_status) = if req.enable_rollback_snapshot {
            if let Some(cwd) = &req.cwd {
                let snap = self.rollback.snapshot_create(cwd).await;
                let pre = AutoRollbackGuard::capture_status(cwd).await;
                match (snap, pre) {
                    (Ok(id), Ok(st)) => {
                        if !id.is_empty() {
                            info!(%id, "快照已创建");
                        }
                        (Some(id), st)
                    }
                    (Ok(id), Err(e)) => {
                        // 命令前 status 采集失败 — 非 git repo 或 git 异常。pre_status 空集,
                        // guard detect 时 post 若非空则全部算命令新增 (保守: 当作全命令导致)。
                        warn!(error = %e, cwd, "命令前 git status 采集失败, pre_status 置空");
                        if !id.is_empty() {
                            info!(%id, "快照已创建");
                        }
                        (Some(id), std::collections::HashSet::new())
                    }
                    (Err(e), _) => {
                        info!(error = %e, "快照创建失败, 继续 (非致命)");
                        (None, std::collections::HashSet::new())
                    }
                }
            } else {
                (None, std::collections::HashSet::new())
            }
        } else {
            (None, std::collections::HashSet::new())
        };

        let env = req.env_vars.unwrap_or_default();
        let sb_cfg = SandboxConfig {
            command: req.command.clone(),
            cwd: req.cwd.clone(),
            env,
            timeout_sec: req.timeout_sec,
            max_output_chars: 100_000,
            seatbelt: req.seatbelt,
            inherit_env: req.inherit_env,
            use_pty: req.use_pty,
            max_nproc: req.max_nproc,
            max_cpu_sec: req.max_cpu_sec,
            max_nofile: req.max_nofile,
        };
        info!(
            seatbelt = req.seatbelt,
            use_pty = req.use_pty,
            "execute_async — 沙箱执行"
        );
        let sb = self.sandbox.run(sb_cfg).await?;

        // 诊断切片 — exit_code != 0 且非拦截/超时时填充 (PRD §4.2)
        // Issue #4: use_pty=false 时 stderr 独立 → Slicer 优先吃 stderr (error channel);
        // PTY 模式 stderr 恒空 → 退回 stdout (traceback 在 tail)
        #[cfg(feature = "diagnostics")]
        let diag = if sb.exit_code != 0 && !sb.timed_out {
            let cwd_ref = req.cwd.as_deref();
            let diag_src = if !sb.stderr.is_empty() {
                &sb.stderr
            } else {
                &sb.stdout
            };
            Some(Diagnostics::from(self.slicer.slice(diag_src, cwd_ref)))
        } else {
            None
        };
        #[cfg(not(feature = "diagnostics"))]
        let diag: Option<Diagnostics> = None;

        let sid_filtered = snapshot_id.as_ref().filter(|s| !s.is_empty()).cloned();
        let mut result = ExecutionResult {
            exit_code: sb.exit_code,
            stdout: sb.stdout,
            stderr: sb.stderr,
            task_id: req.task_id.clone(),
            command: Some(req.command.clone()),
            duration_sec: start.elapsed().as_secs_f64(),
            timed_out: sb.timed_out,
            snapshot_id: sid_filtered.clone(),
            diagnostics: diag,
            trace_id: Some(trace_id),
            ..Default::default()
        };

        // 自动回滚 (FR-04) — 调用方传 policy 且有快照+cwd 时, 单次内 guard 判定
        // pre_status 命令前已采集, 传入 guard 供 detect_damage diff (C-CORE-01)
        if let (Some(policy), Some(cwd), Some(sid)) = (
            req.auto_rollback_policy.clone(),
            req.cwd.clone(),
            sid_filtered.as_ref(),
        ) {
            if !sid.is_empty() {
                let guard = AutoRollbackGuard::new(policy, sid.clone(), cwd, pre_status.clone());
                if let Err(e) = guard.record_result(&mut result).await {
                    // L-2: fail-loud — 旧版 warn!-降级后静默继续, 调用方无信号知回滚保障失效。
                    // 标 rollback_unavailable=true 让调用方可见, 仍 warn! 记日志 (双通道可见)。
                    warn!(error = %e, "自动回滚 guard 异常 — rollback_unavailable 已置位");
                    result.rollback_unavailable = true;
                }
            }
        }

        Ok(result)
    }

    /// 同步执行 — 走 BLOCKING_RT，供 PyO3 sync 入口
    pub fn execute(&self, req: ExecutionRequest) -> Result<ExecutionResult> {
        BLOCKING_RT.block_on(self.execute_async(req))
    }

    /// 流式执行 — 校验 → 快照 → sandbox.run_streaming → 转发 Chunk, Done 时填 diagnostics。
    /// 被安全拦截 → 单帧 Done(blocked); 其余走 run_streaming 的实时分块。
    /// 非破坏性: 与 execute_async 并存, Done 帧的 ExecutionResult 逻辑等价 (诊断切片在 Done 时填充)。
    pub async fn execute_streaming(
        &self,
        req: ExecutionRequest,
    ) -> Result<(mpsc::Receiver<ExecutionStreamEvent>, JoinHandle<()>)> {
        // M-OPS-06/m-OPS-03: 入口解析 trace_id + span (同 execute_async)
        let trace_id = req
            .trace_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let span = tracing::span!(
            tracing::Level::INFO,
            "execute_stream",
            trace_id = %trace_id,
            command = %req.command
        );
        let _enter = span.enter();
        info!(command = %req.command, "execute_streaming — 校验中");
        let start = Instant::now();
        let verdict = self.security.validate(&req.command);
        if !verdict.allowed {
            let reason = verdict.reason.unwrap_or_else(|| "未知原因".to_string());
            info!(%reason, "安全校验拦截 (streaming)");
            let (tx, rx) = mpsc::channel(8);
            let handle = tokio::spawn(async move {
                let _ = tx
                    .send(ExecutionStreamEvent::Done(Box::new(
                        ExecutionResult::blocked_with(
                            reason,
                            req.task_id.clone(),
                            Some(req.command.clone()),
                            Some(trace_id),
                        ),
                    )))
                    .await;
            });
            return Ok((rx, handle));
        }
        if let Some(cwd) = &req.cwd {
            let cwd_v = self.security.validate_cwd(cwd);
            if !cwd_v.allowed {
                let reason = cwd_v.reason.unwrap_or_else(|| "cwd 非法".to_string());
                info!(%reason, "cwd 校验拦截 (streaming)");
                let (tx, rx) = mpsc::channel(8);
                let handle = tokio::spawn(async move {
                    let _ = tx
                        .send(ExecutionStreamEvent::Done(Box::new(
                            ExecutionResult::blocked_with(
                                reason,
                                req.task_id.clone(),
                                Some(req.command.clone()),
                                Some(trace_id),
                            ),
                        )))
                        .await;
                });
                return Ok((rx, handle));
            }
        }

        // 快照 + 命令前 git status 快照 (与 execute_async 同策略; C-CORE-01 pre_status diff)
        let (snapshot_id, pre_status) = if req.enable_rollback_snapshot {
            if let Some(cwd) = &req.cwd {
                let snap = self.rollback.snapshot_create(cwd).await;
                let pre = AutoRollbackGuard::capture_status(cwd).await;
                match (snap, pre) {
                    (Ok(id), Ok(st)) => {
                        if !id.is_empty() {
                            info!(%id, "快照已创建 (streaming)");
                        }
                        (Some(id), st)
                    }
                    (Ok(id), Err(e)) => {
                        warn!(error = %e, cwd, "命令前 git status 采集失败 (streaming), pre_status 置空");
                        if !id.is_empty() {
                            info!(%id, "快照已创建 (streaming)");
                        }
                        (Some(id), std::collections::HashSet::new())
                    }
                    (Err(e), _) => {
                        info!(error = %e, "快照创建失败, 继续 (非致命, streaming)");
                        (None, std::collections::HashSet::new())
                    }
                }
            } else {
                (None, std::collections::HashSet::new())
            }
        } else {
            (None, std::collections::HashSet::new())
        };

        let env = req.env_vars.unwrap_or_default();
        let sb_cfg = fe_sandbox::SandboxConfig {
            command: req.command.clone(),
            cwd: req.cwd.clone(),
            env,
            timeout_sec: req.timeout_sec,
            max_output_chars: 100_000,
            seatbelt: req.seatbelt,
            inherit_env: req.inherit_env,
            use_pty: req.use_pty,
            max_nproc: req.max_nproc,
            max_cpu_sec: req.max_cpu_sec,
            max_nofile: req.max_nofile,
        };
        info!(seatbelt = req.seatbelt, "execute_streaming — 沙箱流式执行");
        let (mut sb_rx, sb_handle) = self.sandbox.run_streaming(sb_cfg)?;

        #[cfg(feature = "diagnostics")]
        let slicer = self.slicer.clone();
        let cwd_for_diag = req.cwd.clone();
        let task_id_for_done = req.task_id.clone();
        let command_for_done = req.command.clone();
        let trace_id_for_done = trace_id.clone();
        let policy_for_done = req.auto_rollback_policy.clone();
        let cwd_for_guard = req.cwd.clone();
        let pre_status_for_guard = pre_status.clone();

        let (outer_tx, outer_rx) = mpsc::channel::<ExecutionStreamEvent>(64);
        // C-4: spawn 任务体包 catch_unwind — 病态 slicer/guard/unwrap panic 不静默丢 Done 帧。
        // outer_tx 克隆一份给 catch 内 async (move 入), 原始 outer_tx 留 catch 外供 panic 路径发
        // 显式 Done{exit_code:-1, stderr:"internal panic: ..."} (而非让 outer_rx 收 None 当干净 EOF)。
        let panic_tx = outer_tx.clone();
        let trace_id_for_panic = trace_id.clone();
        let task_id_for_panic = req.task_id.clone();
        let command_for_panic = req.command.clone();
        let handle = tokio::spawn(async move {
            let inner = AssertUnwindSafe(async move {
                while let Some(ev) = sb_rx.recv().await {
                    match ev {
                        fe_sandbox::StreamEvent::Chunk { data } => {
                            if outer_tx
                                .send(ExecutionStreamEvent::Chunk { data })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        fe_sandbox::StreamEvent::Done(sb) => {
                            // 诊断切片 — exit_code != 0 且非超时 (PRD §4.2, 同 execute_async)
                            #[cfg(feature = "diagnostics")]
                            let diag = if sb.exit_code != 0 && !sb.timed_out {
                                let cwd_ref = cwd_for_diag.as_deref();
                                // Issue #4: stdio 模式 stderr 独立 → 优先吃 stderr
                                let diag_src = if !sb.stderr.is_empty() {
                                    &sb.stderr
                                } else {
                                    &sb.stdout
                                };
                                Some(Diagnostics::from(slicer.slice(diag_src, cwd_ref)))
                            } else {
                                None
                            };
                            #[cfg(not(feature = "diagnostics"))]
                            let diag: Option<Diagnostics> = None;
                            let sid_filtered =
                                snapshot_id.as_ref().filter(|s| !s.is_empty()).cloned();
                            let mut result = ExecutionResult {
                                exit_code: sb.exit_code,
                                stdout: sb.stdout,
                                stderr: sb.stderr,
                                task_id: task_id_for_done.clone(),
                                command: Some(command_for_done.clone()),
                                duration_sec: start.elapsed().as_secs_f64(),
                                timed_out: sb.timed_out,
                                snapshot_id: sid_filtered.clone(),
                                diagnostics: diag,
                                trace_id: Some(trace_id_for_done.clone()),
                                ..Default::default()
                            };
                            // 自动回滚 (FR-04, 同 execute_async; pre_status diff C-CORE-01)
                            if let (Some(policy), Some(cwd), Some(sid)) = (
                                policy_for_done.as_ref(),
                                cwd_for_guard.as_ref(),
                                sid_filtered.as_ref(),
                            ) {
                                if !sid.is_empty() {
                                    let guard = AutoRollbackGuard::new(
                                        policy.clone(),
                                        sid.clone(),
                                        cwd.clone(),
                                        pre_status_for_guard.clone(),
                                    );
                                    if let Err(e) = guard.record_result(&mut result).await {
                                        // L-2: fail-loud — 旧版 warn!-降级静默吞, 调用方无信号。
                                        // 标 rollback_unavailable=true 让调用方可见 (同 execute_async)。
                                        warn!(
                                            error = %e,
                                            "自动回滚 guard 异常 (streaming) — rollback_unavailable 已置位"
                                        );
                                        result.rollback_unavailable = true;
                                    }
                                }
                            }
                            // L-3: send 错误不再 let _ = 纯吞 — 消费者已 drop (提前 break/异常),
                            // 显式 warn! 记 "Done frame dropped", 让通道关闭可见于日志。
                            if outer_tx
                                .send(ExecutionStreamEvent::Done(Box::new(result)))
                                .await
                                .is_err()
                            {
                                warn!(
                                    "execute_streaming Done 帧被丢弃 — 消费者已提前退出 (outer_tx.send Err)"
                                );
                            }
                            break;
                        }
                    }
                }
                // L-CORE-01: break 后 sb_handle.await 可能阻塞到子进程超时 (chunk 通道断后
                // 沙箱协调任务仍驱动子进程)。abort 先停协调任务, 再 timeout 包 await 兜底 —
                // 子进程由沙箱内部 timeout/supervisor 自管, fe-core 任务不无限挂起。
                sb_handle.abort();
                match tokio::time::timeout(Duration::from_secs(5), sb_handle).await {
                    Ok(_) => debug!("execute_streaming 协调任务已结束"),
                    Err(_) => warn!(
                        "execute_streaming 协调任务 abort 后 5s 仍在运行 (子进程可能仍在超时回收中)"
                    ),
                }
            });
            // C-4: catch_unwind 捕获任务体内 panic。Err(payload) → 发显式 Done{exit_code:-1,
            // stderr:"internal panic: ..."} 而非让 outer_rx 收 None (旧版静默吞结果, 看似成功无结果)。
            if let Err(payload) = inner.catch_unwind().await {
                let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
                    s.to_string()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic payload".to_string()
                };
                error!(panic = %msg, "execute_streaming 任务体 panic — 发显式错误 Done 帧");
                let panic_result = ExecutionResult {
                    exit_code: EXIT_BLOCKED,
                    stderr: format!("internal panic: {msg}"),
                    task_id: task_id_for_panic,
                    command: Some(command_for_panic),
                    duration_sec: start.elapsed().as_secs_f64(),
                    trace_id: Some(trace_id_for_panic),
                    ..Default::default()
                };
                if panic_tx
                    .send(ExecutionStreamEvent::Done(Box::new(panic_result)))
                    .await
                    .is_err()
                {
                    warn!(
                        "execute_streaming panic Done 帧也被丢弃 — 消费者已提前退出 (panic_tx.send Err)"
                    );
                }
            }
        });
        Ok((outer_rx, handle))
    }

    /// 实时遥测流 — 10Hz CPU/内存采样, GPU 由调用方注入 (executor 不跑模型)。
    /// 返回 (Receiver<TelemetrySample>, JoinHandle)。调用方迭代 rx 收帧,
    /// 丢弃 rx 则采样任务自动停止 (通道关闭)。Executor 无状态: 每次调用独立流。
    pub fn telemetry_stream(
        &self,
        cfg: TelemetryConfig,
    ) -> (mpsc::Receiver<TelemetrySample>, JoinHandle<()>) {
        info!(interval_ms = cfg.interval_ms, "telemetry_stream — 启动采样");
        start_telemetry(cfg, BLOCKING_RT.handle().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn execute_streaming_echo_chunk_then_done() {
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "echo hi".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: None,
            };
            let (mut rx, handle) = ex.execute_streaming(req).await.unwrap();
            let mut combined = String::new();
            let mut done = None;
            while let Some(ev) = rx.recv().await {
                match ev {
                    ExecutionStreamEvent::Chunk { data } => combined.push_str(&data),
                    ExecutionStreamEvent::Done(r) => done = Some(r),
                }
            }
            handle.await.unwrap();
            let done = done.expect("应收到 Done");
            assert_eq!(done.exit_code, 0);
            assert!(!done.timed_out);
            assert!(combined.contains("hi"), "chunks={:?}", combined);
            assert!(done.stdout.contains("hi"), "done.stdout={:?}", done.stdout);
        });
    }

    #[test]
    fn trace_id_auto_generated_on_none() {
        // M-OPS-06: 请求不带 trace_id → 入口自动生成 uuid v4, 回填 result
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "echo t".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: None,
            };
            let r = ex.execute_async(req).await.unwrap();
            assert_eq!(r.exit_code, 0);
            assert!(r.trace_id.is_some(), "trace_id 应自动生成");
            let tid = r.trace_id.as_ref().unwrap();
            assert_eq!(tid.len(), 36, "uuid v4 长度 36, 得 {tid}");
            assert_eq!(tid.matches('-').count(), 4, "uuid v4 含 4 段分隔, 得 {tid}");
        });
    }

    #[test]
    fn trace_id_forwarded_when_provided() {
        // M-OPS-06: 调用方传 trace_id → 原样回填 result
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "echo t".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: Some("caller-tid-123".to_string()),
            };
            let r = ex.execute_async(req).await.unwrap();
            assert_eq!(r.trace_id.as_deref(), Some("caller-tid-123"));
        });
    }

    #[test]
    fn trace_id_present_on_blocked() {
        // M-OPS-06: 拦截结果也带 trace_id (blocked_with 转发)
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "rm -rf /".to_string(),
                task_id: Some("tk".to_string()),
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: Some("blk-tid".to_string()),
            };
            let r = ex.execute_async(req).await.unwrap();
            assert!(r.blocked_by_security);
            assert_eq!(r.trace_id.as_deref(), Some("blk-tid"));
        });
    }

    #[test]
    fn trace_id_streaming_done_carries_it() {
        // M-OPS-06: 流式 Done 帧带 trace_id
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "echo s".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: Some("stream-tid".to_string()),
            };
            let (mut rx, handle) = ex.execute_streaming(req).await.unwrap();
            let mut done = None;
            while let Some(ev) = rx.recv().await {
                if let ExecutionStreamEvent::Done(r) = ev {
                    done = Some(r);
                }
            }
            handle.await.unwrap();
            let done = done.expect("应收到 Done");
            assert_eq!(done.trace_id.as_deref(), Some("stream-tid"));
        });
    }

    #[test]
    fn execute_streaming_blocked_single_done_frame() {
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "rm -rf /".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: None,
            };
            let (mut rx, handle) = ex.execute_streaming(req).await.unwrap();
            let mut frames = 0;
            let mut blocked = false;
            while let Some(ev) = rx.recv().await {
                frames += 1;
                if let ExecutionStreamEvent::Done(r) = ev {
                    assert_eq!(r.exit_code, EXIT_BLOCKED);
                    assert!(r.blocked_by_security);
                    blocked = true;
                }
            }
            handle.await.unwrap();
            assert_eq!(frames, 1, "拦截应只发单帧 Done");
            assert!(blocked);
        });
    }

    #[test]
    fn execute_streaming_timeout_done_frame() {
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "python3 -c \"while True: pass\"".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 1.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: None,
            };
            let (mut rx, handle) = ex.execute_streaming(req).await.unwrap();
            let mut done = None;
            while let Some(ev) = rx.recv().await {
                if let ExecutionStreamEvent::Done(r) = ev {
                    done = Some(r);
                }
            }
            handle.await.unwrap();
            let done = done.expect("应收到 Done");
            assert!(done.timed_out);
            assert_eq!(done.exit_code, EXIT_TIMEOUT);
        });
    }

    #[test]
    fn execute_streaming_diagnostics_on_nonzero_exit() {
        rt().block_on(async {
            let ex = Executor::new();
            let req = ExecutionRequest {
                command: "python3 -c \"raise ValueError('boom')\"".to_string(),
                task_id: None,
                cwd: None,
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: false,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: None,
            };
            let (mut rx, handle) = ex.execute_streaming(req).await.unwrap();
            let mut done = None;
            while let Some(ev) = rx.recv().await {
                if let ExecutionStreamEvent::Done(r) = ev {
                    done = Some(r);
                }
            }
            handle.await.unwrap();
            let done = done.unwrap();
            assert_ne!(done.exit_code, 0);
            let diag = done.diagnostics.expect("非零退出应填 diagnostics");
            assert_eq!(diag.error_type.as_deref(), Some("ValueError"));
        });
    }

    fn make_git_repo(dir: &std::path::Path) {
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .output()
                .expect("git 失败")
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        std::fs::write(dir.join("app.py"), "print('ok')\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "init"]);
    }

    #[test]
    fn auto_rollback_triggers_on_failure_with_file_damage() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            // python3 白名单内 — 改写 app.py 后抛错 (失败 + 文件毁损)
            let cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\"";
            let req = ExecutionRequest {
                command: cmd.to_string(),
                task_id: None,
                cwd: Some(cwd.clone()),
                timeout_sec: 15.0,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: Some(RollbackPolicy::default()),
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: None,
            };
            let ex = Executor::new();
            let res = ex.execute_async(req).await.unwrap();
            assert_ne!(res.exit_code, 0, "应失败");
            assert!(res.auto_rolled_back, "应自动回滚");
            // 回滚后 app.py 恢复原始内容
            let content = std::fs::read_to_string(dir.path().join("app.py")).unwrap();
            assert_eq!(content, "print('ok')\n", "回滚后应恢复: {content}");
        });
    }

    #[test]
    fn auto_rollback_skipped_when_exit_ok() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            // 成功命令: commit 后工作区干净, 不应回滚
            let req = ExecutionRequest {
                command: "echo hi".to_string(),
                task_id: None,
                cwd: Some(cwd),
                timeout_sec: 10.0,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: Some(RollbackPolicy::default()),
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: None,
            };
            let ex = Executor::new();
            let res = ex.execute_async(req).await.unwrap();
            assert_eq!(res.exit_code, 0);
            assert!(!res.auto_rolled_back, "成功不应回滚");
        });
    }

    #[test]
    fn auto_rollback_no_policy_means_no_action() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            // 无 policy → 即使失败+文件改动也不回滚
            let cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\"";
            let req = ExecutionRequest {
                command: cmd.to_string(),
                task_id: None,
                cwd: Some(cwd.clone()),
                timeout_sec: 15.0,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: None,
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: None,
            };
            let ex = Executor::new();
            let res = ex.execute_async(req).await.unwrap();
            assert_ne!(res.exit_code, 0);
            assert!(!res.auto_rolled_back, "无 policy 不应回滚");
            // 文件保持损坏 (未回滚)
            let content = std::fs::read_to_string(dir.path().join("app.py")).unwrap();
            assert_eq!(content, "broken\n", "无 policy 文件应保持改动: {content}");
        });
    }

    // Issue #12.3 / A4: max_consecutive_failures 是 DEFERRED-BY-DESIGN 死字段 —
    // Rust 永不读。设极高值 (99) 不应阻止单次执行的文件毁损回滚 (证字段被接受但忽略, 无状态)。
    #[test]
    fn max_consecutive_failures_ignored_stateless() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            let cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\"";
            let req = ExecutionRequest {
                command: cmd.to_string(),
                task_id: None,
                cwd: Some(cwd.clone()),
                timeout_sec: 15.0,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: Some(RollbackPolicy {
                    max_consecutive_failures: 99,
                    file_damage_check: true,
                }),
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: None,
            };
            let ex = Executor::new();
            let res = ex.execute_async(req).await.unwrap();
            assert_ne!(res.exit_code, 0, "应失败");
            // 即使 max_consecutive_failures=99 (远超单次), 文件毁损仍立即回滚 — 字段不限制单次执行
            assert!(
                res.auto_rolled_back,
                "max_consecutive_failures 不影响单次回滚 (死字段)"
            );
            let content = std::fs::read_to_string(dir.path().join("app.py")).unwrap();
            assert_eq!(content, "print('ok')\n", "回滚后应恢复: {content}");
        });
    }

    // C-CORE-01: 命令前已脏 (未跟踪 wip.txt) + 命令失败但不碰任何文件 → 不误触发回滚。
    // 旧版 detect_damage 见 git status 非空 (wip.txt) 即判毁损 → 误回滚 (无谓 reset, 丢 wip.txt
    // 若已 stash 则恢复). 新版 diff pre/post: wip.txt 在 pre_status, 非"命令新增" → 不回滚。
    #[test]
    fn auto_rollback_no_false_trigger_on_preexisting_dirty() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            // 命令前制造未跟踪文件 (WIP) — pre_status 记录它
            std::fs::write(dir.path().join("wip.txt"), "work in progress\n").unwrap();
            // 命令失败但不改任何文件 (纯 raise) — post_status 含 wip.txt 但 pre 也有 → 无新增
            let cmd = "python3 -c \"raise ValueError('boom')\"";
            let req = ExecutionRequest {
                command: cmd.to_string(),
                task_id: None,
                cwd: Some(cwd),
                timeout_sec: 15.0,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: Some(RollbackPolicy::default()),
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: None,
            };
            let ex = Executor::new();
            let res = ex.execute_async(req).await.unwrap();
            assert_ne!(res.exit_code, 0, "应失败");
            assert!(
                !res.auto_rolled_back,
                "命令未新增改动 (wip.txt 命令前已脏) → 不应误回滚"
            );
            // app.py 未被命令触碰, 保持原样
            let app = std::fs::read_to_string(dir.path().join("app.py")).unwrap();
            assert_eq!(app, "print('ok')\n", "app.py 未动");
            // wip.txt 保留 (无回滚, 无丢失)
            let wip = std::fs::read_to_string(dir.path().join("wip.txt")).unwrap();
            assert_eq!(wip, "work in progress\n", "wip.txt 不应被回滚丢失");
        });
    }

    #[test]
    fn telemetry_stream_yields_samples_and_stops() {
        rt().block_on(async {
            let ex = Executor::new();
            let cfg = TelemetryConfig {
                interval_ms: 20,
                max_samples: 4,
                pid: None,
            };
            let (mut rx, handle) = ex.telemetry_stream(cfg);
            let mut samples = Vec::new();
            while let Some(s) = rx.recv().await {
                samples.push(s);
            }
            let _ = handle.await;
            assert_eq!(samples.len(), 4, "应产出 4 帧");
            assert!(samples.iter().all(|s| s.mem_mb >= 0.0));
            assert!(
                samples.iter().all(|s| s.gpu_pct.is_none()),
                "GPU 默认不注入"
            );
        });
    }

    // ===== 0827 fe-core P0-P3 修复回归测试 =====

    /// C-2: is_tracked_mutation porcelain 行码判定 — 仅跟踪文件突变计 damage, ?? /A 不计。
    #[test]
    fn c2_is_tracked_mutation_classifies_porcelain_codes() {
        // 未跟踪新增 (命令有意创建) → 不计 damage
        assert!(!is_tracked_mutation("?? build/"), "?? 未跟踪不算 damage");
        assert!(!is_tracked_mutation("?? __pycache__/"));
        // 暂存新增 (无旧跟踪基线) → 不计 damage
        assert!(
            !is_tracked_mutation("A  new_file.py"),
            "A 暂存新增不算 damage"
        );
        // 工作区新增 (A 在 Y 位) → 不计
        assert!(!is_tracked_mutation(" A new_file.py"), " Y=A 不算 damage");
        // 跟踪文件修改 (任一位置 M) → 计 damage
        assert!(is_tracked_mutation(" M app.py"), " Y=M 工作区改算 damage");
        assert!(is_tracked_mutation("M  app.py"), "X=M 暂存改算 damage");
        assert!(is_tracked_mutation("MM app.py"), "MM 双区改算 damage");
        // 跟踪文件删除 (D) → 计 damage
        assert!(is_tracked_mutation(" D app.py"), " Y=D 删除算 damage");
        assert!(is_tracked_mutation("D  app.py"), "X=D 暂存删除算 damage");
        // 重命名/复制 (R/C) → 计 damage
        assert!(
            is_tracked_mutation("R  old.py -> new.py"),
            "R 重命名算 damage"
        );
        assert!(
            is_tracked_mutation("C  src.py -> dst.py"),
            "C 复制算 damage"
        );
        // 类型变 (T) → 计 damage
        assert!(is_tracked_mutation(" T app.py"), " Y=T 类型变算 damage");
        // 异常短行 → 保守 false (不误回滚)
        assert!(!is_tracked_mutation(""), "空行不算 damage");
        assert!(!is_tracked_mutation("A"), "单字符行不算 damage");
    }

    /// C-2: `mkdir -p build && <失败命令>` — 未跟踪 build/ 在 post 不在 pre,
    /// 不应误判 damage 触发回滚 (C-CORE-01 漏的大问题, fusion-code 典型工作流)。
    #[test]
    fn c2_untracked_build_dir_not_treated_as_damage() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            // mkdir 建未跟踪 build/ 目录, 然后 python3 抛错 (白名单内 + exit!=0)
            // build/ 在 post (?? build/) 不在 pre → 旧版误判 damage → 误回滚。
            // C-2 修后: ?? 不计 damage → damaged=0 → 不回滚, auto_rolled_back=false。
            let cmd = "mkdir -p build && python3 -c \"raise ValueError(1)\"";
            let req = ExecutionRequest {
                command: cmd.to_string(),
                task_id: None,
                cwd: Some(cwd.clone()),
                timeout_sec: 15.0,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: Some(RollbackPolicy::default()),
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: None,
            };
            let ex = Executor::new();
            let res = ex.execute_async(req).await.unwrap();
            assert_ne!(res.exit_code, 0, "应失败 (python 抛错)");
            assert!(
                !res.auto_rolled_back,
                "C-2: 未跟踪 build/ 不应触发回滚, got auto_rolled_back={}",
                res.auto_rolled_back
            );
            // build/ 应保留 (未被回滚清掉)
            assert!(
                dir.path().join("build").exists(),
                "C-2: build/ 目录应保留 (合法产物未误回滚)"
            );
        });
    }

    /// C-2: 跟踪文件被命令改坏 (M) + exit!=0 → 仍应触发回滚 (C-2 不破坏真 damage 路径)。
    #[test]
    fn c2_tracked_modify_still_triggers_rollback() {
        rt().block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let cwd = dir.path().to_str().unwrap().to_string();
            make_git_repo(dir.path());
            // 改写跟踪文件 app.py ( M) 后抛错 → 真damage → 应回滚
            let cmd = "python3 -c \"open('app.py','w').write('broken\\n'); raise ValueError(1)\"";
            let req = ExecutionRequest {
                command: cmd.to_string(),
                task_id: None,
                cwd: Some(cwd),
                timeout_sec: 15.0,
                env_vars: None,
                enable_rollback_snapshot: true,
                auto_rollback_policy: Some(RollbackPolicy::default()),
                seatbelt: false,
                inherit_env: false,
                use_pty: true,
                max_nproc: 1024,
                max_cpu_sec: 0,
                max_nofile: 1024,
                trace_id: None,
            };
            let ex = Executor::new();
            let res = ex.execute_async(req).await.unwrap();
            assert_ne!(res.exit_code, 0, "应失败");
            assert!(
                res.auto_rolled_back,
                "C-2: 跟踪文件 M 突变应触发回滚, got auto_rolled_back={}",
                res.auto_rolled_back
            );
        });
    }

    /// L-2: rollback_unavailable 字段默认 false, 序列化省略 (skip_serializing_if is_false)。
    #[test]
    fn l2_rollback_unavailable_default_and_skip_serialize() {
        let r = ExecutionResult::default();
        assert!(!r.rollback_unavailable, "默认 false");
        // false 时不序列化 (wire 省位)
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("rollback_unavailable"),
            "false 时应 skip: {json}"
        );
        // true 时序列化
        let r2 = ExecutionResult {
            rollback_unavailable: true,
            ..Default::default()
        };
        let json2 = serde_json::to_string(&r2).unwrap();
        assert!(
            json2.contains("rollback_unavailable"),
            "true 时应序列化: {json2}"
        );
        // 反序列化兼容 (缺字段 → default false)
        let back: ExecutionResult = serde_json::from_str(
            r#"{"exit_code":0,"stdout":"","stderr":"","timed_out":false,"blocked_by_security":false}"#,
        )
        .unwrap();
        assert!(!back.rollback_unavailable, "缺字段反序列化应默认 false");
    }

    /// L-1 (审计 0827): rollback_skipped_reason 字段默认 None, 序列化省略 (skip_serializing_if
    /// Option::is_none)。区分 "未回滚(无需)" (None) 与 "未回滚(快照失效)" (Some) — fail-loud。
    #[test]
    fn l1_rollback_skipped_reason_default_and_skip_serialize() {
        let r = ExecutionResult::default();
        assert!(r.rollback_skipped_reason.is_none(), "默认 None");
        // None 时 skip (wire 省位)
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("rollback_skipped_reason"),
            "None 时应 skip: {json}"
        );
        // Some 时序列化
        let r2 = ExecutionResult {
            rollback_skipped_reason: Some("snapshot_id 解析失败".to_string()),
            ..Default::default()
        };
        let json2 = serde_json::to_string(&r2).unwrap();
        assert!(
            json2.contains("rollback_skipped_reason"),
            "Some 时应序列化: {json2}"
        );
        assert!(
            json2.contains("snapshot_id 解析失败"),
            "原因值应在 wire: {json2}"
        );
        // 反序列化兼容 (缺字段 → default None)
        let back: ExecutionResult = serde_json::from_str(
            r#"{"exit_code":0,"stdout":"","stderr":"","timed_out":false,"blocked_by_security":false}"#,
        )
        .unwrap();
        assert!(
            back.rollback_skipped_reason.is_none(),
            "缺字段反序列化应默认 None"
        );
    }

    /// A-5: BLOCKING_RT panic 信息含构建原因 + 不可恢复提示 (文档锚点, 不触发真 panic)。
    /// 验证静态可访问 + runtime 活跃 (能跑任务)。
    #[test]
    fn a5_blocking_rt_symbol_accessible() {
        // 访问触发 init (正常环境必成功); 验证符号可访问且 runtime 活跃 (能 spawn 任务)。
        let entered: bool = BLOCKING_RT.handle().block_on(async { true });
        assert!(entered, "BLOCKING_RT 应可访问且能执行任务");
    }
}
