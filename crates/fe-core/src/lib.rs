// fe-core — Executor orchestrator (P1 minimal pipeline)
//
// Pipeline: validate → spawn → return
// 重型组件 (tree-sitter / git handle) 懒加载，new() <5ms (NFR)

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use fe_diagnostics::Slicer;
use fe_gui::{GuiAction, GuiController, GuiResult};
use fe_rollback::RollbackManager;
use fe_sandbox::{Sandbox, SandboxConfig};
use fe_security::{SecurityGuard, SecurityVerdict};
use fe_telemetry::{start_stream as start_telemetry, TelemetryConfig, TelemetrySample};
use fe_tools::{
    EditResult, GlobEntry, GrepMatch, GrepOptions, GrepOutput, MultiEditItem, NotebookEditMode,
    Tools,
};

pub use fe_diagnostics as diagnostics;
pub use fe_gui as gui;
pub use fe_rollback as rollback;
pub use fe_sandbox as sandbox;
pub use fe_security as security;
pub use fe_telemetry as telemetry;
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
        .expect("failed to build BLOCKING_RT")
});

/// 退出码约定: 0=成功, -124=超时, -1=拦截/内部异常
pub const EXIT_OK: i32 = 0;
pub const EXIT_TIMEOUT: i32 = -124;
pub const EXIT_BLOCKED: i32 = -1;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// 默认 false — 调用方显式开启; 透传 SandboxConfig.seatbelt。
    #[serde(default)]
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
}

fn default_use_pty() -> bool {
    true
}

fn default_nproc() -> u32 {
    1024
}

fn default_timeout() -> f64 {
    30.0
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

    /// 带 task_id/command 的拦截结果 (PRD §4.1 — result 回填请求侧标识)
    pub fn blocked_with(
        reason: impl Into<String>,
        task_id: Option<String>,
        command: Option<String>,
    ) -> Self {
        Self {
            exit_code: EXIT_BLOCKED,
            blocked_by_security: true,
            security_reason: Some(reason.into()),
            task_id,
            command,
            ..Default::default()
        }
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
/// max_consecutive_failures 保留字段, 供未来 stateful 扩展 (A4: 当前死字段, 文档标注非删除)。
///
/// C-CORE-01: 旧版 `git status --porcelain` 非空即判毁损 — 未跟踪 `__pycache__`/WIP/并发编辑
/// 全算 → 误触发回滚丢无关改动。修: 命令前 capture `pre_status` (porcelain 快照), 命令后
/// 再 capture `post_status`, diff 出**命令新增**的改动条目才判毁损。pre 已记录的未跟踪文件
/// 不算 (命令前就脏)。这样 WIP/`__pycache__` 等命令前已存在的脏状态不误触发。
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

    /// 检测命令导致的文件毁损 — diff 命令后状态与命令前快照, 只算**命令新增**的条目。
    /// (C-CORE-01) 返回新增条目数。git 失败 fail-loud (L-CORE-02)。
    async fn detect_damage(&self) -> Result<usize> {
        let post = Self::capture_status(&self.cwd).await?;
        let new_entries: Vec<&String> = post
            .iter()
            .filter(|entry| !self.pre_status.contains(*entry))
            .collect();
        if !new_entries.is_empty() {
            info!(new = ?new_entries, "命令新增改动条目 (命令导致)");
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
        let ok = self.rollback.rollback(&self.snapshot_id, &self.cwd).await?;
        if ok {
            result.auto_rolled_back = true;
            info!(snapshot = %self.snapshot_id, "自动回滚成功");
        } else {
            warn!(snapshot = %self.snapshot_id, "自动回滚未生效 (rollback 返回 false)");
        }
        Ok(())
    }
}

/// Executor — 校验 + 沙箱执行的编排器
pub struct Executor {
    security: SecurityGuard,
    sandbox: Sandbox,
    slicer: Slicer,
    rollback: RollbackManager,
    gui: GuiController,
    tools: Tools,
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

impl Executor {
    pub fn new() -> Self {
        info!("Executor::new() — 初始化 SecurityGuard + Sandbox + Slicer + Rollback + Gui + Tools");
        Self {
            security: SecurityGuard::new(),
            sandbox: Sandbox::new(),
            slicer: Slicer::new(),
            rollback: RollbackManager::new(),
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

    /// GUI 动作 (P4 FR-05) — 同步入口, 供 fe-pyo3/fe-ipc 调用
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

    /// 回滚 — 公开供 fe-pyo3 直接调用
    pub async fn rollback_async(&self, snapshot_id: &str, cwd: &str) -> Result<bool> {
        self.rollback.rollback(snapshot_id, cwd).await
    }

    /// 校验命令 — 公开供 fe-ipc/fe-pyo3 直接调用
    pub fn validate(&self, command: &str) -> SecurityVerdict {
        self.security.validate(command)
    }

    /// 异步执行 — 校验 → 沙箱执行 → return
    pub async fn execute_async(&self, req: ExecutionRequest) -> Result<ExecutionResult> {
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
                    warn!(error = %e, "自动回滚 guard 异常 (非致命)");
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
        };
        info!(seatbelt = req.seatbelt, "execute_streaming — 沙箱流式执行");
        let (mut sb_rx, sb_handle) = self.sandbox.run_streaming(sb_cfg)?;

        let slicer = self.slicer.clone();
        let cwd_for_diag = req.cwd.clone();
        let task_id_for_done = req.task_id.clone();
        let command_for_done = req.command.clone();
        let policy_for_done = req.auto_rollback_policy.clone();
        let cwd_for_guard = req.cwd.clone();
        let pre_status_for_guard = pre_status.clone();

        let (outer_tx, outer_rx) = mpsc::channel::<ExecutionStreamEvent>(64);
        let handle = tokio::spawn(async move {
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
                        let sid_filtered = snapshot_id.as_ref().filter(|s| !s.is_empty()).cloned();
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
                                    warn!(error = %e, "自动回滚 guard 异常 (streaming, 非致命)");
                                }
                            }
                        }
                        let _ = outer_tx
                            .send(ExecutionStreamEvent::Done(Box::new(result)))
                            .await;
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
}
