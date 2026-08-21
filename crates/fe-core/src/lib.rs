// fe-core — Executor orchestrator (P1 minimal pipeline)
//
// Pipeline: validate → spawn → return
// 重型组件 (tree-sitter / git handle) 懒加载，new() <5ms (NFR)

use std::sync::LazyLock;
use std::time::Instant;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use fe_diagnostics::Slicer;
use fe_gui::{GuiAction, GuiController, GuiResult};
use fe_rollback::RollbackManager;
use fe_sandbox::{Sandbox, SandboxConfig};
use fe_security::{SecurityGuard, SecurityVerdict};
use fe_tools::{EditResult, GlobEntry, GrepMatch, Tools};

pub use fe_diagnostics as diagnostics;
pub use fe_gui as gui;
pub use fe_rollback as rollback;
pub use fe_sandbox as sandbox;
pub use fe_security as security;
pub use fe_tools as tools;
pub use fe_tools::{
    EditResult as ToolsEditResult, GlobEntry as ToolsGlobEntry, GrepMatch as ToolsGrepMatch,
};

// BLOCKING_RT — 多线程 1 worker，避免 asyncio 调用者嵌套 runtime panic
// 模式源自 fusion-design/crates/fd-ai-adapter/src/lib.rs:251-257
pub static BLOCKING_RT: LazyLock<Runtime> =
    LazyLock::new(|| Runtime::new().expect("failed to build BLOCKING_RT"));

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

/// 自动回滚守卫 (FR-04) — 单次执行内追踪连续失败 + 文件毁损, 达阈值触发 rollback。
/// 生命周期限定单次 execute_async: 不跨请求累积 (Executor 无状态锁定决策)。
/// 连续失败计数靠调用方多次传同一 policy 维持? 否 — caller-driven 无状态, 单次内仅能基于
/// 本次结果 + 上次快照判断 "文件毁损" (git status 比对快照前后)。连续失败计数本设计降级为:
/// 单次执行内部 exit_code!=0 即视为 "本次失败", 配合 file_damage_check 触发回滚。
/// 真正的连续失败计数归 caller (fusion-code 自愈循环 owns retry count, PRD §重构 明确)。
/// 故此 guard 实现: exit_code==0 不回滚; exit_code!=0 且检测到文件改动 (git status 非空
/// 且非本次命令预期改动) → rollback(last_snapshot)。max_consecutive_failures 保留字段,
/// 供未来 stateful 扩展; 当前单次内阈值=1 (本次失败即检毁损)。
pub struct AutoRollbackGuard {
    policy: RollbackPolicy,
    snapshot_id: String,
    cwd: String,
    rollback: RollbackManager,
}

impl AutoRollbackGuard {
    /// 构造 — 持有本次执行前创建的快照 id + cwd
    pub fn new(policy: RollbackPolicy, snapshot_id: String, cwd: String) -> Self {
        Self {
            policy,
            snapshot_id,
            cwd,
            rollback: RollbackManager::new(),
        }
    }

    /// 检测文件毁损 — git status --porcelain 比对快照后工作区状态。
    /// 非空 (有改动) 视为 "文件被本次命令改动/毁损"。返回改动文件数。
    async fn detect_damage(&self) -> Result<usize> {
        let out = tokio::process::Command::new("git")
            .arg("-C")
            .arg(&self.cwd)
            .args(["status", "--porcelain"])
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("git status 启动失败: {e}"))?;
        let s = String::from_utf8_lossy(&out.stdout);
        Ok(s.lines().filter(|l| !l.is_empty()).count())
    }

    /// 记录结果 — exit_code==0 无动作; !=0 且检测毁损 → rollback, 标记 auto_rolled_back。
    /// 就地修改 result.auto_rolled_back。非 git repo → 跳过 (rollback no-op)。
    pub async fn record_result(&self, result: &mut ExecutionResult) -> Result<()> {
        if result.exit_code == 0 {
            return Ok(());
        }
        if !self.policy.file_damage_check {
            return Ok(());
        }
        let damaged = self.detect_damage().await.unwrap_or(0);
        if damaged == 0 {
            info!(exit_code = result.exit_code, "失败但无文件改动, 不回滚");
            return Ok(());
        }
        info!(
            damaged,
            exit_code = result.exit_code,
            "检测到文件改动, 触发自动回滚"
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

    /// GUI 动作 (P4 FR-05) — 同步入口, 供 fe-pyo3/fe-ipc 调用
    pub fn gui_action(&self, action: GuiAction) -> Result<GuiResult> {
        self.gui.execute(action)
    }

    /// 原生文件工具 — file_edit (PRD FileEdit 本地化)
    pub fn file_edit(
        &self,
        path: &str,
        old_string: &str,
        new_string: &str,
        cwd: Option<&str>,
    ) -> Result<EditResult> {
        self.tools.file_edit(path, old_string, new_string, cwd)
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

        // 快照 (caller-driven 锁定决策: 仅当 enable_rollback_snapshot 且有 cwd)
        let snapshot_id = if req.enable_rollback_snapshot {
            if let Some(cwd) = &req.cwd {
                match self.rollback.snapshot_create(cwd).await {
                    Ok(id) => {
                        if !id.is_empty() {
                            info!(%id, "快照已创建");
                        }
                        Some(id)
                    }
                    Err(e) => {
                        info!(error = %e, "快照创建失败, 继续 (非致命)");
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        let env = req.env_vars.unwrap_or_default();
        let sb_cfg = SandboxConfig {
            command: req.command.clone(),
            cwd: req.cwd.clone(),
            env,
            timeout_sec: req.timeout_sec,
            max_output_chars: 100_000,
        };
        info!("execute_async — 沙箱执行");
        let sb = self.sandbox.run(sb_cfg).await?;

        // 诊断切片 — exit_code != 0 且非拦截/超时时填充 (PRD §4.2)
        let diag = if sb.exit_code != 0 && !sb.timed_out {
            let cwd_ref = req.cwd.as_deref();
            Some(Diagnostics::from(self.slicer.slice(&sb.stdout, cwd_ref)))
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
        if let (Some(policy), Some(cwd), Some(sid)) = (
            req.auto_rollback_policy.clone(),
            req.cwd.clone(),
            sid_filtered.as_ref(),
        ) {
            if !sid.is_empty() {
                let guard = AutoRollbackGuard::new(policy, sid.clone(), cwd);
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

        // 快照 (与 execute_async 同策略: caller-driven, 仅 enable + 有 cwd)
        let snapshot_id = if req.enable_rollback_snapshot {
            if let Some(cwd) = &req.cwd {
                match self.rollback.snapshot_create(cwd).await {
                    Ok(id) => {
                        if !id.is_empty() {
                            info!(%id, "快照已创建 (streaming)");
                        }
                        Some(id)
                    }
                    Err(e) => {
                        info!(error = %e, "快照创建失败, 继续 (非致命, streaming)");
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        let env = req.env_vars.unwrap_or_default();
        let sb_cfg = fe_sandbox::SandboxConfig {
            command: req.command.clone(),
            cwd: req.cwd.clone(),
            env,
            timeout_sec: req.timeout_sec,
            max_output_chars: 100_000,
        };
        info!("execute_streaming — 沙箱流式执行");
        let (mut sb_rx, sb_handle) = self.sandbox.run_streaming(sb_cfg)?;

        let slicer = self.slicer.clone();
        let cwd_for_diag = req.cwd.clone();
        let task_id_for_done = req.task_id.clone();
        let command_for_done = req.command.clone();
        let policy_for_done = req.auto_rollback_policy.clone();
        let cwd_for_guard = req.cwd.clone();

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
                            Some(Diagnostics::from(slicer.slice(&sb.stdout, cwd_ref)))
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
                        // 自动回滚 (FR-04, 同 execute_async)
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
            let _ = sb_handle.await;
        });
        Ok((outer_rx, handle))
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
}
