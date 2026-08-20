// fe-core — Executor orchestrator (P1 minimal pipeline)
//
// Pipeline: validate → spawn → return
// 重型组件 (tree-sitter / git handle) 懒加载，new() <5ms (NFR)

use std::sync::LazyLock;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::info;

use fe_diagnostics::Slicer;
use fe_gui::{GuiAction, GuiController, GuiResult};
use fe_rollback::RollbackManager;
use fe_sandbox::{Sandbox, SandboxConfig};
use fe_security::{SecurityGuard, SecurityVerdict};

pub use fe_diagnostics as diagnostics;
pub use fe_gui as gui;
pub use fe_rollback as rollback;
pub use fe_sandbox as sandbox;
pub use fe_security as security;

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
    pub timed_out: bool,
    pub blocked_by_security: bool,
    pub security_reason: Option<String>,
    pub snapshot_id: Option<String>,
    pub diagnostics: Option<Diagnostics>,
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
}

/// 流式事件 — Chunk (实时 stdio 分块) / Done (最终 ExecutionResult, 含 diagnostics)
/// 镜像 fe-sandbox::StreamEvent, 但 Done 携带完整 ExecutionResult (经诊断切片 + 快照 id)
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecutionStreamEvent {
    Chunk { data: String },
    Done(ExecutionResult),
}

/// Executor — 校验 + 沙箱执行的编排器
pub struct Executor {
    security: SecurityGuard,
    sandbox: Sandbox,
    slicer: Slicer,
    rollback: RollbackManager,
    gui: GuiController,
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

impl Executor {
    pub fn new() -> Self {
        info!("Executor::new() — 初始化 SecurityGuard + Sandbox + Slicer + Rollback + Gui");
        Self {
            security: SecurityGuard::new(),
            sandbox: Sandbox::new(),
            slicer: Slicer::new(),
            rollback: RollbackManager::new(),
            gui: GuiController::new(),
        }
    }

    /// GUI 动作 (P4 FR-05) — 同步入口, 供 fe-pyo3/fe-ipc 调用
    pub fn gui_action(&self, action: GuiAction) -> Result<GuiResult> {
        self.gui.execute(action)
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
        let verdict = self.security.validate(&req.command);
        if !verdict.allowed {
            let reason = verdict.reason.unwrap_or_else(|| "未知原因".to_string());
            info!(%reason, "安全校验拦截");
            return Ok(ExecutionResult::blocked(reason));
        }
        // cwd 校验
        if let Some(cwd) = &req.cwd {
            let cwd_v = self.security.validate_cwd(cwd);
            if !cwd_v.allowed {
                let reason = cwd_v.reason.unwrap_or_else(|| "cwd 非法".to_string());
                info!(%reason, "cwd 校验拦截");
                return Ok(ExecutionResult::blocked(reason));
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

        Ok(ExecutionResult {
            exit_code: sb.exit_code,
            stdout: sb.stdout,
            stderr: sb.stderr,
            timed_out: sb.timed_out,
            snapshot_id: snapshot_id.filter(|s| !s.is_empty()),
            diagnostics: diag,
            ..Default::default()
        })
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
        let verdict = self.security.validate(&req.command);
        if !verdict.allowed {
            let reason = verdict.reason.unwrap_or_else(|| "未知原因".to_string());
            info!(%reason, "安全校验拦截 (streaming)");
            let (tx, rx) = mpsc::channel(8);
            let handle = tokio::spawn(async move {
                let _ = tx
                    .send(ExecutionStreamEvent::Done(ExecutionResult::blocked(reason)))
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
                        .send(ExecutionStreamEvent::Done(ExecutionResult::blocked(reason)))
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
                        let result = ExecutionResult {
                            exit_code: sb.exit_code,
                            stdout: sb.stdout,
                            stderr: sb.stderr,
                            timed_out: sb.timed_out,
                            snapshot_id: snapshot_id.filter(|s| !s.is_empty()),
                            diagnostics: diag,
                            ..Default::default()
                        };
                        let _ = outer_tx.send(ExecutionStreamEvent::Done(result)).await;
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
}
