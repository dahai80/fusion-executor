// fe-sandbox — PTY 沙箱 (FR-02/03, NFR)
//
// portable-pty 0.8: openpty → spawn(sh -c cmd, setsid 使子为组长) → 阻塞 reader 线程 → child.wait
// 超时: SIGINT (graceful) → 50ms → try_wait 仍活 → SIGKILL (forceful), killpg(-pid) 进程树杀
// 截断: stdout head H=4096 + tail T=8192, 中间折叠 [truncated N chars]
// OOM: 环形缓冲 cap = 2*effective_max; effective_max = max_output_chars.min(HARD_CEILING) 绝对上限
// PTY 合并 stdout+stderr → 全入 stdout (stderr 空; traceback 在 tail 可读)

use std::io::Read;
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const HEAD_CHARS: usize = 4096;
const TAIL_CHARS: usize = 8192;
const DEFAULT_MAX_OUTPUT: usize = 100_000;
/// C-SB-05: 环形缓冲绝对上限 — 防调用方设 max_output_chars=usize::MAX 打 OOM-kill 主机
const HARD_CEILING: usize = 64 * 1024 * 1024;
/// C-SB-01: SIGINT→SIGKILL grace window
const KILL_GRACE_MS: u64 = 50;
/// C-SB-02/03: kill 后收 reader 输出超时 — 子进程忽略信号时 reader 永不 EOF
const READER_RECV_TIMEOUT_MS: u64 = 2000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxResult {
    pub exit_code: i32,
    pub stdout: String,
    /// L-SB-05: PTY 合并 stdout+stderr → 本字段恒空。保留以匹配 PRD §4.1 wire 契约;
    /// Slicer 解析 stdout (traceback 在 tail)。需分离流者另起 stdio-only 后端 (本沙箱不支持)。
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
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            command: String::new(),
            cwd: None,
            env: std::collections::HashMap::new(),
            timeout_sec: 30.0,
            max_output_chars: DEFAULT_MAX_OUTPUT,
        }
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
        info!(command = %cfg.command, timeout = cfg.timeout_sec, "sandbox run");

        let pty_system = NativePtySystem::default();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("openpty 失败")?;

        // sh -c <command> — 走 shell 以支持管道/重定向 (已通过 fe-security 校验)
        let mut cmd = CommandBuilder::new("sh");
        cmd.arg("-c");
        cmd.arg(&cfg.command);
        if let Some(cwd) = &cfg.cwd {
            cmd.cwd(cwd);
        }
        for (k, v) in &cfg.env {
            cmd.env(k, v);
        }

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .context("spawn_command 失败")?;
        let pid = child.process_id();
        debug!(?pid, "child spawned");

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
                        let _ = tx.send(Err(anyhow::anyhow!("read 失败: {}", e)));
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

        // wait 阻塞 → spawn_blocking; 超时 → SIGINT→50ms→SIGKILL 进程树杀 (C-SB-01/04)
        let wait_fut = tokio::task::spawn_blocking(move || child.wait());
        // L-SB-06: timeout<=0 视"无超时"跳 sleep 分支; 负值 (调用方 bug) 拒绝
        if cfg.timeout_sec < 0.0 {
            drop(pair.master);
            bail!("timeout_sec 不能为负: {}", cfg.timeout_sec);
        }
        let no_timeout = cfg.timeout_sec == 0.0;
        let timeout_dur = Duration::from_secs_f64(if no_timeout { 1.0 } else { cfg.timeout_sec });
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
            _ = sleep, if !no_timeout => {
                warn!(?pid, timeout_sec = cfg.timeout_sec, "超时, kill 进程组");
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
            Ok(Err(_)) => String::new(),
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

        let mut cmd = CommandBuilder::new("sh");
        cmd.arg("-c");
        cmd.arg(&cfg.command);
        if let Some(cwd) = &cfg.cwd {
            cmd.cwd(cwd);
        }
        for (k, v) in &cfg.env {
            cmd.env(k, v);
        }

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .context("spawn_command 失败")?;
        let pid = child.process_id();
        debug!(?pid, "child spawned (streaming)");
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
                        let _ = inner_tx.blocking_send(ReaderMsg::Eof(String::new()));
                        warn!("streaming read 失败: {e}");
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
        // L-SB-06: timeout<=0 无超时; 负值拒绝
        if cfg.timeout_sec < 0.0 {
            drop(pair.master);
            bail!("timeout_sec 不能为负: {}", cfg.timeout_sec);
        }
        let no_timeout = cfg.timeout_sec == 0.0;
        let timeout_dur = Duration::from_secs_f64(if no_timeout { 1.0 } else { cfg.timeout_sec });
        let max_output_final = effective_output_cap(cfg.max_output_chars);

        // 协调任务 — 转发 chunk 到 outer; wait/timeout 并行; EOF+exit 后发 Done
        let (outer_tx, outer_rx) = mpsc::channel::<StreamEvent>(64);
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
                    _ = tokio::time::sleep(timeout_dur), if !no_timeout => {
                        warn!(?pid, timeout_sec = cfg.timeout_sec, "超时, kill 进程组 (streaming)");
                        let exit = kill_tree(pid);
                        drop(_writer);
                        drop(pair.master);
                        (true, exit)
                    }
                }
            });

            let mut eof_output: Option<String> = None;
            let mut exit_done: Option<(bool, i32)> = None;

            // 阶段 1: exit 与 chunk 并发 — 未收到 exit 前无超时收 chunk
            while exit_done.is_none() {
                tokio::select! {
                    biased; // L-SB-01: exit 优先
                    e = &mut exit_fut => {
                        exit_done = Some(e);
                    }
                    msg = inner_rx.recv() => {
                        match msg {
                            Some(ReaderMsg::Chunk(c)) => {
                                let _ = outer_tx.send(StreamEvent::Chunk { data: c }).await;
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

            // 阶段 2: exit 已到 — 等 reader EOF, C-SB-03 grace 超时防 reader 永不 EOF
            if eof_output.is_none() {
                match tokio::time::timeout(
                    Duration::from_millis(READER_RECV_TIMEOUT_MS),
                    inner_rx.recv(),
                )
                .await
                {
                    Ok(Some(ReaderMsg::Chunk(c))) => {
                        let _ = outer_tx.send(StreamEvent::Chunk { data: c }).await;
                    }
                    Ok(Some(ReaderMsg::Eof(s))) => eof_output = Some(s),
                    Ok(None) => eof_output = Some(String::new()),
                    Err(_) => {
                        warn!(?pid, "streaming kill 后 reader 未 EOF, 合成空 eof");
                        eof_output = Some(String::new());
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
pub fn truncate_output(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if s.chars().count() <= max {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let total = chars.len();
    if max <= HEAD_CHARS + TAIL_CHARS {
        // 极小上限: 只保留尾部
        let keep: String = chars[total.saturating_sub(max)..].iter().collect();
        return keep;
    }
    let head: String = chars[..HEAD_CHARS].iter().collect();
    let tail_start = total - TAIL_CHARS;
    let tail: String = chars[tail_start..].iter().collect();
    let dropped = total - HEAD_CHARS - TAIL_CHARS;
    let out = format!("{}\n[truncated {} chars]\n{}", head, dropped, tail);
    // L-SB-04: head+marker+tail 超 max 时回退 tail-only
    if out.chars().count() > max {
        let keep: String = chars[total.saturating_sub(max)..].iter().collect();
        return keep;
    }
    out
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

    // L-SB-06: timeout=0 无超时, 命令正常完成
    #[test]
    fn run_no_timeout_zero() {
        let mut c = cfg("echo hi");
        c.timeout_sec = 0.0;
        let r = rt().block_on(Sandbox::new().run(c)).unwrap();
        assert!(!r.timed_out);
        assert_eq!(r.exit_code, 0);
        assert!(r.stdout.contains("hi"));
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
}
