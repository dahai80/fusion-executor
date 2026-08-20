// fe-sandbox — PTY 沙箱 (FR-02/03, NFR)
//
// portable-pty 0.8: openpty → spawn(sh -c cmd) → 阻塞 reader 线程 → child.wait
// 超时: tokio::time::timeout 包裹 wait; 触发 → clone_killer().kill() (SIGHUP→SIGKILL)
// 截断: stdout head H=4096 + tail T=8192, 中间折叠 [truncated N chars]
// OOM: 环形缓冲 — 累积超 2*max_output_chars 时只保留 tail
// PTY 合并 stdout+stderr → 全入 stdout (stderr 空; traceback 在 tail 可读)

use std::io::Read;
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const HEAD_CHARS: usize = 4096;
const TAIL_CHARS: usize = 8192;
const DEFAULT_MAX_OUTPUT: usize = 100_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxResult {
    pub exit_code: i32,
    pub stdout: String,
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
        let max_cap = cfg.max_output_chars.saturating_mul(2);
        let mut reader = pair
            .master
            .try_clone_reader()
            .context("try_clone_reader 失败")?;
        let (tx, rx) = std_mpsc::channel::<Result<String>>();
        let _reader_handle = std::thread::spawn(move || {
            // 环形缓冲: 超过 max_cap 时只保留尾部 max_output_chars
            let mut buf = Vec::<u8>::with_capacity(8192);
            let mut tmp = [0u8; 4096];
            loop {
                match reader.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() > max_cap {
                            let keep = buf.len().saturating_sub(cfg.max_output_chars);
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

        // take_writer 持有到子进程结束 — 不送 EOF, 避免 ^D 等控制字符污染输出
        // (本沙箱不提供 stdin; 子进程自行退出)
        let _writer = pair.master.take_writer().context("take_writer 失败")?;

        // wait 阻塞 → spawn_blocking; 超时 → clone_killer kill
        let mut killer = child.clone_killer();
        let wait_fut = tokio::task::spawn_blocking(move || child.wait());
        let timeout_dur = Duration::from_secs_f64(cfg.timeout_sec.max(0.1));
        let sleep = tokio::time::sleep(timeout_dur);

        let (timed_out, raw_exit) = tokio::select! {
            join_res = wait_fut => {
                drop(_writer);
                drop(pair.master);
                let status = join_res.context("wait 线程 panic")?.context("wait 失败")?;
                (false, status.exit_code() as i32)
            }
            _ = sleep => {
                warn!(?pid, timeout_sec = cfg.timeout_sec, "超时, kill 进程组");
                if let Err(e) = killer.kill() {
                    warn!(?pid, "kill 失败: {}", e);
                }
                drop(_writer);
                drop(pair.master);
                (true, -124)
            }
        };

        // 收集 reader 输出 (reader 线程在 child 退出 + master drop 后结束)
        let raw_output = rx
            .recv()
            .unwrap_or_else(|_| Ok(String::new()))
            .unwrap_or_default();

        // PTY ONLCR 把 \n 转 \r\n — 归一化 CRLF→LF (保留程序输出的独立 \r 如进度条)
        let normalized = raw_output.replace("\r\n", "\n");
        let stdout = truncate_output(&normalized, cfg.max_output_chars);
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
        let max_cap = cfg.max_output_chars.saturating_mul(2);
        let mut reader = pair
            .master
            .try_clone_reader()
            .context("try_clone_reader 失败")?;
        enum ReaderMsg {
            Chunk(String),
            Eof(String),
        }
        let (inner_tx, mut inner_rx) = mpsc::channel::<ReaderMsg>(64);
        let max_output_chars = cfg.max_output_chars;
        let _reader_handle = std::thread::spawn(move || {
            let mut buf = Vec::<u8>::with_capacity(8192);
            let mut tmp = [0u8; 4096];
            loop {
                match reader.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = String::from_utf8_lossy(&tmp[..n]).replace("\r\n", "\n");
                        if !chunk.is_empty() {
                            let _ = inner_tx.blocking_send(ReaderMsg::Chunk(chunk));
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() > max_cap {
                            let keep = buf.len().saturating_sub(max_output_chars);
                            buf.drain(0..keep);
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

        let _writer = pair.master.take_writer().context("take_writer 失败")?;
        let mut killer = child.clone_killer();
        let wait_fut = tokio::task::spawn_blocking(move || child.wait());
        let timeout_dur = Duration::from_secs_f64(cfg.timeout_sec.max(0.1));
        let max_output_final = cfg.max_output_chars;

        // 协调任务 — 转发 chunk 到 outer; wait/timeout 并行; EOF+exit 后发 Done
        let (outer_tx, outer_rx) = mpsc::channel::<StreamEvent>(64);
        let handle = tokio::spawn(async move {
            // exit future: wait 或 timeout, 先到者决定 (timed_out, raw_exit)
            let mut exit_fut = Box::pin(async move {
                tokio::select! {
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
                        warn!(?pid, timeout_sec = cfg.timeout_sec, "超时, kill 进程组 (streaming)");
                        if let Err(e) = killer.kill() {
                            warn!(?pid, "kill 失败: {e}");
                        }
                        drop(_writer);
                        drop(pair.master);
                        (true, -124)
                    }
                }
            });

            let mut eof_output: Option<String> = None;
            let mut exit_done: Option<(bool, i32)> = None;

            // 循环: 并发收 chunk + exit; 两者齐备后发 Done
            loop {
                tokio::select! {
                    biased;
                    e = &mut exit_fut, if exit_done.is_none() => {
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
                                // reader 线程结束 (通道关闭)
                            }
                        }
                    }
                }
                if exit_done.is_some() && eof_output.is_some() {
                    break;
                }
                if exit_done.is_some() && inner_rx.is_empty() {
                    continue;
                }
            }

            let (timed_out, raw_exit) = exit_done.unwrap_or((false, -1));
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
pub fn truncate_output(s: &str, max: usize) -> String {
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
    format!("{}\n[truncated {} chars]\n{}", head, dropped, tail)
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
}
