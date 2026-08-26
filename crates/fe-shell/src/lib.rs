// fe-shell — 后台持久 Shell 注册表 (Issue #1, Claude Code run_in_background/BashOutput/KillShell parity)
//
// ShellRegistry = Arc<Mutex<HashMap<shell_id, ShellHandle>>>。shell_start 复用 fe-sandbox::spawn_pty
// (proven env/seatbelt/PTY setup) → 自管 std::thread reader (累积 tail) + std::thread waiter (child.wait)
// shell_output 轮询 tail 快照 + running/exit_code; kill_shell 复用 fe_sandbox::kill_tree; list_shells
// 轮询模型 (poll-only): 不接 BroadcastHub server-push — 后续 issue 再补 live-tail
//
// 安全: fe-shell 不做命令校验 — fe-core 在 shell_start 前用 self.security.validate 拦 (fail-closed)
// fe-shell 仅 spawn allowed 命令。0 新增 unsafe (复用 fe-sandbox safe wrapper + portable-pty)

use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use fe_sandbox::{kill_tree, spawn_pty, SpawnedPty};

/// 尾部输出上限 — 防 OOM (同 fe-sandbox DEFAULT_MAX_OUTPUT/HARD_CEILING 语义)
const TAIL_CAP: usize = 100_000;

/// 后台 shell 启动结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellStartResult {
    pub ok: bool,
    pub shell_id: Option<String>,
    /// fe-core 已校验, 这里恒 false — 保留字段对齐 wire schema
    pub blocked_by_security: bool,
    pub security_reason: Option<String>,
    pub error: Option<String>,
}

/// shell_output 轮询结果 — output = 累积 tail 快照 (非增量; 调用方自去重)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellOutput {
    pub shell_id: String,
    pub output: String,
    pub running: bool,
    pub exit_code: Option<i32>,
}

/// list_shells 条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellInfo {
    pub shell_id: String,
    pub pid: Option<u32>,
    pub task_id: Option<String>,
    pub command: String,
    pub started_at_ms: u128,
    pub finished: bool,
    pub exit_code: Option<i32>,
}

/// shell_start 参数聚合 (fe-core 组装; fe-shell 不接 SecurityGuard)
#[derive(Debug, Clone)]
pub struct ShellStartParams {
    pub command: String,
    pub cwd: Option<String>,
    pub env: std::collections::HashMap<String, String>,
    pub task_id: Option<String>,
    pub max_output_chars: usize,
    pub seatbelt: bool,
    pub inherit_env: bool,
    pub max_nproc: u32,
    pub max_cpu_sec: u32,
}

struct ShellHandle {
    pid: Option<u32>,
    tail: Arc<Mutex<String>>,
    exit: Arc<OnceLock<i32>>,
    task_id: Option<String>,
    command: String,
    started_at_ms: u128,
    finished: Arc<std::sync::atomic::AtomicBool>,
}

pub struct ShellRegistry {
    shells: Mutex<HashMap<String, ShellHandle>>,
    counter: AtomicU64,
}

impl ShellRegistry {
    pub fn new() -> Self {
        info!("ShellRegistry::new()");
        Self {
            shells: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(1),
        }
    }

    /// 启动后台 shell — 复用 fe-sandbox::spawn_pty, 自管 reader + waiter 线程
    pub fn shell_start(&self, p: ShellStartParams) -> ShellStartResult {
        if p.command.trim().is_empty() {
            return ShellStartResult {
                ok: false,
                shell_id: None,
                blocked_by_security: false,
                security_reason: None,
                error: Some("命令为空".to_string()),
            };
        }
        let sb_cfg = fe_sandbox::SandboxConfig {
            command: p.command.clone(),
            cwd: p.cwd.clone(),
            env: p.env,
            timeout_sec: 0.0,
            max_output_chars: p.max_output_chars,
            seatbelt: p.seatbelt,
            inherit_env: p.inherit_env,
            use_pty: true,
            max_nproc: p.max_nproc,
            max_cpu_sec: p.max_cpu_sec,
        };
        let spawned: SpawnedPty = match spawn_pty(&sb_cfg) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, command = %p.command, "shell_start spawn 失败");
                return ShellStartResult {
                    ok: false,
                    shell_id: None,
                    blocked_by_security: false,
                    security_reason: None,
                    error: Some(format!("spawn 失败: {e}")),
                };
            }
        };
        let pid = spawned.pid;
        let shell_id = format!("sh-{}", self.counter.fetch_add(1, Ordering::Relaxed));
        let tail = Arc::new(Mutex::new(String::new()));
        let exit = Arc::new(OnceLock::new());
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        info!(%shell_id, ?pid, command = %p.command, "后台 shell 已起");

        // reader 线程 — 累积 tail (超 TAIL_CAP 留尾), EOF 时 drop master
        let tail_r = Arc::clone(&tail);
        let mut reader = spawned.reader;
        let master = spawned.master;
        std::thread::spawn(move || {
            let mut tmp = [0u8; 4096];
            let mut pending: Vec<u8> = Vec::new();
            loop {
                match reader.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut combined = std::mem::take(&mut pending);
                        combined.extend_from_slice(&tmp[..n]);
                        let safe = utf8_safe_prefix_len(&combined);
                        let decodable = &combined[..safe];
                        pending = combined[safe..].to_vec();
                        let chunk = String::from_utf8_lossy(decodable).replace("\r\n", "\n");
                        if !chunk.is_empty() {
                            let mut g = match tail_r.lock() {
                                Ok(g) => g,
                                Err(e) => {
                                    warn!("shell reader tail lock poisoned: {e}");
                                    break;
                                }
                            };
                            g.push_str(&chunk);
                            if g.len() > TAIL_CAP {
                                let keep = g.len() - TAIL_CAP;
                                g.drain(0..keep);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("shell reader read 失败: {e}");
                        break;
                    }
                }
            }
            drop(master);
            debug!("shell reader 线程结束");
        });

        // waiter 线程 — 阻塞 child.wait → 记 exit_code + finished
        let exit_w = Arc::clone(&exit);
        let finished_w = Arc::clone(&finished);
        let child = spawned.child;
        std::thread::spawn(move || {
            let mut child = child;
            let status = child.wait();
            let code = match status {
                Ok(s) => s.exit_code() as i32,
                Err(e) => {
                    warn!("shell waiter child.wait 失败: {e}");
                    -1
                }
            };
            let _ = exit_w.set(code);
            finished_w.store(true, Ordering::Release);
            debug!(exit_code = code, "shell waiter: 子进程已退");
        });

        let handle = ShellHandle {
            pid,
            tail: Arc::clone(&tail),
            exit: Arc::clone(&exit),
            task_id: p.task_id,
            command: p.command,
            started_at_ms,
            finished: Arc::clone(&finished),
        };
        self.shells.lock().unwrap().insert(shell_id.clone(), handle);
        ShellStartResult {
            ok: true,
            shell_id: Some(shell_id),
            blocked_by_security: false,
            security_reason: None,
            error: None,
        }
    }

    /// 轮询 tail 快照 + 运行/退出状态
    pub fn shell_output(&self, shell_id: &str) -> Result<ShellOutput> {
        let g = self.shells.lock().unwrap();
        let h = g
            .get(shell_id)
            .with_context(|| format!("shell 未找到: {shell_id}"))?;
        let output = h.tail.lock().map(|s| s.clone()).unwrap_or_default();
        let exit_code = h.exit.get().copied();
        let running = !h.finished.load(Ordering::Acquire);
        Ok(ShellOutput {
            shell_id: shell_id.to_string(),
            output,
            running,
            exit_code,
        })
    }

    /// kill 进程树 — 复用 fe_sandbox::kill_tree (SIGINT→grace→SIGKILL)
    pub fn kill_shell(&self, shell_id: &str) -> Result<bool> {
        let pid = {
            let g = self.shells.lock().unwrap();
            let h = g
                .get(shell_id)
                .with_context(|| format!("shell 未找到: {shell_id}"))?;
            h.pid
        };
        let exit = kill_tree(pid);
        // 标记 finished (waiter 线程会重设 exit_code, 这里仅防 running 永真)
        let g = self.shells.lock().unwrap();
        if let Some(h) = g.get(shell_id) {
            h.finished.store(true, Ordering::Release);
            let _ = h.exit.set(exit);
        }
        info!(%shell_id, ?pid, kill_exit = exit, "kill_shell 完成");
        Ok(true)
    }

    /// 列出全部 shell (含已退)
    pub fn list_shells(&self) -> Vec<ShellInfo> {
        let g = self.shells.lock().unwrap();
        g.iter()
            .map(|(id, h)| ShellInfo {
                shell_id: id.clone(),
                pid: h.pid,
                task_id: h.task_id.clone(),
                command: h.command.clone(),
                started_at_ms: h.started_at_ms,
                finished: h.finished.load(Ordering::Acquire),
                exit_code: h.exit.get().copied(),
            })
            .collect()
    }
}

impl Default for ShellRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// 跨块多字节 UTF-8 — 保留尾部不完整字节 (同 fe-sandbox L-SB-02)
fn utf8_safe_prefix_len(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    let n = bytes.len();
    let mut i = n;
    let max_back = n.min(4);
    while i > n - max_back {
        i -= 1;
        let lead = bytes[i];
        if !(0x80..0xC0).contains(&lead) {
            let expected = if lead >= 0xF0 {
                4
            } else if lead >= 0xE0 {
                3
            } else if lead >= 0xC0 {
                2
            } else {
                1
            };
            if n - i >= expected {
                return n;
            }
            return i;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn params(cmd: &str, cwd: Option<String>) -> ShellStartParams {
        ShellStartParams {
            command: cmd.to_string(),
            cwd,
            env: std::collections::HashMap::new(),
            task_id: None,
            max_output_chars: TAIL_CAP,
            seatbelt: false,
            inherit_env: true,
            max_nproc: 0,
            max_cpu_sec: 0,
        }
    }

    #[test]
    fn shell_start_returns_id() {
        let reg = ShellRegistry::new();
        let r = reg.shell_start(params("echo hi", None));
        assert!(r.ok);
        let id = r.shell_id.unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let out = reg.shell_output(&id).unwrap();
        assert!(out.output.contains("hi"), "output: {}", out.output);
    }

    #[test]
    fn shell_output_running_then_finished() {
        let reg = ShellRegistry::new();
        let id = reg.shell_start(params("echo done", None)).shell_id.unwrap();
        std::thread::sleep(Duration::from_millis(800));
        let out = reg.shell_output(&id).unwrap();
        assert!(!out.running, "应已结束");
        assert_eq!(out.exit_code, Some(0));
    }

    #[test]
    fn kill_shell_long_running() {
        let reg = ShellRegistry::new();
        let id = reg
            .shell_start(params("python3 -c 'import time; time.sleep(30)'", None))
            .shell_id
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let mid = reg.shell_output(&id).unwrap();
        assert!(mid.running, "长任务应仍在跑");
        let ok = reg.kill_shell(&id).unwrap();
        assert!(ok);
        std::thread::sleep(Duration::from_millis(800));
        let after = reg.shell_output(&id).unwrap();
        assert!(!after.running, "kill 后应结束");
    }

    #[test]
    fn list_shells_records_all() {
        let reg = ShellRegistry::new();
        let _a = reg.shell_start(params("echo a", None)).shell_id.unwrap();
        let _b = reg.shell_start(params("echo b", None)).shell_id.unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let list = reg.list_shells();
        assert_eq!(list.len(), 2);
        assert!(list.iter().all(|i| i.finished));
    }

    #[test]
    fn shell_output_unknown_id_errors() {
        let reg = ShellRegistry::new();
        assert!(reg.shell_output("sh-999").is_err());
    }

    #[test]
    fn shell_start_empty_command_rejected() {
        let reg = ShellRegistry::new();
        let r = reg.shell_start(params("   ", None));
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("空"));
    }

    #[test]
    fn shell_captures_repeated_output() {
        let reg = ShellRegistry::new();
        let id = reg
            .shell_start(params("python3 -c 'for i in range(5): print(i)'", None))
            .shell_id
            .unwrap();
        std::thread::sleep(Duration::from_millis(800));
        let out = reg.shell_output(&id).unwrap();
        for i in 0..5 {
            assert!(
                out.output.contains(&i.to_string()),
                "缺 {i}: {}",
                out.output
            );
        }
    }

    #[test]
    fn utf8_safe_prefix_len_handles_multibyte() {
        // 完整 3 字节中文字符
        let full = "中".as_bytes();
        assert_eq!(utf8_safe_prefix_len(full), 3);
        // 截断首字节 — 应回退到 0 (留全字符到下块)
        let partial = &"中".as_bytes()[..1];
        assert_eq!(utf8_safe_prefix_len(partial), 0);
    }
}
