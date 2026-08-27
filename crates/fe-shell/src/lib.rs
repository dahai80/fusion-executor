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

use fe_sandbox::{kill_process_group, spawn_pty, SpawnedPty};

/// 尾部输出上限 — 防 OOM (同 fe-sandbox DEFAULT_MAX_OUTPUT/HARD_CEILING 语义)
const TAIL_CAP: usize = 100_000;

/// 注册表上限 — 超 MAX_SHELLS 时自动回收已退 shell (最旧优先), 防长寿命 serve() 内存单调增长
/// pub: M-OPS-05 health 告警阈值需读此值 (fe-ipc probe_health_depth)。
pub const MAX_SHELLS: usize = 256;

/// m-SEC-02: 已退 shell 保留上限 — 每次 shell_start/list_shells 回收超出此数的已退 shell (最旧优先),
/// 防 256 个已退 shell 各 100KB tail 累积 (最坏 25MB)。保留近 MAX_FINISHED_RETAINED 个供调用方查 exit_code。
const MAX_FINISHED_RETAINED: usize = 32;

/// m-SEC-01: 默认空闲超时 (秒) — 无输出超此值的后台 shell 自动 kill (调用方忘 kill 不永跑)。0 = 不限。
pub const DEFAULT_MAX_IDLE_SEC: u64 = 3600;

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
    /// m-SEC-01: 空闲超时 (秒) — 无输出超此值的 shell 自动 kill。0 = 不限 (向后兼容)。
    pub max_idle_sec: u64,
}

struct ShellHandle {
    pid: Option<u32>,
    tail: Arc<Mutex<String>>,
    exit: Arc<OnceLock<i32>>,
    task_id: Option<String>,
    command: String,
    started_at_ms: u128,
    finished: Arc<std::sync::atomic::AtomicBool>,
    /// m-SEC-01: 最近一次输出/启动时间 (ms since epoch)。空闲超时判定 = now - last_output_ms > max_idle_sec*1000。
    last_output_ms: Arc<std::sync::atomic::AtomicU64>,
    /// m-SEC-01: 该 shell 的空闲超时 (秒); 0 = 不限。存 handle 供 list_shells/Drop 无参 expire 判定。
    max_idle_sec: u64,
    // m-PERF-02: 持有 reader/waiter 线程 handle, Drop 时 join 回收 (防 detach 线程泄漏)
    reader_thread: Option<std::thread::JoinHandle<()>>,
    waiter_thread: Option<std::thread::JoinHandle<()>>,
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
        // m-SEC-01: idle 计时起点 = 启动时刻 (无输出也算空闲流逝)
        let started_at_ms = now_ms() as u128;
        let last_output = Arc::new(std::sync::atomic::AtomicU64::new(started_at_ms as u64));
        info!(%shell_id, ?pid, command = %p.command, max_idle_sec = p.max_idle_sec, "后台 shell 已起");

        // reader 线程 — 累积 tail (超 TAIL_CAP 留尾), EOF 时 drop master, 然后 mark finished
        // finished 由 reader 置位 (非 waiter) — 保证 running=false 时 tail 已全部落地, 调用方轮询无末段丢失
        let tail_r = Arc::clone(&tail);
        let finished_r = Arc::clone(&finished);
        // m-SEC-01: 每次输出刷新 last_output_ms, 供 idle-timeout 判定 (now - last_output_ms > max_idle_sec*1000)
        let last_output_r = Arc::clone(&last_output);
        let mut reader = spawned.reader;
        let master = spawned.master;
        let reader_thread = std::thread::spawn(move || {
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
                            // m-SEC-01: 输出到达即刷新 idle 计时
                            last_output_r.store(now_ms(), Ordering::Release);
                            let mut g = match tail_r.lock() {
                                Ok(g) => g,
                                Err(e) => {
                                    warn!(error = %e, "shell reader tail lock poisoned");
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
                        warn!(error = %e, "shell reader read 失败");
                        break;
                    }
                }
            }
            drop(master);
            // EOF: tail 已落地, 置 finished (running=false 必伴随 tail 完整)
            finished_r.store(true, Ordering::Release);
            debug!("shell reader 线程结束 (finished 已置)");
        });

        // waiter 线程 — 仅阻塞 child.wait → 记 exit_code (finished 由 reader 置, 不在此)
        let exit_w = Arc::clone(&exit);
        let child = spawned.child;
        let waiter_thread = std::thread::spawn(move || {
            let mut child = child;
            let status = child.wait();
            let code = match status {
                Ok(s) => s.exit_code() as i32,
                Err(e) => {
                    warn!(error = %e, "shell waiter child.wait 失败");
                    -1
                }
            };
            let _ = exit_w.set(code);
            debug!(
                exit_code = code,
                "shell waiter: 子进程已退 (exit_code 已记)"
            );
        });

        let handle = ShellHandle {
            pid,
            tail: Arc::clone(&tail),
            exit: Arc::clone(&exit),
            task_id: p.task_id,
            command: p.command,
            started_at_ms,
            finished: Arc::clone(&finished),
            last_output_ms: Arc::clone(&last_output),
            max_idle_sec: p.max_idle_sec,
            reader_thread: Some(reader_thread),
            waiter_thread: Some(waiter_thread),
        };
        {
            let mut g = self.shells.lock().unwrap_or_else(|e| e.into_inner());
            // m-SEC-02: 每次注册前回收超 MAX_FINISHED_RETAINED 的已退 shell (不仅超 256 ceiling)
            // m-SEC-01: 空闲超时 shell 自动 kill (idle > max_idle_sec), 逐 shell 判定 (0=不限跳过)
            reap_finished(&mut g);
            expire_idle(&mut g);
            g.insert(shell_id.clone(), handle);
        }
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
        let g = self.shells.lock().unwrap_or_else(|e| e.into_inner());
        let h = g
            .get(shell_id)
            .with_context(|| format!("shell 未找到: {shell_id}"))?;
        let output = match h.tail.lock() {
            Ok(s) => s.clone(),
            Err(e) => {
                warn!(error = %e, %shell_id, "shell_output tail lock poisoned, 返回哨兵标记 (可能丢数据)");
                "\n<lock-poisoned-output-lost>\n".to_string()
            }
        };
        let exit_code = h.exit.get().copied();
        let running = !h.finished.load(Ordering::Acquire);
        Ok(ShellOutput {
            shell_id: shell_id.to_string(),
            output,
            running,
            exit_code,
        })
    }

    /// kill 进程组 — 复用 fe_sandbox::kill_process_group (SIGINT→grace→SIGKILL)
    /// finished 正常由 reader EOF 置位; kill 强制置 finished 防 reader 在死 PTY 上阻塞永挂
    /// (kill 场景调用方期望终止非末段输出, 末段丢失可接受)
    /// reap=false: fe-shell 自管 waiter 线程 child.wait 回收, 避 L-13 双重 waitpid 竞态
    pub fn kill_shell(&self, shell_id: &str) -> Result<bool> {
        let pid = {
            let g = self.shells.lock().unwrap_or_else(|e| e.into_inner());
            let h = g
                .get(shell_id)
                .with_context(|| format!("shell 未找到: {shell_id}"))?;
            h.pid
        };
        let res = kill_process_group(pid, false, 500);
        let exit = res.exit_code;
        let g = self.shells.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = g.get(shell_id) {
            h.finished.store(true, Ordering::Release);
            let _ = h.exit.set(exit);
        }
        info!(%shell_id, ?pid, kill_exit = exit, "kill_shell 完成");
        Ok(true)
    }

    /// 列出全部 shell (含已退) — 回收超 MAX_FINISHED_RETAINED 已退 (最旧优先) + 空闲超时 kill
    pub fn list_shells(&self) -> Vec<ShellInfo> {
        let mut g = self.shells.lock().unwrap_or_else(|e| e.into_inner());
        reap_finished(&mut g);
        expire_idle(&mut g);
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

/// C-OPS-02: ShellRegistry drop 时 kill 所有活跃 shell, 防 serve() 退出孤儿进程泄漏。
/// 进程退出 (signal/crash) 时 registry drop → 遍历 finished==false 的 shell kill_process_group,
/// reader/waiter 线程随 PTY 关闭自然退出。fail-loud: 记录 kill 失败, 不静默吞。
/// reap=false: drop 阶段 waiter 线程随 PTY 关闭速退并回收, 此处仅信号不重复回收。
impl Drop for ShellRegistry {
    fn drop(&mut self) {
        let mut g = self.shells.lock().unwrap_or_else(|e| e.into_inner());
        let active: Vec<(String, Option<u32>)> = g
            .iter()
            .filter(|(_, h)| !h.finished.load(Ordering::Acquire))
            .map(|(id, h)| (id.clone(), h.pid))
            .collect();
        if active.is_empty() {
            return;
        }
        info!(count = active.len(), "ShellRegistry drop: drain 活跃 shell");
        for (shell_id, pid) in active {
            if let Some(pid) = pid {
                let res = kill_process_group(Some(pid), false, 500);
                info!(%shell_id, pid, kill_exit = res.exit_code, "drop drain kill 完成");
            } else {
                warn!(%shell_id, "drop drain: shell 无 pid, 跳过 kill");
            }
        }
        // m-PERF-02: kill 后 join 全部 shell 的 reader/waiter 线程回收 (PTY 关闭后线程速退)
        join_all_threads(&mut g);
    }
}

impl Default for ShellRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// 回收已退 shell (m-SEC-02) — 每次 shell_start/list_shells 触发 (不再仅超 MAX_SHELLS):
/// 1. 超 MAX_SHELLS ceiling 必收 (防无界注册);
/// 2. 已退条目超 MAX_FINISHED_RETAINED 时按 started_at_ms 最旧优先收 (防 256×100KB=25MB tail 累积)。
///
/// 仅移除 finished 且 exit_code 已知的条目 (running=false 尚无 exit_code 过渡态保留, 防 waiter 落后误删)。
fn reap_finished(shells: &mut HashMap<String, ShellHandle>) {
    let finished_count = shells
        .values()
        .filter(|h| h.finished.load(Ordering::Acquire) && h.exit.get().is_some())
        .count();
    if shells.len() <= MAX_SHELLS && finished_count <= MAX_FINISHED_RETAINED {
        return;
    }
    let mut finished: Vec<(String, u128)> = shells
        .iter()
        .filter(|(_, h)| h.finished.load(Ordering::Acquire) && h.exit.get().is_some())
        .map(|(id, h)| (id.clone(), h.started_at_ms))
        .collect();
    if finished.is_empty() {
        return;
    }
    finished.sort_unstable_by_key(|(_, t)| *t);
    // 收到 ceiling 之下且已退保留数 <= MAX_FINISHED_RETAINED: 至少收 (总-上限) 或 (已退-保留)
    let over_ceiling = shells.len().saturating_sub(MAX_SHELLS);
    let over_retained = finished_count.saturating_sub(MAX_FINISHED_RETAINED);
    let remove_count = over_ceiling.max(over_retained);
    for (id, _) in finished.into_iter().take(remove_count) {
        if let Some(mut h) = shells.remove(&id) {
            join_handle_threads(&mut h, &id);
            debug!(%id, "reap_finished: 已退 shell 已回收 (线程已 join)");
        }
    }
}

/// m-SEC-01: 空闲超时回收 — 无输出超 max_idle_sec 的活跃 shell 自动 kill_process_group。
/// 逐 shell 读自身 max_idle_sec (0=不限跳过); 已退 shell 不处理 (reap_finished 负责)。
/// kill 后置 finished + exit(-124 超时惯例), reader 线程随 PTY 关闭速退, 线程 join 在 reap/Drop 阶段。
/// reap=false: waiter 线程自管回收, 避 L-13 双重 waitpid 竞态。
fn expire_idle(shells: &mut HashMap<String, ShellHandle>) {
    let now = now_ms();
    let expired: Vec<String> = shells
        .iter()
        .filter(|(_, h)| {
            if h.finished.load(Ordering::Acquire) || h.max_idle_sec == 0 {
                return false;
            }
            let last = h.last_output_ms.load(Ordering::Acquire);
            now.saturating_sub(last) > h.max_idle_sec * 1000
        })
        .map(|(id, _)| id.clone())
        .collect();
    for id in expired {
        if let Some(h) = shells.get(&id) {
            let pid = h.pid;
            let res = kill_process_group(pid, false, 500);
            let exit = res.exit_code;
            h.finished.store(true, Ordering::Release);
            let _ = h.exit.set(exit);
            warn!(%id, ?pid, max_idle_sec = h.max_idle_sec, kill_exit = exit,
                "m-SEC-01: 空闲超时 shell 已自动 kill (调用方忘 kill 不永跑)");
        }
    }
}

/// m-SEC-01: 当前 ms since epoch (reader 线程刷新 last_output_ms + idle 判定用)
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// m-PERF-02: join 一个 shell 的 reader/waiter 线程回收 (防 detach 线程泄漏)。
/// 已退 shell join 即返; 活跃 shell 调用方应先 kill (PTY 关闭后线程速退)。
fn join_handle_threads(h: &mut ShellHandle, shell_id: &str) {
    if let Some(t) = h.reader_thread.take() {
        if let Err(e) = t.join() {
            warn!(%shell_id, error = ?e, "reader 线程 join 失败 (panic?)");
        }
    }
    if let Some(t) = h.waiter_thread.take() {
        if let Err(e) = t.join() {
            warn!(%shell_id, error = ?e, "waiter 线程 join 失败 (panic?)");
        }
    }
}

/// m-PERF-02: join registry 内全部 shell 线程 (ShellRegistry drop 用)
fn join_all_threads(shells: &mut HashMap<String, ShellHandle>) {
    for (id, h) in shells.iter_mut() {
        join_handle_threads(h, id);
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
            max_idle_sec: 0,
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

    // reader-sets-finished 保证: finished=true 时末段输出已落地, 无末段丢失
    #[test]
    fn finished_implies_final_output_drained() {
        let reg = ShellRegistry::new();
        let id = reg
            .shell_start(params("echo final_marker_xyz", None))
            .shell_id
            .unwrap();
        // 轮询直到 running=false, 然后立即读 output — 末段必须已在
        let mut out = reg.shell_output(&id).unwrap();
        let mut waited = 0;
        while out.running && waited < 2000 {
            std::thread::sleep(Duration::from_millis(50));
            out = reg.shell_output(&id).unwrap();
            waited += 50;
        }
        assert!(!out.running, "应已结束 (waited={}ms)", waited);
        assert!(
            out.output.contains("final_marker_xyz"),
            "finished=true 时末段应已落地: {}",
            out.output
        );
    }

    // 自动回收: 超 MAX_SHELLS 时 list_shells 触发 reap_finished 移除最旧已退 shell
    #[test]
    fn reap_finished_drops_oldest_when_over_ceiling() {
        let reg = ShellRegistry::new();
        // 起超 MAX_SHELLS 个快速退出的 shell, 触发 shell_start 内的 reap
        for _ in 0..(MAX_SHELLS + 10) {
            let _ = reg.shell_start(params("echo x", None)).shell_id.unwrap();
        }
        std::thread::sleep(Duration::from_millis(600));
        // list_shells 再 reap 一次; 总数应回落到 <= MAX_SHELLS
        let list = reg.list_shells();
        assert!(
            list.len() <= MAX_SHELLS,
            "reap 后应 <= {} 条, 实际 {}",
            MAX_SHELLS,
            list.len()
        );
    }

    /// C-OPS-02: ShellRegistry drop 必须 kill 活跃 shell, 防孤儿进程。
    /// 起一个 sleep 长任务, drop registry 后确认子进程不再存活 (kill -0 退出码非 0)。
    #[test]
    fn drop_drains_active_shells() {
        let pid = {
            let reg = ShellRegistry::new();
            let id = reg
                .shell_start(params("python3 -c 'import time; time.sleep(60)'", None))
                .shell_id
                .unwrap();
            std::thread::sleep(Duration::from_millis(300));
            let out = reg.shell_output(&id).unwrap();
            assert!(out.running, "drop 前长任务应仍在跑");
            // pid 在 ShellInfo (list_shells), 不在 ShellOutput
            reg.list_shells()
                .into_iter()
                .find(|i| i.shell_id == id)
                .and_then(|i| i.pid)
                .expect("shell 应有 pid")
        };
        // reg 离作用域 → Drop 触发 kill_tree; 等待 kill 生效
        std::thread::sleep(Duration::from_millis(1500));
        // kill -0 探进程存活: 存活返 exit 0, 不存在返非 0 (无 unsafe, 走子进程)
        let status = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .expect("kill 命令应可执行");
        assert!(
            !status.success(),
            "drop 后子进程 pid={} 应被 kill, kill -0 仍成功 = 孤儿进程",
            pid
        );
    }

    /// m-SEC-01: 空闲超时自动 kill — max_idle_sec=1, 无输出 sleep 30s 任务,
    /// 启动另一 shell 触发 expire_idle, 超时 shell 应被 kill (running=false)。
    /// exit_code 可能是 kill_tree 的 -124 或 waiter 线程 race 先记的信号杀码 (OnceLock first-wins);
    /// 关键断言 = 不再 running (kill 生效), 非具体码值。
    #[test]
    fn msec01_idle_timeout_kills_silent_shell() {
        let reg = ShellRegistry::new();
        let mut p = params("python3 -c 'import time; time.sleep(30)'", None);
        p.max_idle_sec = 1;
        let id = reg.shell_start(p).shell_id.unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let mid = reg.shell_output(&id).unwrap();
        assert!(mid.running, "触发前长任务应仍在跑");
        // 等 idle > 1s, 再起另一 shell 触发 shell_start 内 expire_idle
        std::thread::sleep(Duration::from_millis(1500));
        let _trigger = reg.shell_start(params("echo trigger", None));
        std::thread::sleep(Duration::from_millis(500));
        let out = reg.shell_output(&id).unwrap();
        assert!(
            !out.running,
            "m-SEC-01: 空闲超时 shell 应被自动 kill, 仍 running = {}",
            out.running
        );
    }

    /// m-SEC-01: max_idle_sec=0 (默认) 不限 — 持续输出的 shell 不被 idle 误杀。
    #[test]
    fn msec01_zero_idle_no_kill() {
        let reg = ShellRegistry::new();
        let id = reg
            .shell_start(params("python3 -c 'import time; time.sleep(2)'", None))
            .shell_id
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        // 触发 expire_idle (max_idle_sec=0 → 跳过)
        let _ = reg.list_shells();
        std::thread::sleep(Duration::from_millis(200));
        let out = reg.shell_output(&id).unwrap();
        assert!(out.running, "m-SEC-01: max_idle_sec=0 不应 kill 活跃 shell");
    }

    /// m-SEC-02: 每次 shell_start 回收超 MAX_FINISHED_RETAINED 的已退 shell (不积 25MB)。
    /// 起 MAX_FINISHED_RETAINED+N 个快速退出 shell, 末次 shell_start 后已退数应 <= MAX_FINISHED_RETAINED。
    #[test]
    fn msec02_reap_finished_beyond_retention() {
        let reg = ShellRegistry::new();
        let extra = 10;
        for _ in 0..(MAX_FINISHED_RETAINED + extra) {
            let _ = reg.shell_start(params("echo x", None)).shell_id.unwrap();
        }
        std::thread::sleep(Duration::from_millis(600));
        let list = reg.list_shells();
        let finished_count = list.iter().filter(|i| i.finished).count();
        assert!(
            finished_count <= MAX_FINISHED_RETAINED,
            "m-SEC-02: 已退 shell 应 <= 保留上限 {}, 实际 {}",
            MAX_FINISHED_RETAINED,
            finished_count
        );
    }
}
