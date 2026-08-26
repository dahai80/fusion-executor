// fe-ipc — UDS JSON-RPC 2.0 server (P3) + 双向 server-push (v1.5 #14)
//
// Socket /tmp/fusion-executor.sock (override FUSION_EXECUTOR_SOCK), 换行分隔
// Mirror fusion-cowork/fusion_cowork/server/desk_rpc.py 协议:
//   line = read_line(); 响应 = serde_json::to_string(resp) + "\n"
//   jsonrpc "2.0", id 透传; 错误码 -32700(parse)/-32600(invalid req)/-32601(method)/-32603(internal)
//   扩展: -32010 安全拦截, -32011 超时, -32012 回滚失败, -32013 AX 未授权
// 匹配 fusion-studio IPCClient.swift: 按字节读到 0x0A, 8s 超时
//
// 方法: executor.health/execute/execute_stream/telemetry_stream/snapshot_create/rollback/gui_action/diagnostics
//       executor.file_edit/glob/grep/apply_patch/replace_function/shutdown
//       executor.subscribe/unsubscribe  (v1.5 #14 — 双向 server-push)
//
// v1.5 #14 双向 server-push (PRD §5 — fusion-studio 120Hz 看板广播):
//   连接 DUPLEX: read_task (分发请求) + push_task (写 server-push 帧) 共享 writer (Arc<Mutex>)。
//   subscribe {channels:["telemetry"|"stdio"|"screenshot"], interval_ms?:100, screenshot_interval_ms?:1000}
//     → 响应 {ok:true, subscription_id:"sub-N"}; 之后 server 持续推 notification 帧:
//       {"jsonrpc":"2.0","method":"executor.event","params":{"subscription_id":..,"channel":..,"data":..}}
//     notification 无 id (JSON-RPC notification 约定), 客户端按有无 id 区分响应 vs 推送。
//   通道源 (hub 内 lazy 启停, 0 订阅自退):
//     telemetry — 单一 executor.telemetry_stream 扇出给所有 telemetry 订阅 (10Hz 默认)。
//     screenshot — 周期 executor.gui_action(Screenshot), TCC 未授权 → 帧 data.ok=false 不崩。
//     stdio — execute/execute_stream 处理器扇出 chunk/done, 按 per-sub scope 过滤 (Blocker 10, 默认 own_conn)。
//   unsubscribe {subscription_id} → 停该订阅; 连接断开 → 清该连接所有订阅。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Semaphore};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use fe_core::gui::GuiAction;
use fe_core::TelemetryStreamConfig;
use fe_core::{Diagnostics, ExecutionRequest, ExecutionResult, Executor};

pub mod logging;

/// 默认 socket 目录 — M-SEC-01: 私有 0o700 目录 (非全局可扫描 /tmp)。
/// 同主机他 UID 无法进入该目录 → 无法 connect socket, 阻跨 UID 越权。
/// 仍可经 FUSION_EXECUTOR_SOCK 覆盖回 /tmp (用户显式 opt-in, 自担风险)。
pub const DEFAULT_SOCK_DIR: &str = ".fusion-executor";
pub const DEFAULT_SOCK_NAME: &str = "fe.sock";

/// 解析默认 socket 路径 — ~/.fusion-executor/fe.sock (HOME 下私有目录)。
/// HOME 缺失时回退 /tmp/fusion-executor.sock (退化为旧路径, 仅 chmod 0o600)。
fn default_sock_path() -> String {
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => {
            let mut p = PathBuf::from(h);
            p.push(DEFAULT_SOCK_DIR);
            p.push(DEFAULT_SOCK_NAME);
            p.to_string_lossy().into_owned()
        }
        _ => "/tmp/fusion-executor.sock".to_string(),
    }
}

/// JSON-RPC 错误码
const ERR_PARSE: i64 = -32700;
const ERR_INVALID_REQ: i64 = -32600;
const ERR_METHOD_NOT_FOUND: i64 = -32601;
const ERR_INTERNAL: i64 = -32603;

/// 通道名常量
const CH_TELEMETRY: &str = "telemetry";
const CH_STDIO: &str = "stdio";
const CH_SCREENSHOT: &str = "screenshot";

/// 默认采样间隔
const DEFAULT_INTERVAL_MS: u64 = 100;
const DEFAULT_SCREENSHOT_INTERVAL_MS: u64 = 1000;

/// 单行 JSON-RPC 请求上限 (1MB) — 防 10GB 无换行 OOM (C-IPC-04)
const MAX_LINE_BYTES: usize = 1024 * 1024;
/// 并发连接上限 — 防 accept 无限累积 DoS (C-IPC-05)
const MAX_CONNECTIONS: usize = 64;
/// 审计 2.11: 并发 **执行** 上限 — 连接信号量限连接非限执行 (64 连接各跑 cargo build = 64 并发子进程超额)。
/// 独立执行信号量限真实子进程并发, 与连接数解耦。8 核机 16 并发重命令留 2x 余量。
const MAX_CONCURRENT_EXECS: usize = 16;
/// 单连接 idle 读超时 — 防 slowloris 占连接不读 (C-IPC-05)
const IDLE_READ_TIMEOUT_SECS: u64 = 30;
/// 截图 b64 帧上限 (4MB) — 超此降级去 png_b64 防 N 订阅内存堆积 (P-IPC-03)
const MAX_SCREENSHOT_B64_BYTES: usize = 4 * 1024 * 1024;
/// C-OPS-03: 优雅 drain 默认截止 — join in-flight 连接 10s, 超时 abort 剩余 (强制停, 防挂死)。
/// M-OPS-03: 运行时可经 FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS 覆盖 (1..=300s, 越界回退此默认)。
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

/// M-OPS-03: 解析优雅 drain 超时 — env `FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS` 覆盖默认 10s。
/// 合法区间 1..=300 (秒): 过短误杀 in-flight, 过长拖延停机。越界/非数字 → 回退默认, fail-loud warn。
fn resolve_shutdown_timeout() -> Duration {
    parse_shutdown_timeout(std::env::var("FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS").ok())
}

/// M-OPS-03: 纯函数解析 (无 env 副作用, 可单测) — env 值 → Duration。
fn parse_shutdown_timeout(raw: Option<String>) -> Duration {
    match raw {
        Some(v) => match v.trim().parse::<u64>() {
            Ok(secs) if (1..=300).contains(&secs) => {
                info!(secs, "M-OPS-03: shutdown drain 超时 env 覆盖");
                Duration::from_secs(secs)
            }
            Ok(secs) => {
                warn!(
                    secs,
                    "M-OPS-03: shutdown 超时越界 (须 1..=300), 回退默认 10s"
                );
                SHUTDOWN_DEADLINE
            }
            Err(e) => {
                warn!(raw = %v, error = %e, "M-OPS-03: shutdown 超时非数字, 回退默认 10s");
                SHUTDOWN_DEADLINE
            }
        },
        None => SHUTDOWN_DEADLINE,
    }
}

/// stdio 订阅作用域 (审计 2.9 / Blocker 10) — per-sub 过滤防跨租户泄漏。
/// 默认 OwnConn: 仅收本连接发起命令的 stdio (多租户隔离基线)。
/// All: 收全部 (向后兼容 dashboard 场景, 显式 opt-in)。
/// Tasks: 仅收白名单 task_id 的 stdio (跨连接精确订阅)。
#[derive(Clone)]
enum StdioScope {
    All,
    OwnConn(u64),
    Tasks(HashSet<String>),
}

impl StdioScope {
    /// 命令 (task_id + 发起连接 conn_id) 是否落本作用域。
    /// source_conn = 命令发起连接 conn_id; scope 内 OwnConn 存订阅者自身 conn_id。
    fn allows(&self, task_id: Option<&str>, source_conn: u64) -> bool {
        match self {
            StdioScope::All => true,
            StdioScope::OwnConn(c) => *c == source_conn,
            StdioScope::Tasks(set) => task_id.map(|t| set.contains(t)).unwrap_or(false),
        }
    }
}

/// 订阅者 — 一条连接可能持多个订阅, 共享该连接的 push tx
struct Subscriber {
    conn_id: u64,
    channels: HashSet<String>,
    scope: StdioScope,
    tx: mpsc::Sender<Value>,
}

/// 广播中心 (v1.5 #14) — Arc 共享给 accept_loop/handle_conn/源任务。
/// registry: sub_id → Subscriber。源任务 lazy 启停: 0 订阅自退, 下次 subscribe 重启。
/// C-OPS-04: shutdown Notify — executor.shutdown IPC 触发, accept_loop 监听 → 优雅 drain。
/// C-OPS-05: 运维指标 — AtomicU64 计数 (exec_total/blocked/timeout/success/failed, rollback) +
///   duration/stdio 累加器 (无锁, 调用方读 snapshot 算均值)。无直方图存储 (内存预算), 聚合够运维。
struct BroadcastHub {
    registry: Mutex<HashMap<String, Subscriber>>,
    executor: Arc<Executor>,
    conn_counter: AtomicU64,
    /// M-OPS-04: 活跃连接计数 — handle_conn 入口 fetch_add, drop_conn fetch_sub。无锁, health 读快照。
    active_conns: AtomicU64,
    sub_counter: AtomicU64,
    telemetry_task: Mutex<Option<JoinHandle<()>>>,
    screenshot_task: Mutex<Option<JoinHandle<()>>>,
    shutdown: Arc<tokio::sync::Notify>,
    // C-OPS-05 指标
    exec_total: AtomicU64,
    exec_blocked: AtomicU64,
    exec_timeout: AtomicU64,
    exec_success: AtomicU64,
    exec_failed: AtomicU64,
    rollback_total: AtomicU64,
    rollback_failed: AtomicU64,
    /// execute 累计墙钟 (ns) + stdio 累计字节 — 配合 exec_total 算均值
    exec_duration_nanos_sum: AtomicU64,
    stdio_bytes_sum: AtomicU64,
}

impl BroadcastHub {
    fn new(executor: Arc<Executor>) -> Arc<Self> {
        Arc::new(Self {
            registry: Mutex::new(HashMap::new()),
            executor,
            conn_counter: AtomicU64::new(1),
            active_conns: AtomicU64::new(0),
            sub_counter: AtomicU64::new(1),
            telemetry_task: Mutex::new(None),
            screenshot_task: Mutex::new(None),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            exec_total: AtomicU64::new(0),
            exec_blocked: AtomicU64::new(0),
            exec_timeout: AtomicU64::new(0),
            exec_success: AtomicU64::new(0),
            exec_failed: AtomicU64::new(0),
            rollback_total: AtomicU64::new(0),
            rollback_failed: AtomicU64::new(0),
            exec_duration_nanos_sum: AtomicU64::new(0),
            stdio_bytes_sum: AtomicU64::new(0),
        })
    }

    /// C-OPS-05: 记一次 execute 结果 → 原子累加指标。
    /// exit_code 0=success, -124=timeout, -1=blocked/internal, 其他=failed。
    fn record_exec(&self, r: &ExecutionResult) {
        self.exec_total.fetch_add(1, Ordering::Relaxed);
        if r.blocked_by_security {
            self.exec_blocked.fetch_add(1, Ordering::Relaxed);
        } else if r.timed_out || r.exit_code == -124 {
            self.exec_timeout.fetch_add(1, Ordering::Relaxed);
        } else if r.exit_code == 0 {
            self.exec_success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.exec_failed.fetch_add(1, Ordering::Relaxed);
        }
        // 墙钟 (duration_sec 秒 → ns; f64 截断到 u64 纳秒, 累加溢出极不可能 — u64 ns ≈ 584 年)
        let dur_ns = (r.duration_sec.max(0.0) * 1e9) as u64;
        self.exec_duration_nanos_sum
            .fetch_add(dur_ns, Ordering::Relaxed);
        // stdio 字节 (stdout+stderr 截断后长度 — 真实传输量)
        let bytes = (r.stdout.len() + r.stderr.len()) as u64;
        self.stdio_bytes_sum.fetch_add(bytes, Ordering::Relaxed);
    }

    /// C-OPS-05: 记一次 rollback — ok=true 算 total, false 算 total+failed
    fn record_rollback(&self, ok: bool) {
        self.rollback_total.fetch_add(1, Ordering::Relaxed);
        if !ok {
            self.rollback_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// C-OPS-05: 指标快照 — 转为 JSON 给 executor.metrics handler。
    /// 均值用 exec_total 算 (blocked/timeout 不计 duration — 它们 duration_sec=0)。
    fn metrics_snapshot(&self) -> Value {
        let total = self.exec_total.load(Ordering::Relaxed);
        let dur_ns_sum = self.exec_duration_nanos_sum.load(Ordering::Relaxed);
        let stdio_sum = self.stdio_bytes_sum.load(Ordering::Relaxed);
        let avg_dur_sec = if total > 0 {
            (dur_ns_sum as f64) / 1e9 / (total as f64)
        } else {
            0.0
        };
        let avg_stdio_bytes = stdio_sum.checked_div(total).unwrap_or(0);
        json!({
            "exec_total": total,
            "exec_success": self.exec_success.load(Ordering::Relaxed),
            "exec_blocked": self.exec_blocked.load(Ordering::Relaxed),
            "exec_timeout": self.exec_timeout.load(Ordering::Relaxed),
            "exec_failed": self.exec_failed.load(Ordering::Relaxed),
            "execute_duration_sec_avg": avg_dur_sec,
            "stdio_bytes_total": stdio_sum,
            "stdio_bytes_avg": avg_stdio_bytes,
            "rollback_total": self.rollback_total.load(Ordering::Relaxed),
            "rollback_failed": self.rollback_failed.load(Ordering::Relaxed),
        })
    }

    fn next_conn_id(&self) -> u64 {
        self.conn_counter.fetch_add(1, Ordering::Relaxed)
    }

    fn next_sub_id(&self) -> String {
        format!("sub-{}", self.sub_counter.fetch_add(1, Ordering::Relaxed))
    }

    /// 注册订阅 — 返回 subscription_id。channels 去重存小写。
    /// scope = stdio 作用域 (Blocker 10); interval_ms/screenshot_interval_ms 透传源任务 (M-IPC-01)。
    fn subscribe(
        self: &Arc<Self>,
        conn_id: u64,
        channels: HashSet<String>,
        scope: StdioScope,
        tx: mpsc::Sender<Value>,
        interval_ms: u64,
        screenshot_interval_ms: u64,
    ) -> String {
        let sub_id = self.next_sub_id();
        let has_telemetry = channels.contains(CH_TELEMETRY);
        let has_screenshot = channels.contains(CH_SCREENSHOT);
        {
            let mut reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
            reg.insert(
                sub_id.clone(),
                Subscriber {
                    conn_id,
                    channels,
                    scope,
                    tx,
                },
            );
        }
        info!(%sub_id, conn_id, "订阅注册");
        if has_telemetry {
            self.ensure_telemetry_source(interval_ms);
        }
        if has_screenshot {
            self.ensure_screenshot_source(screenshot_interval_ms);
        }
        sub_id
    }

    /// 取消订阅 — 返回是否找到并移除
    fn unsubscribe(&self, sub_id: &str) -> bool {
        let removed = self
            .registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sub_id)
            .is_some();
        if removed {
            info!(%sub_id, "订阅取消");
        }
        removed
    }

    /// 连接断开 — 清该连接所有订阅
    fn drop_conn(&self, conn_id: u64) {
        self.active_conns.fetch_sub(1, Ordering::Relaxed);
        let mut reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let before = reg.len();
        reg.retain(|_, s| s.conn_id != conn_id);
        let dropped = before - reg.len();
        if dropped > 0 {
            info!(conn_id, dropped, "连接断开, 清理订阅");
        }
    }

    /// 确保遥测源任务运行 — handle 不在或已结束 (含 panic) 则启动 (C-IPC-02/03)。
    /// 源任务 0 telemetry 订阅自退并清 handle; panic 后 handle.is_finished()=true 触发重启。
    /// interval_ms 由调用方传入 (M-IPC-01), 缺省 DEFAULT_INTERVAL_MS。
    fn ensure_telemetry_source(self: &Arc<Self>, interval_ms: u64) {
        let mut slot = self
            .telemetry_task
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if slot.as_ref().is_some_and(|h| !h.is_finished()) {
            return;
        }
        let effective = if interval_ms == 0 {
            DEFAULT_INTERVAL_MS
        } else {
            interval_ms
        };
        let hub = self.clone();
        let handle = tokio::spawn(async move {
            hub.run_telemetry_source(effective).await;
            hub.telemetry_task
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        });
        *slot = Some(handle);
        info!(interval_ms = effective, "遥测源任务启动");
    }

    /// 确保截图源任务运行 — 同 telemetry 逻辑 (C-IPC-02/03)。
    /// screenshot_interval_ms 由调用方传入 (M-IPC-01)。
    fn ensure_screenshot_source(self: &Arc<Self>, screenshot_interval_ms: u64) {
        let mut slot = self
            .screenshot_task
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if slot.as_ref().is_some_and(|h| !h.is_finished()) {
            return;
        }
        let effective = if screenshot_interval_ms == 0 {
            DEFAULT_SCREENSHOT_INTERVAL_MS
        } else {
            screenshot_interval_ms
        };
        let hub = self.clone();
        let handle = tokio::spawn(async move {
            hub.run_screenshot_source(effective).await;
            hub.screenshot_task
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        });
        *slot = Some(handle);
        info!(interval_ms = effective, "截图源任务启动");
    }

    /// 遥测源 — executor.telemetry_stream 单流扇出, 0 订阅自退。
    async fn run_telemetry_source(&self, interval_ms: u64) {
        let cfg = TelemetryStreamConfig {
            interval_ms,
            max_samples: 0,
        };
        let (mut rx, handle) = self.executor.telemetry_stream(cfg);
        while let Some(sample) = rx.recv().await {
            let targets = self.collect_targets(CH_TELEMETRY);
            if targets.is_empty() {
                info!("遥测 0 订阅, 源任务自退");
                break;
            }
            let data = serde_json::to_value(&sample).unwrap_or(json!({}));
            for (sub_id, _scope, tx) in targets {
                let frame = notification(sub_id.clone(), CH_TELEMETRY, data.clone());
                if tx.try_send(frame).is_err() {
                    warn!(%sub_id, "遥测帧满通道被丢 (P-IPC-01)");
                }
            }
        }
        drop(rx);
        let _ = handle.await;
    }

    /// 截图源 — 周期 gui_action(Screenshot) 扇出, TCC 未授权帧 data.ok=false 不崩。0 订阅自退。
    async fn run_screenshot_source(&self, interval_ms: u64) {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
        interval.tick().await;
        loop {
            interval.tick().await;
            let targets = self.collect_targets(CH_SCREENSHOT);
            if targets.is_empty() {
                info!("截图 0 订阅, 源任务自退");
                break;
            }
            let executor = self.executor.clone();
            let shot =
                tokio::task::spawn_blocking(move || executor.gui_action(GuiAction::Screenshot {}))
                    .await;
            let data = match shot {
                Ok(Ok(r)) => {
                    let val = serde_json::to_value(&r).unwrap_or(json!({"ok": false}));
                    // P-IPC-03: 大帧 (含 PNG b64) 扇出 N 订阅会无界占内存。
                    // 超 4MB 降级为元数据帧 (去 png_b64), 避免慢消费方堆积。
                    if val
                        .get("screenshot_png_b64")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| s.len() > MAX_SCREENSHOT_B64_BYTES)
                    {
                        warn!(
                            b64_len = val
                                .get("screenshot_png_b64")
                                .and_then(|v| v.as_str())
                                .map(|s| s.len())
                                .unwrap_or(0),
                            "截图帧超 {} 字节, 降级去 png_b64 (P-IPC-03)", MAX_SCREENSHOT_B64_BYTES
                        );
                        let mut lite = val.clone();
                        if let Some(obj) = lite.as_object_mut() {
                            obj.remove("screenshot_png_b64");
                            obj.insert("screenshot_dropped".to_string(), json!(true));
                        }
                        lite
                    } else {
                        val
                    }
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "截图源 gui_action 失败");
                    json!({"ok": false, "error": format!("screenshot 失败: {e}")})
                }
                Err(e) => {
                    warn!(error = %e, "截图源 spawn_blocking 失败");
                    json!({"ok": false, "error": format!("screenshot 任务失败: {e}")})
                }
            };
            for (sub_id, _scope, tx) in targets {
                let frame = notification(sub_id.clone(), CH_SCREENSHOT, data.clone());
                if tx.try_send(frame).is_err() {
                    warn!(%sub_id, "截图帧满通道被丢 (P-IPC-01)");
                }
            }
        }
    }

    /// 收集某通道所有 (sub_id, tx, scope) — 锁内快照, 锁外发送
    fn collect_targets(&self, channel: &str) -> Vec<(String, StdioScope, mpsc::Sender<Value>)> {
        let reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        reg.iter()
            .filter(|(_, s)| s.channels.contains(channel))
            .map(|(id, s)| (id.clone(), s.scope.clone(), s.tx.clone()))
            .collect()
    }

    /// stdio 广播 — execute/execute_stream 处理器调, 扇出给**通过 scope 过滤**的 stdio 订阅。
    /// source_conn = 发起该命令的连接 conn_id (OwnConn 过滤用); data 含 task_id (Tasks 过滤用)。
    /// Blocker 10 (审计 2.9): 旧版无过滤全广播 = 跨租户泄漏 (Agent A 见 Agent B stdout)。
    fn broadcast_stdio(&self, data: Value, source_conn: u64) {
        let task_id = data
            .get("task_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let targets = self.collect_targets(CH_STDIO);
        for (sub_id, scope, tx) in targets {
            if !scope.allows(task_id.as_deref(), source_conn) {
                continue;
            }
            let frame = notification(sub_id.clone(), CH_STDIO, data.clone());
            if tx.try_send(frame).is_err() {
                warn!(%sub_id, "stdio 帧满通道被丢 (P-IPC-01)");
            }
        }
    }
}

/// 构造 server-push notification Value。
/// 无 id — JSON-RPC notification 约定 (M-IPC-02): 客户端按有无 id 区分响应 vs 推送。
/// spec 合规; 隐性契约 = 客户端必须实现此区分, 文档已注明。
fn notification(sub_id: String, channel: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "executor.event",
        "params": {
            "subscription_id": sub_id,
            "channel": channel,
            "data": data,
        }
    })
}

/// IPC 服务器 — 持有 Arc<Executor> + Arc<BroadcastHub> + Arc<ShellRegistry>,
/// 换行分隔 JSON-RPC 2.0 over UDS。
/// M-ARCH-1: ShellRegistry 移此层 (与 BroadcastHub 并列) — Executor 保持 per-task 无状态;
/// IPC 层重启 Executor 不丢后台 shell 句柄; serve-path 与 in-process path 可共享同一 registry。
pub struct IpcServer {
    executor: Arc<Executor>,
    hub: Arc<BroadcastHub>,
    shells: Arc<fe_core::shell::ShellRegistry>,
}

impl IpcServer {
    pub fn new() -> Self {
        info!("IpcServer::new() — 持有 Executor + BroadcastHub + ShellRegistry");
        let executor = Arc::new(Executor::new());
        let hub = BroadcastHub::new(executor.clone());
        let shells = Arc::new(fe_core::shell::ShellRegistry::new());
        Self {
            executor,
            hub,
            shells,
        }
    }

    pub fn with_executor(executor: Executor) -> Self {
        info!("IpcServer::with_executor()");
        let executor = Arc::new(executor);
        let hub = BroadcastHub::new(executor.clone());
        let shells = Arc::new(fe_core::shell::ShellRegistry::new());
        Self {
            executor,
            hub,
            shells,
        }
    }

    /// M-ARCH-1: 共享调用方已持有的 registry — fe-pyo3 serve() 与 in-process path 见同一批 shell。
    pub fn with_executor_and_shells(
        executor: Executor,
        shells: Arc<fe_core::shell::ShellRegistry>,
    ) -> Self {
        info!("IpcServer::with_executor_and_shells() — 共享 ShellRegistry");
        let executor = Arc::new(executor);
        let hub = BroadcastHub::new(executor.clone());
        Self {
            executor,
            hub,
            shells,
        }
    }

    /// M-ARCH-1: 暴露 registry 引用 (health probe / dispatch 取用)。
    pub fn shells(&self) -> &Arc<fe_core::shell::ShellRegistry> {
        &self.shells
    }

    /// 解析 socket 路径 — 参数覆盖 > 环境变量 FUSION_EXECUTOR_SOCK > 默认
    pub fn resolve_sock(override_path: Option<&str>) -> String {
        if let Some(p) = override_path {
            if !p.is_empty() {
                return p.to_string();
            }
        }
        std::env::var("FUSION_EXECUTOR_SOCK").unwrap_or_else(|_| default_sock_path())
    }

    /// 异步 serve — bind + unlink 旧 sock + chmod 0o600 + accept 循环
    /// 返回 (shutdown_tx, join_handle): 调用方发 shutdown_tx 触发优雅退出, 可 await join 等待清理
    pub async fn serve(
        &self,
        sock_path: &str,
    ) -> Result<(oneshot::Sender<()>, tokio::task::JoinHandle<()>)> {
        let path = Path::new(sock_path).to_path_buf();
        if path.exists() {
            info!(sock = %path.display(), "清理旧 socket");
            let _ = std::fs::remove_file(&path);
        }
        ensure_sock_dir(&path);
        let listener = UnixListener::bind(&path)
            .map_err(|e| anyhow::anyhow!("bind {} 失败: {}", path.display(), e))?;
        chmod_secure(&path);
        info!(sock = %path.display(), "IPC 服务器监听中");
        // C-SEC-02: seatbelt 治理 — 默认 false, 生产环境须调用方透传 seatbelt:true 启运行时隔离。
        warn!(
            "⚠️ seatbelt 默认关闭 — 子进程无 macOS sandbox-exec 隔离 (禁网/execve deny 均未启)。生产部署须在 ExecutionRequest 透传 seatbelt:true。查 health.seatbelt_default_off"
        );

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let executor = self.executor.clone();
        let hub = self.hub.clone();
        let shells = self.shells.clone();
        // M-OPS-03: 运行时可配 drain 超时 (env, 默认 10s)。
        let drain_deadline = resolve_shutdown_timeout();
        let join = tokio::spawn(async move {
            accept_loop(listener, executor, hub, shells, shutdown_rx, drain_deadline).await;
            let _ = std::fs::remove_file(&path);
        });
        Ok((shutdown_tx, join))
    }

    /// 同步阻塞 serve — 供 PyO3 serve() 直接调用 (走 BLOCKING_RT)
    /// C-PYO3-02: serve_blocking 持 GIL 时 Python 信号 handler 不执行 (主线程阻在
    /// Rust block_on) → SIGTERM 无法中断。改 Rust 侧 tokio::signal 监听 SIGINT/SIGTERM。
    /// C-OPS-03: 信号不 select-丢弃 accept_loop (否则 drain 不跑, 孤儿连接)。改为
    /// 信号任务收信号后 hub.shutdown.notify_waiters(), accept_loop 自身监听该 Notify
    /// 退出并 drain in-flight 连接 (join_all 10s deadline)。PyO3 serve() 须 py.detach 释 GIL。
    pub fn serve_blocking(&self, sock_path: &str) -> Result<()> {
        let path = sock_path.to_string();
        let executor = self.executor.clone();
        let hub = self.hub.clone();
        let shells = self.shells.clone();
        fe_core::BLOCKING_RT.block_on(async move {
            let p = Path::new(&path).to_path_buf();
            if p.exists() {
                let _ = std::fs::remove_file(&p);
            }
            ensure_sock_dir(&p);
            let listener = UnixListener::bind(&p)
                .map_err(|e| anyhow::anyhow!("bind {} 失败: {}", p.display(), e))?;
            chmod_secure(&p);
            info!(sock = %p.display(), "IPC 服务器监听中 (blocking, 信号可停)");
            // C-SEC-02: seatbelt 治理 — 默认 false, 生产环境须调用方透传 seatbelt:true 启运行时隔离。
            warn!(
                "⚠️ seatbelt 默认关闭 — 子进程无 macOS sandbox-exec 隔离 (禁网/execve deny 均未启)。生产部署须在 ExecutionRequest 透传 seatbelt:true。查 health.seatbelt_default_off"
            );
            let (_tx, rx) = oneshot::channel::<()>();
            // 信号任务: 收 SIGINT/SIGTERM → notify_waiters, accept_loop 自行退出并 drain
            let signal_task = tokio::spawn(wait_signal_and_notify(hub.clone()));
            // M-OPS-03: 运行时可配 drain 超时 (env, 默认 10s)。
            let drain_deadline = resolve_shutdown_timeout();
            // accept_loop 运行至 shutdown_notify (信号) 或 shutdown_rx 触发, 内部 drain in-flight
            accept_loop(listener, executor, hub, shells, rx, drain_deadline).await;
            signal_task.abort();
            let _ = std::fs::remove_file(&p);
            Ok(())
        })
    }
}

/// C-OPS-03/04: 阻塞至 SIGINT/SIGTERM, 然后触发 hub.shutdown.notify_waiters()。
/// accept_loop 监听该 Notify → 退出 accept 并 drain in-flight 连接 (不被 select 丢弃)。
async fn wait_signal_and_notify(hub: Arc<BroadcastHub>) {
    #[cfg(unix)]
    {
        let sigint = tokio::signal::ctrl_c();
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    biased;
                    _ = sigint => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(e) => {
                warn!(error = %e, "SIGTERM 注册失败, 仅监听 SIGINT");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    info!("收到 SIGINT/SIGTERM, 触发优雅 drain");
    hub.shutdown.notify_waiters();
}

impl Default for IpcServer {
    fn default() -> Self {
        Self::new()
    }
}

/// accept 循环 — 收到 shutdown 信号 (oneshot 编程式 或 IPC Notify) 或 listener 关闭则退出。
/// C-OPS-03: 收集 handle_conn JoinHandle, 退出后 drain (join_all 带 deadline 超时, 超时 abort)。
/// M-OPS-03: deadline 由调用方传入 (FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS, 默认 10s)。
/// 并发连接受 MAX_CONNECTIONS 信号量限制 (C-IPC-05)。
async fn accept_loop(
    listener: UnixListener,
    executor: Arc<Executor>,
    hub: Arc<BroadcastHub>,
    shells: Arc<fe_core::shell::ShellRegistry>,
    mut shutdown_rx: oneshot::Receiver<()>,
    drain_deadline: Duration,
) {
    let sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    // 审计 2.11: 执行信号量 — 限并发 **执行** (子进程) 非并发连接。全 server 共享, 与连接信号量解耦。
    let exec_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_EXECS));
    // C-OPS-03: in-flight 连接 JoinHandle 收集 — drain 时 join_all + deadline
    let conns: Arc<AsyncMutex<Vec<JoinHandle<()>>>> = Arc::new(AsyncMutex::new(Vec::new()));
    let shutdown_notify = hub.shutdown.clone();
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown_rx => {
                info!("shutdown (oneshot) 收到, 停止 accept");
                break;
            }
            _ = shutdown_notify.notified() => {
                info!("shutdown (IPC Notify) 收到, 停止 accept");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        // M-SEC-01: LOCAL_PEERCRED UID 校验 — 他 UID 立即拒, 不占信号量不跑 handler。
                        if !peer_uid_matches(&stream) {
                            continue;
                        }
                        // 连接数上限 — 信号量满则拒连 (C-IPC-05)
                        let permit = match sem.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(e) => {
                                warn!(error = %e, "信号量已关闭, 停止 accept");
                                break;
                            }
                        };
                        let ex = executor.clone();
                        let h = hub.clone();
                        let sh = shells.clone();
                        let es = exec_sem.clone();
                        let handle = tokio::spawn(async move {
                            handle_conn(stream, ex, h, sh, es).await;
                            drop(permit);
                        });
                        conns.lock().await.push(handle);
                    }
                    Err(e) => warn!(error = %e, "accept 失败"),
                }
            }
        }
    }
    // C-OPS-03: drain in-flight 连接 — join_all 带 deadline, 超时 abort 剩余
    drain_connections(conns, drain_deadline).await;
}

/// C-OPS-03/M-OPS-03: 优雅 drain — join 所有 in-flight 连接, deadline 内未完则 abort。
/// deadline 由 serve/serve_blocking 从 FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS 解析 (默认 10s)。
/// 完成的移出, 超时的 abort (强制停, 防孤儿响应/子进程挂死)。fail-loud 记 abort 数。
async fn drain_connections(conns: Arc<AsyncMutex<Vec<JoinHandle<()>>>>, deadline: Duration) {
    let mut handles = conns.lock().await;
    let total = handles.len();
    if total == 0 {
        return;
    }
    info!(
        in_flight = total,
        deadline_secs = deadline.as_secs(),
        "drain in-flight 连接"
    );
    // join_all 带超时: 超时则 abort 剩余未完成的
    let join_all = async {
        let mut remaining = Vec::new();
        for h in handles.drain(..) {
            remaining.push(h);
        }
        let mut joined_ok = 0usize;
        for mut h in remaining {
            if h.is_finished() {
                let _ = h.await;
                joined_ok += 1;
            } else {
                match tokio::time::timeout(deadline, &mut h).await {
                    Ok(Ok(())) => joined_ok += 1,
                    Ok(Err(e)) => warn!(error = %e, "连接 task join 失败"),
                    Err(_) => {
                        warn!("连接 drain 超时, abort (强制停)");
                        h.abort();
                    }
                }
            }
        }
        joined_ok
    };
    let ok = join_all.await;
    info!(in_flight = total, drained_ok = ok, "drain 完成");
}

/// 单连接处理 — DUPLEX (v1.5 #14):
///   read_task: read_line 分发请求, 响应/流式帧写 locked writer
///   push_task: 读 push_rx, server-push notification 写 locked writer
///   共享 writer = Arc<AsyncMutex<OwnedWriteHalf>>, 行写原子 (锁内 write_all)
///   连接断开 → 清订阅 + close push_task
async fn handle_conn(
    stream: UnixStream,
    executor: Arc<Executor>,
    hub: Arc<BroadcastHub>,
    shells: Arc<fe_core::shell::ShellRegistry>,
    exec_sem: Arc<Semaphore>,
) {
    let conn_id = hub.next_conn_id();
    hub.active_conns.fetch_add(1, Ordering::Relaxed);
    let (reader, writer) = stream.into_split();
    let writer = Arc::new(AsyncMutex::new(writer));
    let (push_tx, push_rx) = mpsc::channel::<Value>(128);
    let (close_tx, close_rx) = oneshot::channel::<()>();

    // push_task — server-push 帧写出
    let push_writer = writer.clone();
    let push_handle = tokio::spawn(async move {
        let mut rx = push_rx;
        let mut close = close_rx;
        loop {
            tokio::select! {
                biased;
                _ = &mut close => {
                    info!(conn_id, "push_task 收 close, 退出");
                    break;
                }
                frame = rx.recv() => {
                    match frame {
                        Some(v) => {
                            let line = match serde_json::to_string(&v) {
                                Ok(s) => s + "\n",
                                Err(e) => {
                                    warn!(error = %e, "push 帧序列化失败, 跳过");
                                    continue;
                                }
                            };
                            let mut w = push_writer.lock().await;
                            if w.write_all(line.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    // read_task — 逐行分发 (带 1MB 上限 + idle 超时, C-IPC-04/C-IPC-05)
    // 审计 2.12: 旧版 execute_stream/telemetry_stream 在 read_task 循环内 inline await,
    // 流式期间不读下一行 → 单连接 subscribe 后 execute_stream 响应被阻到流结束。
    // 解法: 每请求 spawn 独立任务 (单连接请求并发多路复用), read_task 持续读下一行不阻塞。
    // 响应/流式帧写共享 Arc<AsyncMutex<Writer>> (锁内 write_all 原子), 跨任务写安全。
    let mut reader = BufReader::new(reader);
    let read_hub = hub.clone();
    let read_exec = executor.clone();
    let read_shells = shells.clone();
    let read_push_tx = push_tx.clone();
    let read_writer = writer.clone();
    let read_close = close_tx;
    let mut req_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    loop {
        let line = match read_capped_line(&mut reader).await {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(code) => {
                // 超限/超时 → 回 JSON-RPC 错误后断开该连接
                let data = serde_json::to_string(&err_resp(
                    Value::Null,
                    code,
                    if code == ERR_PARSE {
                        "请求行超过 1MB 上限"
                    } else {
                        "idle 读超时"
                    },
                ))
                .unwrap_or_default()
                    + "\n";
                let mut w = read_writer.lock().await;
                let _ = w.write_all(data.as_bytes()).await;
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let data = serde_json::to_string(&err_resp(
                    Value::Null,
                    ERR_PARSE,
                    &format!("Parse error: {}", e),
                ))
                .unwrap_or_default()
                    + "\n";
                let mut w = read_writer.lock().await;
                let _ = w.write_all(data.as_bytes()).await;
                continue;
            }
        };
        let req_id = parsed.get("id").cloned().unwrap_or(Value::Null);
        let method = parsed
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        let params = parsed.get("params").cloned().unwrap_or(Value::Null);

        // 2.12: 每请求 spawn 任务, read_task 不阻塞。共享 writer 锁保证行写原子。
        let w = read_writer.clone();
        let ex = read_exec.clone();
        let h = read_hub.clone();
        let sh = read_shells.clone();
        let ptx = read_push_tx.clone();
        let es = exec_sem.clone();
        let handle = tokio::spawn(async move {
            dispatch_request(&w, req_id, method, params, &ex, &h, &sh, conn_id, &ptx, &es).await;
        });
        req_tasks.push(handle);
    }
    // 连接断开 — 等所有在飞请求任务收尾 (它们持 writer 锁写响应), 清订阅, 关 push_task
    for t in req_tasks {
        let _ = t.await;
    }
    hub.drop_conn(conn_id);
    let _ = read_close.send(());
    let _ = push_handle.await;
}

/// 单请求分发 — 从 read_task spawn 调用 (审计 2.12 单连接请求多路复用)。
/// execute 类方法 (execute/execute_stream) 取 exec_sem permit 限并发子进程 (审计 2.11)。
#[allow(clippy::too_many_arguments)]
async fn dispatch_request(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    method: String,
    params: Value,
    executor: &Arc<Executor>,
    hub: &Arc<BroadcastHub>,
    shells: &Arc<fe_core::shell::ShellRegistry>,
    conn_id: u64,
    push_tx: &mpsc::Sender<Value>,
    exec_sem: &Arc<Semaphore>,
) {
    if method == "executor.execute_stream" {
        if let Err(e) =
            handle_execute_stream(writer, id, params, executor, hub, conn_id, exec_sem).await
        {
            warn!(error = %e, "execute_stream 写帧失败");
        }
        return;
    }
    if method == "executor.telemetry_stream" {
        if let Err(e) = handle_telemetry_stream(writer, id, params, executor).await {
            warn!(error = %e, "telemetry_stream 写帧失败");
        }
        return;
    }
    if method == "executor.subscribe" {
        handle_subscribe(writer, id, params, conn_id, hub, push_tx).await;
        return;
    }
    if method == "executor.unsubscribe" {
        handle_unsubscribe(writer, id, params, hub).await;
        return;
    }

    let resp = match handle_method(&method, params, executor, hub, shells, conn_id, exec_sem).await
    {
        Ok(r) => ok_resp(id, r),
        Err((code, msg)) => err_resp(id, code, &msg),
    };
    let data = serde_json::to_string(&resp)
        .unwrap_or_else(|_| err_str(Value::Null, ERR_INTERNAL, "响应序列化失败"))
        + "\n";
    let mut w = writer.lock().await;
    let _ = w.write_all(data.as_bytes()).await;
}

/// 带 1MB 上限 + idle 超时的行读 (C-IPC-04/C-IPC-05)。
/// Ok(Some(line)) — 一行 (不含换行); Ok(None) — EOF; Err(code) — 超限 ERR_PARSE / 超时 ERR_INTERNAL。
/// 审计 Blocker 7 / 2.10: 原 read_until 无界缓冲到换行才查上限 → 无换行洪水 OOM。
/// 解法: fill_buf+consume 分块, 每次 extend 前查 buf.len()+take > MAX_LINE_BYTES 即拒 (in-loop cap, fail-loud)。
async fn read_capped_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<String>, i64> {
    let mut buf = Vec::with_capacity(4096);
    loop {
        let fill_fut = reader.fill_buf();
        let slice =
            match tokio::time::timeout(Duration::from_secs(IDLE_READ_TIMEOUT_SECS), fill_fut).await
            {
                Ok(Ok(s)) => s,
                Ok(Err(_)) => return Err(ERR_INTERNAL),
                Err(_) => return Err(ERR_INTERNAL),
            };
        if slice.is_empty() {
            return Ok(None);
        }
        let nl = slice.iter().position(|&b| b == b'\n');
        let take = match nl {
            Some(i) => i + 1,
            None => slice.len(),
        };
        if buf.len() + take > MAX_LINE_BYTES {
            warn!(
                len = buf.len() + take,
                max = MAX_LINE_BYTES,
                "请求行超 1MB, 拒连 (in-loop cap, 无换行洪水防护)"
            );
            return Err(ERR_PARSE);
        }
        buf.extend_from_slice(&slice[..take]);
        reader.consume(take);
        if nl.is_some() {
            let line = String::from_utf8_lossy(&buf[..buf.len() - 1])
                .trim_end_matches('\r')
                .to_string();
            return Ok(Some(line));
        }
        // 无换行继续读 (buf.len()+take 已限, 不会无界增长)
    }
}

/// 订阅 — 解析 channels/interval_ms/screenshot_interval_ms, 注册 hub, 响应 {ok, subscription_id} (M-IPC-01)
async fn handle_subscribe(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    params: Value,
    conn_id: u64,
    hub: &Arc<BroadcastHub>,
    push_tx: &mpsc::Sender<Value>,
) {
    let channels: HashSet<String> = params
        .get("channels")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    if channels.is_empty() {
        let resp = err_resp(id, ERR_INVALID_REQ, "缺少 channels");
        write_line(writer, resp).await;
        return;
    }
    // interval_ms (遥测) / screenshot_interval_ms (截图) — 透传源任务 (M-IPC-01)
    let interval_ms = params
        .get("interval_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_INTERVAL_MS);
    let screenshot_interval_ms = params
        .get("screenshot_interval_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_SCREENSHOT_INTERVAL_MS);
    // stdio 作用域 (Blocker 10, 破审计 §2.9 跨租户泄漏):
    //   all=true → All (全广播); task_ids=[...] → Tasks 白名单; 默认 → OwnConn(仅本连接命令)
    let scope = if params.get("all").and_then(|v| v.as_bool()).unwrap_or(false) {
        StdioScope::All
    } else if let Some(arr) = params.get("task_ids").and_then(|v| v.as_array()) {
        let set: HashSet<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        StdioScope::Tasks(set)
    } else {
        StdioScope::OwnConn(conn_id)
    };
    let sub_id = hub.subscribe(
        conn_id,
        channels,
        scope,
        push_tx.clone(),
        interval_ms,
        screenshot_interval_ms,
    );
    let resp = ok_resp(id, json!({"ok": true, "subscription_id": sub_id}));
    write_line(writer, resp).await;
}

/// 取消订阅 — 移除 hub 注册, 响应 {ok}
async fn handle_unsubscribe(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    params: Value,
    hub: &Arc<BroadcastHub>,
) {
    let sub_id = match params.get("subscription_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            let resp = err_resp(id, ERR_INVALID_REQ, "缺少 subscription_id");
            write_line(writer, resp).await;
            return;
        }
    };
    let ok = hub.unsubscribe(&sub_id);
    let resp = ok_resp(id, json!({"ok": ok}));
    write_line(writer, resp).await;
}

/// 写一行 JSON Value (锁内 write_all, 原子)。
/// 序列化失败回退有效错误帧, 裸 `\n` 会让客户端挂起 (P-IPC-02)。
async fn write_line(writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>, v: Value) {
    let line = match serde_json::to_string(&v) {
        Ok(s) => s + "\n",
        Err(e) => {
            warn!(error = %e, "Value 序列化失败, 回退错误帧");
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{{\"code\":{},\"message\":\"响应序列化失败\"}}}}\n",
                ERR_INTERNAL
            )
        }
    };
    let mut w = writer.lock().await;
    let _ = w.write_all(line.as_bytes()).await;
}

/// 流式执行 — chunk 帧 + done 帧, 共用 id, 换行分隔逐帧写出。
/// v1.5 #14: chunk/done 同时广播给 stdio 订阅 (跨连接 fan-out)。
/// chunk: {"jsonrpc":"2.0","id":id,"result":{"type":"chunk","data":"..."}}
/// done:  {"jsonrpc":"2.0","id":id,"result":{"type":"done","result":{...ExecutionResult}}}
async fn handle_execute_stream(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    params: Value,
    executor: &Arc<Executor>,
    hub: &Arc<BroadcastHub>,
    conn_id: u64,
    exec_sem: &Arc<Semaphore>,
) -> Result<()> {
    let req: ExecutionRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            let frame = serde_json::to_string(&err_resp(
                id,
                ERR_INVALID_REQ,
                &format!("params 无效: {}", e),
            ))? + "\n";
            let mut w = writer.lock().await;
            w.write_all(frame.as_bytes()).await?;
            return Ok(());
        }
    };
    let task_id = req.task_id.clone();
    // 审计 2.11: 取执行 permit — 限并发子进程 (非连接)。持 permit 跨整流式生命周期
    // (execute_streaming 启子进程 → chunk/done 全程), drop 时释放供下一执行。
    let _exec_permit = exec_sem
        .acquire()
        .await
        .map_err(|e| anyhow::anyhow!("exec_sem 已关闭: {e}"))?;
    let (mut rx, handle) = match executor.execute_streaming(req).await {
        Ok(p) => p,
        Err(e) => {
            let frame = serde_json::to_string(&err_resp(
                id,
                ERR_INTERNAL,
                &format!("execute_stream 失败: {}", e),
            ))? + "\n";
            let mut w = writer.lock().await;
            w.write_all(frame.as_bytes()).await?;
            return Ok(());
        }
    };
    while let Some(ev) = rx.recv().await {
        let result = match ev {
            fe_core::ExecutionStreamEvent::Chunk { data } => {
                hub.broadcast_stdio(
                    json!({"task_id": task_id, "event": "chunk", "data": data}),
                    conn_id,
                );
                json!({"type": "chunk", "data": data})
            }
            fe_core::ExecutionStreamEvent::Done(r) => {
                let result_val = serde_json::to_value(&r).unwrap_or(json!({}));
                hub.broadcast_stdio(
                    json!({
                        "task_id": task_id,
                        "event": "done",
                        "result": result_val.clone(),
                    }),
                    conn_id,
                );
                json!({"type": "done", "result": result_val})
            }
        };
        let frame = serde_json::to_string(&ok_resp(id.clone(), result))? + "\n";
        let mut w = writer.lock().await;
        if w.write_all(frame.as_bytes()).await.is_err() {
            break;
        }
    }
    let _ = handle.await;
    Ok(())
}

/// 实时遥测流 (请求发起, 非 subscribe) — 逐帧写出 TelemetrySample, 共用 id。
/// sample: {"jsonrpc":"2.0","id":id,"result":{"type":"sample",...TelemetrySample}}
/// params: {interval_ms?:u64, max_samples?:u64} (缺省 10Hz / 无限)
async fn handle_telemetry_stream(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    params: Value,
    executor: &Arc<Executor>,
) -> Result<()> {
    let interval_ms = params
        .get("interval_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(100);
    let max_samples = params
        .get("max_samples")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cfg = TelemetryStreamConfig {
        interval_ms,
        max_samples,
    };
    let (mut rx, handle) = executor.telemetry_stream(cfg);
    while let Some(sample) = rx.recv().await {
        let frame = serde_json::to_string(&ok_resp(
            id.clone(),
            json!({"type": "sample", "sample": serde_json::to_value(&sample).unwrap_or(json!({}))}),
        ))? + "\n";
        let mut w = writer.lock().await;
        if w.write_all(frame.as_bytes()).await.is_err() {
            break;
        }
    }
    let _ = handle.await;
    Ok(())
}

/// 处理单个方法 → Ok(Value) | Err((code, msg))
/// v1.5 #14: execute (非流式) 完成后广播 stdio done 给订阅
async fn handle_method(
    method: &str,
    params: Value,
    executor: &Arc<Executor>,
    hub: &Arc<BroadcastHub>,
    shells: &Arc<fe_core::shell::ShellRegistry>,
    conn_id: u64,
    exec_sem: &Arc<Semaphore>,
) -> Result<Value, (i64, String)> {
    match method {
        "executor.health" => {
            // C-OPS-05: ok 由真实探针决定 (非硬编码) — 探 BLOCKING_RT 响应 + 外部依赖 (git)。
            // BLOCKING_RT 停摆 / worker 全阻塞 / 死锁 → spawn 超时 → ok:false, 负载均衡器摘除卡死实例。
            let rt_ok = probe_runtime(Duration::from_secs(1)).await;
            let deps = probe_dependencies().await;
            // 任一核心依赖缺失 → ok:false (依赖不健康 = 服务降级)
            let deps_ok = deps.iter().all(|d| d["ok"].as_bool() == Some(true));
            let ok = rt_ok && deps_ok;
            Ok(json!({
                "ok": ok,
                "version": env!("CARGO_PKG_VERSION"),
                "git_sha": env!("FE_GIT_SHA"),
                "build_time": env!("FE_BUILD_TIME"),
                "ax_trusted": fe_core::gui::GuiController::ax_trusted(),
                // C-SEC-02: seatbelt 治理信号 — 默认 false (调用方须显式 opt-in seatbelt:true)。
                // 负载均衡器/运维查此字段知实例未开运行时隔离, 提示生产环境须透传 seatbelt:true。
                "seatbelt_default_off": true,
                "runtime": { "ok": rt_ok },
                "dependencies": deps,
                // M-OPS-04/M-OPS-05: 运维深度指标 — 连接数/worker 线程/活跃 shell/内存。
                // 运维面板 + 负载均衡器据此判断实例负载与 shell 注册表水位。
                "depth": probe_health_depth(shells, hub)
            }))
        }
        "executor.execute" => {
            let req: ExecutionRequest = serde_json::from_value(params)
                .map_err(|e| (ERR_INVALID_REQ, format!("params 无效: {}", e)))?;
            let task_id = req.task_id.clone();
            // 审计 2.11: 取执行 permit 限并发子进程 (非连接)。execute_async 启子进程, permit 持到返回。
            let _exec_permit = exec_sem
                .acquire()
                .await
                .map_err(|e| (ERR_INTERNAL, format!("exec_sem 已关闭: {e}")))?;
            let r: ExecutionResult = executor
                .execute_async(req)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("execute 失败: {}", e)))?;
            hub.record_exec(&r);
            let val = serde_json::to_value(&r).unwrap_or(json!({}));
            hub.broadcast_stdio(
                json!({
                    "task_id": task_id,
                    "event": "done",
                    "result": val.clone(),
                }),
                conn_id,
            );
            Ok(val)
        }
        "executor.snapshot_create" => {
            let cwd = param_str(&params, "cwd").ok_or((ERR_INVALID_REQ, "缺少 cwd".to_string()))?;
            let id = executor
                .snapshot_create_async(&cwd)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("snapshot_create 失败: {}", e)))?;
            Ok(json!({"snapshot_id": id}))
        }
        // Issue #11 / #12.4: 非执行预校验 — 调用方 (fusion-code) 先问用户授权再 execute。
        // Executor 只强制硬黑名单 (never-blocked); interactive confirmation 归 caller (Option A, stateless)。
        "executor.validate" => {
            let command = param_str(&params, "command")
                .ok_or((ERR_INVALID_REQ, "缺少 command".to_string()))?;
            let verdict = executor.validate(&command);
            let allowed = verdict.allowed;
            let reason = verdict.reason.clone();
            // 手工映射为小写串 — 与 fe-pyo3 validate() 一致, 两传输层 wire shape 统一
            let stage = verdict.stage.map(|s| match s {
                fe_core::security::SecurityStage::Regex => "regex",
                fe_core::security::SecurityStage::Tokenizer => "tokenizer",
            });
            Ok(json!({
                "allowed": allowed,
                "blocked": !allowed,
                "reason": reason,
                "stage": stage,
            }))
        }
        "executor.rollback" => {
            let snapshot_id = param_str(&params, "snapshot_id")
                .ok_or((ERR_INVALID_REQ, "缺少 snapshot_id".to_string()))?;
            let cwd = param_str(&params, "cwd").ok_or((ERR_INVALID_REQ, "缺少 cwd".to_string()))?;
            let ok = executor
                .rollback_async(&snapshot_id, &cwd)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("rollback 失败: {}", e)))?;
            hub.record_rollback(ok);
            if !ok {
                return Err((-32012, "rollback 失败 (stash apply 或非 repo)".to_string()));
            }
            Ok(json!({"ok": true}))
        }
        "executor.diagnostics" => {
            // 审计 3.9: PTY 合并 stdout+stderr → traceback 在 stdout (stderr 恒空, 见 fe-sandbox
            // SandboxResult.stderr 文档)。旧版仅读 params.stderr → 切片器拿空串无诊断。
            // 优先 stdout (PTY 合并流), 回退 stderr/output (stdio-only 后端或旧客户端向后兼容)。
            let output = param_str(&params, "stdout")
                .or_else(|| param_str(&params, "stderr"))
                .or_else(|| param_str(&params, "output"))
                .unwrap_or_default();
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let slicer = fe_core::diagnostics::Slicer::new();
            let d: Diagnostics = slicer.slice(&output, cwd).into();
            Ok(serde_json::to_value(&d).unwrap_or(json!({})))
        }
        "executor.gui_action" => {
            let action_val = params
                .get("action")
                .ok_or((ERR_INVALID_REQ, "缺少 action".to_string()))?;
            let action: GuiAction = serde_json::from_value(action_val.clone())
                .map_err(|e| (ERR_INVALID_REQ, format!("action 反序列化失败: {e}")))?;
            let result = executor
                .gui_action(action)
                .map_err(|e| (ERR_INTERNAL, format!("gui_action 失败: {e}")))?;
            Ok(serde_json::to_value(&result).unwrap_or(json!({})))
        }
        "executor.metrics" => {
            // C-OPS-05: 自服务指标 — exec 计数 + duration/stdio 聚合 + rollback 计数。
            // 运维面板/负载均衡器读此判健康趋势 (拦截率/超时率/回滚失败率), 无外部 exporter 依赖。
            Ok(hub.metrics_snapshot())
        }
        "executor.shutdown" => {
            // C-OPS-04: IPC 触发优雅 drain — notify_waiters 唤醒 accept_loop 的 shutdown_notify
            // 分支 → 停止 accept + drain in-flight 连接 (join_all 10s deadline)。
            // 响应先回再让 accept_loop 退出 (本连接的 read_task 在 dispatch 后自然结束)。
            info!("收到 shutdown 请求, 触发优雅 drain (C-OPS-04)");
            hub.shutdown.notify_waiters();
            Ok(json!({"ok": true, "shutting_down": true}))
        }
        "executor.file_edit" => {
            let path =
                param_str(&params, "path").ok_or((ERR_INVALID_REQ, "缺少 path".to_string()))?;
            let old_string = param_str(&params, "old_string")
                .ok_or((ERR_INVALID_REQ, "缺少 old_string".to_string()))?;
            let new_string = param_str(&params, "new_string")
                .ok_or((ERR_INVALID_REQ, "缺少 new_string".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let replace_all = params
                .get("replace_all")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let r = executor
                .file_edit(&path, &old_string, &new_string, cwd, replace_all)
                .map_err(|e| (ERR_INTERNAL, format!("file_edit 失败: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.write_file" => {
            // #2: write_file(path, content, cwd?) — 整文件创建/覆盖 + 建父目录
            let path =
                param_str(&params, "path").ok_or((ERR_INVALID_REQ, "缺少 path".to_string()))?;
            let content = param_str(&params, "content")
                .ok_or((ERR_INVALID_REQ, "缺少 content".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .write_file(&path, &content, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("write_file 失败: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.glob" => {
            let pattern = param_str(&params, "pattern")
                .ok_or((ERR_INVALID_REQ, "缺少 pattern".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let entries = executor
                .glob(&pattern, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("glob 失败: {}", e)))?;
            Ok(serde_json::to_value(&entries).unwrap_or(json!({})))
        }
        "executor.grep" => {
            let pattern = param_str(&params, "pattern")
                .ok_or((ERR_INVALID_REQ, "缺少 pattern".to_string()))?;
            let paths: Vec<String> = params
                .get("paths")
                .and_then(|p| p.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .ok_or((ERR_INVALID_REQ, "缺少 paths 数组".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let matches = executor
                .grep(&pattern, &paths, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("grep 失败: {}", e)))?;
            Ok(serde_json::to_value(&matches).unwrap_or(json!({})))
        }
        "executor.grep_with_opts" => {
            let pattern = param_str(&params, "pattern")
                .ok_or((ERR_INVALID_REQ, "缺少 pattern".to_string()))?;
            let paths: Vec<String> = params
                .get("paths")
                .and_then(|p| p.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .ok_or((ERR_INVALID_REQ, "缺少 paths 数组".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            // #7: opts 子对象 serde 反序列化 (字段全 #[serde(default)], 缺省=默认)
            let opts: fe_core::tools::GrepOptions = match params.get("opts") {
                Some(v) => serde_json::from_value(v.clone())
                    .map_err(|e| (ERR_INVALID_REQ, format!("opts 解析失败: {}", e)))?,
                None => fe_core::tools::GrepOptions::default(),
            };
            let out = executor
                .grep_with_opts(&pattern, &paths, cwd, &opts)
                .map_err(|e| (ERR_INTERNAL, format!("grep_with_opts 失败: {}", e)))?;
            Ok(serde_json::to_value(&out).unwrap_or(json!({})))
        }
        "executor.apply_patch" => {
            let diff =
                param_str(&params, "diff").ok_or((ERR_INVALID_REQ, "缺少 diff".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .apply_patch(&diff, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("apply_patch 失败: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.replace_function" => {
            let path =
                param_str(&params, "path").ok_or((ERR_INVALID_REQ, "缺少 path".to_string()))?;
            let fn_name = param_str(&params, "fn_name")
                .ok_or((ERR_INVALID_REQ, "缺少 fn_name".to_string()))?;
            let new_body = param_str(&params, "new_body")
                .ok_or((ERR_INVALID_REQ, "缺少 new_body".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .replace_function(&path, &fn_name, &new_body, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("replace_function 失败: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.multi_edit" => {
            let path =
                param_str(&params, "path").ok_or((ERR_INVALID_REQ, "缺少 path".to_string()))?;
            let edits_val = params
                .get("edits")
                .ok_or((ERR_INVALID_REQ, "缺少 edits 数组".to_string()))?;
            let edits: Vec<fe_core::tools::MultiEditItem> =
                serde_json::from_value(edits_val.clone())
                    .map_err(|e| (ERR_INVALID_REQ, format!("edits 解析失败: {}", e)))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .multi_edit(&path, &edits, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("multi_edit 失败: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.notebook_edit" => {
            let path =
                param_str(&params, "path").ok_or((ERR_INVALID_REQ, "缺少 path".to_string()))?;
            let cell_id = params.get("cell_id").and_then(|v| v.as_str());
            let cell_number = params.get("cell_number").and_then(|v| v.as_i64());
            let new_source = param_str(&params, "new_source")
                .ok_or((ERR_INVALID_REQ, "缺少 new_source".to_string()))?;
            let edit_mode: fe_core::tools::NotebookEditMode =
                match params.get("edit_mode").and_then(|v| v.as_str()) {
                    Some(m) => serde_json::from_value(serde_json::Value::String(m.to_string()))
                        .map_err(|e| (ERR_INVALID_REQ, format!("edit_mode 解析失败: {}", e)))?,
                    None => fe_core::tools::NotebookEditMode::Replace,
                };
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .notebook_edit(&path, cell_id, cell_number, &new_source, edit_mode, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("notebook_edit 失败: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.shell_start" => {
            // #1: 后台持久 shell 启动 — 安全校验在 fe-core (fail-closed)
            let command = param_str(&params, "command")
                .ok_or((ERR_INVALID_REQ, "缺少 command".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str()).map(String::from);
            let task_id = params
                .get("task_id")
                .and_then(|v| v.as_str())
                .map(String::from);
            let env: std::collections::HashMap<String, String> = match params.get("env_vars") {
                Some(v) => serde_json::from_value(v.clone())
                    .map_err(|e| (ERR_INVALID_REQ, format!("env_vars 解析失败: {}", e)))?,
                None => std::collections::HashMap::new(),
            };
            let max_output_chars = params
                .get("max_output_chars")
                .and_then(|v| v.as_u64())
                .map(|n| n as usize)
                .unwrap_or(100_000);
            let seatbelt = params
                .get("seatbelt")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let inherit_env = params
                .get("inherit_env")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let max_nproc = params
                .get("max_nproc")
                .and_then(|v| v.as_u64())
                .map(|n| n as u32)
                .unwrap_or(1024);
            let max_cpu_sec = params
                .get("max_cpu_sec")
                .and_then(|v| v.as_u64())
                .map(|n| n as u32)
                .unwrap_or(0);
            let max_idle_sec = params
                .get("max_idle_sec")
                .and_then(|v| v.as_u64())
                .unwrap_or(fe_core::shell::DEFAULT_MAX_IDLE_SEC);
            let sp = fe_core::shell::ShellStartParams {
                command,
                cwd,
                env,
                task_id,
                max_output_chars,
                seatbelt,
                inherit_env,
                max_nproc,
                max_cpu_sec,
                max_idle_sec,
            };
            let r = executor.shell_start(shells, sp);
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.shell_output" => {
            // #1: 轮询 tail 快照 + 运行/退出状态
            let shell_id = param_str(&params, "shell_id")
                .ok_or((ERR_INVALID_REQ, "缺少 shell_id".to_string()))?;
            let out = Executor::shell_output(shells, &shell_id)
                .map_err(|e| (ERR_INTERNAL, format!("shell_output 失败: {}", e)))?;
            Ok(serde_json::to_value(&out).unwrap_or(json!({})))
        }
        "executor.kill_shell" => {
            // #1: kill 进程树 (KillShell parity)
            let shell_id = param_str(&params, "shell_id")
                .ok_or((ERR_INVALID_REQ, "缺少 shell_id".to_string()))?;
            let ok = Executor::kill_shell(shells, &shell_id)
                .map_err(|e| (ERR_INTERNAL, format!("kill_shell 失败: {}", e)))?;
            Ok(json!({ "ok": ok }))
        }
        "executor.list_shells" => {
            // #1: 列出全部后台 shell
            let list = Executor::list_shells(shells);
            Ok(serde_json::to_value(&list).unwrap_or(json!({})))
        }
        _ => Err((
            ERR_METHOD_NOT_FOUND,
            format!("Method not found: {}", method),
        )),
    }
}

/// C-OPS-05: 探 BLOCKING_RT 响应 — spawn 空任务 + 超时, 超时即 rt_ok=false (worker 停摆/死锁)。
/// BLOCKING_RT 是 executor 异步 runtime; 停摆则一切 execute 阻塞, 健康检查必须探测到。
async fn probe_runtime(timeout: Duration) -> bool {
    let h = fe_core::BLOCKING_RT.handle();
    let task = h.spawn(async {});
    tokio::time::timeout(timeout, task).await.is_ok()
}

/// C-OPS-05: 探外部依赖 — `git --version` (rollback/快照依赖 git CLI)。
/// 任一依赖缺失 → 服务降级, ok=false。返回 [{name, ok, version?}]。
async fn probe_dependencies() -> Vec<Value> {
    let git_ok = tokio::process::Command::new("git")
        .arg("--version")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    let git_version = if git_ok {
        tokio::process::Command::new("git")
            .arg("--version")
            .output()
            .await
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        None
    };
    let mut d = json!({ "name": "git", "ok": git_ok });
    if let Some(v) = git_version {
        d["version"] = json!(v);
    }
    vec![d]
}

/// M-OPS-04/M-OPS-05: health 深度指标 — 连接数/worker 线程数/活跃 shell 数/内存 (MB)。
/// - connections: BroadcastHub.active_conns 原子快照 (无锁)。
/// - workers: BLOCKING_RT worker_threads — 与 fe-core 初始化公式一致 (available_parallelism, 下限 2)。
/// - active_shells: Executor::list_shells(registry).filter(!finished) 计数; M-OPS-05 接近 MAX_SHELLS 时 warn。
/// - mem_mb: 本进程 RSS via sysinfo (轻量单次 refresh, 无采样任务)。
///
/// M-ARCH-1: registry 由 IpcServer 持有 (Executor 无状态), 经 dispatch_request 传引用。
fn probe_health_depth(shells: &Arc<fe_core::shell::ShellRegistry>, hub: &BroadcastHub) -> Value {
    let connections = hub.active_conns.load(Ordering::Relaxed);
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .max(2);
    let sh = Executor::list_shells(shells);
    let active_shells = sh.iter().filter(|s| !s.finished).count();
    // M-OPS-05: 接近上限告警 (80%) — 防 registry 打满导致新 shell_start 被迫 reap。
    let max_shells = fe_core::shell::MAX_SHELLS;
    if max_shells > 0 && active_shells * 5 >= max_shells * 4 {
        warn!(
            active_shells,
            max_shells, "M-OPS-05: 活跃 shell 接近上限 (>=80%), 调用方应清理后台任务"
        );
    }
    // mem_mb — 本进程 RSS (sysinfo 轻量 refresh)
    let mem_mb = current_proc_mem_mb();
    json!({
        "connections": connections,
        "workers": workers,
        "active_shells": active_shells,
        "max_shells": max_shells,
        "mem_mb": mem_mb,
    })
}

/// sysinfo 取本进程 RSS (MB) — M-OPS-04 health mem_mb 探针。
/// 复用 fe-telemetry 同款 3-arg refresh_processes_specifics (sysinfo 0.32 API)。
fn current_proc_mem_mb() -> f64 {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let pid = sysinfo::Pid::from_u32(std::process::id());
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        false,
        ProcessRefreshKind::new().with_memory(),
    );
    sys.process(pid)
        .map(|p| (p.memory() as f64) / (1024.0 * 1024.0))
        .unwrap_or(0.0)
}
fn param_str(params: &Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn ok_resp(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn err_resp(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn err_str(id: Value, code: i64, message: &str) -> String {
    serde_json::to_string(&err_resp(id, code, message)).unwrap_or_default()
}

/// chmod 0o600 — 仅 owner 可读写 (本地提权防护, C-IPC-01)。
/// 监听前已 unlink 旧 socket, bind 后立即收紧权限。
#[cfg(unix)]
fn chmod_secure(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        warn!(path = %path.display(), error = %e, "chmod 0o600 失败");
    }
}

#[cfg(not(unix))]
fn chmod_secure(_path: &Path) {}

/// M-SEC-01: 建 socket 父目录 0o700 — 私有目录阻他 UID connect (目录无搜索权限)。
/// 仅对 HOME 下默认路径生效; 显式 /tmp 覆盖路径不建目录 (退化为 chmod 0o600 单文件)。
/// 已存在目录不重设权限 (防误改用户定制目录), 仅缺失时 create_dir_all 0o700。
#[cfg(unix)]
fn ensure_sock_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Some(parent) = path.parent() else {
        return;
    };
    if parent.as_os_str().is_empty() {
        return;
    }
    if parent.exists() {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(parent) {
        warn!(dir = %parent.display(), error = %e, "M-SEC-01: 建 socket 私有目录失败");
        return;
    }
    if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)) {
        warn!(dir = %parent.display(), error = %e, "M-SEC-01: chmod 0o700 私有目录失败");
    }
    info!(dir = %parent.display(), "M-SEC-01: socket 私有目录已建 (0o700, 阻他 UID)");
}

#[cfg(not(unix))]
fn ensure_sock_dir(_path: &Path) {}

/// M-SEC-01: LOCAL_PEERCRED UID 校验 — accept 后查对端 UID, 须等于本进程 UID。
/// 防同主机他 UID 经符号链接或 /tmp 覆盖路径越权 connect。零 unsafe (nix safe wrapper)。
/// 返回 true=放行 (同 UID), false=拒 (他 UID 或取凭证失败, fail-closed)。
#[cfg(unix)]
fn peer_uid_matches(stream: &tokio::net::UnixStream) -> bool {
    use nix::sys::socket::getsockopt;
    use nix::sys::socket::sockopt::LocalPeerCred;
    use nix::unistd::getuid;
    let self_uid = getuid().as_raw();
    match getsockopt(stream, LocalPeerCred) {
        Ok(cred) => {
            let peer_uid = cred.uid();
            if peer_uid == self_uid {
                true
            } else {
                warn!(
                    peer_uid,
                    self_uid, "M-SEC-01: 拒他 UID 连接 (LOCAL_PEERCRED)"
                );
                false
            }
        }
        Err(e) => {
            // fail-closed: 取不到对端凭证 → 拒 (防降级绕过)
            warn!(error = %e, "M-SEC-01: LOCAL_PEERCRED 取凭证失败, fail-closed 拒连");
            false
        }
    }
}

#[cfg(not(unix))]
fn peer_uid_matches(_stream: &tokio::net::UnixStream) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixStream;

    fn tmp_sock(tag: &str) -> String {
        let p =
            std::env::temp_dir().join(format!("fe-ipc-test-{}-{}.sock", std::process::id(), tag));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    async fn rpc(sock: &str, req: &str) -> Value {
        let mut s = UnixStream::connect(sock).await.unwrap();
        s.write_all((req.to_string() + "\n").as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        let mut reader = BufReader::new(s);
        reader.read_until(b'\n', &mut buf).await.unwrap();
        let line = String::from_utf8_lossy(&buf).trim().to_string();
        serde_json::from_str(&line).unwrap_or(Value::Null)
    }

    #[tokio::test]
    async fn health_ok() {
        let sock = tmp_sock("health");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.health","params":{}}"#,
        )
        .await;
        // C-OPS-05: ok 由真实探针决定 (BLOCKING_RT + git 依赖), CI 环境 git 存在 → ok=true。
        assert_eq!(resp["result"]["ok"], true);
        // C-SEC-02: seatbelt 治理信号 — 默认关闭, 调用方须显式 opt-in seatbelt:true
        assert_eq!(resp["result"]["seatbelt_default_off"], true);
        // ax_trusted = 真实 AXIsProcessTrusted() 查询 (C-GUI-01), CI 无 TCC 时为 false。
        // 仅断言字段存在且为布尔, 不硬编码 true。
        assert!(
            resp["result"]["ax_trusted"].is_boolean(),
            "ax_trusted 应为布尔: {}",
            resp["result"]["ax_trusted"]
        );
        // C-OPS-05: runtime 探针 — BLOCKING_RT spawn 空任务超时探活
        assert_eq!(
            resp["result"]["runtime"]["ok"], true,
            "runtime 应健康 (BLOCKING_RT 可响应): {}",
            resp["result"]["runtime"]
        );
        // C-OPS-05: dependencies 数组 — git CLI (rollback 依赖)
        let deps = &resp["result"]["dependencies"];
        assert!(deps.is_array(), "dependencies 应为数组: {}", deps);
        let git_dep = deps
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == "git")
            .expect("dependencies 应含 git");
        assert_eq!(git_dep["ok"], true, "git 依赖应健康: {}", git_dep);
        assert!(
            git_dep["version"].is_string(),
            "git 应报 version: {}",
            git_dep
        );
        let _ = std::fs::remove_file(&sock);
    }

    // M-OPS-04/M-OPS-05: health 深度指标 — connections/workers/active_shells/max_shells/mem_mb
    #[tokio::test]
    async fn health_depth_fields_present() {
        let sock = tmp_sock("health_depth");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.health","params":{}}"#,
        )
        .await;
        let depth = &resp["result"]["depth"];
        assert!(depth.is_object(), "depth 应为对象: {}", depth);
        // M-OPS-04: 五字段齐
        for key in [
            "connections",
            "workers",
            "active_shells",
            "max_shells",
            "mem_mb",
        ] {
            assert!(depth.get(key).is_some(), "depth 缺字段 {key}: {depth}");
        }
        // M-OPS-04: 本次 RPC 连接计入 — 至少 1 个活跃连接
        let conns = depth["connections"].as_u64();
        assert!(
            conns.is_some() && conns.unwrap() >= 1,
            "connections 应 >=1 (本次 RPC 在连): {depth}"
        );
        // M-OPS-04: workers >=2 (BLOCKING_RT 下限)
        let workers = depth["workers"].as_u64();
        assert!(
            workers.is_some() && workers.unwrap() >= 2,
            "workers 应 >=2: {depth}"
        );
        // M-OPS-05: max_shells == 256 (fe-shell 上限)
        assert_eq!(
            depth["max_shells"].as_u64(),
            Some(256),
            "max_shells 应为 256: {depth}"
        );
        // M-OPS-05: active_shells == 0 (无后台 shell 启动)
        assert_eq!(
            depth["active_shells"].as_u64(),
            Some(0),
            "active_shells 应为 0: {depth}"
        );
        // M-OPS-04: mem_mb 非负 (本进程 RSS)
        let mem = depth["mem_mb"].as_f64();
        assert!(
            mem.is_some() && mem.unwrap() >= 0.0,
            "mem_mb 应 >=0: {depth}"
        );
        let _ = std::fs::remove_file(&sock);
    }

    // M-OPS-03: 可配 shutdown drain 超时 — 纯函数解析 (无 env 副作用, 线程安全单测)。
    #[test]
    fn mops03_shutdown_timeout_parse() {
        // 缺省 → 默认 10s
        assert_eq!(parse_shutdown_timeout(None), SHUTDOWN_DEADLINE);
        // 合法区间内 → 覆盖
        assert_eq!(
            parse_shutdown_timeout(Some("5".into())),
            Duration::from_secs(5)
        );
        assert_eq!(
            parse_shutdown_timeout(Some("300".into())),
            Duration::from_secs(300)
        );
        assert_eq!(
            parse_shutdown_timeout(Some("  42  ".into())),
            Duration::from_secs(42)
        );
        // 越界 → 回退默认
        assert_eq!(parse_shutdown_timeout(Some("0".into())), SHUTDOWN_DEADLINE);
        assert_eq!(
            parse_shutdown_timeout(Some("301".into())),
            SHUTDOWN_DEADLINE
        );
        assert_eq!(
            parse_shutdown_timeout(Some("99999".into())),
            SHUTDOWN_DEADLINE
        );
        // 非数字 → 回退默认
        assert_eq!(
            parse_shutdown_timeout(Some("abc".into())),
            SHUTDOWN_DEADLINE
        );
        assert_eq!(parse_shutdown_timeout(Some("".into())), SHUTDOWN_DEADLINE);
    }

    // Issue #11 / #12.4: executor.validate 非执行预校验 over UDS — 调用方先问授权再 execute
    #[tokio::test]
    async fn validate_roundtrip() {
        let sock = tmp_sock("validate");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // 安全命令
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.validate","params":{"command":"echo hi"}}"#,
        )
        .await;
        assert_eq!(resp["result"]["allowed"], true);
        assert_eq!(resp["result"]["blocked"], false);
        assert!(resp["result"]["reason"].is_null());
        // 危险命令 — 非执行, 仅返 verdict
        let resp2 = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"executor.validate","params":{"command":"rm -rf /"}}"#,
        )
        .await;
        assert_eq!(resp2["result"]["allowed"], false);
        assert_eq!(resp2["result"]["blocked"], true);
        assert!(resp2["result"]["reason"].is_string(), "reason 应为字符串");
        assert_eq!(resp2["result"]["stage"], "regex");
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn unknown_method_returns_32601() {
        let sock = tmp_sock("unknown");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"nope","params":{}}"#,
        )
        .await;
        assert_eq!(resp["error"]["code"], -32601);
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn malformed_json_returns_32700() {
        let sock = tmp_sock("malformed");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(&sock, r#"{not valid json"#).await;
        assert_eq!(resp["error"]["code"], -32700);
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn execute_echo_over_uds() {
        let sock = tmp_sock("exec");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","id":3,"method":"executor.execute","params":{"command":"echo hi"}}"#;
        let resp = rpc(&sock, req).await;
        assert_eq!(resp["result"]["exit_code"], 0);
        assert_eq!(resp["result"]["stdout"], "hi\n");
        let _ = std::fs::remove_file(&sock);
    }

    // C-OPS-05b: executor.metrics 返运行态计数 — execute 一次后 exec_total>=1, exec_success>=1
    #[tokio::test]
    async fn metrics_roundtrip_after_execute() {
        let sock = tmp_sock("metrics");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // 先跑一次成功命令, 累 metrics 计数
        let req = r#"{"jsonrpc":"2.0","id":3,"method":"executor.execute","params":{"command":"echo hi"}}"#;
        let resp = rpc(&sock, req).await;
        assert_eq!(resp["result"]["exit_code"], 0);
        // 读 metrics 快照
        let mresp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":4,"method":"executor.metrics","params":{}}"#,
        )
        .await;
        let m = &mresp["result"];
        assert!(m["exec_total"].as_u64().unwrap() >= 1, "exec_total: {}", m);
        assert!(
            m["exec_success"].as_u64().unwrap() >= 1,
            "exec_success: {}",
            m
        );
        assert!(
            m["execute_duration_sec_avg"].is_number(),
            "execute_duration_sec_avg 应为数字: {}",
            m["execute_duration_sec_avg"]
        );
        assert!(
            m["stdio_bytes_total"].as_u64().is_some(),
            "stdio_bytes_total 应为 u64: {}",
            m["stdio_bytes_total"]
        );
        assert_eq!(m["exec_blocked"], 0);
        assert_eq!(m["rollback_total"], 0);
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn execute_stream_chunks_then_done_over_uds() {
        let sock = tmp_sock("stream");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","id":7,"method":"executor.execute_stream","params":{"command":"echo hi","enable_rollback_snapshot":false}}"#;
        let mut s = UnixStream::connect(&sock).await.unwrap();
        s.write_all((req.to_string() + "\n").as_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new(s);
        let mut buf = Vec::new();
        let mut saw_hi = false;
        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            let line = String::from_utf8_lossy(&buf).trim().to_string();
            if line.is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["id"], 7, "所有帧应共用 id");
            let rtype = v["result"]["type"].as_str().unwrap_or("");
            if rtype == "chunk" {
                if v["result"]["data"].as_str().unwrap_or("").contains("hi") {
                    saw_hi = true;
                }
                continue;
            }
            if rtype == "done" {
                assert_eq!(v["result"]["result"]["exit_code"], 0);
                // stdout 可在 chunk 帧或 done.result.stdout (快 echo 时 done 聚合可能空,
                // 数据在 chunk) — 二者见一即过, 避免流式聚合竞态假失败。
                let done_stdout = v["result"]["result"]["stdout"].as_str().unwrap_or("");
                assert!(
                    saw_hi || done_stdout.contains("hi"),
                    "应在 chunk 或 done.stdout 见 'hi'"
                );
                break;
            }
        }
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn execute_stream_blocked_single_done_frame_over_uds() {
        let sock = tmp_sock("stream-blocked");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","id":9,"method":"executor.execute_stream","params":{"command":"rm -rf /","enable_rollback_snapshot":false}}"#;
        let mut s = UnixStream::connect(&sock).await.unwrap();
        s.write_all((req.to_string() + "\n").as_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new(s);
        let mut buf = Vec::new();
        reader.read_until(b'\n', &mut buf).await.unwrap();
        let v: Value = serde_json::from_str(String::from_utf8_lossy(&buf).trim()).unwrap();
        assert_eq!(v["id"], 9);
        assert_eq!(v["result"]["type"], "done");
        assert_eq!(v["result"]["result"]["exit_code"], -1);
        assert_eq!(v["result"]["result"]["blocked_by_security"], true);
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn telemetry_stream_samples_over_uds() {
        let sock = tmp_sock("telemetry");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","id":11,"method":"executor.telemetry_stream","params":{"interval_ms":20,"max_samples":3}}"#;
        let mut s = UnixStream::connect(&sock).await.unwrap();
        s.write_all((req.to_string() + "\n").as_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new(s);
        let mut buf = Vec::new();
        let mut count = 0;
        loop {
            buf.clear();
            if reader.read_until(b'\n', &mut buf).await.unwrap() == 0 {
                break;
            }
            let line = String::from_utf8_lossy(&buf).trim().to_string();
            if line.is_empty() {
                break;
            }
            let v: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["id"], 11, "遥测帧共用 id");
            assert_eq!(v["result"]["type"], "sample");
            let sample = &v["result"]["sample"];
            assert!(sample["mem_mb"].as_f64().unwrap_or(0.0) >= 0.0);
            assert!(sample["cpu_pct"].as_f64().unwrap_or(-1.0) >= 0.0);
            count += 1;
            if count >= 3 {
                break;
            }
        }
        assert_eq!(count, 3, "应收到 3 帧遥测样本");
        let _ = std::fs::remove_file(&sock);
    }

    // ── v1.5 #14 双向 server-push 测试 ──

    /// 读一行 (用于 subscribe 后持续读推送帧)
    async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Option<Value> {
        let mut buf = Vec::new();
        if reader.read_until(b'\n', &mut buf).await.unwrap() == 0 {
            return None;
        }
        let line = String::from_utf8_lossy(&buf).trim().to_string();
        if line.is_empty() {
            return None;
        }
        serde_json::from_str(&line).ok()
    }

    #[tokio::test]
    async fn subscribe_telemetry_pushes_event_frames() {
        let sock = tmp_sock("sub-telemetry");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let mut s = UnixStream::connect(&sock).await.unwrap();
        s.write_all(
            br#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["telemetry"],"interval_ms":20}}
"#,
        )
        .await
        .unwrap();
        let mut reader = BufReader::new(s);
        // 第一行 = subscribe 响应
        let resp = read_line(&mut reader).await.expect("subscribe 响应");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["ok"], true);
        let sub_id = resp["result"]["subscription_id"]
            .as_str()
            .expect("subscription_id")
            .to_string();
        assert!(sub_id.starts_with("sub-"));
        // 后续行 = server-push notification (无 id, 有 method=executor.event)
        let mut got = 0;
        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                frame = read_line(&mut reader) => {
                    let frame = match frame { Some(f) => f, None => break };
                    assert!(frame.get("id").is_none(), "notification 无 id: {frame}");
                    assert_eq!(frame["method"], "executor.event");
                    assert_eq!(frame["params"]["subscription_id"], sub_id);
                    assert_eq!(frame["params"]["channel"], "telemetry");
                    assert!(frame["params"]["data"]["mem_mb"].as_f64().unwrap_or(-1.0) >= 0.0);
                    got += 1;
                    if got >= 3 { break; }
                }
            }
        }
        assert!(got >= 3, "应收到 >=3 telemetry 推送帧, got={got}");
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn subscribe_missing_channels_returns_32600() {
        let sock = tmp_sock("sub-bad");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{}}"#,
        )
        .await;
        assert_eq!(resp["error"]["code"], -32600);
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn unsubscribe_stops_push_for_that_sub() {
        let sock = tmp_sock("unsub");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let s = UnixStream::connect(&sock).await.unwrap();
        let (rh, mut writer) = s.into_split();
        let mut reader = BufReader::new(rh);
        let req = br#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["telemetry"],"interval_ms":20}}
"#;
        writer.write_all(req).await.unwrap();
        let resp = read_line(&mut reader).await.unwrap();
        let sub_id = resp["result"]["subscription_id"]
            .as_str()
            .unwrap()
            .to_string();
        // 等一帧确认推送在工作
        let first = read_line(&mut reader).await.unwrap();
        assert_eq!(first["params"]["subscription_id"], sub_id);
        // 取消订阅
        let unsub = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"executor.unsubscribe","params":{{"subscription_id":"{sub_id}"}}}}
"#,
        );
        writer.write_all(unsub.as_bytes()).await.unwrap();
        let unsub_resp = read_line(&mut reader).await.unwrap();
        assert_eq!(unsub_resp["id"], 2);
        assert_eq!(unsub_resp["result"]["ok"], true);
        // 取消后短时内不应再收到该 sub 的推送 (遥测源 0 订阅自退)
        // 读 300ms — 最多拿到 0 帧 (源已停); 容忍可能的残留 1 帧
        let mut extra = 0;
        let deadline = tokio::time::sleep(Duration::from_millis(300));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                frame = read_line(&mut reader) => {
                    if frame.is_some() { extra += 1; }
                }
            }
        }
        assert!(extra <= 1, "取消订阅后不应持续推送, extra={extra}");
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn stdio_broadcasts_across_connections() {
        // 连接 A 订阅 stdio (scope=all 跨连接收), 连接 B execute_stream → A 收推送
        // Blocker 10: 默认 own_conn 已隔离跨连接; 显式 all 才全广播。
        let sock = tmp_sock("stdio-bcast");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // 连接 A: subscribe stdio, all=true
        let sa = UnixStream::connect(&sock).await.unwrap();
        let (rha, mut writer_a) = sa.into_split();
        let mut reader_a = BufReader::new(rha);
        let _ = writer_a
            .write_all(
                br#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["stdio"],"all":true}}
"#,
            )
            .await;
        let resp = read_line(&mut reader_a).await.unwrap();
        assert_eq!(resp["result"]["ok"], true);
        let sub_id = resp["result"]["subscription_id"]
            .as_str()
            .unwrap()
            .to_string();
        // 连接 B: execute_stream echo
        let sb = UnixStream::connect(&sock).await.unwrap();
        let (rhb, mut writer_b) = sb.into_split();
        let mut reader_b = BufReader::new(rhb);
        let _ = writer_b.write_all(
            br#"{"jsonrpc":"2.0","id":7,"method":"executor.execute_stream","params":{"command":"echo hi","enable_rollback_snapshot":false}}
"#,
        )
        .await;
        // B 读到自己的 done 帧
        let mut b_done = false;
        // A 应收到 stdio 推送 (chunk 和/或 done)
        let mut a_stdio = false;
        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        let mut buf_b = Vec::new();
        let mut buf_a = Vec::new();
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                r = async {
                    buf_b.clear();
                    let n = reader_b.read_until(b'\n', &mut buf_b).await.unwrap();
                    if n == 0 { return None; }
                    let line = String::from_utf8_lossy(&buf_b).trim().to_string();
                    serde_json::from_str::<Value>(&line).ok()
                } => {
                    match r {
                        Some(v) => {
                            if v["id"] == 7 && v["result"]["type"] == "done" { b_done = true; }
                        }
                        None => break,
                    }
                }
                r = async {
                    buf_a.clear();
                    let n = reader_a.read_until(b'\n', &mut buf_a).await.unwrap();
                    if n == 0 { return None; }
                    let line = String::from_utf8_lossy(&buf_a).trim().to_string();
                    serde_json::from_str::<Value>(&line).ok()
                } => {
                    match r {
                        Some(v) => {
                            if v.get("id").is_none() && v["method"] == "executor.event"
                                && v["params"]["channel"] == "stdio"
                                && v["params"]["subscription_id"] == sub_id {
                                a_stdio = true;
                            }
                        }
                        None => break,
                    }
                }
            }
            if b_done && a_stdio {
                break;
            }
        }
        assert!(b_done, "B 应收到自己 done 帧");
        assert!(a_stdio, "A 应收到 stdio 跨连接推送");
        let _ = std::fs::remove_file(&sock);
    }

    // ── T3 审计修复测试 ──

    #[tokio::test]
    async fn capped_line_rejects_oversize_request() {
        // C-IPC-04: 超 1MB 无换行请求 → ERR_PARSE (-32700) 拒连
        let sock = tmp_sock("capped");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let s = UnixStream::connect(&sock).await.unwrap();
        let (rd, mut wr) = s.into_split();
        // 发 2MB 无换行字节 — 应触发拒连 (server 读到超限即回错误帧 + 断开)
        let blob = vec![b'A'; MAX_LINE_BYTES + 100];
        // 后台写完 (server 消费前 write_all 会阻塞)
        let write_task = tokio::spawn(async move { wr.write_all(&blob).await });
        let mut buf = Vec::new();
        let mut reader = BufReader::new(rd);
        let _ =
            tokio::time::timeout(Duration::from_secs(10), reader.read_until(b'\n', &mut buf)).await;
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("-32700"),
            "超限应回含 -32700 的错误帧: {text}"
        );
        let _ = write_task.await;
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn read_capped_line_rejects_no_newline_flood() {
        // Blocker 7 / 2.10: 无换行洪水 (2MB 无 \n) 应 in-loop 拒连 ERR_PARSE, 不 OOM 不无界缓冲
        let blob = vec![b'A'; MAX_LINE_BYTES + 100];
        let mut reader = BufReader::new(std::io::Cursor::new(blob));
        let res = read_capped_line(&mut reader).await;
        assert_eq!(
            res,
            Err(ERR_PARSE),
            "无换行洪水应回 ERR_PARSE 非 OOM/缓冲到换行"
        );
    }

    #[tokio::test]
    async fn read_capped_line_chunked_under_limit_succeeds() {
        // 分块读: 多次 fill_buf (无换行累积) 到恰 <1MB 后给换行 → 仍 Ok
        let mut blob = vec![b'A'; MAX_LINE_BYTES - 10];
        blob.push(b'\n');
        let mut reader = BufReader::new(std::io::Cursor::new(blob));
        let res = read_capped_line(&mut reader).await;
        assert!(res.is_ok(), "恰 <1MB 行应成功: {res:?}");
        let line = res.unwrap().unwrap();
        assert_eq!(line.len(), MAX_LINE_BYTES - 10);
    }

    #[tokio::test]
    async fn socket_permissions_are_owner_only() {
        // C-IPC-01: socket 权限 0o600 (仅 owner)
        let sock = tmp_sock("perm");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&sock).expect("socket 元数据");
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "socket 权限应为 0o600, 实际 0o{:o}", mode);
        }
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn health_reports_real_ax_trusted() {
        // C-GUI-01: ax_trusted = 真实 AXIsProcessTrusted(), 非硬编码 true
        let sock = tmp_sock("health-ax");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert!(resp["result"]["ax_trusted"].is_boolean());
        // 与直接查询一致
        assert_eq!(
            resp["result"]["ax_trusted"],
            fe_core::gui::GuiController::ax_trusted()
        );
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn subscribe_with_custom_interval_accepted() {
        // M-IPC-01: interval_ms/screenshot_interval_ms 透传, 不报错
        let sock = tmp_sock("sub-interval");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let s = UnixStream::connect(&sock).await.unwrap();
        let (rd, mut wr) = s.into_split();
        wr.write_all(
            br#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["telemetry"],"interval_ms":50,"screenshot_interval_ms":500}}
"#,
        )
        .await
        .unwrap();
        let mut reader = BufReader::new(rd);
        let resp = read_line(&mut reader).await.expect("subscribe 响应");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["ok"], true);
        let sub_id = resp["result"]["subscription_id"]
            .as_str()
            .expect("subscription_id")
            .to_string();
        // 取消订阅, 停源
        let unsub = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"executor.unsubscribe\",\"params\":{{\"subscription_id\":\"{}\"}}}}\n",
            sub_id
        );
        wr.write_all(unsub.as_bytes()).await.unwrap();
        let _ = read_line(&mut reader).await;
        let _ = std::fs::remove_file(&sock);
    }

    // ── Blocker 10 (审计 §2.9 跨租户泄漏) per-sub scope 过滤 ──

    #[tokio::test]
    async fn stdio_own_conn_default_blocks_cross_connection() {
        // 连接 A 默认订阅 stdio (own_conn), 连接 B execute_stream → A 不应收 B 的 stdio。
        // 这是跨租户隔离基线 (审计 §2.9: 旧版全广播致 Agent A 见 Agent B stdout)。
        let sock = tmp_sock("stdio-ownconn");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // 连接 A: subscribe stdio (无 scope 字段 → 默认 own_conn)
        let sa = UnixStream::connect(&sock).await.unwrap();
        let (rha, mut writer_a) = sa.into_split();
        let mut reader_a = BufReader::new(rha);
        let _ = writer_a
            .write_all(
                br#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["stdio"]}}
"#,
            )
            .await;
        let resp = read_line(&mut reader_a).await.unwrap();
        assert_eq!(resp["result"]["ok"], true);
        // 连接 B: execute_stream echo
        let sb = UnixStream::connect(&sock).await.unwrap();
        let (rhb, mut writer_b) = sb.into_split();
        let mut reader_b = BufReader::new(rhb);
        let _ = writer_b
            .write_all(
                br#"{"jsonrpc":"2.0","id":7,"method":"executor.execute_stream","params":{"command":"echo hi","enable_rollback_snapshot":false}}
"#,
            )
            .await;
        // B 读到自己 done 帧 (确认命令执行了)
        let mut b_done = false;
        let mut a_got_stdio = false;
        let deadline = tokio::time::sleep(Duration::from_secs(3));
        tokio::pin!(deadline);
        let mut buf_b = Vec::new();
        let mut buf_a = Vec::new();
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                r = async {
                    buf_b.clear();
                    let n = reader_b.read_until(b'\n', &mut buf_b).await.unwrap();
                    if n == 0 { return None; }
                    let line = String::from_utf8_lossy(&buf_b).trim().to_string();
                    serde_json::from_str::<Value>(&line).ok()
                } => {
                    if let Some(v) = r {
                        if v["id"] == 7 && v["result"]["type"] == "done" { b_done = true; }
                    } else { break; }
                }
                r = async {
                    buf_a.clear();
                    let n = reader_a.read_until(b'\n', &mut buf_a).await.unwrap();
                    if n == 0 { return None; }
                    let line = String::from_utf8_lossy(&buf_a).trim().to_string();
                    serde_json::from_str::<Value>(&line).ok()
                } => {
                    if let Some(v) = r {
                        if v.get("id").is_none() && v["method"] == "executor.event"
                            && v["params"]["channel"] == "stdio" {
                            a_got_stdio = true;
                        }
                    } else { break; }
                }
            }
            if b_done {
                // 命令已完成, 给 A 一小窗确认无推送后退出
                tokio::time::sleep(Duration::from_millis(200)).await;
                break;
            }
        }
        assert!(b_done, "B 应收到自己 done 帧");
        assert!(!a_got_stdio, "默认 own_conn 应拦截跨连接 stdio (审计 §2.9)");
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn stdio_task_ids_whitelist_receives_matched() {
        // 连接 A 订阅 stdio task_ids=["t1"], 连接 B execute_stream task_id="t1" → A 收推送。
        let sock = tmp_sock("stdio-taskids");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // 连接 A: subscribe stdio, task_ids=["t1"]
        let sa = UnixStream::connect(&sock).await.unwrap();
        let (rha, mut writer_a) = sa.into_split();
        let mut reader_a = BufReader::new(rha);
        let _ = writer_a
            .write_all(
                br#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["stdio"],"task_ids":["t1"]}}
"#,
            )
            .await;
        let resp = read_line(&mut reader_a).await.unwrap();
        assert_eq!(resp["result"]["ok"], true);
        // 连接 B: execute_stream echo, task_id="t1"
        let sb = UnixStream::connect(&sock).await.unwrap();
        let (rhb, mut writer_b) = sb.into_split();
        let mut reader_b = BufReader::new(rhb);
        let _ = writer_b
            .write_all(
                br#"{"jsonrpc":"2.0","id":7,"method":"executor.execute_stream","params":{"command":"echo hi","task_id":"t1","enable_rollback_snapshot":false}}
"#,
            )
            .await;
        let mut b_done = false;
        let mut a_stdio = false;
        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        let mut buf_b = Vec::new();
        let mut buf_a = Vec::new();
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                r = async {
                    buf_b.clear();
                    let n = reader_b.read_until(b'\n', &mut buf_b).await.unwrap();
                    if n == 0 { return None; }
                    serde_json::from_str::<Value>(String::from_utf8_lossy(&buf_b).trim()).ok()
                } => {
                    if let Some(v) = r {
                        if v["id"] == 7 && v["result"]["type"] == "done" { b_done = true; }
                    } else { break; }
                }
                r = async {
                    buf_a.clear();
                    let n = reader_a.read_until(b'\n', &mut buf_a).await.unwrap();
                    if n == 0 { return None; }
                    serde_json::from_str::<Value>(String::from_utf8_lossy(&buf_a).trim()).ok()
                } => {
                    if let Some(v) = r {
                        if v.get("id").is_none() && v["method"] == "executor.event"
                            && v["params"]["channel"] == "stdio" {
                            a_stdio = true;
                        }
                    } else { break; }
                }
            }
            if b_done && a_stdio {
                break;
            }
        }
        assert!(b_done, "B 应收到自己 done 帧");
        assert!(a_stdio, "task_ids 白名单匹配应收到 stdio 推送");
        let _ = std::fs::remove_file(&sock);
    }

    // Issue #1: 后台 shell 启停轮询 over UDS — shell_start→shell_output→kill_shell→list_shells
    #[tokio::test]
    async fn shell_start_output_kill_list_over_uds() {
        let sock = tmp_sock("shell");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();

        // 启动长任务
        let start = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.shell_start","params":{"command":"python3 -c 'import time; time.sleep(30)'"}}"#,
        )
        .await;
        assert_eq!(start["result"]["ok"], true);
        let sid = start["result"]["shell_id"].as_str().unwrap().to_string();
        assert!(sid.starts_with("sh-"));

        // 轮询: 运行中, 无 exit_code
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let out = rpc(
            &sock,
            &format!(
                r#"{{"jsonrpc":"2.0","id":2,"method":"executor.shell_output","params":{{"shell_id":"{}"}}}}"#,
                sid
            ),
        )
        .await;
        assert_eq!(out["result"]["shell_id"], sid);
        assert_eq!(out["result"]["running"], true);
        assert!(out["result"]["exit_code"].is_null());

        // kill
        let kill = rpc(
            &sock,
            &format!(
                r#"{{"jsonrpc":"2.0","id":3,"method":"executor.kill_shell","params":{{"shell_id":"{}"}}}}"#,
                sid
            ),
        )
        .await;
        assert_eq!(kill["result"]["ok"], true);

        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        let after = rpc(
            &sock,
            &format!(
                r#"{{"jsonrpc":"2.0","id":4,"method":"executor.shell_output","params":{{"shell_id":"{}"}}}}"#,
                sid
            ),
        )
        .await;
        assert_eq!(after["result"]["running"], false, "kill 后应结束");

        // list_shells 含本 shell
        let list = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":5,"method":"executor.list_shells","params":{}}"#,
        )
        .await;
        assert!(list["result"].is_array());
        let arr = list["result"].as_array().unwrap();
        assert!(arr.iter().any(|e| e["shell_id"] == sid));

        // 拦截: rm -rf / → blocked_by_security, shell_id null
        let blocked = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":6,"method":"executor.shell_start","params":{"command":"rm -rf /"}}"#,
        )
        .await;
        assert_eq!(blocked["result"]["ok"], false);
        assert_eq!(blocked["result"]["blocked_by_security"], true);
        assert!(blocked["result"]["shell_id"].is_null());

        let _ = std::fs::remove_file(&sock);
    }

    // C-OPS-04: executor.shutdown IPC 触发 hub.shutdown.notify_waiters() →
    // accept_loop 退出 + drain in-flight。响应应为 {ok:true, shutting_down:true}。
    // serve 的 join handle 应在 deadline 内完成 (accept_loop 返回)。
    #[tokio::test]
    async fn shutdown_ipc_triggers_graceful_drain() {
        let sock = tmp_sock("shutdown");
        let server = IpcServer::new();
        let (_tx, join) = server.serve(&sock).await.unwrap();
        // 先 health 确认 server 活
        let h = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert_eq!(h["result"]["ok"], true);
        // 触发 shutdown
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"executor.shutdown","params":{}}"#,
        )
        .await;
        assert_eq!(resp["result"]["ok"], true);
        assert_eq!(resp["result"]["shutting_down"], true);
        // accept_loop 退出 → serve join 在 deadline 内完成 (drain 空连接秒退)
        let done = tokio::time::timeout(SHUTDOWN_DEADLINE, join).await;
        assert!(
            done.is_ok(),
            "serve join 应在 SHUTDOWN_DEADLINE 内完成 (drain 后)"
        );
        // socket 文件应被 serve 清理
        assert!(!Path::new(&sock).exists(), "shutdown 后 sock 应被清理");
    }

    // C-OPS-03: in-flight 连接在 shutdown 时被 drain (join 完成, 非孤儿)。
    // 起一个 sleep 长命令 → 触发 shutdown → drain 超时 abort 该连接 (其内子进程
    // 由 sandbox 退出 kill)。验证: serve join 在 deadline+缓冲 内完成。
    #[tokio::test]
    async fn shutdown_drains_inflight_connection() {
        let sock = tmp_sock("drain");
        let server = IpcServer::new();
        let (_tx, join) = server.serve(&sock).await.unwrap();
        // 起长命令 (sleep 30s, 不等响应 — 慢请求占连接)
        let mut long_conn = UnixStream::connect(&sock).await.unwrap();
        long_conn
            .write_all(
                (r#"{"jsonrpc":"2.0","id":1,"method":"executor.execute","params":{"command":"python3 -c 'import time; time.sleep(30)'","timeout_sec":30}}"#
                    .to_string()
                    + "\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        // 确认命令已派发 (health 走另一连接)
        let h = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert_eq!(h["result"]["ok"], true);
        // 触发 shutdown → drain in-flight (长命令连接超 10s → abort)
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":3,"method":"executor.shutdown","params":{}}"#,
        )
        .await;
        assert_eq!(resp["result"]["shutting_down"], true);
        // drain deadline 10s + abort 缓冲: serve join 应在 ~12s 内完成
        let done = tokio::time::timeout(Duration::from_secs(12), join).await;
        assert!(
            done.is_ok(),
            "serve join 应在 drain deadline+缓冲内完成 (in-flight abort 后)"
        );
        drop(long_conn);
        let _ = std::fs::remove_file(&sock);
    }

    // M-SEC-01: LOCAL_PEERCRED UID 校验 — 同 UID 连接应放行 (CI 进程同 UID connect 自己)。
    // 跨 UID 拒绝需不同 UID 进程, 非单测可行 (记于 README/审计报告)。
    // 此测验证: (1) peer_uid_matches 对真实同 UID stream 返 true;
    //          (2) ensure_sock_dir 建私有 0o700 目录;
    //          (3) default_sock_path 落在 HOME/.fusion-executor/fe.sock (非 /tmp)。
    #[tokio::test]
    async fn msec01_peer_uid_same_uid_allowed() {
        // (1) 同 UID stream 放行
        let sock = tmp_sock("msec01");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let connect_task = tokio::spawn({
            let s = sock.clone();
            async move {
                let _ = UnixStream::connect(&s).await.unwrap();
            }
        });
        let (stream, _) = listener.accept().await.unwrap();
        assert!(
            peer_uid_matches(&stream),
            "M-SEC-01: 同 UID 连接应被 LOCAL_PEERCRED 放行"
        );
        connect_task.await.unwrap();
        let _ = std::fs::remove_file(&sock);

        // (2) default_sock_path 落在 HOME 私有目录, 非 /tmp (m-OPS-01 + M-SEC-01)
        let def = default_sock_path();
        assert!(
            !def.starts_with("/tmp/"),
            "M-SEC-01/m-OPS-01: 默认 socket 不应落在全局可扫描 /tmp: {}",
            def
        );
        assert!(
            def.ends_with(DEFAULT_SOCK_NAME),
            "默认 socket 应以 {} 结尾: {}",
            DEFAULT_SOCK_NAME,
            def
        );

        // (3) ensure_sock_dir 在不存在的 HOME 下子目录建 0o700 私有目录
        let probe = std::env::temp_dir()
            .join(format!("fe-msec01-probe-{}", std::process::id()))
            .join("subdir")
            .join("fe.sock");
        ensure_sock_dir(&probe);
        let parent = probe.parent().unwrap();
        assert!(parent.exists(), "ensure_sock_dir 应建父目录");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(parent).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o700,
                "M-SEC-01: 私有 socket 目录应 0o700, 实际 {:#o}",
                mode
            );
        }
        let _ = std::fs::remove_dir_all(parent);
    }

    // M-SEC-01/m-OPS-01: 默认 socket 路径 (~/.fusion-executor/fe.sock) serve 能起 —
    // 捕获 bind-before-mkdir 顺序 bug: ensure_sock_dir 必须在 UnixListener::bind 前,
    // 否则父目录不存在时 bind 失败。隔离 HOME 到 tempdir, 走真实 default_sock_path。
    #[tokio::test]
    async fn msec01_default_sock_dir_serve_works() {
        let fake_home = std::env::temp_dir().join(format!("fe-msec01-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fake_home);
        std::fs::create_dir_all(&fake_home).unwrap();
        // 注入 HOME (default_sock_path 读 HOME), 测试结束恢复
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &fake_home);

        let sock = IpcServer::resolve_sock(None);
        assert!(
            sock.starts_with(fake_home.display().to_string().as_str()),
            "resolve_sock(None) 应落在隔离 HOME 下: {}",
            sock
        );
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert_eq!(resp["result"]["ok"], true);

        // 私有目录权限 0o700
        let dir = Path::new(&sock).parent().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "私有 socket 目录应 0o700, 实际 {:#o}", mode);
        }

        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&fake_home);
        match old_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
}
