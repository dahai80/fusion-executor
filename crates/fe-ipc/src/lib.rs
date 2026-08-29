// fe-ipc — UDS JSON-RPC 2.0 server (P3) + 双向 server-push (v1.5 #14)
//
// Socket /tmp/fusion-executor.sock (override FUSION_EXECUTOR_SOCK), 换行分隔
// Mirror fusion-cowork/fusion_cowork/server/desk_rpc.py 协议:
//   line = read_line(); 响应 = serde_json::to_string(resp) + "\n"
//   jsonrpc "2.0", id 透传; 错误码 -32700(parse)/-32600(invalid req)/-32601(method)/-32603(internal)
//   扩展: -32010 安全拦截, -32011 超时, -32012 回滚失败, -32013 AX 未授权
// 匹配 fusion-studio IPCClient.swift: 按字节读到 0x0A, 8s 超时
//
// 方法: executor.health/execute/execute_stream/telemetry_stream/snapshot_create/list_snapshots/rollback/gui_action/diagnostics
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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::Result;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Semaphore};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

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
/// RUN-3: 并发 **流式执行** 上限 — 与非流式 exec_sem (16) 分离。
/// 流式 (execute_stream) 持 permit 跨整 chunk→done 生命周期; 若共用 exec_sem (16),
/// 16 长流占满 permit → 短 execute 命令饿死。独立 stream_sem 容量 = MAX_CONNECTIONS (64),
/// 流式按连接数上限 (连接信号量已限总连接), 不与非流式短执行争抢。
const MAX_CONCURRENT_STREAMS: usize = MAX_CONNECTIONS;
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

/// D6-02: execute 墙钟直方图固定桶上界 (秒)。+Inf 末桶不计入数组 (独立 total = exec_total)。
/// 桶选型覆盖 CLI 沙箱典型档: <5ms init / <50ms 快命令 / <500ms 编译 / <5s 测试套 / <30s 长跑 / +Inf 尾部。
const DURATION_BUCKETS_LE: [f64; 5] = [0.005, 0.05, 0.5, 5.0, 30.0];

/// D6-02: 墙钟 (秒) → 桶下标; 越过所有有限桶 → None (落入 +Inf 末桶, 不递增数组)。
fn duration_bucket_index(sec: f64) -> Option<usize> {
    for (i, le) in DURATION_BUCKETS_LE.iter().enumerate() {
        if sec <= *le {
            return Some(i);
        }
    }
    None
}

/// D6-02: histogram_quantile 插值 — 累计计数数组 (每桶含自身及更小) → 分位值 (秒)。
/// q ∈ [0,1]。线性插值跨相邻桶 (Prometheus _quantile_ 约定)。空/不足 → 0.0。
fn histogram_quantile(cumulative: &[u64], q: f64) -> f64 {
    let total = cumulative.last().copied().unwrap_or(0);
    if total == 0 {
        return 0.0;
    }
    let target = (total as f64) * q.clamp(0.0, 1.0);
    for i in 0..cumulative.len() {
        if (cumulative[i] as f64) >= target {
            if i == 0 {
                return DURATION_BUCKETS_LE.first().copied().unwrap_or(0.0);
            }
            let prev = cumulative[i - 1] as f64;
            let cur = cumulative[i] as f64;
            if cur <= prev {
                return DURATION_BUCKETS_LE[i];
            }
            let lo = if i == 1 {
                0.0
            } else {
                DURATION_BUCKETS_LE[i - 2]
            };
            let hi = DURATION_BUCKETS_LE[i - 1];
            let frac = (target - prev) / (cur - prev);
            return lo + (hi - lo) * frac;
        }
    }
    // q 落在 +Inf 末桶 (超过所有有限桶累计) → 返回最大有限上界 (保守, 不假装无限)。
    DURATION_BUCKETS_LE.last().copied().unwrap_or(0.0)
}

/// M-OPS-02: Prometheus recorder handle — global, idempotent 安装。
/// metrics-exporter-prometheus 的 PrometheusBuilder::install() 安装全局 recorder,
/// 返 PrometheusHandle (render() 出 Prometheus text format 供 scrape)。
/// install 幂等: 重复调返 Err, 我们吞掉 — 首次成功后全局 recorder 已就位。
static PROM_HANDLE: OnceLock<Option<PrometheusHandle>> = OnceLock::new();

/// 安装 Prometheus recorder (幂等) 并返 handle 克隆; 已装则从 static 取。
/// describe_counter 让 render() 带 HELP/TYPE 头 (无观测值时也有 schema)。
/// ARCH-4: pub 化 — 进程内路径 (fe-pyo3 execute_sync, 不经 fe-ipc/BroadcastHub)
/// 也须装 recorder, 否则 record_exec_outcome 的 metrics::counter! 无 recorder = no-op。
/// 幂等 (OnceLock), 多调安全。
pub fn install_prometheus_recorder() -> Option<PrometheusHandle> {
    PROM_HANDLE
        .get_or_init(|| {
            // D6-02: 配置直方图桶与 DURATION_BUCKETS_LE 对齐 — render() 出 _bucket{le=...} 行。
            // set_buckets_for_metric 消费 self 返 Result<PrometheusBuilder, BuildError>;
            // .ok()? 转 Option<PrometheusBuilder> (空桶→BuildError→None, 降级仅 JSON)。
            let builder = PrometheusBuilder::new()
                .set_buckets_for_metric(
                    Matcher::Prefix("fe_exec_duration".to_string()),
                    &DURATION_BUCKETS_LE,
                )
                .map_err(|e| {
                    warn!(error = %e, "D6-02: set_buckets_for_metric 失败");
                    e
                })
                .ok()?;
            let handle = builder
                .install_recorder()
                .map_err(|e| {
                    warn!(error = %e, "M-OPS-02: Prometheus recorder install 失败");
                    e
                })
                .ok()?;
            metrics::describe_counter!("fe_exec_total", "Total execute() calls");
            metrics::describe_counter!("fe_exec_success", "Executes exited 0");
            metrics::describe_counter!("fe_exec_blocked", "Executes blocked by security");
            metrics::describe_counter!("fe_exec_timeout", "Executes timed out (-124)");
            metrics::describe_counter!("fe_exec_failed", "Executes failed (non-0/timeout/blocked)");
            metrics::describe_counter!("fe_rollback_total", "Total rollback() calls");
            metrics::describe_counter!("fe_rollback_failed", "Rollback failures");
            metrics::describe_histogram!(
                "fe_exec_duration_seconds",
                "Execute() wall-clock duration (seconds)"
            );
            metrics::describe_gauge!("fe_shell_active", "Active background shells");
            metrics::describe_gauge!("fe_connections", "Active UDS connections");
            // D4-9: 非流式 exec_sem 可用许可 — LB/运维面板据此判饱和 (0=满载分流)。与 health
            // response available_permits 同源; Prometheus exporter 镜像成 gauge 供 scrape。
            metrics::describe_gauge!("fe_exec_sem_available", "Available exec semaphore permits");
            Some(handle)
        })
        .clone()
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
    /// 0827 C-9: 源生命周期代数 — subscribe 该通道时 fetch_add, 源任务启动捕获本代。
    /// 源任务 0 订阅拟退出时重比对: 若代未变 (无新订阅进入) 才真退; 代变 (中途有新订阅) 续跑。
    /// 破旧版竞态: 源 0 订阅 break + trailing take() vs 并发 subscribe ensure 见 slot=running 早 return → 源不启。
    telemetry_gen: AtomicU64,
    screenshot_gen: AtomicU64,
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
    /// D6-02: execute 墙钟固定桶直方图 (ns) — p50/p95/p99 经 histogram_quantile 插值。
    /// 6 桶上界 (秒): 0.005 / 0.05 / 0.5 / 5 / 30 / +Inf。AtomicU64 无锁, snapshot 累加走桶。
    exec_duration_buckets: [AtomicU64; DURATION_BUCKETS_LE.len()],
    /// D6-02: 墙钟 min/max (ns) — 单次最快/最慢, 配合直方图看尾部分布。
    exec_duration_nanos_min: AtomicU64,
    exec_duration_nanos_max: AtomicU64,
    /// M-OPS-02: Prometheus handle — render() 出 text format 供 executor.metrics_prometheus。
    /// None = recorder install 失败 (降级: 仅 JSON snapshot, 无 prometheus 端点)。
    prom_handle: Option<PrometheusHandle>,
}

impl BroadcastHub {
    fn new(executor: Arc<Executor>) -> Arc<Self> {
        Arc::new(Self {
            registry: Mutex::new(HashMap::new()),
            executor,
            conn_counter: AtomicU64::new(1),
            active_conns: AtomicU64::new(0),
            sub_counter: AtomicU64::new(1),
            telemetry_gen: AtomicU64::new(0),
            screenshot_gen: AtomicU64::new(0),
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
            exec_duration_buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            exec_duration_nanos_min: AtomicU64::new(u64::MAX),
            exec_duration_nanos_max: AtomicU64::new(0),
            prom_handle: install_prometheus_recorder(),
        })
    }

    /// C-OPS-05: 记一次 execute 结果 → 原子累加指标。
    /// exit_code 0=success, -124=timeout, -1=blocked/internal, 其他=failed。
    fn record_exec(&self, r: &ExecutionResult) {
        self.exec_total.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("fe_exec_total").increment(1);
        if r.blocked_by_security {
            self.exec_blocked.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("fe_exec_blocked").increment(1);
        } else if r.timed_out || r.exit_code == -124 {
            self.exec_timeout.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("fe_exec_timeout").increment(1);
        } else if r.exit_code == 0 {
            self.exec_success.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("fe_exec_success").increment(1);
        } else {
            self.exec_failed.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("fe_exec_failed").increment(1);
        }
        // 墙钟 (duration_sec 秒 → ns; f64 截断到 u64 纳秒, 累加溢出极不可能 — u64 ns ≈ 584 年)
        let dur_ns = (r.duration_sec.max(0.0) * 1e9) as u64;
        self.exec_duration_nanos_sum
            .fetch_add(dur_ns, Ordering::Relaxed);
        // stdio 字节 (stdout+stderr 截断后长度 — 真实传输量)
        let bytes = (r.stdout.len() + r.stderr.len()) as u64;
        self.stdio_bytes_sum.fetch_add(bytes, Ordering::Relaxed);
        // D6-02: 墙钟直方图 (blocked/timeout duration=0 落首桶; 真实墙钟按桶上界分档)。
        let dur_sec = r.duration_sec.max(0.0);
        if let Some(i) = duration_bucket_index(dur_sec) {
            self.exec_duration_buckets[i].fetch_add(1, Ordering::Relaxed);
        }
        // min/max (CAS 循环: 无锁更新, 无混叠)
        if dur_ns < self.exec_duration_nanos_min.load(Ordering::Relaxed) {
            let mut cur = self.exec_duration_nanos_min.load(Ordering::Relaxed);
            while dur_ns < cur {
                match self.exec_duration_nanos_min.compare_exchange_weak(
                    cur,
                    dur_ns,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(v) => cur = v,
                }
            }
        }
        let mut cur_max = self.exec_duration_nanos_max.load(Ordering::Relaxed);
        while dur_ns > cur_max {
            match self.exec_duration_nanos_max.compare_exchange_weak(
                cur_max,
                dur_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => cur_max = v,
            }
        }
        // D6-02: 镜像进 Prometheus 直方图 (render() 出 _bucket{le=...})。
        metrics::histogram!("fe_exec_duration_seconds").record(dur_sec);
    }

    /// C-OPS-05: 记一次 rollback — ok=true 算 total, false 算 total+failed
    fn record_rollback(&self, ok: bool) {
        self.rollback_total.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("fe_rollback_total").increment(1);
        if !ok {
            self.rollback_failed.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("fe_rollback_failed").increment(1);
        }
    }

    /// C-OPS-05: 指标快照 — 转为 JSON 给 executor.metrics handler。
    /// 均值用 exec_total 算 (blocked/timeout 不计 duration — 它们 duration_sec=0)。
    /// D6-02: 墙钟直方图 — 累计计数 (每桶含自身及更小) → histogram_quantile 插值 p50/p95/p99。
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
        // D6-02: 累计计数 — cumulative[i] = 桶 0..=i 原子求和, 末位 = total (含 +Inf)。
        let per_bucket: Vec<u64> = self
            .exec_duration_buckets
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect();
        let mut cumulative: Vec<u64> = Vec::with_capacity(per_bucket.len() + 1);
        let mut acc = 0u64;
        for c in &per_bucket {
            acc += c;
            cumulative.push(acc);
        }
        cumulative.push(total); // +Inf 末桶 = 全部 execute
        let p50 = histogram_quantile(&cumulative, 0.5);
        let p95 = histogram_quantile(&cumulative, 0.95);
        let p99 = histogram_quantile(&cumulative, 0.99);
        let min_sec = {
            let m = self.exec_duration_nanos_min.load(Ordering::Relaxed);
            if m == u64::MAX {
                0.0
            } else {
                (m as f64) / 1e9
            }
        };
        let max_sec = (self.exec_duration_nanos_max.load(Ordering::Relaxed) as f64) / 1e9;
        json!({
            "exec_total": total,
            "exec_success": self.exec_success.load(Ordering::Relaxed),
            "exec_blocked": self.exec_blocked.load(Ordering::Relaxed),
            "exec_timeout": self.exec_timeout.load(Ordering::Relaxed),
            "exec_failed": self.exec_failed.load(Ordering::Relaxed),
            "execute_duration_sec_avg": avg_dur_sec,
            "execute_duration_sec_min": min_sec,
            "execute_duration_sec_max": max_sec,
            "execute_duration_sec_p50": p50,
            "execute_duration_sec_p95": p95,
            "execute_duration_sec_p99": p99,
            "execute_duration_buckets": per_bucket,
            "execute_duration_bucket_le": DURATION_BUCKETS_LE,
            "stdio_bytes_total": stdio_sum,
            "stdio_bytes_avg": avg_stdio_bytes,
            "rollback_total": self.rollback_total.load(Ordering::Relaxed),
            "rollback_failed": self.rollback_failed.load(Ordering::Relaxed),
        })
    }

    /// M-OPS-02: Prometheus text format — render() 出 scrape 文本给 executor.metrics_prometheus。
    /// recorder install 失败 → None → handler 返 -32603 (降级, 仅 JSON snapshot 可用)。
    /// 不开 HTTP 端口 (保 M-SEC-01 UDS-only); 调用方经 UDS 拉 text 喂自家 exporter。
    fn metrics_prometheus(&self) -> Option<String> {
        self.prom_handle.as_ref().map(|h| h.render())
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
        // C-9: insert + gen bump 同一 registry 锁内 — 源任务重比对 gen 时见最新代, 续跑不误退。
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
        // gen bump 在锁外 (AtomicU64, 顺序保证: insert 先于 bump; 源任务读 gen≥本值见新订阅)。
        if has_telemetry {
            self.telemetry_gen.fetch_add(1, Ordering::SeqCst);
        }
        if has_screenshot {
            self.screenshot_gen.fetch_add(1, Ordering::SeqCst);
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
        metrics::gauge!("fe_connections").set(self.active_conns.load(Ordering::Relaxed) as f64);
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
    /// 0827 C-9: 启动时捕获本代 gen — 源任务 0 订阅拟退时重比对 gen, 变化则续跑 (见 run_telemetry_source)。
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
        let gen = self.telemetry_gen.load(Ordering::SeqCst);
        let hub = self.clone();
        let handle = tokio::spawn(async move {
            hub.run_telemetry_source(effective, gen).await;
            hub.telemetry_task
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        });
        *slot = Some(handle);
        info!(interval_ms = effective, gen, "遥测源任务启动");
    }

    /// 确保截图源任务运行 — 同 telemetry 逻辑 (C-IPC-02/03)。
    /// screenshot_interval_ms 由调用方传入 (M-IPC-01)。
    /// 0827 C-9: 同 telemetry, 启动捕获 gen 供 run_screenshot_source 重比对。
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
        let gen = self.screenshot_gen.load(Ordering::SeqCst);
        let hub = self.clone();
        let handle = tokio::spawn(async move {
            hub.run_screenshot_source(effective, gen).await;
            hub.screenshot_task
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
        });
        *slot = Some(handle);
        info!(interval_ms = effective, gen, "截图源任务启动");
    }

    /// 遥测源 — executor.telemetry_stream 单流扇出, 0 订阅自退。
    /// 0827 C-9: 0 订阅拟退前重比对 gen — gen 变 (中途有新 telemetry 订阅) 则续跑, 不误退漏帧。
    async fn run_telemetry_source(&self, interval_ms: u64, start_gen: u64) {
        let cfg = TelemetryStreamConfig {
            interval_ms,
            max_samples: 0,
            // L-15: 广播源采样 executor 自身 (聚合视图), 不绑特定子进程 PID
            pid: None,
        };
        let (mut rx, handle) = self.executor.telemetry_stream(cfg);
        while let Some(sample) = rx.recv().await {
            let targets = self.collect_targets(CH_TELEMETRY);
            if targets.is_empty() {
                // C-9: 重比对 gen — 变化表示 0 订阅判断后又有新订阅进入, 续跑不退。
                let cur_gen = self.telemetry_gen.load(Ordering::SeqCst);
                if cur_gen != start_gen {
                    info!(
                        start_gen,
                        cur_gen, "遥测 0 订阅但 gen 变 (新订阅进入), 续跑"
                    );
                    continue;
                }
                info!(gen = cur_gen, "遥测 0 订阅且 gen 未变, 源任务自退");
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
    /// 0827 C-9: 0 订阅拟退前重比对 gen — gen 变 (中途有新 screenshot 订阅) 则续跑, 不误退漏帧。
    async fn run_screenshot_source(&self, interval_ms: u64, start_gen: u64) {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
        interval.tick().await;
        loop {
            interval.tick().await;
            let targets = self.collect_targets(CH_SCREENSHOT);
            if targets.is_empty() {
                // C-9: 重比对 gen — 变化表示 0 订阅判断后又有新订阅进入, 续跑不退。
                let cur_gen = self.screenshot_gen.load(Ordering::SeqCst);
                if cur_gen != start_gen {
                    info!(
                        start_gen,
                        cur_gen, "截图 0 订阅但 gen 变 (新订阅进入), 续跑"
                    );
                    continue;
                }
                info!(gen = cur_gen, "截图 0 订阅且 gen 未变, 源任务自退");
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
        // D4-4: 快路径 — 0 stdio 订阅时跳过 task_id 提取 + 逐订阅 frame 构建 (避免无订阅时
        // 仍锁 registry 建 Vec + clone Value)。collect_targets 空即无订阅, 直接返回零工作。
        let targets = self.collect_targets(CH_STDIO);
        if targets.is_empty() {
            return;
        }
        let task_id = data
            .get("task_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
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

    /// A-4: 共享调用方已持有的 Executor Arc — fe-pyo3 serve() 不再重建 Executor。
    /// 调用方先在进程内用 with_extra_whitelist 配的白名单 + SIGHUP 重载的 extras 跨 serve-path 持久
    /// (旧版 with_executor_and_shells 取 owned Executor 再 Arc::new, serve 重建丢 in-process 白名单)。
    /// registry 同 M-ARCH-1 共享。三参全 Arc — 与 serve()/serve_blocking() 取 self.executor.clone() 兼容。
    pub fn with_executor_arc_and_shells(
        executor: Arc<Executor>,
        shells: Arc<fe_core::shell::ShellRegistry>,
    ) -> Self {
        info!("IpcServer::with_executor_arc_and_shells() — 共享 Executor Arc + ShellRegistry");
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
        // C-10: 先建 + 收紧父目录 0o700, 再 bind — 消除 bind→chmod 间窗口。
        // ensure_sock_dir 内对已存在目录也收紧权限 (旧版早 return 跳过 = 残留宽松目录)。
        // D3-8: 权限收紧失败 → fail-loud, serve 拒绝启动 (世界可读写 socket = M-SEC-01 绕过)。
        ensure_sock_dir(&path)?;
        let listener = UnixListener::bind(&path)
            .map_err(|e| anyhow::anyhow!("bind {} 失败: {}", path.display(), e))?;
        chmod_secure(&path)?;
        info!(sock = %path.display(), "IPC 服务器监听中");
        // ARCH-1: seatbelt 治理 — execute + shell_start 均默认 true (商用安全默认, 对齐 fe-core serde default_true)。
        // 调用方显式传 seatbelt:false 关闭隔离 (受信本地 opt-out)。
        info!(
            "seatbelt 默认开启 (execute + shell_start 路径) — 子进程经 macOS sandbox-exec 隔离 (禁网 + 危险二进制 execve deny)。受信本地可透传 seatbelt:false opt-out。查 health.seatbelt_default_on"
        );

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let executor = self.executor.clone();
        let hub = self.hub.clone();
        let shells = self.shells.clone();
        // m-OPS-02: SIGHUP 配置热重载任务 — 与 accept_loop 并行, 退出时 abort
        let sighup_task = tokio::spawn(handle_sighup_reload(executor.clone()));
        // M-OPS-03: 运行时可配 drain 超时 (env, 默认 10s)。
        let drain_deadline = resolve_shutdown_timeout();
        let join = tokio::spawn(async move {
            accept_loop(listener, executor, hub, shells, shutdown_rx, drain_deadline).await;
            sighup_task.abort();
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
            ensure_sock_dir(&p)?;
            let listener = UnixListener::bind(&p)
                .map_err(|e| anyhow::anyhow!("bind {} 失败: {}", p.display(), e))?;
            chmod_secure(&p)?;
            info!(sock = %p.display(), "IPC 服务器监听中 (blocking, 信号可停)");
            // ARCH-1: seatbelt 治理 — execute + shell_start 均默认 true (商用安全默认, 对齐 fe-core serde default_true)。
            // 调用方显式传 seatbelt:false 关闭隔离 (受信本地 opt-out)。
            info!(
                "seatbelt 默认开启 (execute + shell_start 路径) — 子进程经 macOS sandbox-exec 隔离 (禁网 + 危险二进制 execve deny)。受信本地可透传 seatbelt:false opt-out。查 health.seatbelt_default_on"
            );
            let (_tx, rx) = oneshot::channel::<()>();
            // 信号任务: 收 SIGINT/SIGTERM → notify_waiters, accept_loop 自行退出并 drain
            let signal_task = tokio::spawn(wait_signal_and_notify(hub.clone()));
            // m-OPS-02: SIGHUP 配置热重载任务 — 重载日志级别 + 白名单 (不触发退出)
            let sighup_task = tokio::spawn(handle_sighup_reload(executor.clone()));
            // M-OPS-03: 运行时可配 drain 超时 (env, 默认 10s)。
            let drain_deadline = resolve_shutdown_timeout();
            // accept_loop 运行至 shutdown_notify (信号) 或 shutdown_rx 触发, 内部 drain in-flight
            accept_loop(listener, executor, hub, shells, rx, drain_deadline).await;
            signal_task.abort();
            sighup_task.abort();
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

/// m-OPS-02: SIGHUP 配置热重载 — 重读 RUST_LOG (日志级别) + FUSION_EXECUTOR_EXTRA_WHITELIST (白名单)。
/// 与 wait_signal_and_notify 并列 (后者管 SIGINT/SIGTERM 退出; SIGHUP 不退出, 仅重载)。
/// 无配置 → no-op (不报错); tracing 未 init → 跳过日志重载; env 缺失 → 跳过白名单重载。
/// 遵守 Executor 无状态约定: executor: Arc<Executor> 经 reload_whitelist(&self) 透传 ArcSwap store。
///
/// IMPL-12 信号竞态断言: 本 handler **永不触发 shutdown** — 不调 hub.shutdown.notify_waiters(),
/// 不清理连接, 不 abort accept_loop。shutdown 单源 = wait_signal_and_notify (SIGINT/SIGTERM)。
/// SIGHUP 仅重载配置, server 继续服务。竞态面 = 单源 shutdown, SIGHUP 与退出正交。测试覆盖见
/// tests::sighup_does_not_trigger_shutdown。
async fn handle_sighup_reload(executor: Arc<Executor>) {
    #[cfg(unix)]
    {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "SIGHUP 注册失败, 配置热重载不可用");
                return;
            }
        };
        loop {
            sighup.recv().await;
            info!("收到 SIGHUP, 重载配置 (日志级别 + 白名单)");
            reload_log_level();
            reload_extra_whitelist(&executor);
        }
    }
    #[cfg(not(unix))]
    {
        // 非 unix 无 SIGHUP — 永久挂起 (不耗 CPU)。
        std::future::pending::<()>().await;
    }
}

/// SIGHUP: 重读 RUST_LOG env, 经 FilterHandle.reload_log_filter 换日志级别。
/// 未设 RUST_LOG → 回退 DEFAULT_FILTER_DIRECTIVE (info); tracing 未 init (handle None) → 跳过。
fn reload_log_level() {
    let directive = std::env::var("RUST_LOG")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| logging::DEFAULT_FILTER_DIRECTIVE.to_string());
    match logging::current_handle() {
        Some(handle) => match handle.reload_log_filter(&directive) {
            Ok(()) => info!(directive = %directive, "SIGHUP 日志级别重载完成"),
            Err(e) => warn!(error = %e, "SIGHUP 日志级别重载失败 (fail-loud, 当前级别不变)"),
        },
        None => warn!("SIGHUP 日志重载: tracing 未初始化, 跳过 (init_tracing 未调)"),
    }
}

/// SIGHUP: 重读 FUSION_EXECUTOR_EXTRA_WHITELIST env (逗号分割) → Executor.reload_whitelist。
/// 未设 / 空 → 传空切片 (回退纯基线白名单); Executor 透传 SecurityGuard.reload_extras (基线重建)。
fn reload_extra_whitelist(executor: &Arc<Executor>) {
    let extras: Vec<String> = std::env::var("FUSION_EXECUTOR_EXTRA_WHITELIST")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let extras_ref: Vec<&str> = extras.iter().map(|s| s.as_str()).collect();
    executor.reload_whitelist(&extras_ref);
    info!(count = extras.len(), "SIGHUP 白名单重载完成 (基线 + 扩展)");
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
    // 审计 2.11: 执行信号量 — 限并发 **非流式执行** (子进程) 非并发连接。全 server 共享, 与连接信号量解耦。
    let exec_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_EXECS));
    // RUN-3: 流式执行信号量 — 与 exec_sem 分离。流式 permit 跨整 chunk→done (长生命周期),
    // 非流式短 execute 用 exec_sem (16)。分离防 16 长流饿死短命令。
    let stream_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_STREAMS));
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
                        let ss = stream_sem.clone();
                        let handle = tokio::spawn(async move {
                            handle_conn(stream, ex, h, sh, es, ss).await;
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

/// C-OPS-03/M-OPS-03 + 0827 C-8/P-1: 优雅 drain — join 所有 in-flight 连接, deadline 内未完则 abort。
/// deadline 由 serve/serve_blocking 从 FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS 解析 (默认 10s)。
/// C-8 修: (1) 先 drain handles 出锁再放锁 — join/abort 全锁外, 不阻塞 accept_loop 其他路径;
///   (2) **全局 deadline** — 记 start, 每条 handle 用 shrink 的 remain = deadline - elapsed,
///   总耗时 ≤ deadline (旧版 per-handle reset deadline → 64 连接最坏 64×10s = 640s)。
/// &mut h 引用 await (非 move) → 超时分支 h 仍 owned, h.abort() 可调 (drop JoinHandle 仅 detach 不停 task)。
async fn drain_connections(conns: Arc<AsyncMutex<Vec<JoinHandle<()>>>>, deadline: Duration) {
    // C-8: 取出 handles 立即放锁 — 锁外 join/abort。
    let handles: Vec<JoinHandle<()>> = {
        let mut g = conns.lock().await;
        std::mem::take(&mut *g)
    };
    let total = handles.len();
    if total == 0 {
        return;
    }
    info!(
        in_flight = total,
        deadline_secs = deadline.as_secs(),
        "drain in-flight 连接 (全局 deadline, 锁外 join)"
    );
    let start = tokio::time::Instant::now();
    let mut joined_ok = 0usize;
    let mut aborted = 0usize;
    for mut h in handles {
        let elapsed = start.elapsed();
        if elapsed >= deadline {
            // 全局预算已耗尽 — 剩余全部 abort + reap。
            h.abort();
            let _ = h.await;
            aborted += 1;
            continue;
        }
        let remain = deadline - elapsed;
        match tokio::time::timeout(remain, &mut h).await {
            Ok(Ok(())) => joined_ok += 1,
            Ok(Err(e)) => warn!(error = %e, "连接 task join 失败"),
            Err(_) => {
                warn!("连接 drain 全局预算耗尽, abort (强制停)");
                h.abort();
                let _ = h.await;
                aborted += 1;
            }
        }
    }
    if aborted > 0 {
        warn!(aborted, "drain 超时 abort 连接数 (fail-loud)");
    }
    info!(
        in_flight = total,
        drained_ok = joined_ok,
        aborted,
        "drain 完成"
    );
}

/// 单连接处理 — DUPLEX (v1.5 #14):
///   read_task: read_line 分发请求, 响应/流式帧写 locked writer
///   push_task: 读 push_rx, server-push notification 写 locked writer
///   共享 writer = Arc<AsyncMutex<OwnedWriteHalf>>, 行写原子 (锁内 write_all)
///   连接断开 → 清订阅 + close push_task
///
/// 0827 A-6(1) push 通道模型说明 (deferred):
///   每连接单 push_tx (容量 128) 多路复用该连接所有订阅 (telemetry/stdio/screenshot)。
///   风险: 慢消费方 (如 telemetry 帧未读) 占满 128 → 同连接其他通道帧背压。
///   已缓解: 源端 try_send 满即丢 (P-IPC-01, overflow-drop 不阻塞源任务, 不无界占内存),
///   丢帧仅 warn 不崩 (fail-visible)。per-sub 独立通道 multiplex 是更大架构改动 (需
///   push_task 按 sub_id 路由多 rx), 现 try_send 丢帧语义对等 bounded channel, 非安全
///   缺陷, 按 Rule 2 简单优先暂缓。调用方: 慢消费方应开多连接或 own_conn 隔离 stdio。
async fn handle_conn(
    stream: UnixStream,
    executor: Arc<Executor>,
    hub: Arc<BroadcastHub>,
    shells: Arc<fe_core::shell::ShellRegistry>,
    exec_sem: Arc<Semaphore>,
    stream_sem: Arc<Semaphore>,
) {
    let conn_id = hub.next_conn_id();
    hub.active_conns.fetch_add(1, Ordering::Relaxed);
    metrics::gauge!("fe_connections").set(hub.active_conns.load(Ordering::Relaxed) as f64);
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
        let ss = stream_sem.clone();
        let handle = tokio::spawn(async move {
            dispatch_request(
                &w, req_id, method, params, &ex, &h, &sh, conn_id, &ptx, &es, &ss,
            )
            .await;
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
/// execute (非流式) 取 exec_sem permit; execute_stream 取 stream_sem permit (RUN-3 分离, 防长流饿死短命令)。
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
    stream_sem: &Arc<Semaphore>,
) {
    if method == "executor.execute_stream" {
        if let Err(e) =
            handle_execute_stream(writer, id, params, executor, hub, conn_id, stream_sem).await
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
    // L-7 + M-7(1): channels 规范化 + 校验。旧版原样存 (大小写敏感) → "Telemetry" 不匹配
    // 小写 CH_TELEMETRY, 源任务永不启 = 幽灵订阅 (收不到推帧); 未知通道名也静默接受。
    // 修: 统一 to_lowercase, 拒非 {telemetry,stdio,screenshot} 通道名 (-32600, fail-loud)。
    let known_channels = [CH_TELEMETRY, CH_STDIO, CH_SCREENSHOT];
    let channels: HashSet<String> = params
        .get("channels")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                .collect()
        })
        .unwrap_or_default();
    if channels.is_empty() {
        let resp = err_resp(id, ERR_INVALID_REQ, "缺少 channels");
        write_line(writer, resp).await;
        return;
    }
    // M-7(1): 拒未知通道名 (旧版静默接受 → 幽灵订阅)。
    let unknown: Vec<&str> = channels
        .iter()
        .filter(|c| !known_channels.contains(&c.as_str()))
        .map(|s| s.as_str())
        .collect();
    if !unknown.is_empty() {
        let resp = err_resp(
            id,
            ERR_INVALID_REQ,
            &format!(
                "未知通道: {} (合法: telemetry/stdio/screenshot)",
                unknown.join(",")
            ),
        );
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
        // M-7(3): 旧版空 task_ids 静默变空 Tasks 集 (永不匹配 = 死订阅, 收不到任何 stdio, 无信号)。
        // 修: 空 task_ids → fail-loud -32600 (调用方明显误用, 非"无过滤")。
        let set: HashSet<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        if set.is_empty() {
            let resp = err_resp(
                id,
                ERR_INVALID_REQ,
                "task_ids 非空数组 (空集永不匹配, 用 all=true 或省略 task_ids)",
            );
            write_line(writer, resp).await;
            return;
        }
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
    stream_sem: &Arc<Semaphore>,
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
    // RUN-3: 取流式 permit — stream_sem 与非流式 exec_sem 分离 (容量 64 vs 16)。
    // 流式持 permit 跨整 chunk→done 生命周期 (长); 若共用 exec_sem, 16 长流占满 → 短 execute 饿死。
    // stream_sem 容量 = MAX_CONNECTIONS, 受连接信号量上限保护, 不与非流式短执行争抢。
    let _stream_permit = stream_sem
        .acquire()
        .await
        .map_err(|e| anyhow::anyhow!("stream_sem 已关闭: {e}"))?;
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
                // L-6: streaming exec 完成也记指标 — 旧版漏 record_exec, Prometheus
                // fe_exec_total 漏计流式执行 (仅非流式 execute 计)。与非流式 handler 对齐。
                hub.record_exec(&r);
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
/// params: {interval_ms?:u64, max_samples?:u64, pid?:u32} (缺省 10Hz / 无限 / executor pid)
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
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|p| p as u32);
    let cfg = TelemetryStreamConfig {
        interval_ms,
        max_samples,
        pid,
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
            // D2-2 修 (2026-08-28): 旧版 probe_runtime 在 BLOCKING_RT 上 spawn 空任务 + 1s 超时;
            // 16 并发执行饱和 + worker 数有限时, 探针任务排队 → 超时 → rt_ok=false → 误报摘除正常忙碌实例。
            // 新版区分 alive/busy/dead: 短超时 (200ms) 探 BLOCKING_RT 响应 (空闲 worker 立即拾取);
            // 超时再查 exec_sem 可用许可 — 0=饱和 (忙碌但健康, LB 应分流非摘除), >0 仍超时=停摆 (真不健康)。
            let rt = probe_runtime(Duration::from_millis(200), exec_sem.available_permits()).await;
            // D4-9: health 探针同步镜像 exec_sem 可用数成 Prometheus gauge (scrape 路径互补)。
            metrics::gauge!("fe_exec_sem_available").set(exec_sem.available_permits() as f64);
            let deps = probe_dependencies().await;
            // 任一核心依赖缺失 → ok:false (依赖不健康 = 服务降级)
            let deps_ok = deps.iter().all(|d| d["ok"].as_bool() == Some(true));
            // ok 仅在 dead (停摆) 或依赖缺失时 false; busy 仍 ok=true (忙碌是正常负载, 非故障)。
            let ok = rt.healthy() && deps_ok;
            Ok(json!({
                "ok": ok,
                "version": env!("CARGO_PKG_VERSION"),
                "git_sha": env!("FE_GIT_SHA"),
                "build_time": env!("FE_BUILD_TIME"),
                "ax_trusted": fe_core::gui::GuiController::ax_trusted(),
                // ARCH-1: seatbelt 治理信号 — execute + shell_start 均默认 true (商用安全默认)。
                // 负载均衡器/运维查此字段知实例默认开运行时隔离。
                "seatbelt_default_on": true,
                // D2-2: runtime 三态 — alive (空闲响应)/busy (饱和分流)/dead (停摆摘除)。
                // ok=alive||busy; dead → ok=false。busy 供 LB 分流 (非摘除)。
                "runtime": { "ok": rt.healthy(), "state": rt.state(), "available_permits": rt.available_permits },
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
            // D4-9: 取 permit 后镜像可用数成 gauge (permit drop 在 handler 末尾, Rust 无 drop 钩子点位,
            // 故 acquire 后即时 set 一次反映新水位; 下一请求 acquire 时再刷新)。
            metrics::gauge!("fe_exec_sem_available").set(exec_sem.available_permits() as f64);
            let r: ExecutionResult = executor
                .execute_async(req)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("execute 失败: {}", e)))?;
            hub.record_exec(&r);
            // D4-9: 释放前刷新水位 (permit 即将 drop 归还)。
            metrics::gauge!("fe_exec_sem_available").set((exec_sem.available_permits() + 1) as f64);
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
        // D6-03 (审计 0827 product): 快照清单 — on-disk NDJSON 索引读回, 供 on-call/审计查询。
        "executor.list_snapshots" => {
            let cwd = param_str(&params, "cwd").ok_or((ERR_INVALID_REQ, "缺少 cwd".to_string()))?;
            let snaps = executor
                .list_snapshots_async(&cwd)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("list_snapshots 失败: {}", e)))?;
            let arr: Vec<serde_json::Value> = snaps
                .into_iter()
                .map(|s| {
                    json!({
                        "id": s.id,
                        "created_ms": s.created_ms,
                        "kind": s.kind,
                    })
                })
                .collect();
            Ok(json!({"snapshots": arr}))
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
        "executor.metrics_prometheus" => {
            // M-OPS-02: Prometheus text format — 调用方经 UDS 拉, 喂自家 exporter。
            // 不开 HTTP 端口 (保 M-SEC-01 UDS-only)。recorder install 失败 → -32603。
            match hub.metrics_prometheus() {
                Some(text) => Ok(json!({ "ok": true, "text": text })),
                None => Err((
                    ERR_INTERNAL,
                    "Prometheus recorder 未安装, 仅 executor.metrics JSON 可用".to_string(),
                )),
            }
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
                .unwrap_or(true);
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
            let max_nofile = params
                .get("max_nofile")
                .and_then(|v| v.as_u64())
                .map(|n| n as u32)
                .unwrap_or(1024);
            let max_idle_sec = params
                .get("max_idle_sec")
                .and_then(|v| v.as_u64())
                .unwrap_or(fe_core::shell::DEFAULT_MAX_IDLE_SEC);
            let kill_grace_ms = params
                .get("kill_grace_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(500);
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
                max_nofile,
                max_idle_sec,
                kill_grace_ms,
            };
            let r = executor.shell_start(shells, sp);
            // M-OPS-02: fe_shell_active gauge — list_shells 已 reap finished, running 计数即活跃。
            let active = Executor::list_shells(shells)
                .iter()
                .filter(|s| !s.finished)
                .count() as f64;
            metrics::gauge!("fe_shell_active").set(active);
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
            // M-OPS-02: fe_shell_active gauge — kill 后重算活跃数。
            let active = Executor::list_shells(shells)
                .iter()
                .filter(|s| !s.finished)
                .count() as f64;
            metrics::gauge!("fe_shell_active").set(active);
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

/// D2-2 (2026-08-28): 运行时健康三态 — 区分 "忙碌但健康" 与 "停摆故障"。
/// 旧版 bool 探针在饱和负载下误报不健康 (探针任务排队超时), 导致 LB 摘除正常忙碌实例。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeState {
    Alive,
    Busy,
    Dead,
}

struct RuntimeHealth {
    state: RuntimeState,
    available_permits: usize,
}

impl RuntimeHealth {
    /// ok=alive||busy; dead 才算不健康 (停摆需摘除)。
    fn healthy(&self) -> bool {
        !matches!(self.state, RuntimeState::Dead)
    }

    /// JSON 序列化用状态字符串。
    fn state(&self) -> &'static str {
        match self.state {
            RuntimeState::Alive => "alive",
            RuntimeState::Busy => "busy",
            RuntimeState::Dead => "dead",
        }
    }
}

/// C-OPS-05 + D2-2: 探 BLOCKING_RT 响应, 区分三态。
/// 短超时 (调用方传 200ms) spawn 空任务 — 空闲 worker 立即拾取 = alive;
/// 超时再查 exec_sem 可用许可: 0=饱和 (busy, 忙碌但健康), >0 仍超时=停摆 (dead, 真故障)。
/// BLOCKING_RT 停摆 / worker 全死锁 → spawn 永不完成 + 有空闲许可 → dead → ok:false 摘除。
async fn probe_runtime(timeout: Duration, available_permits: usize) -> RuntimeHealth {
    let h = fe_core::BLOCKING_RT.handle();
    let task = h.spawn(async {});
    let state = if tokio::time::timeout(timeout, task).await.is_ok() {
        RuntimeState::Alive
    } else if available_permits == 0 {
        // 无可用执行许可 = 16 槽全占 = 饱和负载, 探针排队是预期非故障。
        warn!(
            available_permits,
            "D2-2: 健康探针超时但 exec_sem 饱和, 判 busy (忙碌但健康, 非停摆)"
        );
        RuntimeState::Busy
    } else {
        // 有空闲执行许可但 runtime 不响应 = worker 停摆/死锁, 真故障。
        error!(
            available_permits,
            "D2-2: 健康探针超时且有空闲许可, 判 dead (BLOCKING_RT 停摆/死锁)"
        );
        RuntimeState::Dead
    };
    RuntimeHealth {
        state,
        available_permits,
    }
}

/// C-OPS-05 + 0827 P-1: 探外部依赖 — `git --version` (rollback/快照依赖 git CLI)。
/// 任一依赖缺失 → 服务降级, ok=false。返回 [{name, ok, version?}]。
/// P-1 修: 旧版 spawn 两次 `git --version` (一次判 ok, 一次取 version) — 合并为单次 spawn。
async fn probe_dependencies() -> Vec<Value> {
    let out = tokio::process::Command::new("git")
        .arg("--version")
        .output()
        .await;
    let mut d = json!({ "name": "git", "ok": false });
    if let Ok(o) = out {
        let ok = o.status.success();
        d["ok"] = json!(ok);
        if ok {
            let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !v.is_empty() {
                d["version"] = json!(v);
            }
        }
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
/// D3-8 企业硬化: 权限收紧失败 = world 可读写 socket = M-SEC-01 绕过 → fail-loud 返 Err, serve 拒绝启动。
#[cfg(unix)]
fn chmod_secure(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        error!(path = %path.display(), error = %e, "FATAL: chmod 0o600 socket 失败 — 拒绝 world-readable socket 启动 (D3-8)");
        anyhow::anyhow!("chmod 0o600 socket 失败 (D3-8 企业硬化): {}: {}", path.display(), e)
    })?;
    info!(path = %path.display(), "socket 收紧 0o600 (owner-only rw, C-IPC-01)");
    Ok(())
}

#[cfg(not(unix))]
fn chmod_secure(_path: &Path) -> Result<()> {
    Ok(())
}

/// M-SEC-01 + 0827 C-10: 建 socket 父目录 0o700 — 私有目录阻他 UID connect (目录无搜索权限)。
/// 仅对 HOME 下默认路径生效; 显式 /tmp 覆盖路径走 chmod_secure 0o600 单文件。
/// C-10 修: 已存在目录**也收紧 0o700** (旧版早 return = 残留宽松目录, 他 UID 可 traverse+connect)。
/// 仅对本次新建/本服务 socket 父目录收紧; 上级 (HOME 本身) 不动 — 收紧的是 ~/.fusion-executor。
/// D3-8 企业硬化:
///   - create_dir_all 失败 → fail-loud Err (无法建私有目录 = 无法保证隔离)。
///   - 我们新建的目录 chmod 0o700 失败 → fail-loud Err (自己建的目录理应可收紧, 失败 = FS 异常)。
///   - 已存在非自有目录 (如共享 /tmp 根) chmod EPERM/EACCES → 降级 warn + Ok (非 HOME 默认路径, 靠文件 0o600 兜底)。
///   - chmod 其他错误 (只读 FS/IO) → fail-loud Err。
#[cfg(unix)]
fn ensure_sock_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    let pre_existing = parent.exists();
    if !pre_existing {
        std::fs::create_dir_all(parent).map_err(|e| {
            error!(dir = %parent.display(), error = %e, "FATAL: 建 socket 私有目录失败 — 拒绝启动 (D3-8 M-SEC-01)");
            anyhow::anyhow!("建 socket 私有目录失败 (D3-8 M-SEC-01): {}: {}", parent.display(), e)
        })?;
        info!(dir = %parent.display(), "M-SEC-01: socket 父目录已建");
    }
    // C-10: 无论新建或已存在, 尝试收紧 0o700。
    match std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)) {
        Ok(()) => {
            info!(dir = %parent.display(), "M-SEC-01: socket 父目录收紧 0o700 (阻他 UID traverse/connect)");
        }
        Err(e) => {
            let perm_denied = matches!(e.raw_os_error(), Some(1) | Some(13)); // EPERM/EACCES
            if !pre_existing || !perm_denied {
                // 新建目录收紧失败 (我们拥有, 应可收紧) 或非权限类 IO 错误 → fail-loud。
                error!(dir = %parent.display(), error = %e, "FATAL: chmod 0o700 私有目录失败 — 拒绝其他 UID traverse/connect (D3-8 M-SEC-01)");
                return Err(anyhow::anyhow!(
                    "chmod 0o700 私有目录失败 (D3-8 M-SEC-01): {}: {}",
                    parent.display(),
                    e
                ));
            }
            // 已存在非自有目录 (如共享 /tmp 根) 无权 chmod → 降级: 靠 socket 文件 0o600 兜底。
            warn!(
                dir = %parent.display(),
                error = %e,
                "M-SEC-01: 非自有 socket 父目录无权收紧 0o700 (共享 /tmp 等) — 降级靠文件 0o600 兜底"
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_sock_dir(_path: &Path) -> Result<()> {
    Ok(())
}

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
        // ARCH-1: seatbelt 治理信号 — execute 默认开启 (商用安全默认)。
        assert_eq!(resp["result"]["seatbelt_default_on"], true);
        // ax_trusted = 真实 AXIsProcessTrusted() 查询 (C-GUI-01), CI 无 TCC 时为 false。
        // 仅断言字段存在且为布尔, 不硬编码 true。
        assert!(
            resp["result"]["ax_trusted"].is_boolean(),
            "ax_trusted 应为布尔: {}",
            resp["result"]["ax_trusted"]
        );
        // C-OPS-05: runtime 探针 — BLOCKING_RT spawn 空任务超时探活
        // D2-2: runtime 三态 (alive/busy/dead); 空闲测试环境应 alive, ok=true。
        assert_eq!(
            resp["result"]["runtime"]["ok"], true,
            "runtime 应健康 (BLOCKING_RT 可响应): {}",
            resp["result"]["runtime"]
        );
        assert!(
            matches!(
                resp["result"]["runtime"]["state"].as_str(),
                Some("alive") | Some("busy")
            ),
            "D2-2: runtime.state 应为 alive 或 busy (非 dead): {}",
            resp["result"]["runtime"]
        );
        assert!(
            resp["result"]["runtime"]["available_permits"].is_number(),
            "D2-2: runtime.available_permits 应为数字: {}",
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

    // M-OPS-02: executor.metrics_prometheus 返 Prometheus text format — execute 一次后
    // fe_exec_total 命中 + HELP/TYPE 头 (describe_counter 注册)。
    #[tokio::test]
    async fn metrics_prometheus_after_execute() {
        let sock = tmp_sock("metrics-prom");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","id":3,"method":"executor.execute","params":{"command":"echo hi"}}"#;
        let resp = rpc(&sock, req).await;
        assert_eq!(resp["result"]["exit_code"], 0);
        let presp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":5,"method":"executor.metrics_prometheus","params":{}}"#,
        )
        .await;
        assert!(presp["result"]["ok"].as_bool().unwrap_or(false));
        let text = presp["result"]["text"].as_str().unwrap_or("");
        // describe_counter 注册的 HELP/TYPE 头应在文本里。
        assert!(
            text.contains("# HELP fe_exec_total"),
            "缺 fe_exec_total HELP: {text}"
        );
        assert!(
            text.contains("# TYPE fe_exec_total counter"),
            "缺 fe_exec_total TYPE: {text}"
        );
        assert!(
            text.contains("fe_exec_total"),
            "缺 fe_exec_total 指标行: {text}"
        );
        assert!(
            text.contains("# TYPE fe_connections gauge"),
            "缺 fe_connections gauge: {text}"
        );
        // D4-9: exec_sem 可用许可 gauge — execute 后 health 路径镜像, 应含 HELP/TYPE/指标行。
        assert!(
            text.contains("# HELP fe_exec_sem_available"),
            "缺 fe_exec_sem_available HELP: {text}"
        );
        assert!(
            text.contains("# TYPE fe_exec_sem_available gauge"),
            "缺 fe_exec_sem_available TYPE: {text}"
        );
        assert!(
            text.contains("fe_exec_sem_available"),
            "缺 fe_exec_sem_available 指标行: {text}"
        );
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
        // D3-1: python3 -c 内联解释器需 opt-in (此用例测 shell_start 非 D3-1)
        let server = IpcServer::with_executor(Executor::new().with_allow_inline_interpreter(true));
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

    // D3-2: shell_start 默认 seatbelt=true (商用安全默认)。不传 seatbelt →
    // fe-ipc unwrap_or(true) → 经 sandbox-exec 隔离; 白名单 python3 正常 echo。
    // 显式 seatbelt:false → opt-out 关隔离。两路径白名单命令均 ok=true。
    #[tokio::test]
    async fn shell_start_defaults_seatbelt_on() {
        let sock = tmp_sock("shell_seatbelt");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();

        // 不传 seatbelt → 默认 true, 白名单 echo 经 sandbox-exec 正常
        let on = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.shell_start","params":{"command":"echo d3-2-on"}}"#,
        )
        .await;
        assert_eq!(on["result"]["ok"], true);
        let sid_on = on["result"]["shell_id"].as_str().unwrap().to_string();

        // 显式 seatbelt:false → opt-out
        let off = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"executor.shell_start","params":{"command":"echo d3-2-off","seatbelt":false}}"#,
        )
        .await;
        assert_eq!(off["result"]["ok"], true);
        let sid_off = off["result"]["shell_id"].as_str().unwrap().to_string();

        // 收尾: 两 shell 均 kill (防泄漏)
        for sid in [sid_on.as_str(), sid_off.as_str()] {
            let _ = rpc(
                &sock,
                &format!(
                    r#"{{"jsonrpc":"2.0","id":9,"method":"executor.kill_shell","params":{{"shell_id":"{}"}}}}"#,
                    sid
                ),
            )
            .await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
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
        ensure_sock_dir(&probe).expect("ensure_sock_dir 应成功建 0o700 父目录");
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

    // D3-8 企业硬化: socket 父目录权限收紧失败 → serve fail-loud 拒绝启动 (不残留 world-accessible socket)。
    // 构造只读父目录: create_dir_all 成功但 chmod 0o700 因父目录无写权限失败 → ensure_sock_dir Err → serve Err。
    // 注: macOS root 可绕 chmod, 故本测试仅非 root 跑断言; root 跳过 (CI 非 root)。
    #[cfg(unix)]
    #[tokio::test]
    async fn d38_serve_fails_when_sock_dir_not_tightenable() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::getuid().as_raw() == 0 {
            eprintln!("skip d38 chmod test under root (root bypasses mode bits)");
            return;
        }
        let tmp = std::env::temp_dir().join(format!("fe-d38-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // 建外层目录, 然后剥写权限 — 内层子目录 create_dir_all 会失败
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o555)).unwrap();
        let sock = tmp.join("nope").join("fe.sock");
        let server = IpcServer::new();
        let res = server.serve(sock.to_str().unwrap()).await;
        assert!(
            res.is_err(),
            "D3-8: 不可建/不可收紧 socket 私有目录应 fail-loud 返 Err, 实际 Ok"
        );
        // 恢复权限清理 (否则 remove_dir_all 也无写权限)
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // D3-8: 正常路径 ensure_sock_dir + chmod_secure 返 Ok (幂等 — 已 0o700 目录仍 Ok)。
    #[cfg(unix)]
    #[tokio::test]
    async fn d38_sock_hardening_ok_on_normal_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fe-d38-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("fe.sock");
        ensure_sock_dir(&sock_path).expect("D3-8: 正常路径 ensure_sock_dir 应 Ok");
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "D3-8: 正常路径目录应收紧 0o700");
        // 幂等: 二次调用已收紧目录仍 Ok
        ensure_sock_dir(&sock_path).expect("D3-8: ensure_sock_dir 幂等应 Ok");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // m-OPS-02: env-var 测试串行化 (set_var/remove_var 跨并行测试竞态)。
    static MOPS02_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // D3-6: validate 现 fail-closed (不可解析二进制不放行)。SIGHUP reload 测试需真实二进制
    // 落可信目录才能 resolve 通过, 故建临时 bin 目录 + 真实可执行文件 + 登记 Executor 可信目录。
    fn mops02_make_tool(dir: &Path, name: &str) {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\necho ok\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&p, perm).unwrap();
        }
    }

    // m-OPS-02: reload_extra_whitelist 解析 FUSION_EXECUTOR_EXTRA_WHITELIST (逗号分割/去空白/去空) → Executor 白名单更新。
    #[test]
    fn mops02_reload_extra_whitelist_parses_env() {
        let _g = MOPS02_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // D3-6: 真实二进制 + 可信目录 + 绝对路径调用, 否则 validate fail-closed 拦 (resolve 失败)。
        let dir = std::env::temp_dir().join("fe_mops02_sighup_dir");
        let _ = std::fs::remove_dir_all(&dir);
        mops02_make_tool(&dir, "sighup-tool-xyz");
        mops02_make_tool(&dir, "other-tool");
        let executor = Arc::new(Executor::new().with_trusted_bin_dirs(&[dir.to_str().unwrap()]));
        let sighup_abs = dir.join("sighup-tool-xyz");
        let other_abs = dir.join("other-tool");
        // 先用 validate 断言非基线工具默认被拦 (白名单未含 → whitelist-reject)
        let v = executor.validate(&format!("{} --version", sighup_abs.display()));
        assert!(!v.allowed, "扩展前 sighup-tool-xyz 应被拦");
        // 设 env → reload → 应放行
        std::env::set_var(
            "FUSION_EXECUTOR_EXTRA_WHITELIST",
            " sighup-tool-xyz ,,other-tool ",
        );
        reload_extra_whitelist(&executor);
        let v = executor.validate(&format!("{} --version", sighup_abs.display()));
        assert!(
            v.allowed,
            "SIGHUP 重载后 sighup-tool-xyz 应放行: {:?}",
            v.reason
        );
        let v = executor.validate(&format!("{} run", other_abs.display()));
        assert!(v.allowed, "逗号第二项 other-tool 应放行: {:?}", v.reason);
        // 基线恒在
        let v = executor.validate("python3 --version");
        assert!(v.allowed, "基线 python3 恒放行");
        std::env::remove_var("FUSION_EXECUTOR_EXTRA_WHITELIST");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // m-OPS-02: 空 env → 回退纯基线 (项目扩展清空)。
    #[test]
    fn mops02_reload_extra_whitelist_empty_clears_extras() {
        let _g = MOPS02_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // D3-6: 真实二进制 + 可信目录 + 绝对路径调用, 否则 validate fail-closed 拦。
        let dir = std::env::temp_dir().join("fe_mops02_cleartool_dir");
        let _ = std::fs::remove_dir_all(&dir);
        mops02_make_tool(&dir, "temp-tool");
        let executor = Arc::new(Executor::new().with_trusted_bin_dirs(&[dir.to_str().unwrap()]));
        let temp_abs = dir.join("temp-tool");
        // 先加扩展
        std::env::set_var("FUSION_EXECUTOR_EXTRA_WHITELIST", "temp-tool");
        reload_extra_whitelist(&executor);
        assert!(
            executor
                .validate(&format!("{} run", temp_abs.display()))
                .allowed,
            "先加 temp-tool 放行: 详见 reload 后 validate reason"
        );
        // 清 env → reload → 回退基线
        std::env::remove_var("FUSION_EXECUTOR_EXTRA_WHITELIST");
        reload_extra_whitelist(&executor);
        assert!(
            !executor
                .validate(&format!("{} run", temp_abs.display()))
                .allowed,
            "空 reload 后 temp-tool 应已拦 (回退基线)"
        );
        assert!(executor.validate("python3 --version").allowed, "基线恒在");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // m-OPS-02: reload_log_level 无 handle (tracing 未 init) → 不 panic, 仅 warn。
    #[test]
    fn mops02_reload_log_level_no_panic_without_handle() {
        // 不调 init_tracing (避免污染全局 subscriber) → current_handle() 多为 None。
        // 无论 None 或 Some, reload_log_level 不应 panic。
        reload_log_level();
    }

    // m-OPS-02: reload_log_level 读 RUST_LOG env (合法 directive 经 handle 不崩)。
    #[test]
    fn mops02_reload_log_level_reads_rust_log() {
        let _g = MOPS02_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("RUST_LOG", "debug");
        reload_log_level(); // 无 handle → no-op 路径, 不崩; 有 handle → 应接受 debug
        std::env::remove_var("RUST_LOG");
    }

    // ===== 0827 fe-ipc P0-P3 修复回归测试 =====

    // M-7(1): 未知通道名 → -32600 (旧版静默接受 → 幽灵订阅, 永不收推帧)。
    #[tokio::test]
    async fn subscribe_rejects_unknown_channel() {
        let sock = tmp_sock("sub-unknown");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["bogus_channel"]}}
"#,
        )
        .await;
        assert_eq!(
            resp["error"]["code"], -32600,
            "未知通道应 -32600 fail-loud: {resp}"
        );
        let _ = std::fs::remove_file(&sock);
    }

    // L-7: 混合大小写通道名 ("Telemetry") 应规范化为小写并收到推帧 (旧版原样存 →
    // 不匹配小写 CH_TELEMETRY = 幽灵订阅, 源任务永不启)。
    #[tokio::test]
    async fn subscribe_lowercases_mixedcase_channel() {
        let sock = tmp_sock("sub-lower");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let s = UnixStream::connect(&sock).await.unwrap();
        let (rh, mut writer) = s.into_split();
        let mut reader = BufReader::new(rh);
        // 大写 "Telemetry" — 应规范化为 "telemetry" 并匹配源扇出
        let req = br#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["Telemetry"],"interval_ms":20}}
"#;
        writer.write_all(req).await.unwrap();
        let resp = read_line(&mut reader).await.unwrap();
        assert_eq!(
            resp["result"]["ok"], true,
            "大写通道应被接受 (规范化): {resp}"
        );
        let sub_id = resp["result"]["subscription_id"]
            .as_str()
            .unwrap()
            .to_string();
        // 首帧应为 telemetry 推送 (订阅生效, 源任务启)
        let first = read_line(&mut reader).await.unwrap();
        assert_eq!(
            first["params"]["subscription_id"], sub_id,
            "规范化后应收到 telemetry 推帧 (非幽灵订阅): {first}"
        );
        assert_eq!(first["params"]["channel"], "telemetry");
        let _ = std::fs::remove_file(&sock);
    }

    // M-7(3): 空 task_ids 数组 → -32600 (旧版静默变空 Tasks 集 = 死订阅, 永不匹配)。
    #[tokio::test]
    async fn subscribe_rejects_empty_task_ids() {
        let sock = tmp_sock("sub-empty-tids");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["stdio"],"task_ids":[]}}
"#,
        )
        .await;
        assert_eq!(
            resp["error"]["code"], -32600,
            "空 task_ids 应 -32600 (死订阅 fail-loud): {resp}"
        );
        let _ = std::fs::remove_file(&sock);
    }

    // L-6: streaming execute 完成应记指标 — execute_stream 后 metrics_prometheus 含 fe_exec_total。
    // 旧版 Done 分支漏 record_exec → 流式执行 Prometheus 不可见。
    #[tokio::test]
    async fn stream_exec_records_metric() {
        let sock = tmp_sock("stream-metric");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // 先取基线 fe_exec_total 文本行 (可能其他测试已 populate, 取基线计数)
        let base = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.metrics_prometheus","params":{}}"#,
        )
        .await;
        let base_text = base["result"]["text"].as_str().unwrap_or("");
        let base_count = extract_exec_total(base_text);
        // 跑一次 execute_stream (echo)
        let mut s = UnixStream::connect(&sock).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","id":7,"method":"executor.execute_stream","params":{"command":"echo hi","enable_rollback_snapshot":false}}"#;
        s.write_all((req.to_string() + "\n").as_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new(s);
        let mut got_done = false;
        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        let mut buf = Vec::new();
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                _ = async {
                    buf.clear();
                    let n = reader.read_until(b'\n', &mut buf).await.unwrap();
                    if n > 0 {
                        if let Ok(v) = serde_json::from_str::<Value>(String::from_utf8_lossy(&buf).trim()) {
                            if v["id"] == 7 && v["result"]["type"] == "done" {
                                got_done = true;
                            }
                        }
                    }
                } => {}
            }
            if got_done {
                break;
            }
        }
        assert!(got_done, "execute_stream 应收到 done 帧");
        // 再取 metrics — fe_exec_total 应增 1
        let after = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"executor.metrics_prometheus","params":{}}"#,
        )
        .await;
        let after_text = after["result"]["text"].as_str().unwrap_or("");
        let after_count = extract_exec_total(after_text);
        assert!(
            after_count > base_count,
            "L-6: execute_stream 应使 fe_exec_total 递增 ({} → {}), 旧版漏 record_exec 不增",
            base_count,
            after_count
        );
        let _ = std::fs::remove_file(&sock);
    }

    /// 从 Prometheus text 提取 fe_exec_total 计数值。
    fn extract_exec_total(text: &str) -> u64 {
        for line in text.lines() {
            if line.starts_with("fe_exec_total ") || line.starts_with("fe_exec_total{") {
                let num = line
                    .rsplit(|c: char| c.is_whitespace())
                    .next()
                    .unwrap_or("0");
                return num.parse::<u64>().unwrap_or(0);
            }
        }
        0
    }

    // C-9: subscribe telemetry 通道应使 telemetry_gen 递增 (源生命周期代数, 供源任务
    // 0 订阅重比对续跑/自退)。非 telemetry 订阅不动 telemetry_gen。
    #[tokio::test]
    async fn telemetry_gen_bumps_on_telemetry_subscribe() {
        let executor = Arc::new(Executor::new());
        let hub = BroadcastHub::new(executor);
        let (tx, _rx) = mpsc::channel::<Value>(8);
        let before = hub.telemetry_gen.load(Ordering::SeqCst);
        let mut chans = HashSet::new();
        chans.insert(CH_TELEMETRY.to_string());
        // 用大 interval_ms 防 0 订阅自退竞态干扰 gen 断言 (gen bump 在 ensure_source 之前, 源
        // 启动后立刻 0 订阅会 break — 但 telemetry_stream 单流喂帧, 不 break; gen 已 bump 即断言点)。
        let _sid = hub.subscribe(1, chans, StdioScope::OwnConn(1), tx, 5000, 1000);
        let after = hub.telemetry_gen.load(Ordering::SeqCst);
        assert_eq!(
            after,
            before + 1,
            "C-9: telemetry 订阅应 bump telemetry_gen"
        );
        // 非 telemetry 订阅不动 telemetry_gen
        let (tx2, _rx2) = mpsc::channel::<Value>(8);
        let mut chans2 = HashSet::new();
        chans2.insert(CH_STDIO.to_string());
        let before2 = hub.telemetry_gen.load(Ordering::SeqCst);
        let _sid2 = hub.subscribe(2, chans2, StdioScope::OwnConn(2), tx2, 5000, 1000);
        let after2 = hub.telemetry_gen.load(Ordering::SeqCst);
        assert_eq!(after2, before2, "C-9: stdio 订阅不应动 telemetry_gen");
        // screenshot 订阅 bump screenshot_gen 非 telemetry_gen
        let (tx3, _rx3) = mpsc::channel::<Value>(8);
        let mut chans3 = HashSet::new();
        chans3.insert(CH_SCREENSHOT.to_string());
        let _sid3 = hub.subscribe(3, chans3, StdioScope::OwnConn(3), tx3, 5000, 1000);
        let after3 = hub.telemetry_gen.load(Ordering::SeqCst);
        assert_eq!(after3, before2, "C-9: screenshot 订阅不应动 telemetry_gen");
        let shot_after = hub.screenshot_gen.load(Ordering::SeqCst);
        assert_eq!(
            shot_after, 1,
            "C-9: screenshot 订阅应 bump screenshot_gen 到 1"
        );
    }

    // C-10: ensure_sock_dir 对已存在的宽松目录 (0o755) 也收紧 0o700 (旧版早 return = 残留宽松)。
    #[cfg(unix)]
    #[tokio::test]
    async fn ensure_sock_dir_tightens_existing_loose_dir() {
        use std::os::unix::fs::PermissionsExt;
        // 建一个宽松目录 (0o755) 模拟旧版残留
        let dir = std::env::temp_dir().join(format!(
            "fe-ipc-sockdir-test-{}-{}",
            std::process::id(),
            "loose"
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sock_path = dir.join("fe.sock");
        // 调 ensure_sock_dir — 应收紧 0o700
        ensure_sock_dir(&sock_path).expect("ensure_sock_dir 应成功收紧已存在目录 0o700");
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "C-10: 已存在宽松目录应被收紧 0o700, 实际 {:#o}",
            mode
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // IMPL-12 信号竞态: SIGHUP 仅重载配置, 永不触发 shutdown。
    // 不发真 SIGHUP (进程级信号在测试二进制内不可靠, 影响整个 test runner),
    // 改直调 handle_sighup_reload 循环体所调的 reload_log_level + reload_extra_whitelist
    // (与 SIGHUP 等价路径), 验证:
    //   1. serve join 未完成 (shutdown Notify + oneshot 均未被触发 → accept_loop 未退);
    //   2. server 仍可接受 health RPC (连接未被清理, 服务继续)。
    // env 测试须串行 (set_var/remove_var 跨测试竞态)。
    #[cfg(unix)]
    #[tokio::test]
    async fn sighup_does_not_trigger_shutdown() {
        static SIGHUP_ENV_LOCK: Mutex<()> = Mutex::new(());

        let sock = tmp_sock("sighup-noshutdown");
        let server = IpcServer::new();
        let (shutdown_tx, mut join) = server.serve(&sock).await.unwrap();
        // 先确认 server 活
        let h = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert_eq!(h["result"]["ok"], true);

        // 模拟 SIGHUP 效果: 直调 reload 路径 (handle_sighup_reload 循环体的两个调用)。
        // env lock 仅守同步 set_var/remove_var + reload (非 async), 守卫在块末 drop — 不跨 await。
        {
            let _g = SIGHUP_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            // 设可解析的 RUST_LOG + 非空白名单扩展, 走 reload 真实分支。
            std::env::set_var("RUST_LOG", "warn");
            std::env::set_var("FUSION_EXECUTOR_EXTRA_WHITELIST", "jq,gh");
            reload_log_level();
            reload_extra_whitelist(&server.executor);
            std::env::remove_var("RUST_LOG");
            std::env::remove_var("FUSION_EXECUTOR_EXTRA_WHITELIST");
        }

        // 断言 1: serve join 未完成 — shutdown Notify + oneshot 均未触发 (reload 不碰 shutdown)。
        // 短超时探测, join 仍 Pending = server 未退。
        let pending = tokio::time::timeout(Duration::from_millis(200), &mut join).await;
        assert!(
            pending.is_err(),
            "IMPL-12: reload 后 serve 不应退出 (SIGHUP 不触发 shutdown), 实际 join 已完成"
        );

        // 断言 2: server 仍可接受新 RPC — 连接未被清理, 服务继续。
        let h2 = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert_eq!(
            h2["result"]["ok"], true,
            "IMPL-12: reload 后 server 仍应服务, 实际 health 失败"
        );

        // 清理: 显式触发 shutdown 让 serve join 完成 (避免 leak)。
        let _ = shutdown_tx.send(());
        let done = tokio::time::timeout(SHUTDOWN_DEADLINE, join).await;
        assert!(done.is_ok(), "显式 shutdown 后 serve join 应完成");
        let _ = std::fs::remove_file(&sock);
    }

    // D6-02: 墙钟直方图 — 记 N 次不同 duration, p50/p95/p99 插值正确 + 桶计数对齐。
    // 构造 10 次: 5 次 0.001s (首桶 ≤0.005), 3 次 0.1s (次桶 ≤0.05 外, 落 0.5 桶), 2 次 1.0s (落 5.0 桶)。
    #[test]
    fn d602_histogram_quantiles_interpolated() {
        install_prometheus_recorder();
        let executor = Arc::new(Executor::new());
        let hub = BroadcastHub::new(executor);
        for dur in [0.001; 5] {
            hub.record_exec(&ExecutionResult {
                exit_code: 0,
                duration_sec: dur,
                ..Default::default()
            });
        }
        for dur in [0.1; 3] {
            hub.record_exec(&ExecutionResult {
                exit_code: 0,
                duration_sec: dur,
                ..Default::default()
            });
        }
        for dur in [1.0; 2] {
            hub.record_exec(&ExecutionResult {
                exit_code: 0,
                duration_sec: dur,
                ..Default::default()
            });
        }
        let snap = hub.metrics_snapshot();
        let total = snap["exec_total"].as_u64().unwrap();
        assert_eq!(total, 10, "D6-02: 10 次 execute 应全计");
        // 桶上界 [0.005, 0.05, 0.5, 5.0, 30.0] → 0.001 落首(5), 0.1 落 0.5 桶(3), 1.0 落 5.0 桶(2)。
        let buckets = snap["execute_duration_buckets"].as_array().unwrap();
        assert_eq!(buckets[0].as_u64(), Some(5), "≤0.005 桶应 5");
        assert_eq!(buckets[1].as_u64(), Some(0), "0.05 桶应空");
        assert_eq!(buckets[2].as_u64(), Some(3), "0.5 桶应 3");
        assert_eq!(buckets[3].as_u64(), Some(2), "5.0 桶应 2");
        assert_eq!(buckets[4].as_u64(), Some(0), "30.0 桶应空");
        // p50: 累计 [5,5,8,10,10,10], 0.5 分位 target=5, 首桶累计 5 ≥ 5 → 返首桶上界 0.005。
        let p50 = snap["execute_duration_sec_p50"].as_f64().unwrap();
        assert_eq!(p50, 0.005, "D6-02: p50 应插值到首桶上界 0.005");
        // min/max: 0.001 → 1.0s。
        assert!(
            (snap["execute_duration_sec_min"].as_f64().unwrap() - 0.001).abs() < 1e-9,
            "min 应 0.001"
        );
        assert!(
            (snap["execute_duration_sec_max"].as_f64().unwrap() - 1.0).abs() < 1e-9,
            "max 应 1.0"
        );
        // avg: (5*0.001 + 3*0.1 + 2*1.0)/10 = 2.305/10 = 0.2305
        let avg = snap["execute_duration_sec_avg"].as_f64().unwrap();
        assert!((avg - 0.2305).abs() < 1e-9, "avg 应 0.2305, 实际 {avg}");
    }

    // D6-02: Prometheus text format — 直方图 render 出 _bucket{le=...} 行 + HELP/TYPE 头。
    #[test]
    fn d602_prometheus_histogram_buckets_rendered() {
        install_prometheus_recorder();
        let executor = Arc::new(Executor::new());
        let hub = BroadcastHub::new(executor);
        hub.record_exec(&ExecutionResult {
            exit_code: 0,
            duration_sec: 0.02,
            ..Default::default()
        });
        let text = hub.metrics_prometheus().unwrap_or_default();
        assert!(
            text.contains("# HELP fe_exec_duration_seconds"),
            "D6-02: prometheus 应含直方图 HELP 头"
        );
        assert!(
            text.contains("# TYPE fe_exec_duration_seconds histogram"),
            "D6-02: prometheus 应含直方图 TYPE 头"
        );
        assert!(
            text.contains("fe_exec_duration_seconds_bucket{le=\"0.005\"}"),
            "D6-02: 应有 le=0.005 桶行"
        );
        assert!(
            text.contains("fe_exec_duration_seconds_bucket{le=\"+Inf\"}"),
            "D6-02: 应有 +Inf 末桶行"
        );
    }
}
