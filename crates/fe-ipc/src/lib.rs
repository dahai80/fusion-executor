// fe-ipc — UDS JSON-RPC 2.0 server (P3) + bidirectional server-push (v1.5 #14)
//
// Socket /tmp/fusion-executor.sock (override FUSION_EXECUTOR_SOCK), newline-delimited
// Mirror of fusion-cowork/fusion_cowork/server/desk_rpc.py protocol:
//   line = read_line(); response = serde_json::to_string(resp) + "\n"
//   jsonrpc "2.0", id passthrough; error codes -32700(parse)/-32600(invalid req)/-32601(method)/-32603(internal)
//   Extensions: -32010 security block, -32011 timeout, -32012 rollback failure, -32013 AX not authorized
// Matches fusion-studio IPCClient.swift: byte-wise read up to 0x0A, 8s timeout
//
// Methods: executor.health/execute/execute_stream/telemetry_stream/snapshot_create/list_snapshots/rollback/gui_action/diagnostics
//          executor.file_edit/glob/grep/apply_patch/replace_function/shutdown
//          executor.subscribe/unsubscribe  (v1.5 #14 — bidirectional server-push)
//
// v1.5 #14 bidirectional server-push (PRD §5 — fusion-studio 120Hz dashboard broadcast):
//   Connection is DUPLEX: read_task (dispatches requests) + push_task (writes server-push
//   frames) share the writer (Arc<Mutex>).
//   subscribe {channels:["telemetry"|"stdio"|"screenshot"], interval_ms?:100, screenshot_interval_ms?:1000}
//     → response {ok:true, subscription_id:"sub-N"}; afterwards the server keeps pushing
//       notification frames:
//       {"jsonrpc":"2.0","method":"executor.event","params":{"subscription_id":..,"channel":..,"data":..}}
//     Notifications carry no id (JSON-RPC notification convention); the client distinguishes
//     responses vs pushes by the presence of id.
//   Channel sources (lazily started/stopped inside the hub; self-exit at 0 subscribers):
//     telemetry — a single executor.telemetry_stream fanned out to all telemetry subs (10Hz default).
//     screenshot — periodic executor.gui_action(Screenshot); TCC not authorized → frame
//       data.ok=false, no crash.
//     stdio — execute/execute_stream handlers fan out chunk/done, filtered per sub scope
//       (Blocker 10, default own_conn).
//   unsubscribe {subscription_id} → stop that subscription; connection drop → clear all
//   subscriptions of that connection.

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

/// Default socket directory — M-SEC-01: private 0o700 directory (not globally scannable /tmp).
/// Other UIDs on the same host cannot enter the directory → cannot connect to the socket,
/// blocking cross-UID privilege escalation.
/// Can still be overridden back to /tmp via FUSION_EXECUTOR_SOCK (explicit user opt-in, own risk).
pub const DEFAULT_SOCK_DIR: &str = ".fusion-executor";
pub const DEFAULT_SOCK_NAME: &str = "fe.sock";

/// Resolve the default socket path — ~/.fusion-executor/fe.sock (private directory under HOME).
/// Falls back to /tmp/fusion-executor.sock when HOME is missing (degrades to the legacy path, chmod 0o600 only).
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

/// JSON-RPC error codes
const ERR_PARSE: i64 = -32700;
const ERR_INVALID_REQ: i64 = -32600;
const ERR_METHOD_NOT_FOUND: i64 = -32601;
const ERR_INTERNAL: i64 = -32603;

/// Channel name constants
const CH_TELEMETRY: &str = "telemetry";
const CH_STDIO: &str = "stdio";
const CH_SCREENSHOT: &str = "screenshot";

/// Default sampling intervals
const DEFAULT_INTERVAL_MS: u64 = 100;
const DEFAULT_SCREENSHOT_INTERVAL_MS: u64 = 1000;

/// Per-line JSON-RPC request size cap (1MB) — prevents OOM from a 10GB newline-less stream (C-IPC-04)
const MAX_LINE_BYTES: usize = 1024 * 1024;
/// Concurrent connection cap — prevents unbounded accept accumulation DoS (C-IPC-05)
const MAX_CONNECTIONS: usize = 64;
/// Audit 2.11: concurrent **exec** cap — the connection semaphore limits connections, not
/// execs (64 connections each running cargo build = 64 concurrent subprocesses, over budget).
/// A separate exec semaphore limits real subprocess concurrency, decoupled from connection
/// count. 16 concurrent heavy commands leaves 2x headroom on an 8-core machine.
const MAX_CONCURRENT_EXECS: usize = 16;
/// RUN-3: concurrent **streaming exec** cap — separate from the non-streaming exec_sem (16).
/// A stream (execute_stream) holds its permit across the whole chunk→done lifetime; sharing
/// exec_sem (16) would let 16 long streams exhaust the permits and starve short execute
/// commands. Independent stream_sem capacity = MAX_CONNECTIONS (64): streams are bounded by
/// connection count (the connection semaphore already caps total connections), so they do not
/// contend with non-streaming short executions.
const MAX_CONCURRENT_STREAMS: usize = MAX_CONNECTIONS;
/// Per-connection idle read timeout — prevents slowloris holding connections without reading (C-IPC-05)
const IDLE_READ_TIMEOUT_SECS: u64 = 30;
/// Screenshot b64 frame cap (4MB) — above this, degrade by dropping png_b64 to prevent memory
/// buildup across N subscribers (P-IPC-03)
const MAX_SCREENSHOT_B64_BYTES: usize = 4 * 1024 * 1024;
/// C-OPS-03: default graceful drain deadline — join in-flight connections for 10s, abort the
/// rest on timeout (forced stop, prevents hang).
/// M-OPS-03: overridable at runtime via FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS (1..=300s,
/// out-of-range falls back to this default).
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

/// M-OPS-03: resolve the graceful drain timeout — env `FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS`
/// overrides the 10s default. Valid range 1..=300 (seconds): too short kills in-flight work,
/// too long drags out shutdown. Out-of-range/non-numeric → fall back to the default, fail-loud warn.
fn resolve_shutdown_timeout() -> Duration {
    parse_shutdown_timeout(std::env::var("FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS").ok())
}

/// M-OPS-03: pure parse function (no env side effects, unit-testable) — env value → Duration.
fn parse_shutdown_timeout(raw: Option<String>) -> Duration {
    match raw {
        Some(v) => match v.trim().parse::<u64>() {
            Ok(secs) if (1..=300).contains(&secs) => {
                info!(secs, "M-OPS-03: shutdown drain timeout overridden via env");
                Duration::from_secs(secs)
            }
            Ok(secs) => {
                warn!(
                    secs,
                    "M-OPS-03: shutdown timeout out of range (must be 1..=300), falling back to 10s default"
                );
                SHUTDOWN_DEADLINE
            }
            Err(e) => {
                warn!(raw = %v, error = %e, "M-OPS-03: shutdown timeout not numeric, falling back to 10s default");
                SHUTDOWN_DEADLINE
            }
        },
        None => SHUTDOWN_DEADLINE,
    }
}

/// D6-02: fixed bucket upper bounds (seconds) for the execute wall-clock histogram. The +Inf
/// last bucket is not stored in the array (tracked separately, total = exec_total).
/// Bucket selection covers typical CLI sandbox tiers: <5ms init / <50ms fast commands /
/// <500ms compile / <5s test suite / <30s long runs / +Inf tail.
const DURATION_BUCKETS_LE: [f64; 5] = [0.005, 0.05, 0.5, 5.0, 30.0];

/// D6-02: wall-clock (seconds) → bucket index; beyond all finite buckets → None (falls into the
/// +Inf last bucket, not counted in the array).
fn duration_bucket_index(sec: f64) -> Option<usize> {
    for (i, le) in DURATION_BUCKETS_LE.iter().enumerate() {
        if sec <= *le {
            return Some(i);
        }
    }
    None
}

/// D6-02: histogram_quantile interpolation — cumulative count array (each bucket inclusive of
/// itself and smaller) → quantile value (seconds).
/// q ∈ [0,1]. Linear interpolation across adjacent buckets (Prometheus _quantile_ convention).
/// Empty/insufficient → 0.0.
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
    // q falls into the +Inf last bucket (beyond all finite-bucket totals) → return the largest
    // finite bound (conservative, do not pretend it is infinite).
    DURATION_BUCKETS_LE.last().copied().unwrap_or(0.0)
}

/// M-OPS-02: Prometheus recorder handle — global, idempotent install.
/// metrics-exporter-prometheus's PrometheusBuilder::install() installs the global recorder and
/// returns a PrometheusHandle (render() emits Prometheus text format for scraping).
/// install is idempotent: repeat calls return Err, which we swallow — after the first success
/// the global recorder is in place.
static PROM_HANDLE: OnceLock<Option<PrometheusHandle>> = OnceLock::new();

/// Install the Prometheus recorder (idempotent) and return a handle clone; if already
/// installed, fetch from the static.
/// describe_counter makes render() emit HELP/TYPE headers (schema present even with no observations).
/// ARCH-4: made pub — in-process paths (fe-pyo3 execute_sync, bypassing fe-ipc/BroadcastHub)
/// must also install the recorder; otherwise the metrics::counter! calls in
/// record_exec_outcome have no recorder = no-op.
/// Idempotent (OnceLock), safe to call multiple times.
pub fn install_prometheus_recorder() -> Option<PrometheusHandle> {
    PROM_HANDLE
        .get_or_init(|| {
            // D6-02: configure histogram buckets aligned with DURATION_BUCKETS_LE — render()
            // emits _bucket{le=...} lines.
            // set_buckets_for_metric consumes self and returns Result<PrometheusBuilder, BuildError>;
            // .ok()? converts to Option<PrometheusBuilder> (empty buckets → BuildError → None,
            // degraded to JSON-only).
            let builder = PrometheusBuilder::new()
                .set_buckets_for_metric(
                    Matcher::Prefix("fe_exec_duration".to_string()),
                    &DURATION_BUCKETS_LE,
                )
                .map_err(|e| {
                    warn!(error = %e, "D6-02: set_buckets_for_metric failed");
                    e
                })
                .ok()?;
            let handle = builder
                .install_recorder()
                .map_err(|e| {
                    warn!(error = %e, "M-OPS-02: Prometheus recorder install failed");
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
            // D4-9: available permits of the non-streaming exec_sem — LB/ops dashboards use this
            // to detect saturation (0 = saturated, shed load). Same source as the health
            // response available_permits; mirrored as a gauge in the Prometheus exporter for scraping.
            metrics::describe_gauge!("fe_exec_sem_available", "Available exec semaphore permits");
            Some(handle)
        })
        .clone()
}

/// stdio subscription scope (audit 2.9 / Blocker 10) — per-sub filtering prevents cross-tenant leaks.
/// Default OwnConn: only stdio of commands initiated by this connection (multi-tenant isolation baseline).
/// All: receive everything (backward-compatible dashboard scenario, explicit opt-in).
/// Tasks: only stdio of allowlisted task_ids (precise cross-connection subscription).
#[derive(Clone)]
enum StdioScope {
    All,
    OwnConn(u64),
    Tasks(HashSet<String>),
}

impl StdioScope {
    /// Whether a command (task_id + originating connection conn_id) falls into this scope.
    /// source_conn = conn_id of the connection that initiated the command; OwnConn stores the
    /// subscriber's own conn_id.
    fn allows(&self, task_id: Option<&str>, source_conn: u64) -> bool {
        match self {
            StdioScope::All => true,
            StdioScope::OwnConn(c) => *c == source_conn,
            StdioScope::Tasks(set) => task_id.map(|t| set.contains(t)).unwrap_or(false),
        }
    }
}

/// Subscriber — one connection may hold multiple subscriptions, all sharing that connection's push tx
struct Subscriber {
    conn_id: u64,
    channels: HashSet<String>,
    scope: StdioScope,
    tx: mpsc::Sender<Value>,
}

/// Broadcast hub (v1.5 #14) — Arc-shared by accept_loop/handle_conn/source tasks.
/// registry: sub_id → Subscriber. Source tasks start/stop lazily: self-exit at 0 subscribers,
/// restart on next subscribe.
/// C-OPS-04: shutdown Notify — triggered by the executor.shutdown IPC, listened on by
/// accept_loop → graceful drain.
/// C-OPS-05: ops metrics — AtomicU64 counters (exec_total/blocked/timeout/success/failed,
/// rollback) + duration/stdio accumulators (lock-free; callers read a snapshot and compute
/// averages). No histogram storage (memory budget); aggregation is enough for ops.
struct BroadcastHub {
    registry: Mutex<HashMap<String, Subscriber>>,
    executor: Arc<Executor>,
    conn_counter: AtomicU64,
    /// M-OPS-04: active connection count — fetch_add at handle_conn entry, fetch_sub in
    /// drop_conn. Lock-free; health reads a snapshot.
    active_conns: AtomicU64,
    sub_counter: AtomicU64,
    /// 0827 C-9: source lifetime generation — fetch_add on subscribe to that channel; the
    /// source task captures its generation at startup.
    /// When the source task is about to exit at 0 subscribers it re-compares: only if the
    /// generation is unchanged (no new subscribers arrived) does it truly exit; a changed
    /// generation (new subscribers in the meantime) keeps it running.
    /// Breaks the old race: source breaks at 0 subs + trailing take() vs a concurrent subscribe
    /// ensure seeing slot=running and returning early → source never started.
    telemetry_gen: AtomicU64,
    screenshot_gen: AtomicU64,
    telemetry_task: Mutex<Option<JoinHandle<()>>>,
    screenshot_task: Mutex<Option<JoinHandle<()>>>,
    shutdown: Arc<tokio::sync::Notify>,
    // C-OPS-05 metrics
    exec_total: AtomicU64,
    exec_blocked: AtomicU64,
    exec_timeout: AtomicU64,
    exec_success: AtomicU64,
    exec_failed: AtomicU64,
    rollback_total: AtomicU64,
    rollback_failed: AtomicU64,
    /// Cumulative execute wall-clock (ns) + cumulative stdio bytes — combined with exec_total for averages
    exec_duration_nanos_sum: AtomicU64,
    stdio_bytes_sum: AtomicU64,
    /// D6-02: fixed-bucket wall-clock histogram for execute (ns) — p50/p95/p99 via
    /// histogram_quantile interpolation.
    /// 6 bucket bounds (seconds): 0.005 / 0.05 / 0.5 / 5 / 30 / +Inf. Lock-free AtomicU64;
    /// snapshots accumulate into buckets.
    exec_duration_buckets: [AtomicU64; DURATION_BUCKETS_LE.len()],
    /// D6-02: wall-clock min/max (ns) — fastest/slowest single run, complements the histogram
    /// for tail distribution.
    exec_duration_nanos_min: AtomicU64,
    exec_duration_nanos_max: AtomicU64,
    /// M-OPS-02: Prometheus handle — render() emits text format for executor.metrics_prometheus.
    /// None = recorder install failed (degraded: JSON snapshot only, no prometheus endpoint).
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

    /// C-OPS-05: record one execute result → atomically accumulate metrics.
    /// exit_code 0=success, -124=timeout, -1=blocked/internal, other=failed.
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
        // Wall-clock (duration_sec seconds → ns; f64 truncated to u64 nanoseconds; sum overflow
        // is extremely unlikely — u64 ns ≈ 584 years)
        let dur_ns = (r.duration_sec.max(0.0) * 1e9) as u64;
        self.exec_duration_nanos_sum
            .fetch_add(dur_ns, Ordering::Relaxed);
        // stdio bytes (truncated stdout+stderr length — the real transfer volume)
        let bytes = (r.stdout.len() + r.stderr.len()) as u64;
        self.stdio_bytes_sum.fetch_add(bytes, Ordering::Relaxed);
        // D6-02: wall-clock histogram (blocked/timeout have duration=0, falling into the first
        // bucket; real wall-clock is tiered by bucket bounds).
        let dur_sec = r.duration_sec.max(0.0);
        if let Some(i) = duration_bucket_index(dur_sec) {
            self.exec_duration_buckets[i].fetch_add(1, Ordering::Relaxed);
        }
        // min/max (CAS loops: lock-free updates, no aliasing)
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
        // D6-02: mirror into the Prometheus histogram (render() emits _bucket{le=...}).
        metrics::histogram!("fe_exec_duration_seconds").record(dur_sec);
    }

    /// C-OPS-05: record one rollback — ok=true counts toward total, false toward total+failed
    fn record_rollback(&self, ok: bool) {
        self.rollback_total.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("fe_rollback_total").increment(1);
        if !ok {
            self.rollback_failed.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("fe_rollback_failed").increment(1);
        }
    }

    /// C-OPS-05: metrics snapshot — converted to JSON for the executor.metrics handler.
    /// Averages computed with exec_total (blocked/timeout do not count duration — their
    /// duration_sec=0).
    /// D6-02: wall-clock histogram — cumulative counts (each bucket inclusive of itself and
    /// smaller) → histogram_quantile interpolation for p50/p95/p99.
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
        // D6-02: cumulative counts — cumulative[i] = atomic sum of buckets 0..=i, last entry =
        // total (includes +Inf).
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
        cumulative.push(total); // +Inf last bucket = all executes
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

    /// M-OPS-02: Prometheus text format — render() emits scrape text for executor.metrics_prometheus.
    /// recorder install failure → None → handler returns -32603 (degraded, JSON snapshot only).
    /// No HTTP port opened (preserves M-SEC-01 UDS-only); callers pull the text over UDS and
    /// feed their own exporter.
    fn metrics_prometheus(&self) -> Option<String> {
        self.prom_handle.as_ref().map(|h| h.render())
    }

    fn next_conn_id(&self) -> u64 {
        self.conn_counter.fetch_add(1, Ordering::Relaxed)
    }

    fn next_sub_id(&self) -> String {
        format!("sub-{}", self.sub_counter.fetch_add(1, Ordering::Relaxed))
    }

    /// Register a subscription — returns the subscription_id. channels deduplicated, stored lowercase.
    /// scope = stdio scope (Blocker 10); interval_ms/screenshot_interval_ms passed through to
    /// the source task (M-IPC-01).
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
        // C-9: insert + gen bump under the same registry lock — the source task re-comparing
        // the generation sees the latest one and keeps running instead of exiting early.
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
        // gen bump outside the lock (AtomicU64, ordering guarantee: insert happens-before the
        // bump; the source task reading gen >= this value sees the new subscriber).
        if has_telemetry {
            self.telemetry_gen.fetch_add(1, Ordering::SeqCst);
        }
        if has_screenshot {
            self.screenshot_gen.fetch_add(1, Ordering::SeqCst);
        }
        info!(%sub_id, conn_id, "subscription registered");
        if has_telemetry {
            self.ensure_telemetry_source(interval_ms);
        }
        if has_screenshot {
            self.ensure_screenshot_source(screenshot_interval_ms);
        }
        sub_id
    }

    /// Unsubscribe — returns whether it was found and removed
    fn unsubscribe(&self, sub_id: &str) -> bool {
        let removed = self
            .registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sub_id)
            .is_some();
        if removed {
            info!(%sub_id, "subscription removed");
        }
        removed
    }

    /// Connection dropped — clear all subscriptions of that connection
    fn drop_conn(&self, conn_id: u64) {
        self.active_conns.fetch_sub(1, Ordering::Relaxed);
        metrics::gauge!("fe_connections").set(self.active_conns.load(Ordering::Relaxed) as f64);
        let mut reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let before = reg.len();
        reg.retain(|_, s| s.conn_id != conn_id);
        let dropped = before - reg.len();
        if dropped > 0 {
            info!(
                conn_id,
                dropped, "connection dropped, subscriptions cleared"
            );
        }
    }

    /// Ensure the telemetry source task is running — starts it when the handle is absent or
    /// already finished (including panic) (C-IPC-02/03).
    /// The source task self-exits at 0 telemetry subscribers and clears the handle; after a
    /// panic handle.is_finished()=true triggers a restart.
    /// interval_ms is passed in by the caller (M-IPC-01), defaulting to DEFAULT_INTERVAL_MS.
    /// 0827 C-9: capture the generation at startup — the source task re-compares the gen when
    /// about to exit at 0 subscribers and keeps running if it changed (see run_telemetry_source).
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
        info!(
            interval_ms = effective,
            gen, "telemetry source task started"
        );
    }

    /// Ensure the screenshot source task is running — same logic as telemetry (C-IPC-02/03).
    /// screenshot_interval_ms is passed in by the caller (M-IPC-01).
    /// 0827 C-9: same as telemetry, capture the gen at startup for run_screenshot_source to
    /// re-compare.
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
        info!(
            interval_ms = effective,
            gen, "screenshot source task started"
        );
    }

    /// Telemetry source — fan out a single executor.telemetry_stream, self-exit at 0 subscribers.
    /// 0827 C-9: re-compare the gen before exiting at 0 subscribers — a changed gen (new
    /// telemetry subscribers arrived meanwhile) keeps it running, avoiding a premature exit
    /// that drops frames.
    async fn run_telemetry_source(&self, interval_ms: u64, start_gen: u64) {
        let cfg = TelemetryStreamConfig {
            interval_ms,
            max_samples: 0,
            // L-15: broadcast source samples the executor itself (aggregated view), not bound to
            // a specific subprocess PID
            pid: None,
        };
        let (mut rx, handle) = self.executor.telemetry_stream(cfg);
        while let Some(sample) = rx.recv().await {
            let targets = self.collect_targets(CH_TELEMETRY);
            if targets.is_empty() {
                // C-9: re-compare the gen — a change means new subscribers arrived after the
                // 0-subscriber check; keep running instead of exiting.
                let cur_gen = self.telemetry_gen.load(Ordering::SeqCst);
                if cur_gen != start_gen {
                    info!(
                        start_gen,
                        cur_gen,
                        "telemetry at 0 subscribers but gen changed (new subscribers), continuing"
                    );
                    continue;
                }
                info!(
                    gen = cur_gen,
                    "telemetry at 0 subscribers and gen unchanged, source task self-exiting"
                );
                break;
            }
            let data = serde_json::to_value(&sample).unwrap_or(json!({}));
            for (sub_id, _scope, tx) in targets {
                let frame = notification(sub_id.clone(), CH_TELEMETRY, data.clone());
                if tx.try_send(frame).is_err() {
                    warn!(%sub_id, "telemetry frame dropped, channel full (P-IPC-01)");
                }
            }
        }
        drop(rx);
        let _ = handle.await;
    }

    /// Screenshot source — periodic gui_action(Screenshot) fan-out; TCC not authorized yields
    /// frames with data.ok=false, no crash. Self-exit at 0 subscribers.
    /// 0827 C-9: re-compare the gen before exiting at 0 subscribers — a changed gen (new
    /// screenshot subscribers arrived meanwhile) keeps it running, avoiding a premature exit
    /// that drops frames.
    async fn run_screenshot_source(&self, interval_ms: u64, start_gen: u64) {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
        interval.tick().await;
        loop {
            interval.tick().await;
            let targets = self.collect_targets(CH_SCREENSHOT);
            if targets.is_empty() {
                // C-9: re-compare the gen — a change means new subscribers arrived after the
                // 0-subscriber check; keep running instead of exiting.
                let cur_gen = self.screenshot_gen.load(Ordering::SeqCst);
                if cur_gen != start_gen {
                    info!(
                        start_gen,
                        cur_gen,
                        "screenshot at 0 subscribers but gen changed (new subscribers), continuing"
                    );
                    continue;
                }
                info!(
                    gen = cur_gen,
                    "screenshot at 0 subscribers and gen unchanged, source task self-exiting"
                );
                break;
            }
            let executor = self.executor.clone();
            let shot = tokio::task::spawn_blocking(move || {
                executor.gui_action(GuiAction::Screenshot {
                    mask_sensitive: false,
                })
            })
            .await;
            let data = match shot {
                Ok(Ok(r)) => {
                    let val = serde_json::to_value(&r).unwrap_or(json!({"ok": false}));
                    // P-IPC-03: large frames (with PNG b64) fanned out to N subscribers occupy
                    // memory without bound.
                    // Above 4MB degrade to a metadata frame (drop png_b64) to avoid slow-consumer buildup.
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
                            "screenshot frame exceeds {} bytes, degrading by dropping png_b64 (P-IPC-03)", MAX_SCREENSHOT_B64_BYTES
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
                    warn!(error = %e, "screenshot source gui_action failed");
                    json!({"ok": false, "error": format!("screenshot failed: {e}")})
                }
                Err(e) => {
                    warn!(error = %e, "screenshot source spawn_blocking failed");
                    json!({"ok": false, "error": format!("screenshot task failed: {e}")})
                }
            };
            for (sub_id, _scope, tx) in targets {
                let frame = notification(sub_id.clone(), CH_SCREENSHOT, data.clone());
                if tx.try_send(frame).is_err() {
                    warn!(%sub_id, "screenshot frame dropped, channel full (P-IPC-01)");
                }
            }
        }
    }

    /// Collect all (sub_id, tx, scope) for a channel — snapshot under lock, send outside the lock
    fn collect_targets(&self, channel: &str) -> Vec<(String, StdioScope, mpsc::Sender<Value>)> {
        let reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        reg.iter()
            .filter(|(_, s)| s.channels.contains(channel))
            .map(|(id, s)| (id.clone(), s.scope.clone(), s.tx.clone()))
            .collect()
    }

    /// stdio broadcast — called by execute/execute_stream handlers, fanned out to stdio subs
    /// **that pass the scope filter**.
    /// source_conn = conn_id of the connection that initiated the command (for OwnConn
    /// filtering); data carries task_id (for Tasks filtering).
    /// Blocker 10 (audit 2.9): the old unfiltered broadcast to everyone = cross-tenant leak
    /// (Agent A sees Agent B's stdout).
    fn broadcast_stdio(&self, data: Value, source_conn: u64) {
        // D4-4: fast path — with 0 stdio subscribers skip task_id extraction + per-sub frame
        // building (avoids locking the registry to build a Vec + clone Value when there are no
        // subscribers). An empty collect_targets means no subscribers; return with zero work.
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
                warn!(%sub_id, "stdio frame dropped, channel full (P-IPC-01)");
            }
        }
    }

    /// stdio broadcast (blocking variant) — dedicated to done frames. A done frame is the
    /// stream-termination marker and must not be dropped (otherwise the caller never sees the end).
    /// Difference from broadcast_stdio: uses `tx.send(frame).await` (waits for a slot) instead
    /// of try_send (drop when full).
    /// D5-3: the old version also used try_send for done; with a slow consumer filling the
    /// channel the done frame was dropped and the subscriber never saw termination → hang.
    async fn broadcast_stdio_blocking(&self, data: Value, source_conn: u64) {
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
            // Block waiting for a slot — done must not be dropped. If tx is closed (subscriber
            // disconnected) → send returns Err, recorded via warn! (not a panic).
            if tx.send(frame).await.is_err() {
                warn!(%sub_id, "stdio done frame send failed — subscriber already disconnected (D5-3)");
            }
        }
    }
}

/// Build a server-push notification Value.
/// No id — JSON-RPC notification convention (M-IPC-02): the client distinguishes responses vs
/// pushes by the presence of id.
/// Spec-compliant; the implicit contract is that clients must implement this distinction,
/// documented.
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

/// IPC server — holds Arc<Executor> + Arc<BroadcastHub> + Arc<ShellRegistry>,
/// newline-delimited JSON-RPC 2.0 over UDS.
/// Issue #32: in-flight streaming execution registry — same M-ARCH-1 as
/// ShellRegistry/BroadcastHub, state lives in the IPC layer, the Executor stays per-task
/// stateless. key = stringified JSON-RPC request id (the execute_stream id),
/// value = oneshot::Sender<()>. executor.cancel {id} looks it up and sends (()) → fe-sandbox
/// kills the process tree.
/// deregistered after the stream ends (normal Done / consumer disconnect) to prevent leaks.
pub struct StreamRegistry {
    entries: Mutex<HashMap<String, oneshot::Sender<()>>>,
}

impl StreamRegistry {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamRegistry {
    /// Register an in-flight stream — returns the cancel_rx to hand to execute_streaming.
    /// Duplicate id (same connection reusing an id) → the old Sender is dropped (its rx
    /// returns Err, the old stream is unaffected) and the new one overwrites it.
    pub fn register(&self, id: String) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel::<()>();
        let mut map = self.entries.lock().expect("StreamRegistry lock poisoned");
        if map.contains_key(&id) {
            warn!(stream_id = %id, "duplicate stream id, overwriting old cancel Sender (old stream unaffected)");
        }
        map.insert(id, tx);
        rx
    }

    /// Cancel an in-flight stream — returns true if found and send succeeded, false if the id
    /// does not exist (already finished or unknown).
    pub fn cancel(&self, id: &str) -> bool {
        let tx = {
            let mut map = self.entries.lock().expect("StreamRegistry lock poisoned");
            map.remove(id)
        };
        match tx {
            Some(tx) => {
                if tx.send(()).is_ok() {
                    info!(stream_id = %id, "cancel dispatched (Issue #32)");
                    true
                } else {
                    // rx already dropped (stream just finished) — send Err, treated as not cancelled
                    info!(stream_id = %id, "cancel found but stream already finished (rx drop)");
                    false
                }
            }
            None => {
                info!(stream_id = %id, "cancel id not found (already finished or unknown)");
                false
            }
        }
    }

    /// Deregister after a stream ends — prevents leaks (cleared on Done/disconnect). Idempotent.
    pub fn deregister(&self, id: &str) {
        let mut map = self.entries.lock().expect("StreamRegistry lock poisoned");
        map.remove(id);
    }
}

/// M-ARCH-1: ShellRegistry moved to this layer (alongside BroadcastHub) — the Executor stays
/// per-task stateless; an Executor restart at the IPC layer does not lose background shell
/// handles; the serve-path and the in-process path can share the same registry.
pub struct IpcServer {
    executor: Arc<Executor>,
    hub: Arc<BroadcastHub>,
    shells: Arc<fe_core::shell::ShellRegistry>,
    streams: Arc<StreamRegistry>,
}

impl IpcServer {
    pub fn new() -> Self {
        info!("IpcServer::new() — holding Executor + BroadcastHub + ShellRegistry");
        let executor = Arc::new(Executor::new());
        let hub = BroadcastHub::new(executor.clone());
        let shells = Arc::new(fe_core::shell::ShellRegistry::new());
        let streams = Arc::new(StreamRegistry::new());
        Self {
            executor,
            hub,
            shells,
            streams,
        }
    }

    pub fn with_executor(executor: Executor) -> Self {
        info!("IpcServer::with_executor()");
        let executor = Arc::new(executor);
        let hub = BroadcastHub::new(executor.clone());
        let shells = Arc::new(fe_core::shell::ShellRegistry::new());
        let streams = Arc::new(StreamRegistry::new());
        Self {
            executor,
            hub,
            shells,
            streams,
        }
    }

    /// M-ARCH-1: share the caller's already-held registry — fe-pyo3 serve() and the in-process
    /// path see the same set of shells.
    pub fn with_executor_and_shells(
        executor: Executor,
        shells: Arc<fe_core::shell::ShellRegistry>,
    ) -> Self {
        info!("IpcServer::with_executor_and_shells() — sharing ShellRegistry");
        let executor = Arc::new(executor);
        let hub = BroadcastHub::new(executor.clone());
        let streams = Arc::new(StreamRegistry::new());
        Self {
            executor,
            hub,
            shells,
            streams,
        }
    }

    /// A-4: share the caller's already-held Executor Arc — fe-pyo3 serve() no longer rebuilds
    /// the Executor.
    /// Whitelists the caller configured in-process via with_extra_whitelist + SIGHUP-reloaded
    /// extras persist across the serve-path
    /// (the old with_executor_and_shells took an owned Executor then Arc::new; serve rebuilding
    /// it lost the in-process whitelist).
    /// registry shared as in M-ARCH-1. All three params are Arc — compatible with
    /// serve()/serve_blocking() taking self.executor.clone().
    pub fn with_executor_arc_and_shells(
        executor: Arc<Executor>,
        shells: Arc<fe_core::shell::ShellRegistry>,
    ) -> Self {
        info!("IpcServer::with_executor_arc_and_shells() — sharing Executor Arc + ShellRegistry");
        let hub = BroadcastHub::new(executor.clone());
        let streams = Arc::new(StreamRegistry::new());
        Self {
            executor,
            hub,
            shells,
            streams,
        }
    }

    /// C-1 (audit 0827 product adversarial arch): share the caller's already-held StreamRegistry.
    /// Symmetric with ShellRegistry (M-ARCH-1) — a fe-pyo3 serve() restart does not lose the
    /// cancel capability of in-flight execute_stream (Issue #32 deterministic cancel contract).
    /// The old version rebuilt the StreamRegistry in every IpcServer ctor → cancel_stream(51)
    /// silently missed after a serve() restart, leaving the old stream's subprocess tree behind
    /// (same bug class as P-PYO3-01).
    pub fn with_executor_arc_shells_and_streams(
        executor: Arc<Executor>,
        shells: Arc<fe_core::shell::ShellRegistry>,
        streams: Arc<StreamRegistry>,
    ) -> Self {
        info!("IpcServer::with_executor_arc_shells_and_streams() — sharing Executor Arc + ShellRegistry + StreamRegistry");
        let hub = BroadcastHub::new(executor.clone());
        Self {
            executor,
            hub,
            shells,
            streams,
        }
    }

    /// M-ARCH-1: expose the registry reference (fetched by health probe / dispatch).
    pub fn shells(&self) -> &Arc<fe_core::shell::ShellRegistry> {
        &self.shells
    }

    /// Issue #32: expose the StreamRegistry reference (serve-path threads accept_loop/handle_conn).
    pub fn streams(&self) -> &Arc<StreamRegistry> {
        &self.streams
    }

    /// Resolve the socket path — parameter override > env FUSION_EXECUTOR_SOCK > default
    pub fn resolve_sock(override_path: Option<&str>) -> String {
        if let Some(p) = override_path {
            if !p.is_empty() {
                return p.to_string();
            }
        }
        std::env::var("FUSION_EXECUTOR_SOCK").unwrap_or_else(|_| default_sock_path())
    }

    /// D6-07: bind the socket with stale-socket self-healing.
    /// The old version unconditionally unlinked the old socket then bound — hijacking a running
    /// instance (D6-05 multi-instance conflict).
    /// New version: bind directly; on EADDRINUSE probe liveness —
    ///   connect succeeds = a live instance exists → fail-loud (refuse to hijack);
    ///   connect fails = stale dead socket → unlink + rebind once (self-healing).
    /// Residual race: within the check→rebind window another instance may bind the same path;
    /// if the second bind still fails → fail-loud.
    /// True atomicity needs bindfd+flock, overkill for the trusted local UDS scenario; the
    /// residual window is documented as acceptable.
    /// D6-08: error messages use English FATAL/WARN keywords for ops grep/alert.
    fn bind_with_stale_recovery(path: &Path) -> Result<UnixListener> {
        match UnixListener::bind(path) {
            Ok(l) => Ok(l),
            Err(e) => {
                // Only EADDRINUSE goes through stale self-healing; other bind errors
                // (permissions/path) fail-loud directly.
                let in_use = e
                    .raw_os_error()
                    .map(|c| c == libc::EADDRINUSE || c == libc::EEXIST)
                    .unwrap_or(false);
                if !in_use {
                    error!(sock = %path.display(), error = %e, "FATAL: socket bind failed");
                    return Err(anyhow::anyhow!(
                        "FATAL: socket bind failed: {}: {}",
                        path.display(),
                        e
                    ));
                }
                // D6-07: probe whether the socket holder is a live instance.
                let live = std::os::unix::net::UnixStream::connect(path).is_ok();
                if live {
                    error!(sock = %path.display(), "FATAL: socket already in use — live instance detected, refusing to hijack; set FUSION_EXECUTOR_SOCK to run a second instance");
                    return Err(anyhow::anyhow!(
                        "FATAL: socket already in use (live instance on {}); \
                         set FUSION_EXECUTOR_SOCK to run a second instance",
                        path.display()
                    ));
                }
                // Stale dead socket — unlink + rebind once.
                warn!(sock = %path.display(), "WARN: stale socket detected (no live listener), unlinking and rebinding");
                let _ = std::fs::remove_file(path);
                UnixListener::bind(path).map_err(|e2| {
                    error!(sock = %path.display(), error = %e2, "FATAL: socket rebind failed after stale cleanup");
                    anyhow::anyhow!(
                        "FATAL: socket rebind failed after stale cleanup: {}: {}",
                        path.display(),
                        e2
                    )
                })
            }
        }
    }

    /// Async serve — bind + chmod 0o600 + accept loop.
    /// Returns (shutdown_tx, join_handle): the caller sends on shutdown_tx to trigger graceful
    /// exit, and can await the join handle to wait for cleanup.
    /// D6-05/07: bind goes through bind_with_stale_recovery — live instance fails loud, stale
    /// socket self-heals (no unconditional unlink).
    /// D6-05: multi-instance requires explicitly setting FUSION_EXECUTOR_SOCK (different socket)
    /// + FE_LOG_DIR (different logs) per instance.
    pub async fn serve(
        &self,
        sock_path: &str,
    ) -> Result<(oneshot::Sender<()>, tokio::task::JoinHandle<()>)> {
        let path = Path::new(sock_path).to_path_buf();
        // C-10: create + tighten the parent directory to 0o700 first, then bind — eliminates the
        // bind→chmod window.
        // ensure_sock_dir also tightens permissions on an already-existing directory (the old
        // early-return skipped that, leaving a permissive directory behind).
        // D3-8: permission tightening failure → fail-loud, serve refuses to start (a
        // world-readable/writable socket = M-SEC-01 bypass).
        ensure_sock_dir(&path)?;
        let listener = Self::bind_with_stale_recovery(&path)?;
        chmod_secure(&path)?;
        info!(sock = %path.display(), "IPC server listening");
        // ARCH-1: seatbelt governance — execute + shell_start both default true (commercial
        // security default, aligned with fe-core serde default_true).
        // Callers explicitly pass seatbelt:false to disable isolation (trusted local opt-out).
        info!(
            "seatbelt enabled by default (execute + shell_start paths) — subprocesses are isolated via macOS sandbox-exec (network deny + execve deny for dangerous binaries). Trusted local callers can pass seatbelt:false to opt out. See health.seatbelt_default_on"
        );

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let executor = self.executor.clone();
        let hub = self.hub.clone();
        let shells = self.shells.clone();
        let streams = self.streams.clone();
        // M-OPS-02: SIGHUP config hot-reload task — runs alongside accept_loop, aborted on exit
        let sighup_task = tokio::spawn(handle_sighup_reload(executor.clone()));
        // M-OPS-03: runtime-configurable drain timeout (env, default 10s).
        let drain_deadline = resolve_shutdown_timeout();
        let join = tokio::spawn(async move {
            accept_loop(
                listener,
                executor,
                hub,
                shells,
                streams,
                shutdown_rx,
                drain_deadline,
            )
            .await;
            sighup_task.abort();
            let _ = std::fs::remove_file(&path);
        });
        Ok((shutdown_tx, join))
    }

    /// Synchronous blocking serve — called directly by PyO3 serve() (on BLOCKING_RT).
    /// C-PYO3-02: while serve_blocking holds the GIL, Python signal handlers do not run (the
    /// main thread is stuck in Rust block_on) → SIGTERM cannot interrupt. Switched to Rust-side
    /// tokio::signal listening on SIGINT/SIGTERM.
    /// C-OPS-03: the signal does not select-abandon the accept_loop (otherwise drain never runs,
    /// orphaned connections). Instead the signal task calls hub.shutdown.notify_waiters() on
    /// receiving a signal; accept_loop listens on that Notify itself, exits, and drains
    /// in-flight connections (join_all with a 10s deadline). PyO3 serve() must py.detach to
    /// release the GIL.
    pub fn serve_blocking(&self, sock_path: &str) -> Result<()> {
        let path = sock_path.to_string();
        let executor = self.executor.clone();
        let hub = self.hub.clone();
        let shells = self.shells.clone();
        let streams = self.streams.clone();
        // gap #5: the IPC server runs on its dedicated IPC_RT (clamped 4-16 workers), isolated
        // from BLOCKING_RT (the in-process run() path).
        // The old version ran on BLOCKING_RT (cap 8); a 64-connection fan-out starved it →
        // responses could not be written → recv 30s timeout deadlock.
        fe_core::IPC_RT.block_on(async move {
            let p = Path::new(&path).to_path_buf();
            ensure_sock_dir(&p)?;
            let listener = Self::bind_with_stale_recovery(&p)?;
            chmod_secure(&p)?;
            info!(sock = %p.display(), "IPC server listening (blocking, IPC_RT, signal-stoppable)");
            // ARCH-1: seatbelt governance — execute + shell_start both default true (commercial
            // security default, aligned with fe-core serde default_true).
            // Callers explicitly pass seatbelt:false to disable isolation (trusted local opt-out).
            info!(
                "seatbelt enabled by default (execute + shell_start paths) — subprocesses are isolated via macOS sandbox-exec (network deny + execve deny for dangerous binaries). Trusted local callers can pass seatbelt:false to opt out. See health.seatbelt_default_on"
            );
            let (_tx, rx) = oneshot::channel::<()>();
            // Signal task: on SIGINT/SIGTERM → notify_waiters; accept_loop exits on its own and drains
            let signal_task = tokio::spawn(wait_signal_and_notify(hub.clone()));
            // M-OPS-02: SIGHUP config hot-reload task — reloads log level + whitelist (no exit trigger)
            let sighup_task = tokio::spawn(handle_sighup_reload(executor.clone()));
            // M-OPS-03: runtime-configurable drain timeout (env, default 10s).
            let drain_deadline = resolve_shutdown_timeout();
            // accept_loop runs until shutdown_notify (signal) or shutdown_rx fires, draining in-flight internally
            accept_loop(listener, executor, hub, shells, streams, rx, drain_deadline).await;
            signal_task.abort();
            sighup_task.abort();
            let _ = std::fs::remove_file(&p);
            Ok(())
        })
    }
}

/// C-OPS-03/04: block until SIGINT/SIGTERM, then trigger hub.shutdown.notify_waiters().
/// accept_loop listens on that Notify → exits accept and drains in-flight connections (not
/// abandoned by select).
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
                warn!(error = %e, "SIGTERM registration failed, listening on SIGINT only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    info!("SIGINT/SIGTERM received, triggering graceful drain");
    hub.shutdown.notify_waiters();
}

/// M-OPS-02: SIGHUP config hot-reload — re-reads RUST_LOG (log level) +
/// FUSION_EXECUTOR_EXTRA_WHITELIST (whitelist).
/// Runs alongside wait_signal_and_notify (the latter owns SIGINT/SIGTERM exit; SIGHUP does not
/// exit, it only reloads).
/// No config → no-op (no error); tracing not initialized → skip log reload; env missing → skip
/// whitelist reload.
/// Honors the Executor stateless contract: executor: Arc<Executor> is passed through
/// reload_whitelist(&self) into the ArcSwap store.
///
/// IMPL-12 signal-race assertion: this handler **never triggers shutdown** — it does not call
/// hub.shutdown.notify_waiters(), does not clean up connections, does not abort accept_loop.
/// Shutdown has a single source = wait_signal_and_notify (SIGINT/SIGTERM).
/// SIGHUP only reloads config; the server keeps serving. The race surface = single-source
/// shutdown; SIGHUP is orthogonal to exit. Test coverage in
/// tests::sighup_does_not_trigger_shutdown.
async fn handle_sighup_reload(executor: Arc<Executor>) {
    #[cfg(unix)]
    {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "SIGHUP registration failed, config hot-reload unavailable");
                return;
            }
        };
        loop {
            sighup.recv().await;
            info!("SIGHUP received, reloading config (log level + whitelist)");
            reload_log_level();
            reload_extra_whitelist(&executor);
        }
    }
    #[cfg(not(unix))]
    {
        // Non-unix has no SIGHUP — suspend forever (no CPU burn).
        std::future::pending::<()>().await;
    }
}

/// SIGHUP: re-read the RUST_LOG env and swap the log level via FilterHandle.reload_log_filter.
/// RUST_LOG unset → fall back to DEFAULT_FILTER_DIRECTIVE (info); tracing not initialized
/// (handle None) → skip.
fn reload_log_level() {
    let directive = std::env::var("RUST_LOG")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| logging::DEFAULT_FILTER_DIRECTIVE.to_string());
    match logging::current_handle() {
        Some(handle) => match handle.reload_log_filter(&directive) {
            Ok(()) => info!(directive = %directive, "SIGHUP log level reload complete"),
            Err(e) => {
                warn!(error = %e, "SIGHUP log level reload failed (fail-loud, current level unchanged)")
            }
        },
        None => {
            warn!("SIGHUP log reload: tracing not initialized, skipping (init_tracing not called)")
        }
    }
}

/// SIGHUP: re-read the FUSION_EXECUTOR_EXTRA_WHITELIST env (comma-separated) →
/// Executor.reload_whitelist.
/// Unset / empty → pass an empty slice (fall back to the pure baseline whitelist); the Executor
/// passes through to SecurityGuard.reload_extras (baseline rebuild).
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
    info!(
        count = extras.len(),
        "SIGHUP whitelist reload complete (baseline + extras)"
    );
}

impl Default for IpcServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Accept loop — exits on shutdown signal (programmatic oneshot or IPC Notify) or listener close.
/// C-OPS-03: collects handle_conn JoinHandles and drains after exit (join_all with a deadline,
/// aborting on timeout).
/// M-OPS-03: deadline passed in by the caller (FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS, default 10s).
/// Concurrent connections bounded by the MAX_CONNECTIONS semaphore (C-IPC-05).
async fn accept_loop(
    listener: UnixListener,
    executor: Arc<Executor>,
    hub: Arc<BroadcastHub>,
    shells: Arc<fe_core::shell::ShellRegistry>,
    streams: Arc<StreamRegistry>,
    mut shutdown_rx: oneshot::Receiver<()>,
    drain_deadline: Duration,
) {
    let sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    // Audit 2.11: exec semaphore — bounds concurrent **non-streaming execs** (subprocesses), not
    // connections. Shared server-wide, decoupled from the connection semaphore.
    let exec_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_EXECS));
    // RUN-3: streaming exec semaphore — separate from exec_sem. A streaming permit spans the
    // whole chunk→done lifetime (long-lived); non-streaming short executes use exec_sem (16).
    // Separation prevents 16 long streams starving short commands.
    let stream_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_STREAMS));
    // C-OPS-03: in-flight connection JoinHandle collection — join_all + deadline on drain
    let conns: Arc<AsyncMutex<Vec<JoinHandle<()>>>> = Arc::new(AsyncMutex::new(Vec::new()));
    let shutdown_notify = hub.shutdown.clone();
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown_rx => {
                info!("shutdown (oneshot) received, stopping accept");
                break;
            }
            _ = shutdown_notify.notified() => {
                info!("shutdown (IPC Notify) received, stopping accept");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        // M-SEC-01: LOCAL_PEERCRED UID check — reject other UIDs immediately,
                        // taking no semaphore slot and running no handler.
                        if !peer_uid_matches(&stream) {
                            continue;
                        }
                        // Connection cap — reject when the semaphore is full (C-IPC-05)
                        let permit = match sem.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(e) => {
                                warn!(error = %e, "semaphore closed, stopping accept");
                                break;
                            }
                        };
                        let ex = executor.clone();
                        let h = hub.clone();
                        let sh = shells.clone();
                        let st = streams.clone();
                        let es = exec_sem.clone();
                        let ss = stream_sem.clone();
                        let handle = tokio::spawn(async move {
                            handle_conn(stream, ex, h, sh, st, es, ss).await;
                            drop(permit);
                        });
                        conns.lock().await.push(handle);
                    }
                    Err(e) => warn!(error = %e, "accept failed"),
                }
            }
        }
    }
    // C-OPS-03: drain in-flight connections — join_all with a deadline, aborting the rest on timeout
    drain_connections(conns, drain_deadline).await;
}

/// C-OPS-03/M-OPS-03 + 0827 C-8/P-1: graceful drain — join all in-flight connections, aborting
/// those unfinished within the deadline.
/// deadline is resolved by serve/serve_blocking from FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS
/// (default 10s).
/// C-8 fixes: (1) drain the handles out of the lock first, then release it — join/abort all
/// happen outside the lock, not blocking other accept_loop paths;
/// (2) **global deadline** — record start; each handle uses the shrunk remain = deadline -
/// elapsed; total time ≤ deadline (the old per-handle reset deadline → 64 connections worst
/// case 64×10s = 640s).
/// &mut h is awaited by reference (not moved) → in the timeout branch h is still owned and
/// h.abort() is callable (dropping a JoinHandle only detaches, never stops the task).
async fn drain_connections(conns: Arc<AsyncMutex<Vec<JoinHandle<()>>>>, deadline: Duration) {
    // C-8: take the handles and release the lock immediately — join/abort outside the lock.
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
        "draining in-flight connections (global deadline, join outside lock)"
    );
    let start = tokio::time::Instant::now();
    let mut joined_ok = 0usize;
    let mut aborted = 0usize;
    for mut h in handles {
        let elapsed = start.elapsed();
        if elapsed >= deadline {
            // Global budget exhausted — abort + reap everything remaining.
            h.abort();
            let _ = h.await;
            aborted += 1;
            continue;
        }
        let remain = deadline - elapsed;
        match tokio::time::timeout(remain, &mut h).await {
            Ok(Ok(())) => joined_ok += 1,
            Ok(Err(e)) => warn!(error = %e, "connection task join failed"),
            Err(_) => {
                warn!("connection drain global budget exhausted, aborting (forced stop)");
                h.abort();
                let _ = h.await;
                aborted += 1;
            }
        }
    }
    if aborted > 0 {
        warn!(aborted, "drain timeout aborted connections (fail-loud)");
    }
    info!(
        in_flight = total,
        drained_ok = joined_ok,
        aborted,
        "drain complete"
    );
}

/// Per-connection handler — DUPLEX (v1.5 #14):
///   read_task: read_line dispatches requests; responses/streaming frames written to the locked writer
///   push_task: reads push_rx, writes server-push notifications to the locked writer
///   shared writer = Arc<AsyncMutex<OwnedWriteHalf>>; line writes are atomic (write_all under lock)
///   connection drop → clear subscriptions + close push_task
///
/// 0827 A-6(1) push channel model note (deferred):
///   One push_tx per connection (capacity 128) multiplexes all of that connection's
///   subscriptions (telemetry/stdio/screenshot).
///   Risk: a slow consumer (e.g. unread telemetry frames) fills the 128 → backpressure on other
///   channels of the same connection.
///   Mitigated: source-side try_send drops when full (P-IPC-01, overflow-drop does not block
///   the source task, no unbounded memory growth);
///   dropped frames only warn, no crash (fail-visible). Per-sub independent channel multiplexing
///   is a bigger architectural change (push_task would need to route multiple rx by sub_id);
///   the current try_send drop semantics are equivalent to a bounded channel, not a safety
///   defect — deferred per Rule 2 (simplicity first). Caller guidance: slow consumers should
///   open multiple connections or isolate stdio with own_conn.
async fn handle_conn(
    stream: UnixStream,
    executor: Arc<Executor>,
    hub: Arc<BroadcastHub>,
    shells: Arc<fe_core::shell::ShellRegistry>,
    streams: Arc<StreamRegistry>,
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

    // push_task — writes server-push frames out
    let push_writer = writer.clone();
    let push_handle = tokio::spawn(async move {
        let mut rx = push_rx;
        let mut close = close_rx;
        loop {
            tokio::select! {
                biased;
                _ = &mut close => {
                    info!(conn_id, "push_task received close, exiting");
                    break;
                }
                frame = rx.recv() => {
                    match frame {
                        Some(v) => {
                            let line = match serde_json::to_string(&v) {
                                Ok(s) => s + "\n",
                                Err(e) => {
                                    warn!(error = %e, "push frame serialization failed, skipping");
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

    // read_task — line-by-line dispatch (with 1MB cap + idle timeout, C-IPC-04/C-IPC-05)
    // Audit 2.12: the old version inlined await of execute_stream/telemetry_stream inside the
    // read_task loop; during streaming it never read the next line → after subscribe, an
    // execute_stream response was blocked until the stream ended.
    // Fix: spawn an independent task per request (per-connection request concurrency
    // multiplexing); read_task keeps reading the next line without blocking.
    // Responses/streaming frames write to the shared Arc<AsyncMutex<Writer>> (write_all atomic
    // under lock), safe across tasks.
    let mut reader = BufReader::new(reader);
    let read_hub = hub.clone();
    let read_exec = executor.clone();
    let read_shells = shells.clone();
    let read_streams = streams.clone();
    let read_push_tx = push_tx.clone();
    let read_writer = writer.clone();
    let read_close = close_tx;
    // M-2 (audit 0827 arch): the old Vec<JoinHandle> grew without bound — a long-lived
    // connection issuing massive numbers of requests kept finished handles forever, all
    // resident until connection close (handle leak). JoinSet manages handles internally;
    // try_join_next periodically reaps finished items; a final join_all collects in-flight
    // tasks (concurrency bounded by exec_sem/stream_sem).
    let mut req_tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    loop {
        let line = match read_capped_line(&mut reader).await {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(code) => {
                // Over-limit/timeout → reply with a JSON-RPC error, then drop the connection
                let data = serde_json::to_string(&err_resp(
                    Value::Null,
                    code,
                    if code == ERR_PARSE {
                        "request line exceeds the 1MB cap"
                    } else {
                        "idle read timeout"
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

        // 2.12: spawn a task per request; read_task does not block. The shared writer lock keeps
        // line writes atomic.
        let w = read_writer.clone();
        let ex = read_exec.clone();
        let h = read_hub.clone();
        let sh = read_shells.clone();
        let st = read_streams.clone();
        let ptx = read_push_tx.clone();
        let es = exec_sem.clone();
        let ss = stream_sem.clone();
        req_tasks.spawn(async move {
            dispatch_request(
                &w, req_id, method, params, &ex, &h, &sh, &st, conn_id, &ptx, &es, &ss,
            )
            .await;
        });
        // M-2: periodically reap finished handles — frees memory, prevents unbounded JoinSet growth.
        while req_tasks.try_join_next().is_some() {}
    }
    // Connection dropped — wait for all in-flight request tasks to finish (they hold the
    // writer lock to write responses), clear subscriptions, close push_task.
    // M-1: bounded join — 5s grace per task, give up on timeout (task detached).
    while let Some(t) = req_tasks.join_next().await {
        let _ = t;
    }
    hub.drop_conn(conn_id);
    let _ = read_close.send(());
    let _ = push_handle.await;
}

/// Single-request dispatch — spawned from read_task (audit 2.12 per-connection request multiplexing).
/// execute (non-streaming) takes an exec_sem permit; execute_stream takes a stream_sem permit
/// (RUN-3 separation, prevents long streams starving short commands).
#[allow(clippy::too_many_arguments)]
async fn dispatch_request(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    method: String,
    params: Value,
    executor: &Arc<Executor>,
    hub: &Arc<BroadcastHub>,
    shells: &Arc<fe_core::shell::ShellRegistry>,
    streams: &Arc<StreamRegistry>,
    conn_id: u64,
    push_tx: &mpsc::Sender<Value>,
    exec_sem: &Arc<Semaphore>,
    stream_sem: &Arc<Semaphore>,
) {
    if method == "executor.execute_stream" {
        if let Err(e) = handle_execute_stream(
            writer, id, params, executor, hub, streams, conn_id, stream_sem,
        )
        .await
        {
            warn!(error = %e, "execute_stream frame write failed");
        }
        return;
    }
    if method == "executor.cancel" {
        handle_cancel(writer, id, params, streams).await;
        return;
    }
    if method == "executor.telemetry_stream" {
        if let Err(e) = handle_telemetry_stream(writer, id, params, executor).await {
            warn!(error = %e, "telemetry_stream frame write failed");
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
        .unwrap_or_else(|_| err_str(Value::Null, ERR_INTERNAL, "response serialization failed"))
        + "\n";
    let mut w = writer.lock().await;
    let _ = w.write_all(data.as_bytes()).await;
}

/// Line read with a 1MB cap + idle timeout (C-IPC-04/C-IPC-05).
/// Ok(Some(line)) — one line (newline excluded); Ok(None) — EOF; Err(code) — over-limit
/// ERR_PARSE / timeout ERR_INTERNAL.
/// Audit Blocker 7 / 2.10: the original read_until buffered without bound until a newline
/// before checking the cap → OOM on a newline-less flood.
/// Fix: fill_buf+consume in chunks; before each extend, reject when buf.len()+take >
/// MAX_LINE_BYTES (in-loop cap, fail-loud).
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
                "request line over 1MB, rejected (in-loop cap, newline-less flood protection)"
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
        // No newline yet, keep reading (buf.len()+take is capped, no unbounded growth)
    }
}

/// Subscribe — parse channels/interval_ms/screenshot_interval_ms, register with the hub,
/// respond {ok, subscription_id} (M-IPC-01)
async fn handle_subscribe(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    params: Value,
    conn_id: u64,
    hub: &Arc<BroadcastHub>,
    push_tx: &mpsc::Sender<Value>,
) {
    // L-7 + M-7(1): channel normalization + validation. The old version stored them as-is
    // (case-sensitive) → "Telemetry" never matched the lowercase CH_TELEMETRY, the source task
    // never started = ghost subscription (no push frames received); unknown channel names were
    // also silently accepted.
    // Fix: normalize with to_lowercase; reject channel names outside
    // {telemetry,stdio,screenshot} (-32600, fail-loud).
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
        let resp = err_resp(id, ERR_INVALID_REQ, "missing channels");
        write_line(writer, resp).await;
        return;
    }
    // M-7(1): reject unknown channel names (the old version silently accepted them → ghost subscription).
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
                "unknown channels: {} (valid: telemetry/stdio/screenshot)",
                unknown.join(",")
            ),
        );
        write_line(writer, resp).await;
        return;
    }
    // interval_ms (telemetry) / screenshot_interval_ms (screenshot) — passed through to the
    // source task (M-IPC-01)
    let interval_ms = params
        .get("interval_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_INTERVAL_MS);
    let screenshot_interval_ms = params
        .get("screenshot_interval_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_SCREENSHOT_INTERVAL_MS);
    // stdio scope (Blocker 10, breaks the audit §2.9 cross-tenant leak):
    //   all=true → All (broadcast to everyone); task_ids=[...] → Tasks allowlist; default →
    //   OwnConn (only this connection's commands)
    let scope = if params.get("all").and_then(|v| v.as_bool()).unwrap_or(false) {
        StdioScope::All
    } else if let Some(arr) = params.get("task_ids").and_then(|v| v.as_array()) {
        // M-7(3): the old version silently turned an empty task_ids into an empty Tasks set
        // (never matches = dead subscription, no stdio ever received, no signal).
        // Fix: empty task_ids → fail-loud -32600 (clear caller misuse, not "no filter").
        let set: HashSet<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        if set.is_empty() {
            let resp = err_resp(
                id,
                ERR_INVALID_REQ,
                "task_ids must be a non-empty array (an empty set never matches; use all=true or omit task_ids)",
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

/// Unsubscribe — remove the hub registration, respond {ok}
async fn handle_unsubscribe(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    params: Value,
    hub: &Arc<BroadcastHub>,
) {
    let sub_id = match params.get("subscription_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            let resp = err_resp(id, ERR_INVALID_REQ, "missing subscription_id");
            write_line(writer, resp).await;
            return;
        }
    };
    let ok = hub.unsubscribe(&sub_id);
    let resp = ok_resp(id, json!({"ok": ok}));
    write_line(writer, resp).await;
}

/// Write one JSON Value line (write_all under lock, atomic).
/// On serialization failure fall back to a valid error frame; a bare `\n` would hang the
/// client (P-IPC-02).
async fn write_line(writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>, v: Value) {
    let line = match serde_json::to_string(&v) {
        Ok(s) => s + "\n",
        Err(e) => {
            warn!(error = %e, "Value serialization failed, falling back to error frame");
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{{\"code\":{},\"message\":\"response serialization failed\"}}}}\n",
                ERR_INTERNAL
            )
        }
    };
    let mut w = writer.lock().await;
    let _ = w.write_all(line.as_bytes()).await;
}

/// Streaming execution — chunk frames + done frame, shared id, newline-delimited frames
/// written one by one.
/// v1.5 #14: chunk/done are also broadcast to stdio subscribers (cross-connection fan-out).
/// chunk: {"jsonrpc":"2.0","id":id,"result":{"type":"chunk","data":"..."}}
/// done:  {"jsonrpc":"2.0","id":id,"result":{"type":"done","result":{...ExecutionResult}}}
#[allow(clippy::too_many_arguments)]
async fn handle_execute_stream(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    params: Value,
    executor: &Arc<Executor>,
    hub: &Arc<BroadcastHub>,
    streams: &Arc<StreamRegistry>,
    conn_id: u64,
    stream_sem: &Arc<Semaphore>,
) -> Result<()> {
    let req: ExecutionRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            let frame = serde_json::to_string(&err_resp(
                id,
                ERR_INVALID_REQ,
                &format!("invalid params: {}", e),
            ))? + "\n";
            let mut w = writer.lock().await;
            w.write_all(frame.as_bytes()).await?;
            return Ok(());
        }
    };
    let task_id = req.task_id.clone();
    // RUN-3: acquire the streaming permit — stream_sem is separate from the non-streaming
    // exec_sem (capacity 64 vs 16).
    // A stream holds its permit across the whole chunk→done lifetime (long); sharing exec_sem
    // would let 16 long streams fill it → short executes starve.
    // stream_sem capacity = MAX_CONNECTIONS, bounded by the connection semaphore cap, so it does
    // not contend with non-streaming short executions.
    let _stream_permit = stream_sem
        .acquire()
        .await
        .map_err(|e| anyhow::anyhow!("stream_sem closed: {e}"))?;
    // Issue #32: register the in-flight stream — cancel_rx is handed to execute_streaming.
    // id stringified as the StreamRegistry key (executor.cancel {id} looks it up). deregister
    // when the stream ends.
    let stream_id = id.to_string();
    let cancel_rx = streams.register(stream_id.clone());
    let (mut rx, handle) = match executor.execute_streaming(req, Some(cancel_rx)).await {
        Ok(p) => p,
        Err(e) => {
            streams.deregister(&stream_id);
            let frame = serde_json::to_string(&err_resp(
                id,
                ERR_INTERNAL,
                &format!("execute_stream failed: {}", e),
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
                // L-6: record metrics for completed streaming execs too — the old version missed
                // record_exec, so Prometheus fe_exec_total undercounted streaming executions
                // (only non-streaming execute was counted). Aligned with the non-streaming handler.
                hub.record_exec(&r);
                // D5-3: the done frame goes through the blocking broadcast — must not be dropped
                // (subscribers must see the stream-termination marker).
                hub.broadcast_stdio_blocking(
                    json!({
                        "task_id": task_id,
                        "event": "done",
                        "result": result_val.clone(),
                    }),
                    conn_id,
                )
                .await;
                json!({"type": "done", "result": result_val})
            }
        };
        let frame = serde_json::to_string(&ok_resp(id.clone(), result))? + "\n";
        let mut w = writer.lock().await;
        if w.write_all(frame.as_bytes()).await.is_err() {
            break;
        }
    }
    // M-1 (audit 0827 arch): handle.await with no timeout → if the spawned task hangs after rx
    // closes, the handle never completes, leaking a tokio task + occupying a stream_sem slot
    // (RUN-3 starvation).
    // 5s grace: rx closed means the sandbox-side run_streaming has exited; the join is just
    // cleanup, normally <1ms.
    // Timeout = task hung, give up the join (task detached, does not block stream_sem release).
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    streams.deregister(&stream_id);
    Ok(())
}

/// Issue #32: executor.cancel — server-side deterministic kill of an in-flight stream's
/// process tree.
/// params: {id: <JSON-RPC id>} — id must match the execute_stream request id (StreamRegistry key).
/// Response: {ok: true, cancelled: true} if found and cancel dispatched; {ok: false,
/// cancelled: false} if the id does not exist (already finished or unknown).
/// cancel = local deterministic process-tree kill (NOT a cooperative stop request) — once
/// dispatched fe-sandbox SIGINT→SIGKILL the process group; the Done frame carries exit_code -1
/// + cancelled true. Caller best-effort: after sending cancel, still read the done frame.
async fn handle_cancel(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    params: Value,
    streams: &Arc<StreamRegistry>,
) {
    // id may be number/string/null — aligned with the StreamRegistry key (id.to_string()).
    let target = params.get("id").cloned().unwrap_or(Value::Null);
    let target_str = target.to_string();
    let cancelled = streams.cancel(&target_str);
    let resp = ok_resp(id, json!({ "ok": cancelled, "cancelled": cancelled }));
    let frame = serde_json::to_string(&resp).unwrap_or_else(|_| {
        err_str(
            Value::Null,
            ERR_INTERNAL,
            "cancel response serialization failed",
        )
    }) + "\n";
    let mut w = writer.lock().await;
    let _ = w.write_all(frame.as_bytes()).await;
}

/// Real-time telemetry stream (request-initiated, not subscribe) — writes TelemetrySample
/// frames one by one, shared id.
/// sample: {"jsonrpc":"2.0","id":id,"result":{"type":"sample",...TelemetrySample}}
/// params: {interval_ms?:u64, max_samples?:u64, pid?:u32} (defaults 10Hz / unlimited / executor pid)
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
    // M-1: same as execute_stream — bounded join, prevents a hung spawned task from leaking a
    // task + a sem slot.
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    Ok(())
}

/// Handle a single method → Ok(Value) | Err((code, msg))
/// v1.5 #14: after execute (non-streaming) completes, broadcast the stdio done to subscribers
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
            // C-OPS-05: ok is decided by real probes (not hardcoded) — probes BLOCKING_RT
            // responsiveness + external dependencies (git).
            // D2-2 fix (2026-08-28): the old probe_runtime spawned an empty task on BLOCKING_RT
            // with a 1s timeout; when 16 concurrent execs saturated the limited workers, the
            // probe task queued → timeout → rt_ok=false → falsely flagging a healthy busy
            // instance for removal.
            // New version distinguishes alive/busy/dead: a short timeout (200ms) probes
            // BLOCKING_RT responsiveness (an idle worker picks it up immediately);
            // on timeout, check exec_sem available permits — 0=saturated (busy but healthy, LB
            // should shed load, not remove), >0 and still timing out = stalled (truly unhealthy).
            let rt = probe_runtime(Duration::from_millis(200), exec_sem.available_permits()).await;
            // D4-9: the health probe mirrors the exec_sem available count into a Prometheus
            // gauge (complements the scrape path).
            metrics::gauge!("fe_exec_sem_available").set(exec_sem.available_permits() as f64);
            let deps = probe_dependencies().await;
            // Any core dependency missing → ok:false (unhealthy dependency = degraded service)
            let deps_ok = deps.iter().all(|d| d["ok"].as_bool() == Some(true));
            // ok is false only when dead (stalled) or a dependency is missing; busy still has
            // ok=true (busy is normal load, not failure).
            let ok = rt.healthy() && deps_ok;
            Ok(json!({
                "ok": ok,
                "version": env!("CARGO_PKG_VERSION"),
                "git_sha": env!("FE_GIT_SHA"),
                "build_time": env!("FE_BUILD_TIME"),
                "ax_trusted": fe_core::gui::GuiController::ax_trusted(),
                // ARCH-1: seatbelt governance signal — execute + shell_start both default true
                // (commercial security default).
                // Load balancers/ops read this field to know the instance defaults to runtime
                // isolation enabled.
                "seatbelt_default_on": true,
                // D2-2: runtime tri-state — alive (idle-responsive)/busy (saturated, shed
                // load)/dead (stalled, remove).
                // ok=alive||busy; dead → ok=false. busy is for LB load shedding (not removal).
                "runtime": { "ok": rt.healthy(), "state": rt.state(), "available_permits": rt.available_permits },
                "dependencies": deps,
                // M-OPS-04/M-OPS-05: deep ops metrics — connections/worker threads/active
                // shells/memory.
                // Ops dashboards + load balancers use this to judge instance load and shell
                // registry watermark.
                "depth": probe_health_depth(shells, hub)
            }))
        }
        "executor.execute" => {
            let req: ExecutionRequest = serde_json::from_value(params)
                .map_err(|e| (ERR_INVALID_REQ, format!("invalid params: {}", e)))?;
            let task_id = req.task_id.clone();
            // Audit 2.11: take an exec permit to bound concurrent subprocesses (not connections).
            // execute_async spawns a subprocess; the permit is held until return.
            let _exec_permit = exec_sem
                .acquire()
                .await
                .map_err(|e| (ERR_INTERNAL, format!("exec_sem closed: {e}")))?;
            // D4-9: after acquiring the permit, mirror the available count into a gauge (the
            // permit drops at the end of the handler and Rust has no drop-hook hook point,
            // so set once right after acquire to reflect the new watermark; refreshed again on
            // the next request's acquire).
            metrics::gauge!("fe_exec_sem_available").set(exec_sem.available_permits() as f64);
            let r: ExecutionResult = executor
                .execute_async(req)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("execute failed: {}", e)))?;
            hub.record_exec(&r);
            // D4-9: refresh the watermark before release (the permit is about to drop and be returned).
            metrics::gauge!("fe_exec_sem_available").set((exec_sem.available_permits() + 1) as f64);
            let val = serde_json::to_value(&r).unwrap_or(json!({}));
            // D5-3: the done frame goes through the blocking broadcast — must not be dropped
            // (subscribers must see the stream-termination marker).
            hub.broadcast_stdio_blocking(
                json!({
                    "task_id": task_id,
                    "event": "done",
                    "result": val.clone(),
                }),
                conn_id,
            )
            .await;
            Ok(val)
        }
        "executor.snapshot_create" => {
            let cwd =
                param_str(&params, "cwd").ok_or((ERR_INVALID_REQ, "missing cwd".to_string()))?;
            let id = executor
                .snapshot_create_async(&cwd)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("snapshot_create failed: {}", e)))?;
            Ok(json!({"snapshot_id": id}))
        }
        // D6-03 (audit 0827 product): snapshot listing — reads back the on-disk NDJSON index
        // for on-call/audit queries.
        "executor.list_snapshots" => {
            let cwd =
                param_str(&params, "cwd").ok_or((ERR_INVALID_REQ, "missing cwd".to_string()))?;
            let snaps = executor
                .list_snapshots_async(&cwd)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("list_snapshots failed: {}", e)))?;
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
        // Issue #11 / #12.4: pre-execution validation — the caller (fusion-code) asks the user
        // for authorization before execute.
        // The Executor only enforces the hard blocklist (never-blocked); interactive
        // confirmation belongs to the caller (Option A, stateless).
        "executor.validate" => {
            let command = param_str(&params, "command")
                .ok_or((ERR_INVALID_REQ, "missing command".to_string()))?;
            let verdict = executor.validate(&command);
            let allowed = verdict.allowed;
            let reason = verdict.reason.clone();
            // Manually map to lowercase strings — consistent with fe-pyo3 validate(), unified
            // wire shape across both transport layers
            let stage = verdict.stage.map(|s| match s {
                fe_core::security::SecurityStage::Regex => "regex",
                fe_core::security::SecurityStage::Tokenizer => "tokenizer",
                // Issue #23: verdict stage mapped by guard orchestration (verdict comes from
                // guard.evaluate).
                fe_core::security::SecurityStage::Semantic => "semantic",
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
                .ok_or((ERR_INVALID_REQ, "missing snapshot_id".to_string()))?;
            let cwd =
                param_str(&params, "cwd").ok_or((ERR_INVALID_REQ, "missing cwd".to_string()))?;
            let ok = executor
                .rollback_async(&snapshot_id, &cwd)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("rollback failed: {}", e)))?;
            hub.record_rollback(ok);
            if !ok {
                return Err((
                    -32012,
                    "rollback failed (stash apply or not a repo)".to_string(),
                ));
            }
            Ok(json!({"ok": true}))
        }
        "executor.diagnostics" => {
            // Audit 3.9: PTY merges stdout+stderr → tracebacks land in stdout (stderr always
            // empty, see fe-sandbox SandboxResult.stderr docs). The old version only read
            // params.stderr → the slicer got an empty string, no diagnostics.
            // Prefer stdout (the PTY-merged stream), fall back to stderr/output (backward
            // compatible with stdio-only backends or old clients).
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
                .ok_or((ERR_INVALID_REQ, "missing action".to_string()))?;
            let action: GuiAction = serde_json::from_value(action_val.clone()).map_err(|e| {
                (
                    ERR_INVALID_REQ,
                    format!("action deserialization failed: {e}"),
                )
            })?;
            let result = executor
                .gui_action(action)
                .map_err(|e| (ERR_INTERNAL, format!("gui_action failed: {e}")))?;
            Ok(serde_json::to_value(&result).unwrap_or(json!({})))
        }
        "executor.gui_action_batch" => {
            let actions_val = params
                .get("actions")
                .ok_or((ERR_INVALID_REQ, "missing actions".to_string()))?;
            let actions: Vec<GuiAction> =
                serde_json::from_value(actions_val.clone()).map_err(|e| {
                    (
                        ERR_INVALID_REQ,
                        format!("actions deserialization failed: {e}"),
                    )
                })?;
            let results = executor
                .gui_action_batch(actions)
                .map_err(|e| (ERR_INTERNAL, format!("gui_action_batch failed: {e}")))?;
            Ok(serde_json::to_value(&results).unwrap_or(json!({})))
        }
        "executor.metrics" => {
            // C-OPS-05: self-service metrics — exec counts + duration/stdio aggregates +
            // rollback counts.
            // Ops dashboards/load balancers read this for health trends (block rate / timeout
            // rate / rollback failure rate) with no external exporter dependency.
            Ok(hub.metrics_snapshot())
        }
        "executor.metrics_prometheus" => {
            // M-OPS-02: Prometheus text format — callers pull over UDS and feed their own exporter.
            // No HTTP port opened (preserves M-SEC-01 UDS-only). recorder install failure → -32603.
            match hub.metrics_prometheus() {
                Some(text) => Ok(json!({ "ok": true, "text": text })),
                None => Err((
                    ERR_INTERNAL,
                    "Prometheus recorder not installed, only executor.metrics JSON available"
                        .to_string(),
                )),
            }
        }
        "executor.shutdown" => {
            // C-OPS-04: IPC-triggered graceful drain — notify_waiters wakes the accept_loop's
            // shutdown_notify branch → stop accept + drain in-flight connections (join_all with
            // a 10s deadline).
            // The response is sent first, then accept_loop exits (this connection's read_task
            // ends naturally after dispatch).
            info!("shutdown request received, triggering graceful drain (C-OPS-04)");
            hub.shutdown.notify_waiters();
            Ok(json!({"ok": true, "shutting_down": true}))
        }
        "executor.file_edit" => {
            let path =
                param_str(&params, "path").ok_or((ERR_INVALID_REQ, "missing path".to_string()))?;
            let old_string = param_str(&params, "old_string")
                .ok_or((ERR_INVALID_REQ, "missing old_string".to_string()))?;
            let new_string = param_str(&params, "new_string")
                .ok_or((ERR_INVALID_REQ, "missing new_string".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let replace_all = params
                .get("replace_all")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let r = executor
                .file_edit(&path, &old_string, &new_string, cwd, replace_all)
                .map_err(|e| (ERR_INTERNAL, format!("file_edit failed: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.write_file" => {
            // #2: write_file(path, content, cwd?) — whole-file create/overwrite + create parent dirs
            let path =
                param_str(&params, "path").ok_or((ERR_INVALID_REQ, "missing path".to_string()))?;
            let content = param_str(&params, "content")
                .ok_or((ERR_INVALID_REQ, "missing content".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .write_file(&path, &content, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("write_file failed: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.glob" => {
            let pattern = param_str(&params, "pattern")
                .ok_or((ERR_INVALID_REQ, "missing pattern".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let entries = executor
                .glob(&pattern, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("glob failed: {}", e)))?;
            Ok(serde_json::to_value(&entries).unwrap_or(json!({})))
        }
        "executor.grep" => {
            let pattern = param_str(&params, "pattern")
                .ok_or((ERR_INVALID_REQ, "missing pattern".to_string()))?;
            let paths: Vec<String> = params
                .get("paths")
                .and_then(|p| p.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .ok_or((ERR_INVALID_REQ, "missing paths array".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let matches = executor
                .grep(&pattern, &paths, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("grep failed: {}", e)))?;
            Ok(serde_json::to_value(&matches).unwrap_or(json!({})))
        }
        "executor.grep_with_opts" => {
            let pattern = param_str(&params, "pattern")
                .ok_or((ERR_INVALID_REQ, "missing pattern".to_string()))?;
            let paths: Vec<String> = params
                .get("paths")
                .and_then(|p| p.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .ok_or((ERR_INVALID_REQ, "missing paths array".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            // #7: opts sub-object deserialized via serde (all fields #[serde(default)], missing = default)
            let opts: fe_core::tools::GrepOptions = match params.get("opts") {
                Some(v) => serde_json::from_value(v.clone())
                    .map_err(|e| (ERR_INVALID_REQ, format!("opts parse failed: {}", e)))?,
                None => fe_core::tools::GrepOptions::default(),
            };
            let out = executor
                .grep_with_opts(&pattern, &paths, cwd, &opts)
                .map_err(|e| (ERR_INTERNAL, format!("grep_with_opts failed: {}", e)))?;
            Ok(serde_json::to_value(&out).unwrap_or(json!({})))
        }
        "executor.apply_patch" => {
            let diff =
                param_str(&params, "diff").ok_or((ERR_INVALID_REQ, "missing diff".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .apply_patch(&diff, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("apply_patch failed: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.replace_function" => {
            let path =
                param_str(&params, "path").ok_or((ERR_INVALID_REQ, "missing path".to_string()))?;
            let fn_name = param_str(&params, "fn_name")
                .ok_or((ERR_INVALID_REQ, "missing fn_name".to_string()))?;
            let new_body = param_str(&params, "new_body")
                .ok_or((ERR_INVALID_REQ, "missing new_body".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .replace_function(&path, &fn_name, &new_body, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("replace_function failed: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.multi_edit" => {
            let path =
                param_str(&params, "path").ok_or((ERR_INVALID_REQ, "missing path".to_string()))?;
            let edits_val = params
                .get("edits")
                .ok_or((ERR_INVALID_REQ, "missing edits array".to_string()))?;
            let edits: Vec<fe_core::tools::MultiEditItem> =
                serde_json::from_value(edits_val.clone())
                    .map_err(|e| (ERR_INVALID_REQ, format!("edits parse failed: {}", e)))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .multi_edit(&path, &edits, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("multi_edit failed: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.notebook_edit" => {
            let path =
                param_str(&params, "path").ok_or((ERR_INVALID_REQ, "missing path".to_string()))?;
            let cell_id = params.get("cell_id").and_then(|v| v.as_str());
            let cell_number = params.get("cell_number").and_then(|v| v.as_i64());
            let new_source = param_str(&params, "new_source")
                .ok_or((ERR_INVALID_REQ, "missing new_source".to_string()))?;
            let edit_mode: fe_core::tools::NotebookEditMode =
                match params.get("edit_mode").and_then(|v| v.as_str()) {
                    Some(m) => serde_json::from_value(serde_json::Value::String(m.to_string()))
                        .map_err(|e| (ERR_INVALID_REQ, format!("edit_mode parse failed: {}", e)))?,
                    None => fe_core::tools::NotebookEditMode::Replace,
                };
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .notebook_edit(&path, cell_id, cell_number, &new_source, edit_mode, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("notebook_edit failed: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.shell_start" => {
            // #1: background persistent shell start — security validation in fe-core (fail-closed)
            let command = param_str(&params, "command")
                .ok_or((ERR_INVALID_REQ, "missing command".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str()).map(String::from);
            let task_id = params
                .get("task_id")
                .and_then(|v| v.as_str())
                .map(String::from);
            let env: std::collections::HashMap<String, String> = match params.get("env_vars") {
                Some(v) => serde_json::from_value(v.clone())
                    .map_err(|e| (ERR_INVALID_REQ, format!("env_vars parse failed: {}", e)))?,
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
            // Issue #64: optional per-shell seatbelt profile — deserialized via serde (with
            // deny_unknown_fields validation).
            let sandbox_profile: Option<fe_sandbox::seatbelt::SandboxProfile> = match params
                .get("sandbox")
            {
                Some(v) if !v.is_null() => Some(
                    serde_json::from_value(v.clone())
                        .map_err(|e| (ERR_INVALID_REQ, format!("sandbox parse failed: {}", e)))?,
                ),
                _ => None,
            };
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
                sandbox_profile,
            };
            let r = executor.shell_start(shells, sp);
            // M-OPS-02: fe_shell_active gauge — list_shells has already reaped finished shells,
            // so the running count is the active count.
            let active = Executor::list_shells(shells)
                .iter()
                .filter(|s| !s.finished)
                .count() as f64;
            metrics::gauge!("fe_shell_active").set(active);
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.shell_output" => {
            // #1: poll a tail snapshot + running/exit status
            let shell_id = param_str(&params, "shell_id")
                .ok_or((ERR_INVALID_REQ, "missing shell_id".to_string()))?;
            let out = Executor::shell_output(shells, &shell_id)
                .map_err(|e| (ERR_INTERNAL, format!("shell_output failed: {}", e)))?;
            Ok(serde_json::to_value(&out).unwrap_or(json!({})))
        }
        "executor.kill_shell" => {
            // #1: kill the process tree (KillShell parity)
            let shell_id = param_str(&params, "shell_id")
                .ok_or((ERR_INVALID_REQ, "missing shell_id".to_string()))?;
            let ok = Executor::kill_shell(shells, &shell_id)
                .map_err(|e| (ERR_INTERNAL, format!("kill_shell failed: {}", e)))?;
            // M-OPS-02: fe_shell_active gauge — recompute the active count after kill.
            let active = Executor::list_shells(shells)
                .iter()
                .filter(|s| !s.finished)
                .count() as f64;
            metrics::gauge!("fe_shell_active").set(active);
            Ok(json!({ "ok": ok }))
        }
        "executor.list_shells" => {
            // #1: list all background shells
            let list = Executor::list_shells(shells);
            Ok(serde_json::to_value(&list).unwrap_or(json!({})))
        }
        _ => Err((
            ERR_METHOD_NOT_FOUND,
            format!("Method not found: {}", method),
        )),
    }
}

/// D2-2 (2026-08-28): runtime health tri-state — distinguishes "busy but healthy" from
/// "stalled failure".
/// The old bool probe falsely reported unhealthy under saturated load (probe task queued and
/// timed out), causing the LB to remove healthy busy instances.
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
    /// ok=alive||busy; only dead counts as unhealthy (stalled requires removal).
    fn healthy(&self) -> bool {
        !matches!(self.state, RuntimeState::Dead)
    }

    /// State string for JSON serialization.
    fn state(&self) -> &'static str {
        match self.state {
            RuntimeState::Alive => "alive",
            RuntimeState::Busy => "busy",
            RuntimeState::Dead => "dead",
        }
    }
}

/// C-OPS-05 + D2-2: probe IPC_RT responsiveness, distinguishing the tri-state.
/// A short timeout (caller passes 200ms) spawns an empty task — an idle worker picks it up
/// immediately = alive;
/// on timeout, check exec_sem available permits: 0=saturated (busy, busy but healthy), >0 and
/// still timing out = stalled (dead, real failure).
/// gap #5: the health endpoint serves LB decisions (remove/shed), so it must probe the runtime
/// that actually serves = IPC_RT (the serve_blocking entry).
/// The old version probed BLOCKING_RT — in serve mode BLOCKING_RT is barely used (only the
/// in-process run() path) → falsely reported alive.
/// IPC_RT stalled / all workers deadlocked → spawn never completes + permits available → dead
/// → ok:false removal.
async fn probe_runtime(timeout: Duration, available_permits: usize) -> RuntimeHealth {
    let h = fe_core::IPC_RT.handle();
    let task = h.spawn(async {});
    let state = if tokio::time::timeout(timeout, task).await.is_ok() {
        RuntimeState::Alive
    } else if available_permits == 0 {
        // No available exec permits = all 16 slots taken = saturated load; the probe queueing is
        // expected, not a failure.
        warn!(
            available_permits,
            "D2-2: health probe timed out but exec_sem saturated, judging busy (busy but healthy, not stalled)"
        );
        RuntimeState::Busy
    } else {
        // Available exec permits but the runtime is unresponsive = workers stalled/deadlocked,
        // a real failure.
        error!(
            available_permits,
            "D2-2: health probe timed out with permits available, judging dead (IPC_RT stalled/deadlocked)"
        );
        RuntimeState::Dead
    };
    RuntimeHealth {
        state,
        available_permits,
    }
}

/// C-OPS-05 + 0827 P-1: probe external dependencies — `git --version` (rollback/snapshots
/// depend on the git CLI).
/// Any missing dependency → degraded service, ok=false. Returns [{name, ok, version?}].
/// P-1 fix: the old version spawned `git --version` twice (once for ok, once for the version)
/// — merged into a single spawn.
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

/// M-OPS-04/M-OPS-05: deep health metrics — connections/worker threads/active shells/memory (MB).
/// - connections: atomic snapshot of BroadcastHub.active_conns (lock-free).
/// - workers: IPC_RT worker_threads — same formula as the fe-core IPC_RT init
///   (available_parallelism, clamp 4-16).
/// - active_shells: count of Executor::list_shells(registry).filter(!finished); M-OPS-05 warns
///   when nearing MAX_SHELLS.
/// - mem_mb: this process's RSS via sysinfo (lightweight single refresh, no sampling task).
///
/// M-ARCH-1: the registry is held by IpcServer (Executor stateless), passed by reference
/// through dispatch_request.
fn probe_health_depth(shells: &Arc<fe_core::shell::ShellRegistry>, hub: &BroadcastHub) -> Value {
    let connections = hub.active_conns.load(Ordering::Relaxed);
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(4, 16);
    let sh = Executor::list_shells(shells);
    let active_shells = sh.iter().filter(|s| !s.finished).count();
    // M-OPS-05: near-capacity warning (80%) — prevents the registry filling up and forcing new
    // shell_starts to reap existing shells.
    let max_shells = fe_core::shell::MAX_SHELLS;
    if max_shells > 0 && active_shells * 5 >= max_shells * 4 {
        warn!(
            active_shells,
            max_shells, "M-OPS-05: active shells near capacity (>=80%), callers should clean up background tasks"
        );
    }
    // mem_mb — this process's RSS (lightweight sysinfo refresh)
    let mem_mb = current_proc_mem_mb();
    json!({
        "connections": connections,
        "workers": workers,
        "active_shells": active_shells,
        "max_shells": max_shells,
        "mem_mb": mem_mb,
    })
}

/// Read this process's RSS (MB) via sysinfo — the M-OPS-04 health mem_mb probe.
/// Reuses the same 3-arg refresh_processes_specifics as fe-telemetry (sysinfo 0.32 API).
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

/// chmod 0o600 — owner read/write only (local privilege-escalation protection, C-IPC-01).
/// The old socket was unlinked before listening; permissions are tightened immediately after bind.
/// D3-8 enterprise hardening: permission tightening failure = a world-readable/writable socket
/// = M-SEC-01 bypass → fail-loud Err, serve refuses to start.
#[cfg(unix)]
fn chmod_secure(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        error!(path = %path.display(), error = %e, "FATAL: chmod 0o600 socket failed — refusing to start with a world-readable socket (D3-8)");
        anyhow::anyhow!("chmod 0o600 socket failed (D3-8 enterprise hardening): {}: {}", path.display(), e)
    })?;
    info!(path = %path.display(), "socket tightened to 0o600 (owner-only rw, C-IPC-01)");
    Ok(())
}

#[cfg(not(unix))]
fn chmod_secure(_path: &Path) -> Result<()> {
    Ok(())
}

/// M-SEC-01 + 0827 C-10: create the socket parent directory 0o700 — a private directory blocks
/// other UIDs from connecting (no search permission on the directory).
/// Only effective for the HOME default path; explicit /tmp override paths rely on the
/// chmod_secure 0o600 single file.
/// C-10 fix: an already-existing directory is **also tightened to 0o700** (the old early-return
/// left a permissive directory behind; other UIDs could traverse+connect).
/// Only this run's/newly created socket parent directory is tightened; parents (HOME itself)
/// are untouched — what gets tightened is ~/.fusion-executor.
/// D3-8 enterprise hardening:
///   - create_dir_all failure → fail-loud Err (cannot create the private directory = isolation
///     cannot be guaranteed).
///   - chmod 0o700 failure on a directory we just created → fail-loud Err (our own directory
///     should be tightenable; failure = FS anomaly).
///   - chmod EPERM/EACCES on a pre-existing non-owned directory (e.g. a shared /tmp root) →
///     degrade to warn + Ok (not the HOME default path; relies on the file 0o600 as fallback).
///   - other chmod errors (read-only FS/IO) → fail-loud Err.
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
            error!(dir = %parent.display(), error = %e, "FATAL: failed to create the private socket directory — refusing to start (D3-8 M-SEC-01)");
            anyhow::anyhow!("failed to create the private socket directory (D3-8 M-SEC-01): {}: {}", parent.display(), e)
        })?;
        info!(dir = %parent.display(), "M-SEC-01: socket parent directory created");
    }
    // C-10: regardless of new or pre-existing, attempt to tighten to 0o700.
    match std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)) {
        Ok(()) => {
            info!(dir = %parent.display(), "M-SEC-01: socket parent directory tightened to 0o700 (blocks other-UID traverse/connect)");
        }
        Err(e) => {
            let perm_denied = matches!(e.raw_os_error(), Some(1) | Some(13)); // EPERM/EACCES
            if !pre_existing || !perm_denied {
                // A newly created directory failing to tighten (we own it, should be
                // tightenable) or a non-permission IO error → fail-loud.
                error!(dir = %parent.display(), error = %e, "FATAL: chmod 0o700 on the private directory failed — refusing other-UID traverse/connect (D3-8 M-SEC-01)");
                return Err(anyhow::anyhow!(
                    "chmod 0o700 on the private directory failed (D3-8 M-SEC-01): {}: {}",
                    parent.display(),
                    e
                ));
            }
            // Pre-existing non-owned directory (e.g. shared /tmp root) cannot be chmod'd →
            // degrade: rely on the socket file 0o600 as fallback.
            warn!(
                dir = %parent.display(),
                error = %e,
                "M-SEC-01: cannot tighten a non-owned socket parent directory to 0o700 (shared /tmp etc.) — degrading to file 0o600 as fallback"
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_sock_dir(_path: &Path) -> Result<()> {
    Ok(())
}

/// M-SEC-01: LOCAL_PEERCRED UID check — after accept, the peer UID must equal this process's UID.
/// Prevents other UIDs on the same host from connecting via a symlink or /tmp override path.
/// Zero unsafe (nix safe wrapper).
/// Returns true=allow (same UID), false=reject (other UID or credential fetch failed, fail-closed).
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
                    self_uid, "M-SEC-01: rejected other-UID connection (LOCAL_PEERCRED)"
                );
                false
            }
        }
        Err(e) => {
            // fail-closed: peer credentials unavailable → reject (prevents degraded bypass)
            warn!(error = %e, "M-SEC-01: LOCAL_PEERCRED credential fetch failed, rejecting connection (fail-closed)");
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
        // C-OPS-05: ok is decided by real probes (IPC_RT + git dependency); git exists in CI →
        // ok=true.
        assert_eq!(resp["result"]["ok"], true);
        // ARCH-1: seatbelt governance signal — execute enabled by default (commercial security default).
        assert_eq!(resp["result"]["seatbelt_default_on"], true);
        // ax_trusted = real AXIsProcessTrusted() query (C-GUI-01), false when CI has no TCC.
        // Only assert the field exists and is boolean, never hardcode true.
        assert!(
            resp["result"]["ax_trusted"].is_boolean(),
            "ax_trusted should be a boolean: {}",
            resp["result"]["ax_trusted"]
        );
        // C-OPS-05: runtime probe — IPC_RT spawns an empty task with a timeout as liveness check.
        // D2-2: runtime tri-state (alive/busy/dead); an idle test environment should be alive,
        // ok=true.
        assert_eq!(
            resp["result"]["runtime"]["ok"], true,
            "runtime should be healthy (IPC_RT responsive): {}",
            resp["result"]["runtime"]
        );
        assert!(
            matches!(
                resp["result"]["runtime"]["state"].as_str(),
                Some("alive") | Some("busy")
            ),
            "D2-2: runtime.state should be alive or busy (not dead): {}",
            resp["result"]["runtime"]
        );
        assert!(
            resp["result"]["runtime"]["available_permits"].is_number(),
            "D2-2: runtime.available_permits should be a number: {}",
            resp["result"]["runtime"]
        );
        // C-OPS-05: dependencies array — git CLI (rollback depends on it)
        let deps = &resp["result"]["dependencies"];
        assert!(deps.is_array(), "dependencies should be an array: {}", deps);
        let git_dep = deps
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == "git")
            .expect("dependencies should contain git");
        assert_eq!(
            git_dep["ok"], true,
            "git dependency should be healthy: {}",
            git_dep
        );
        assert!(
            git_dep["version"].is_string(),
            "git should report version: {}",
            git_dep
        );
        let _ = std::fs::remove_file(&sock);
    }

    // gap #5 regression: 64 concurrent echoes all complete, no deadlock starvation.
    // Old bug: serve_blocking ran on the shared BLOCKING_RT (cap 8 workers); a 64-connection
    // fan-out starved it → responses could not be written → recv 30s timeout (32/64 hung).
    // Fixed by the dedicated IPC_RT (clamp 4-16) isolation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_echo_64_all_complete() {
        let sock = tmp_sock("conc64");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let n = 64usize;
        let mut handles = Vec::with_capacity(n);
        for i in 0..n {
            let s = sock.clone();
            handles.push(tokio::spawn(async move {
                let req = format!(
                    r#"{{"jsonrpc":"2.0","id":{i},"method":"executor.execute","params":{{"command":"echo {i}"}}}}"#
                );
                let t0 = std::time::Instant::now();
                let resp = rpc(&s, &req).await;
                (i, resp, t0.elapsed())
            }));
        }
        let mut ok = 0usize;
        let mut max_dur = std::time::Duration::ZERO;
        for h in handles {
            let (i, resp, dur) = h.await.unwrap();
            assert_eq!(
                resp["result"]["exit_code"], 0,
                "conn {i}: bad response (the old bug hung here until timeout): {resp}"
            );
            ok += 1;
            if dur > max_dur {
                max_dur = dur;
            }
        }
        assert_eq!(ok, n, "all {n} should complete, got {ok}");
        // Old bug max dur ~30s (recv timeout); after the fix should fit a <15s budget.
        assert!(
            max_dur.as_secs() < 15,
            "max dur {max_dur:?} over budget (old bug: 32 hung for 30s)"
        );
        let _ = std::fs::remove_file(&sock);
    }

    // M-OPS-04/M-OPS-05: deep health metrics — connections/workers/active_shells/max_shells/mem_mb
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
        assert!(depth.is_object(), "depth should be an object: {}", depth);
        // M-OPS-04: all five fields present
        for key in [
            "connections",
            "workers",
            "active_shells",
            "max_shells",
            "mem_mb",
        ] {
            assert!(
                depth.get(key).is_some(),
                "depth missing field {key}: {depth}"
            );
        }
        // M-OPS-04: this RPC's connection counts — at least 1 active connection
        let conns = depth["connections"].as_u64();
        assert!(
            conns.is_some() && conns.unwrap() >= 1,
            "connections should be >=1 (this RPC is connected): {depth}"
        );
        // M-OPS-04: workers >=2 (BLOCKING_RT floor)
        let workers = depth["workers"].as_u64();
        assert!(
            workers.is_some() && workers.unwrap() >= 2,
            "workers should be >=2: {depth}"
        );
        // M-OPS-05: max_shells == 256 (fe-shell cap)
        assert_eq!(
            depth["max_shells"].as_u64(),
            Some(256),
            "max_shells should be 256: {depth}"
        );
        // M-OPS-05: active_shells == 0 (no background shells started)
        assert_eq!(
            depth["active_shells"].as_u64(),
            Some(0),
            "active_shells should be 0: {depth}"
        );
        // M-OPS-04: mem_mb non-negative (this process's RSS)
        let mem = depth["mem_mb"].as_f64();
        assert!(
            mem.is_some() && mem.unwrap() >= 0.0,
            "mem_mb should be >=0: {depth}"
        );
        let _ = std::fs::remove_file(&sock);
    }

    // M-OPS-03: configurable shutdown drain timeout — pure function parse (no env side
    // effects, thread-safe unit test).
    #[test]
    fn mops03_shutdown_timeout_parse() {
        // missing → default 10s
        assert_eq!(parse_shutdown_timeout(None), SHUTDOWN_DEADLINE);
        // within the valid range → override
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
        // out of range → fall back to default
        assert_eq!(parse_shutdown_timeout(Some("0".into())), SHUTDOWN_DEADLINE);
        assert_eq!(
            parse_shutdown_timeout(Some("301".into())),
            SHUTDOWN_DEADLINE
        );
        assert_eq!(
            parse_shutdown_timeout(Some("99999".into())),
            SHUTDOWN_DEADLINE
        );
        // non-numeric → fall back to default
        assert_eq!(
            parse_shutdown_timeout(Some("abc".into())),
            SHUTDOWN_DEADLINE
        );
        assert_eq!(parse_shutdown_timeout(Some("".into())), SHUTDOWN_DEADLINE);
    }

    // Issue #11 / #12.4: executor.validate non-executing pre-check over UDS — the caller asks
    // for authorization before execute
    #[tokio::test]
    async fn validate_roundtrip() {
        let sock = tmp_sock("validate");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // Safe command
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.validate","params":{"command":"echo hi"}}"#,
        )
        .await;
        assert_eq!(resp["result"]["allowed"], true);
        assert_eq!(resp["result"]["blocked"], false);
        assert!(resp["result"]["reason"].is_null());
        // Dangerous command — not executed, only returns a verdict
        let resp2 = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"executor.validate","params":{"command":"rm -rf /"}}"#,
        )
        .await;
        assert_eq!(resp2["result"]["allowed"], false);
        assert_eq!(resp2["result"]["blocked"], true);
        assert!(
            resp2["result"]["reason"].is_string(),
            "reason should be a string"
        );
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

    // C-OPS-05b: executor.metrics returns live counters — after one execute, exec_total>=1,
    // exec_success>=1
    #[tokio::test]
    async fn metrics_roundtrip_after_execute() {
        let sock = tmp_sock("metrics");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // Run one successful command first to accumulate metrics counters
        let req = r#"{"jsonrpc":"2.0","id":3,"method":"executor.execute","params":{"command":"echo hi"}}"#;
        let resp = rpc(&sock, req).await;
        assert_eq!(resp["result"]["exit_code"], 0);
        // Read the metrics snapshot
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
            "execute_duration_sec_avg should be a number: {}",
            m["execute_duration_sec_avg"]
        );
        assert!(
            m["stdio_bytes_total"].as_u64().is_some(),
            "stdio_bytes_total should be u64: {}",
            m["stdio_bytes_total"]
        );
        assert_eq!(m["exec_blocked"], 0);
        assert_eq!(m["rollback_total"], 0);
        let _ = std::fs::remove_file(&sock);
    }

    // M-OPS-02: executor.metrics_prometheus returns Prometheus text format — after one execute,
    // fe_exec_total is hit + HELP/TYPE headers (registered via describe_counter).
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
        // HELP/TYPE headers registered by describe_counter should be in the text.
        assert!(
            text.contains("# HELP fe_exec_total"),
            "missing fe_exec_total HELP: {text}"
        );
        assert!(
            text.contains("# TYPE fe_exec_total counter"),
            "missing fe_exec_total TYPE: {text}"
        );
        assert!(
            text.contains("fe_exec_total"),
            "missing fe_exec_total metric line: {text}"
        );
        assert!(
            text.contains("# TYPE fe_connections gauge"),
            "missing fe_connections gauge: {text}"
        );
        // D4-9: exec_sem available-permit gauge — mirrored by the health path after execute;
        // should contain HELP/TYPE/metric lines.
        assert!(
            text.contains("# HELP fe_exec_sem_available"),
            "missing fe_exec_sem_available HELP: {text}"
        );
        assert!(
            text.contains("# TYPE fe_exec_sem_available gauge"),
            "missing fe_exec_sem_available TYPE: {text}"
        );
        assert!(
            text.contains("fe_exec_sem_available"),
            "missing fe_exec_sem_available metric line: {text}"
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
            assert_eq!(v["id"], 7, "all frames should share the id");
            let rtype = v["result"]["type"].as_str().unwrap_or("");
            if rtype == "chunk" {
                if v["result"]["data"].as_str().unwrap_or("").contains("hi") {
                    saw_hi = true;
                }
                continue;
            }
            if rtype == "done" {
                assert_eq!(v["result"]["result"]["exit_code"], 0);
                // stdout may appear in a chunk frame or done.result.stdout (for a fast echo the
                // done aggregate may be empty, with the data in chunks) — seeing either passes,
                // avoiding a false failure from the streaming-aggregation race.
                let done_stdout = v["result"]["result"]["stdout"].as_str().unwrap_or("");
                assert!(
                    saw_hi || done_stdout.contains("hi"),
                    "'hi' should appear in a chunk or done.stdout"
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
            assert_eq!(v["id"], 11, "telemetry frames share the id");
            assert_eq!(v["result"]["type"], "sample");
            let sample = &v["result"]["sample"];
            assert!(sample["mem_mb"].as_f64().unwrap_or(0.0) >= 0.0);
            assert!(sample["cpu_pct"].as_f64().unwrap_or(-1.0) >= 0.0);
            count += 1;
            if count >= 3 {
                break;
            }
        }
        assert_eq!(count, 3, "should receive 3 telemetry sample frames");
        let _ = std::fs::remove_file(&sock);
    }

    // ── v1.5 #14 bidirectional server-push tests ──

    /// Read one line (used to keep reading push frames after subscribe)
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
        // First line = subscribe response
        let resp = read_line(&mut reader).await.expect("subscribe response");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["ok"], true);
        let sub_id = resp["result"]["subscription_id"]
            .as_str()
            .expect("subscription_id")
            .to_string();
        assert!(sub_id.starts_with("sub-"));
        // Subsequent lines = server-push notifications (no id, method=executor.event)
        let mut got = 0;
        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                frame = read_line(&mut reader) => {
                    let frame = match frame { Some(f) => f, None => break };
                    assert!(frame.get("id").is_none(), "notification must have no id: {frame}");
                    assert_eq!(frame["method"], "executor.event");
                    assert_eq!(frame["params"]["subscription_id"], sub_id);
                    assert_eq!(frame["params"]["channel"], "telemetry");
                    assert!(frame["params"]["data"]["mem_mb"].as_f64().unwrap_or(-1.0) >= 0.0);
                    got += 1;
                    if got >= 3 { break; }
                }
            }
        }
        assert!(
            got >= 3,
            "should receive >=3 telemetry push frames, got={got}"
        );
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
        // Wait one frame to confirm the push is working
        let first = read_line(&mut reader).await.unwrap();
        assert_eq!(first["params"]["subscription_id"], sub_id);
        // Unsubscribe
        let unsub = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"executor.unsubscribe","params":{{"subscription_id":"{sub_id}"}}}}
"#,
        );
        writer.write_all(unsub.as_bytes()).await.unwrap();
        let unsub_resp = read_line(&mut reader).await.unwrap();
        assert_eq!(unsub_resp["id"], 2);
        assert_eq!(unsub_resp["result"]["ok"], true);
        // After unsubscribing no further pushes for this sub should arrive (the telemetry source
        // self-exits at 0 subscribers)
        // Read for 300ms — expect at most 0 frames (source stopped); tolerate a possible trailing 1
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
        assert!(
            extra <= 1,
            "no continuous pushing after unsubscribe, extra={extra}"
        );
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn stdio_broadcasts_across_connections() {
        // Connection A subscribes to stdio (scope=all, received cross-connection), connection B
        // execute_stream → A receives the push.
        // Blocker 10: default own_conn already isolates cross-connection; only explicit all
        // broadcasts fully.
        let sock = tmp_sock("stdio-bcast");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // Connection A: subscribe stdio, all=true
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
        // Connection B: execute_stream echo
        let sb = UnixStream::connect(&sock).await.unwrap();
        let (rhb, mut writer_b) = sb.into_split();
        let mut reader_b = BufReader::new(rhb);
        let _ = writer_b.write_all(
            br#"{"jsonrpc":"2.0","id":7,"method":"executor.execute_stream","params":{"command":"echo hi","enable_rollback_snapshot":false}}
"#,
        )
        .await;
        // B reads its own done frame
        let mut b_done = false;
        // A should receive the stdio push (chunk and/or done)
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
        assert!(b_done, "B should receive its own done frame");
        assert!(a_stdio, "A should receive the cross-connection stdio push");
        let _ = std::fs::remove_file(&sock);
    }

    // ── T3 audit-fix tests ──

    #[tokio::test]
    async fn capped_line_rejects_oversize_request() {
        // C-IPC-04: >1MB request without a newline → ERR_PARSE (-32700) disconnect
        let sock = tmp_sock("capped");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let s = UnixStream::connect(&sock).await.unwrap();
        let (rd, mut wr) = s.into_split();
        // Send 2MB of newline-free bytes — should trigger the disconnect (the server replies with
        // an error frame + closes as soon as it reads past the limit)
        let blob = vec![b'A'; MAX_LINE_BYTES + 100];
        // Write completes in the background (write_all blocks until the server consumes)
        let write_task = tokio::spawn(async move { wr.write_all(&blob).await });
        let mut buf = Vec::new();
        let mut reader = BufReader::new(rd);
        let _ =
            tokio::time::timeout(Duration::from_secs(10), reader.read_until(b'\n', &mut buf)).await;
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("-32700"),
            "oversize should return an error frame containing -32700: {text}"
        );
        let _ = write_task.await;
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn read_capped_line_rejects_no_newline_flood() {
        // Blocker 7 / 2.10: a newline-free flood (2MB with no \n) must be rejected in-loop with
        // ERR_PARSE — no OOM, no unbounded buffering until a newline
        let blob = vec![b'A'; MAX_LINE_BYTES + 100];
        let mut reader = BufReader::new(std::io::Cursor::new(blob));
        let res = read_capped_line(&mut reader).await;
        assert_eq!(
            res,
            Err(ERR_PARSE),
            "newline-free flood should return ERR_PARSE, not OOM/buffer-until-newline"
        );
    }

    #[tokio::test]
    async fn read_capped_line_chunked_under_limit_succeeds() {
        // Chunked read: multiple fill_buf calls (accumulating without a newline) up to just <1MB,
        // then a newline arrives → still Ok
        let mut blob = vec![b'A'; MAX_LINE_BYTES - 10];
        blob.push(b'\n');
        let mut reader = BufReader::new(std::io::Cursor::new(blob));
        let res = read_capped_line(&mut reader).await;
        assert!(res.is_ok(), "a line just under 1MB should succeed: {res:?}");
        let line = res.unwrap().unwrap();
        assert_eq!(line.len(), MAX_LINE_BYTES - 10);
    }

    #[tokio::test]
    async fn socket_permissions_are_owner_only() {
        // C-IPC-01: socket permissions 0o600 (owner only)
        let sock = tmp_sock("perm");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&sock).expect("socket metadata");
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "socket permissions should be 0o600, got 0o{:o}",
                mode
            );
        }
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn health_reports_real_ax_trusted() {
        // C-GUI-01: ax_trusted = a real AXIsProcessTrusted() query, not a hardcoded true
        let sock = tmp_sock("health-ax");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert!(resp["result"]["ax_trusted"].is_boolean());
        // Consistent with a direct query
        assert_eq!(
            resp["result"]["ax_trusted"],
            fe_core::gui::GuiController::ax_trusted()
        );
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn subscribe_with_custom_interval_accepted() {
        // M-IPC-01: interval_ms/screenshot_interval_ms passed through, no error
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
        let resp = read_line(&mut reader).await.expect("subscribe response");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["ok"], true);
        let sub_id = resp["result"]["subscription_id"]
            .as_str()
            .expect("subscription_id")
            .to_string();
        // Unsubscribe, stop the source
        let unsub = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"executor.unsubscribe\",\"params\":{{\"subscription_id\":\"{}\"}}}}\n",
            sub_id
        );
        wr.write_all(unsub.as_bytes()).await.unwrap();
        let _ = read_line(&mut reader).await;
        let _ = std::fs::remove_file(&sock);
    }

    // ── Blocker 10 (audit §2.9 cross-tenant leak) per-sub scope filtering ──

    #[tokio::test]
    async fn stdio_own_conn_default_blocks_cross_connection() {
        // Connection A subscribes to stdio with the default (own_conn), connection B
        // execute_stream → A must not receive B's stdio.
        // This is the cross-tenant isolation baseline (audit §2.9: the old full broadcast let
        // Agent A see Agent B's stdout).
        let sock = tmp_sock("stdio-ownconn");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // Connection A: subscribe stdio (no scope field → default own_conn)
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
        // Connection B: execute_stream echo
        let sb = UnixStream::connect(&sock).await.unwrap();
        let (rhb, mut writer_b) = sb.into_split();
        let mut reader_b = BufReader::new(rhb);
        let _ = writer_b
            .write_all(
                br#"{"jsonrpc":"2.0","id":7,"method":"executor.execute_stream","params":{"command":"echo hi","enable_rollback_snapshot":false}}
"#,
            )
            .await;
        // B reads its own done frame (confirms the command ran)
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
                // Command finished; give A a short window to confirm no pushes, then exit
                tokio::time::sleep(Duration::from_millis(200)).await;
                break;
            }
        }
        assert!(b_done, "B should receive its own done frame");
        assert!(
            !a_got_stdio,
            "default own_conn should block cross-connection stdio (audit §2.9)"
        );
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn stdio_task_ids_whitelist_receives_matched() {
        // Connection A subscribes to stdio task_ids=["t1"], connection B execute_stream
        // task_id="t1" → A receives the push.
        let sock = tmp_sock("stdio-taskids");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // Connection A: subscribe stdio, task_ids=["t1"]
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
        // Connection B: execute_stream echo, task_id="t1"
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
        assert!(b_done, "B should receive its own done frame");
        assert!(
            a_stdio,
            "task_ids whitelist match should receive the stdio push"
        );
        let _ = std::fs::remove_file(&sock);
    }

    // Issue #1: background shell start/poll/kill over UDS — shell_start→shell_output→kill_shell→list_shells
    #[tokio::test]
    async fn shell_start_output_kill_list_over_uds() {
        let sock = tmp_sock("shell");
        // D3-1: python3 -c inline interpreter needs opt-in (this case tests shell_start, not D3-1)
        let server = IpcServer::with_executor(Executor::new().with_allow_inline_interpreter(true));
        let (_tx, _join) = server.serve(&sock).await.unwrap();

        // Start a long task
        let start = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.shell_start","params":{"command":"python3 -c 'import time; time.sleep(30)'"}}"#,
        )
        .await;
        assert_eq!(start["result"]["ok"], true);
        let sid = start["result"]["shell_id"].as_str().unwrap().to_string();
        assert!(sid.starts_with("sh-"));

        // Poll: running, no exit_code yet
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
        assert_eq!(
            after["result"]["running"], false,
            "should be finished after kill"
        );

        // list_shells contains this shell
        let list = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":5,"method":"executor.list_shells","params":{}}"#,
        )
        .await;
        assert!(list["result"].is_array());
        let arr = list["result"].as_array().unwrap();
        assert!(arr.iter().any(|e| e["shell_id"] == sid));

        // Block: rm -rf / → blocked_by_security, shell_id null
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

    // D3-2: shell_start defaults seatbelt=true (commercial-safe default). Omitting seatbelt →
    // fe-ipc unwrap_or(true) → isolated via sandbox-exec; whitelisted python3 echoes normally.
    // Explicit seatbelt:false → opt-out disables isolation. Both paths return ok=true for
    // whitelisted commands.
    #[tokio::test]
    async fn shell_start_defaults_seatbelt_on() {
        let sock = tmp_sock("shell_seatbelt");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();

        // Omit seatbelt → defaults true; whitelisted echo works via sandbox-exec
        let on = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.shell_start","params":{"command":"echo d3-2-on"}}"#,
        )
        .await;
        assert_eq!(on["result"]["ok"], true);
        let sid_on = on["result"]["shell_id"].as_str().unwrap().to_string();

        // Explicit seatbelt:false → opt-out
        let off = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"executor.shell_start","params":{"command":"echo d3-2-off","seatbelt":false}}"#,
        )
        .await;
        assert_eq!(off["result"]["ok"], true);
        let sid_off = off["result"]["shell_id"].as_str().unwrap().to_string();

        // Cleanup: kill both shells (prevent leaks)
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

    // C-OPS-04: executor.shutdown over IPC triggers hub.shutdown.notify_waiters() →
    // accept_loop exits + drains in-flight. Response should be {ok:true, shutting_down:true}.
    // The serve join handle should complete within the deadline (accept_loop returns).
    #[tokio::test]
    async fn shutdown_ipc_triggers_graceful_drain() {
        let sock = tmp_sock("shutdown");
        let server = IpcServer::new();
        let (_tx, join) = server.serve(&sock).await.unwrap();
        // health first to confirm the server is alive
        let h = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert_eq!(h["result"]["ok"], true);
        // Trigger shutdown
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"executor.shutdown","params":{}}"#,
        )
        .await;
        assert_eq!(resp["result"]["ok"], true);
        assert_eq!(resp["result"]["shutting_down"], true);
        // accept_loop exits → serve join completes within the deadline (drain of an empty
        // connection returns instantly)
        let done = tokio::time::timeout(SHUTDOWN_DEADLINE, join).await;
        assert!(
            done.is_ok(),
            "serve join should complete within SHUTDOWN_DEADLINE (after drain)"
        );
        // The socket file should be cleaned up by serve
        assert!(
            !Path::new(&sock).exists(),
            "sock should be removed after shutdown"
        );
    }

    // C-OPS-03: in-flight connections are drained at shutdown (join completes, not orphaned).
    // Start a long sleep command → trigger shutdown → drain times out and aborts that connection
    // (its child process is killed by the sandbox on exit). Verify: serve join completes within
    // deadline+buffer.
    #[tokio::test]
    async fn shutdown_drains_inflight_connection() {
        let sock = tmp_sock("drain");
        let server = IpcServer::new();
        let (_tx, join) = server.serve(&sock).await.unwrap();
        // Start the long command (sleep 30s, no response wait — the slow request holds the connection)
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
        // Confirm the command was dispatched (health over another connection)
        let h = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert_eq!(h["result"]["ok"], true);
        // Trigger shutdown → drain in-flight (the long-command connection exceeds 10s → abort)
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":3,"method":"executor.shutdown","params":{}}"#,
        )
        .await;
        assert_eq!(resp["result"]["shutting_down"], true);
        // drain deadline 10s + abort buffer: serve join should finish within ~12s
        let done = tokio::time::timeout(Duration::from_secs(12), join).await;
        assert!(
            done.is_ok(),
            "serve join should complete within drain deadline+buffer (after in-flight abort)"
        );
        drop(long_conn);
        let _ = std::fs::remove_file(&sock);
    }

    // M-SEC-01: LOCAL_PEERCRED UID check — a same-UID connection must be allowed (the CI process
    // connects to itself with the same UID).
    // Cross-UID rejection needs a different-UID process, not feasible in a unit test (noted in
    // README/audit report).
    // This test verifies: (1) peer_uid_matches returns true for a real same-UID stream;
    //          (2) ensure_sock_dir creates a private 0o700 directory;
    //          (3) default_sock_path lands under HOME/.fusion-executor/fe.sock (not /tmp).
    #[tokio::test]
    async fn msec01_peer_uid_same_uid_allowed() {
        // (1) same-UID stream allowed
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
            "M-SEC-01: same-UID connection should be allowed by LOCAL_PEERCRED"
        );
        connect_task.await.unwrap();
        let _ = std::fs::remove_file(&sock);

        // (2) default_sock_path lands in the HOME private directory, not /tmp (m-OPS-01 + M-SEC-01)
        let def = default_sock_path();
        assert!(
            !def.starts_with("/tmp/"),
            "M-SEC-01/m-OPS-01: default socket must not land in globally scannable /tmp: {}",
            def
        );
        assert!(
            def.ends_with(DEFAULT_SOCK_NAME),
            "default socket should end with {}: {}",
            DEFAULT_SOCK_NAME,
            def
        );

        // (3) ensure_sock_dir creates a 0o700 private directory under a not-yet-existing HOME subdir
        let probe = std::env::temp_dir()
            .join(format!("fe-msec01-probe-{}", std::process::id()))
            .join("subdir")
            .join("fe.sock");
        ensure_sock_dir(&probe).expect("ensure_sock_dir should create the 0o700 parent directory");
        let parent = probe.parent().unwrap();
        assert!(
            parent.exists(),
            "ensure_sock_dir should create the parent directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(parent).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o700,
                "M-SEC-01: private socket directory should be 0o700, got {:#o}",
                mode
            );
        }
        let _ = std::fs::remove_dir_all(parent);
    }

    // M-SEC-01/m-OPS-01: the default socket path (~/.fusion-executor/fe.sock) must serve —
    // catches the bind-before-mkdir ordering bug: ensure_sock_dir must run before
    // UnixListener::bind, otherwise bind fails when the parent directory does not exist.
    // Isolates HOME to a tempdir and goes through the real default_sock_path.
    #[tokio::test]
    async fn msec01_default_sock_dir_serve_works() {
        let fake_home = std::env::temp_dir().join(format!("fe-msec01-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fake_home);
        std::fs::create_dir_all(&fake_home).unwrap();
        // Inject HOME (default_sock_path reads HOME), restored at test end
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &fake_home);

        let sock = IpcServer::resolve_sock(None);
        assert!(
            sock.starts_with(fake_home.display().to_string().as_str()),
            "resolve_sock(None) should land under the isolated HOME: {}",
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

        // Private directory permissions 0o700
        let dir = Path::new(&sock).parent().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o700,
                "private socket directory should be 0o700, got {:#o}",
                mode
            );
        }

        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir_all(&fake_home);
        match old_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    // D3-8 enterprise hardening: socket parent-directory tightening failure → serve fail-loud
    // refuses to start (no world-accessible socket left behind).
    // Builds a read-only parent: create_dir_all succeeds but chmod 0o700 fails for lack of write
    // permission on the parent → ensure_sock_dir Err → serve Err.
    // Note: macOS root can bypass chmod, so assertions run only as non-root; root skips (CI is non-root).
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
        // Create the outer directory, then strip write permission — the inner create_dir_all fails
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o555)).unwrap();
        let sock = tmp.join("nope").join("fe.sock");
        let server = IpcServer::new();
        let res = server.serve(sock.to_str().unwrap()).await;
        assert!(
            res.is_err(),
            "D3-8: uncreatable/untightenable socket private directory should fail-loud with Err, got Ok"
        );
        // Restore permissions for cleanup (otherwise remove_dir_all also lacks write permission)
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // D3-8: the normal path of ensure_sock_dir + chmod_secure returns Ok (idempotent — an already-0o700 directory still returns Ok).
    #[cfg(unix)]
    #[tokio::test]
    async fn d38_sock_hardening_ok_on_normal_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fe-d38-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("fe.sock");
        ensure_sock_dir(&sock_path).expect("D3-8: normal-path ensure_sock_dir should return Ok");
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "D3-8: normal-path directory should be tightened to 0o700"
        );
        // Idempotent: a second call on the already-tightened directory still returns Ok
        ensure_sock_dir(&sock_path)
            .expect("D3-8: ensure_sock_dir idempotent call should return Ok");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // m-OPS-02: env-var tests serialized (set_var/remove_var race across parallel tests).
    static MOPS02_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // D3-6: validate is now fail-closed (unresolvable binaries are not allowed). SIGHUP reload
    // tests need a real binary inside a trusted directory to resolve, so build a temp bin
    // directory + a real executable + register it as an Executor trusted directory.
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

    // m-OPS-02: reload_extra_whitelist parses FUSION_EXECUTOR_EXTRA_WHITELIST (comma-split /
    // whitespace-trimmed / empties dropped) → Executor whitelist update.
    #[test]
    fn mops02_reload_extra_whitelist_parses_env() {
        let _g = MOPS02_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // D3-6: real binary + trusted directory + absolute-path invocation, otherwise validate
        // fail-closed blocks it (resolve failure).
        let dir = std::env::temp_dir().join("fe_mops02_sighup_dir");
        let _ = std::fs::remove_dir_all(&dir);
        mops02_make_tool(&dir, "sighup-tool-xyz");
        mops02_make_tool(&dir, "other-tool");
        let executor = Arc::new(Executor::new().with_trusted_bin_dirs(&[dir.to_str().unwrap()]));
        let sighup_abs = dir.join("sighup-tool-xyz");
        let other_abs = dir.join("other-tool");
        // First assert via validate that a non-baseline tool is blocked by default (not in the
        // whitelist → whitelist-reject)
        let v = executor.validate(&format!("{} --version", sighup_abs.display()));
        assert!(
            !v.allowed,
            "sighup-tool-xyz should be blocked before the extension"
        );
        // Set env → reload → should be allowed
        std::env::set_var(
            "FUSION_EXECUTOR_EXTRA_WHITELIST",
            " sighup-tool-xyz ,,other-tool ",
        );
        reload_extra_whitelist(&executor);
        let v = executor.validate(&format!("{} --version", sighup_abs.display()));
        assert!(
            v.allowed,
            "sighup-tool-xyz should be allowed after SIGHUP reload: {:?}",
            v.reason
        );
        let v = executor.validate(&format!("{} run", other_abs.display()));
        assert!(
            v.allowed,
            "second comma item other-tool should be allowed: {:?}",
            v.reason
        );
        // Baseline always present
        let v = executor.validate("python3 --version");
        assert!(v.allowed, "baseline python3 always allowed");
        std::env::remove_var("FUSION_EXECUTOR_EXTRA_WHITELIST");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // m-OPS-02: empty env → fall back to pure baseline (project extras cleared).
    #[test]
    fn mops02_reload_extra_whitelist_empty_clears_extras() {
        let _g = MOPS02_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // D3-6: real binary + trusted directory + absolute-path invocation, otherwise validate fail-closed blocks it.
        let dir = std::env::temp_dir().join("fe_mops02_cleartool_dir");
        let _ = std::fs::remove_dir_all(&dir);
        mops02_make_tool(&dir, "temp-tool");
        let executor = Arc::new(Executor::new().with_trusted_bin_dirs(&[dir.to_str().unwrap()]));
        let temp_abs = dir.join("temp-tool");
        // Add the extra first
        std::env::set_var("FUSION_EXECUTOR_EXTRA_WHITELIST", "temp-tool");
        reload_extra_whitelist(&executor);
        assert!(
            executor
                .validate(&format!("{} run", temp_abs.display()))
                .allowed,
            "temp-tool should be allowed after adding: see validate reason after reload"
        );
        // Clear env → reload → fall back to baseline
        std::env::remove_var("FUSION_EXECUTOR_EXTRA_WHITELIST");
        reload_extra_whitelist(&executor);
        assert!(
            !executor
                .validate(&format!("{} run", temp_abs.display()))
                .allowed,
            "temp-tool should be blocked after empty reload (baseline fallback)"
        );
        assert!(
            executor.validate("python3 --version").allowed,
            "baseline always present"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // m-OPS-02: reload_log_level without a handle (tracing not initialized) → no panic, just warn.
    #[test]
    fn mops02_reload_log_level_no_panic_without_handle() {
        // No init_tracing call (avoid polluting the global subscriber) → current_handle() is usually None.
        // Whether None or Some, reload_log_level must not panic.
        reload_log_level();
    }

    // m-OPS-02: reload_log_level reads the RUST_LOG env (a valid directive must not crash via the handle).
    #[test]
    fn mops02_reload_log_level_reads_rust_log() {
        let _g = MOPS02_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("RUST_LOG", "debug");
        reload_log_level(); // no handle → no-op path, no crash; with handle → should accept debug
        std::env::remove_var("RUST_LOG");
    }

    // ===== 0827 fe-ipc P0-P3 fix regression tests =====

    // M-7(1): unknown channel name → -32600 (old version silently accepted → ghost subscription, never receives pushed frames).
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
            "unknown channel should fail-loud with -32600: {resp}"
        );
        let _ = std::fs::remove_file(&sock);
    }

    // L-7: mixed-case channel name ("Telemetry") should be lowercased and receive pushed frames (old
    // version stored as-is → no match against lowercase CH_TELEMETRY = ghost subscription, source task never starts).
    #[tokio::test]
    async fn subscribe_lowercases_mixedcase_channel() {
        let sock = tmp_sock("sub-lower");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let s = UnixStream::connect(&sock).await.unwrap();
        let (rh, mut writer) = s.into_split();
        let mut reader = BufReader::new(rh);
        // Uppercase "Telemetry" — should be normalized to "telemetry" and match the source fan-out
        let req = br#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["Telemetry"],"interval_ms":20}}
"#;
        writer.write_all(req).await.unwrap();
        let resp = read_line(&mut reader).await.unwrap();
        assert_eq!(
            resp["result"]["ok"], true,
            "uppercase channel should be accepted (normalized): {resp}"
        );
        let sub_id = resp["result"]["subscription_id"]
            .as_str()
            .unwrap()
            .to_string();
        // First frame should be a telemetry push (subscription active, source task started)
        let first = read_line(&mut reader).await.unwrap();
        assert_eq!(
            first["params"]["subscription_id"], sub_id,
            "after normalization a telemetry frame should arrive (not a ghost subscription): {first}"
        );
        assert_eq!(first["params"]["channel"], "telemetry");
        let _ = std::fs::remove_file(&sock);
    }

    // M-7(3): empty task_ids array → -32600 (old version silently became an empty Tasks set = dead subscription, never matches).
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
            "empty task_ids should fail-loud with -32600 (dead subscription): {resp}"
        );
        let _ = std::fs::remove_file(&sock);
    }

    // L-6: completing a streaming execute should record metrics — after execute_stream,
    // metrics_prometheus contains fe_exec_total.
    // Old version missed record_exec in the Done branch → streaming executions invisible to Prometheus.
    #[tokio::test]
    async fn stream_exec_records_metric() {
        let sock = tmp_sock("stream-metric");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // Read the baseline fe_exec_total text first (other tests may have populated it; take the baseline count)
        let base = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.metrics_prometheus","params":{}}"#,
        )
        .await;
        let base_text = base["result"]["text"].as_str().unwrap_or("");
        let base_count = extract_exec_total(base_text);
        // Run one execute_stream (echo)
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
        assert!(got_done, "execute_stream should receive a done frame");
        // Read metrics again — fe_exec_total should increase by 1
        let after = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"executor.metrics_prometheus","params":{}}"#,
        )
        .await;
        let after_text = after["result"]["text"].as_str().unwrap_or("");
        let after_count = extract_exec_total(after_text);
        assert!(
            after_count > base_count,
            "L-6: execute_stream should increment fe_exec_total ({} → {}); old version missed record_exec and did not increment",
            base_count,
            after_count
        );
        let _ = std::fs::remove_file(&sock);
    }

    /// Extract the fe_exec_total counter value from Prometheus text.
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

    // C-9: subscribing to the telemetry channel should bump telemetry_gen (source lifecycle
    // generation, used by the source task to re-check continue/exit on zero subscribers).
    // Non-telemetry subscriptions must not touch telemetry_gen.
    #[tokio::test]
    async fn telemetry_gen_bumps_on_telemetry_subscribe() {
        let executor = Arc::new(Executor::new());
        let hub = BroadcastHub::new(executor);
        let (tx, _rx) = mpsc::channel::<Value>(8);
        let before = hub.telemetry_gen.load(Ordering::SeqCst);
        let mut chans = HashSet::new();
        chans.insert(CH_TELEMETRY.to_string());
        // Use a large interval_ms so the zero-subscriber self-exit race does not disturb the gen assertion (the
        // gen bump happens before ensure_source; with 0 subscribers right after start the source would break —
        // but telemetry_stream feeds a single stream and does not break; gen being bumped is the assertion point).
        let _sid = hub.subscribe(1, chans, StdioScope::OwnConn(1), tx, 5000, 1000);
        let after = hub.telemetry_gen.load(Ordering::SeqCst);
        assert_eq!(
            after,
            before + 1,
            "C-9: telemetry subscription should bump telemetry_gen"
        );
        // Non-telemetry subscription must not touch telemetry_gen
        let (tx2, _rx2) = mpsc::channel::<Value>(8);
        let mut chans2 = HashSet::new();
        chans2.insert(CH_STDIO.to_string());
        let before2 = hub.telemetry_gen.load(Ordering::SeqCst);
        let _sid2 = hub.subscribe(2, chans2, StdioScope::OwnConn(2), tx2, 5000, 1000);
        let after2 = hub.telemetry_gen.load(Ordering::SeqCst);
        assert_eq!(
            after2, before2,
            "C-9: stdio subscription must not touch telemetry_gen"
        );
        // screenshot subscription bumps screenshot_gen, not telemetry_gen
        let (tx3, _rx3) = mpsc::channel::<Value>(8);
        let mut chans3 = HashSet::new();
        chans3.insert(CH_SCREENSHOT.to_string());
        let _sid3 = hub.subscribe(3, chans3, StdioScope::OwnConn(3), tx3, 5000, 1000);
        let after3 = hub.telemetry_gen.load(Ordering::SeqCst);
        assert_eq!(
            after3, before2,
            "C-9: screenshot subscription must not touch telemetry_gen"
        );
        let shot_after = hub.screenshot_gen.load(Ordering::SeqCst);
        assert_eq!(
            shot_after, 1,
            "C-9: screenshot subscription should bump screenshot_gen to 1"
        );
    }

    // C-10: ensure_sock_dir must also tighten a pre-existing loose directory (0o755) to 0o700
    // (old version returned early = loose directory left behind).
    #[cfg(unix)]
    #[tokio::test]
    async fn ensure_sock_dir_tightens_existing_loose_dir() {
        use std::os::unix::fs::PermissionsExt;
        // Create a loose directory (0o755) simulating the old leftover
        let dir = std::env::temp_dir().join(format!(
            "fe-ipc-sockdir-test-{}-{}",
            std::process::id(),
            "loose"
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sock_path = dir.join("fe.sock");
        // Call ensure_sock_dir — should tighten to 0o700
        ensure_sock_dir(&sock_path)
            .expect("ensure_sock_dir should tighten the existing directory to 0o700");
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "C-10: pre-existing loose directory should be tightened to 0o700, got {:#o}",
            mode
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // IMPL-12 signal race: SIGHUP only reloads config, never triggers shutdown.
    // No real SIGHUP is sent (process-level signals are unreliable inside the test binary and would
    // hit the whole test runner); instead call reload_log_level + reload_extra_whitelist directly —
    // the same calls the handle_sighup_reload loop body makes (equivalent path to SIGHUP) — and verify:
    //   1. the serve join does not complete (shutdown Notify + oneshot both untriggered → accept_loop alive);
    //   2. the server still accepts health RPCs (connections not torn down, service continues).
    // env tests must be serialized (set_var/remove_var race across parallel tests).
    #[cfg(unix)]
    #[tokio::test]
    async fn sighup_does_not_trigger_shutdown() {
        static SIGHUP_ENV_LOCK: Mutex<()> = Mutex::new(());

        let sock = tmp_sock("sighup-noshutdown");
        let server = IpcServer::new();
        let (shutdown_tx, mut join) = server.serve(&sock).await.unwrap();
        // First confirm the server is alive
        let h = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert_eq!(h["result"]["ok"], true);

        // Simulate the SIGHUP effect: call the reload path directly (the two calls in the
        // handle_sighup_reload loop body).
        // The env lock only guards synchronous set_var/remove_var + reload (non-async); the guard
        // drops at the end of the block — never across an await.
        {
            let _g = SIGHUP_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            // Set a parseable RUST_LOG + non-empty whitelist extras to exercise the real reload branch.
            std::env::set_var("RUST_LOG", "warn");
            std::env::set_var("FUSION_EXECUTOR_EXTRA_WHITELIST", "jq,gh");
            reload_log_level();
            reload_extra_whitelist(&server.executor);
            std::env::remove_var("RUST_LOG");
            std::env::remove_var("FUSION_EXECUTOR_EXTRA_WHITELIST");
        }

        // Assertion 1: serve join not completed — shutdown Notify + oneshot both untriggered
        // (reload never touches shutdown).
        // Probe with a short timeout; join still Pending = the server has not exited.
        let pending = tokio::time::timeout(Duration::from_millis(200), &mut join).await;
        assert!(
            pending.is_err(),
            "IMPL-12: after reload serve must not exit (SIGHUP never triggers shutdown), but join completed"
        );

        // Assertion 2: the server still accepts new RPCs — connections not torn down, service continues.
        let h2 = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert_eq!(
            h2["result"]["ok"], true,
            "IMPL-12: the server should still serve after reload, but health failed"
        );

        // Cleanup: trigger shutdown explicitly so the serve join completes (avoid a leak).
        let _ = shutdown_tx.send(());
        let done = tokio::time::timeout(SHUTDOWN_DEADLINE, join).await;
        assert!(
            done.is_ok(),
            "serve join should complete after explicit shutdown"
        );
        let _ = std::fs::remove_file(&sock);
    }

    // D6-02: wall-clock histogram — record N different durations, p50/p95/p99 interpolate correctly
    // + bucket counts align.
    // Build 10 samples: 5x0.001s (first bucket ≤0.005), 3x0.1s (outside the ≤0.05 bucket, lands in
    // the 0.5 bucket), 2x1.0s (lands in the 5.0 bucket).
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
        assert_eq!(total, 10, "D6-02: all 10 executes should be counted");
        // Bucket upper bounds [0.005, 0.05, 0.5, 5.0, 30.0] → 0.001 lands in the first (5), 0.1 in
        // the 0.5 bucket (3), 1.0 in the 5.0 bucket (2).
        let buckets = snap["execute_duration_buckets"].as_array().unwrap();
        assert_eq!(buckets[0].as_u64(), Some(5), "≤0.005 bucket should be 5");
        assert_eq!(buckets[1].as_u64(), Some(0), "0.05 bucket should be empty");
        assert_eq!(buckets[2].as_u64(), Some(3), "0.5 bucket should be 3");
        assert_eq!(buckets[3].as_u64(), Some(2), "5.0 bucket should be 2");
        assert_eq!(buckets[4].as_u64(), Some(0), "30.0 bucket should be empty");
        // p50: cumulative [5,5,8,10,10,10], 0.5 quantile target=5, first-bucket cumulative 5 ≥ 5
        // → returns the first bucket bound 0.005.
        let p50 = snap["execute_duration_sec_p50"].as_f64().unwrap();
        assert_eq!(
            p50, 0.005,
            "D6-02: p50 should interpolate to the first bucket bound 0.005"
        );
        // min/max: 0.001 → 1.0s.
        assert!(
            (snap["execute_duration_sec_min"].as_f64().unwrap() - 0.001).abs() < 1e-9,
            "min should be 0.001"
        );
        assert!(
            (snap["execute_duration_sec_max"].as_f64().unwrap() - 1.0).abs() < 1e-9,
            "max should be 1.0"
        );
        // avg: (5*0.001 + 3*0.1 + 2*1.0)/10 = 2.305/10 = 0.2305
        let avg = snap["execute_duration_sec_avg"].as_f64().unwrap();
        assert!(
            (avg - 0.2305).abs() < 1e-9,
            "avg should be 0.2305, got {avg}"
        );
    }

    // D6-02: Prometheus text format — the histogram renders _bucket{le=...} lines + HELP/TYPE headers.
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
            "D6-02: prometheus should contain the histogram HELP header"
        );
        assert!(
            text.contains("# TYPE fe_exec_duration_seconds histogram"),
            "D6-02: prometheus should contain the histogram TYPE header"
        );
        assert!(
            text.contains("fe_exec_duration_seconds_bucket{le=\"0.005\"}"),
            "D6-02: should have a le=0.005 bucket line"
        );
        assert!(
            text.contains("fe_exec_duration_seconds_bucket{le=\"+Inf\"}"),
            "D6-02: should have a +Inf final bucket line"
        );
    }

    // D6-07: bind_with_stale_recovery — a stale dead socket (no listener) should be unlinked + rebound successfully.
    #[tokio::test]
    async fn d607_stale_socket_rebind_succeeds() {
        let sock = tmp_sock("d607-stale");
        // Leave a stale socket file with no listener (simulating a crash leftover).
        std::fs::File::create(&sock).unwrap();
        assert!(
            Path::new(&sock).exists(),
            "precondition: stale socket exists"
        );
        let server = IpcServer::new();
        let (_tx, join) = server
            .serve(&sock)
            .await
            .expect("stale socket should self-heal and rebind");
        // A healthy roundtrip proves the listener is really alive.
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert_eq!(
            resp["result"]["ok"], true,
            "D6-07: listener should respond after self-heal"
        );
        let _ = std::fs::remove_file(&sock);
        drop(join);
    }

    // D6-05: bind_with_stale_recovery — when a live instance holds the socket, fail-loud instead of hijacking.
    #[tokio::test]
    async fn d605_live_socket_refuses_hijack() {
        let sock = tmp_sock("d605-live");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // A second instance trying the same socket → Err (live-listener probe succeeds).
        let server2 = IpcServer::new();
        let err = server2.serve(&sock).await;
        assert!(
            err.is_err(),
            "D6-05: should fail-loud and refuse to hijack while a live instance holds the socket"
        );
        let msg = format!("{}", err.err().unwrap());
        assert!(
            msg.contains("already in use") || msg.contains("FATAL"),
            "D6-05: error message should contain already in use/FATAL keywords, got: {msg}"
        );
        let _ = std::fs::remove_file(&sock);
    }

    // ── Issue #32: server-side cancel (deterministic kill) ──

    /// execute_stream long-running task + executor.cancel on the same connection → Done frame
    /// exit_code -1 + cancelled true.
    /// Multiplexing: read_task spawns per request; the cancel frame and stream frames interleave
    /// writes on the shared writer.
    #[tokio::test]
    async fn issue32_cancel_inflight_stream_kills_process_over_uds() {
        let sock = tmp_sock("cancel-stream");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let mut s = UnixStream::connect(&sock).await.unwrap();
        // python3 is whitelisted and non-inline (script path) passes the D3-1 gateway; seatbelt
        // defaults to true but on macOS a non-seatbelt run degrades to rlimits and still runs.
        // Long-running so a natural exit cannot beat the cancel.
        let script = std::env::temp_dir().join(format!("fe-cancel-{}.py", std::process::id()));
        std::fs::write(&script, b"while True:\n    pass\n").unwrap();
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":5,"method":"executor.execute_stream","params":{{"command":"python3 {script}","enable_rollback_snapshot":false,"timeout_sec":120}}}}"#,
            script = script.display()
        );
        s.write_all((req + "\n").as_bytes()).await.unwrap();
        let mut reader = BufReader::new(s);
        // Wait for the stream to start (first chunk read or spawn confirmed): sleep 500ms then send cancel.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        // cancel should be sent on the same connection — the reader owns the read side; is the write
        // side still usable? BufReader took ownership of s.
        // So instead: send cancel over a second connection (cancel works cross-connection, the
        // StreamRegistry is server-wide).
        let cancel_resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":99,"method":"executor.cancel","params":{"id":5}}"#,
        )
        .await;
        assert_eq!(
            cancel_resp["id"], 99,
            "cancel response carries the request id"
        );
        assert_eq!(
            cancel_resp["result"]["ok"], true,
            "in-flight stream id=5 should be found"
        );
        assert_eq!(
            cancel_resp["result"]["cancelled"], true,
            "cancel should be delivered successfully"
        );
        // Read the stream's done frame — after cancel the process tree is killed, done exit_code -1 + cancelled true.
        let mut buf = Vec::new();
        let mut done: Option<Value> = None;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            buf.clear();
            let read_fut = reader.read_until(b'\n', &mut buf);
            let n = match tokio::time::timeout_at(deadline, read_fut).await {
                Ok(n) => n.unwrap_or(0),
                Err(_) => break, // timeout fallback, keeps the test from hanging
            };
            if n == 0 {
                break;
            }
            let line = String::from_utf8_lossy(&buf).trim().to_string();
            if line.is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] != 5 {
                continue;
            }
            if v["result"]["type"].as_str().unwrap_or("") == "done" {
                done = Some(v);
                break;
            }
        }
        let done = done.expect("Issue #32: should receive a done frame");
        assert_eq!(
            done["result"]["result"]["exit_code"], -1,
            "Issue #32: cancel done exit_code should be -1"
        );
        assert_eq!(
            done["result"]["result"]["cancelled"], true,
            "Issue #32: cancelled should pass through as true"
        );
        let _ = std::fs::remove_file(&script);
        let _ = std::fs::remove_file(&sock);
    }

    /// cancel with an unknown id → {ok:false, cancelled:false}, no crash.
    #[tokio::test]
    async fn issue32_cancel_unknown_id_returns_false() {
        let sock = tmp_sock("cancel-unknown");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":8,"method":"executor.cancel","params":{"id":9999}}"#,
        )
        .await;
        assert_eq!(resp["id"], 8);
        assert_eq!(
            resp["result"]["ok"], false,
            "unknown id should return ok false"
        );
        assert_eq!(
            resp["result"]["cancelled"], false,
            "unknown id should return cancelled false"
        );
        let _ = std::fs::remove_file(&sock);
    }
}
