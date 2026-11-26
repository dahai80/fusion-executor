// fe-telemetry — real-time telemetry sampling (GPU/CPU/memory), broadcast over UDS to the
// fusion-studio dashboard
//
// Design: CPU/memory sampled locally (sysinfo), GPU data injected by the caller (executor
// does not run models and holds no GPU handles). 10Hz sampling → mpsc<telemetry::TelemetrySample>
// stream. The executor accumulates no cross-request state: every telemetry_stream() returns
// an independent stream + JoinHandle.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// One telemetry sample frame — local CPU/memory sampling, optional GPU (caller-injected)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySample {
    /// Sample timestamp (ms, caller epoch)
    pub ts_ms: u64,
    /// Process CPU usage percentage (0-100, multi-core multiples; sysinfo cpu_usage)
    pub cpu_pct: f32,
    /// Process resident memory (MB)
    pub mem_mb: f64,
    /// GPU usage percentage (caller-injected; None = not sampled on this host)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_pct: Option<f32>,
    /// GPU VRAM usage (MB, caller-injected)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_mem_mb: Option<f64>,
    /// Associated task id (passed through from the request side)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

impl TelemetrySample {
    /// M-11: sanitize GPU-injected fields — NaN/Inf/negative (serde_json renders NaN→null
    /// losing information, negative values are semantically wrong) → None (the alerting
    /// system reads null as "no GPU data" rather than "caller sent dirty data"; better to
    /// silently drop bad values than leave a false signal)
    pub fn sanitize_gpu(&mut self) {
        if let Some(g) = self.gpu_pct {
            if !g.is_finite() || g < 0.0 {
                warn!(
                    gpu_pct = g,
                    "GPU pct invalid value (NaN/Inf/negative), set to None"
                );
                self.gpu_pct = None;
            }
        }
        if let Some(g) = self.gpu_mem_mb {
            if !g.is_finite() || g < 0.0 {
                warn!(
                    gpu_mem_mb = g,
                    "GPU mem invalid value (NaN/Inf/negative), set to None"
                );
                self.gpu_mem_mb = None;
            }
        }
    }
}

/// Telemetry sampling configuration
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Sampling interval (default 100ms = 10Hz)
    pub interval_ms: u64,
    /// Max frames (default 0 = unlimited, until the caller drops rx)
    pub max_samples: u64,
    /// Target process PID to sample (L-15) — None samples the executor itself (current
    /// behavior, documented). Real task telemetry: the caller passes the sandbox child PID
    /// from SandboxResult.pid.
    pub pid: Option<u32>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            interval_ms: 100,
            max_samples: 0,
            pid: None,
        }
    }
}

/// Start a telemetry sampling stream — spawn on the given runtime handle, return
/// (Receiver, JoinHandle). The spawned task samples CPU/memory per interval (sysinfo);
/// GPU fields are filled in by the caller after each frame via the inject path (this
/// layer only emits None; injection is done by the fe-core wrapper).
///
/// Stop contract (A-9): the dominant path = caller drops the receiver → send fails → task
/// exits. max_samples>0 also ends at that count. Dropping the JoinHandle = detach (tokio
/// convention), not a zombie (receiver drop stops it). Buffer 64 — tolerates a 6.4s
/// consumer stall at 10Hz.
///
/// PID semantics (L-15): cfg.pid=None samples the executor itself (default, current
/// behavior); pass the sandbox child PID (from SandboxResult.pid) to sample the real task
/// process. PID gone (child exited) → warn and skip the frame, never silently emit 0 (P-7).
pub fn start_stream(
    cfg: TelemetryConfig,
    rt: tokio::runtime::Handle,
) -> (mpsc::Receiver<TelemetrySample>, JoinHandle<()>) {
    // A-9: buffer 64 — at 10Hz a consumer stall of 6.4s is needed to block send; drift
    // tolerance window for ts_ms is wider than the old 16
    let (tx, rx) = mpsc::channel(64);
    let handle = rt.spawn(async move {
        // P-7: new_all builds a full process-table baseline (single-PID refresh on a fresh
        // System may report mem 0); narrowing to a single-PID refresh inside the loop saves
        // CPU. macOS libproc quirk: building the memory baseline from the full table is stable.
        let mut sys = sysinfo::System::new_all();
        // L-15 + RUN-11: pid=None samples the executor itself — legal only for the ops
        // self-monitoring scenario, not sandbox task telemetry.
        // Audit RUN-11: defaulting to the executor makes task telemetry read as an idle
        // broker, misleading capacity decisions.
        // Keep None=samples-self (back-compat, legal for ops self-monitoring), but warn
        // fail-loud so "sampling the executor, not the task" is visible;
        // sandbox task telemetry callers must pass the real child PID from
        // ExecutionResult.pid (exposed across all 4 layers).
        let raw_pid = cfg.pid.unwrap_or_else(|| {
            warn!(
                "telemetry pid=None — sampling the executor itself (not a sandbox task). \
                 sandbox task telemetry must pass the child PID from ExecutionResult.pid, \
                 otherwise it reads an idle broker (RUN-11)"
            );
            std::process::id()
        });
        let pid = sysinfo::Pid::from_u32(raw_pid);
        info!(
            interval_ms = cfg.interval_ms,
            pid = raw_pid,
            "telemetry sampling started"
        );
        // L-TEL-03: 0 = unspecified, use default 100ms; <10 raised to 10ms to prevent CPU
        // hogging (warn explicitly, not a silent clamp)
        let interval_ms = if cfg.interval_ms == 0 {
            100
        } else if cfg.interval_ms < 10 {
            warn!(
                requested = cfg.interval_ms,
                "interval_ms < 10, raised to 10ms to prevent CPU hogging"
            );
            10
        } else {
            cfg.interval_ms
        };
        let interval = Duration::from_millis(interval_ms);
        let mut count: u64 = 0;
        let kind = sysinfo::ProcessRefreshKind::new().with_memory().with_cpu();
        // L-TEL-02: refresh once before the loop to build a baseline, so the first frame's
        // sleep+refresh yields a real delta (the old version had no baseline refresh, so the
        // first frame's cpu_usage was always 0.0 — sysinfo needs two refreshes spaced apart)
        sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::Some(&[pid]), false, kind);
        loop {
            tokio::time::sleep(interval).await;
            sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::Some(&[pid]), false, kind);
            let proc = sys.process(pid);
            // P-7: process gone (child exited or executor PID anomaly) — not a silent 0,
            // warn fail-loud then skip the frame
            let (cpu_pct, mem_mb) = match proc {
                Some(p) => (p.cpu_usage(), (p.memory() as f64) / (1024.0 * 1024.0)),
                None => {
                    // P-7: process gone (child exited or executor PID anomaly) — not a
                    // silent 0, warn then skip the frame
                    warn!(
                        pid = raw_pid,
                        "sampled process gone, skipping frame (child exited?)"
                    );
                    if tx.is_closed() {
                        info!("telemetry channel closed (caller dropped it), stopping sampling");
                        break;
                    }
                    continue;
                }
            };
            // L-TEL-01: wall-clock timestamp (the old version's interval_ms*count was a fake
            // counter, not a real point in time)
            let ts_ms = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let mut sample = TelemetrySample {
                ts_ms,
                cpu_pct,
                mem_mb,
                gpu_pct: None,
                gpu_mem_mb: None,
                task_id: None,
            };
            // M-11: sanitize GPU-injected fields (always None here; boundary left for the
            // fe-core injection path)
            sample.sanitize_gpu();
            count += 1;
            if tx.send(sample).await.is_err() {
                info!("telemetry channel closed (caller dropped it), stopping sampling");
                break;
            }
            if cfg.max_samples > 0 && count >= cfg.max_samples {
                info!(count, "telemetry reached max_samples, ending");
                break;
            }
        }
    });
    (rx, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stream_produces_samples() {
        let cfg = TelemetryConfig {
            interval_ms: 20,
            max_samples: 3,
            pid: None,
        };
        let (mut rx, handle) = start_stream(cfg, tokio::runtime::Handle::current());
        let mut samples = Vec::new();
        while let Some(s) = rx.recv().await {
            samples.push(s);
        }
        let _ = handle.await;
        assert_eq!(samples.len(), 3, "expected 3 frames");
        assert!(samples[0].cpu_pct >= 0.0);
        assert!(samples[0].mem_mb > 0.0, "this process's memory is non-zero");
        // L-TEL-01: ts_ms is wall clock (not a fake counter); monotonically increasing,
        // last frame > first frame (≈2*20ms intervals)
        assert!(samples[0].ts_ms > 0, "wall-clock timestamp is non-zero");
        assert!(
            samples[2].ts_ms > samples[0].ts_ms,
            "last frame ts > first frame (monotonically increasing)"
        );
        assert!(samples[0].gpu_pct.is_none(), "GPU not injected by default");
    }

    #[tokio::test]
    async fn stream_stops_on_rx_drop() {
        let cfg = TelemetryConfig {
            interval_ms: 20,
            max_samples: 0,
            pid: None,
        };
        let (rx, handle) = start_stream(cfg, tokio::runtime::Handle::current());
        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn sample_serializes() {
        let s = TelemetrySample {
            ts_ms: 100,
            cpu_pct: 42.0,
            mem_mb: 128.5,
            gpu_pct: Some(77.0),
            gpu_mem_mb: Some(4096.0),
            task_id: Some("t1".into()),
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: TelemetrySample = serde_json::from_str(&j).unwrap();
        assert_eq!(back.cpu_pct, 42.0);
        assert_eq!(back.gpu_pct, Some(77.0));
        assert_eq!(back.task_id, Some("t1".into()));
    }

    // M-11: GPU sanitize — NaN/Inf/negative → None, valid values kept
    #[test]
    fn sanitize_gpu_drops_bad_values() {
        let mut s = TelemetrySample {
            ts_ms: 1,
            cpu_pct: 0.0,
            mem_mb: 0.0,
            gpu_pct: Some(f32::NAN),
            gpu_mem_mb: Some(f64::INFINITY),
            task_id: None,
        };
        s.sanitize_gpu();
        assert!(s.gpu_pct.is_none(), "NaN gpu_pct → None");
        assert!(s.gpu_mem_mb.is_none(), "Inf gpu_mem → None");

        let mut neg = TelemetrySample {
            ts_ms: 1,
            cpu_pct: 0.0,
            mem_mb: 0.0,
            gpu_pct: Some(-5.0),
            gpu_mem_mb: Some(-1.0),
            task_id: None,
        };
        neg.sanitize_gpu();
        assert!(neg.gpu_pct.is_none(), "negative gpu_pct → None");
        assert!(neg.gpu_mem_mb.is_none(), "negative gpu_mem → None");

        let mut ok = TelemetrySample {
            ts_ms: 1,
            cpu_pct: 0.0,
            mem_mb: 0.0,
            gpu_pct: Some(50.0),
            gpu_mem_mb: Some(2048.0),
            task_id: None,
        };
        ok.sanitize_gpu();
        assert_eq!(ok.gpu_pct, Some(50.0), "valid value kept");
        assert_eq!(ok.gpu_mem_mb, Some(2048.0), "valid value kept");
    }

    // L-15 + P-7: non-existent PID — process gone skips frames, no silent 0, channel empty
    #[tokio::test]
    async fn pid_gone_skips_frames() {
        let cfg = TelemetryConfig {
            interval_ms: 10,
            max_samples: 5,
            pid: Some(u32::MAX), // almost certainly no such PID
        };
        let (mut rx, handle) = start_stream(cfg, tokio::runtime::Handle::current());
        // Short timeout: expect no frames (process-gone frame skip), max_samples never
        // reached → rely on the timeout to prove emptiness
        let got = tokio::time::timeout(Duration::from_millis(80), rx.recv()).await;
        drop(rx);
        let _ = handle.await;
        assert!(
            got.is_err() || got.unwrap().is_none(),
            "non-existent PID should skip frames, channel empty (no zero frames)"
        );
    }
}
