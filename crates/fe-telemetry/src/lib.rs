// fe-telemetry — 实时遥测采样 (GPU/CPU/内存), UDS 广播给 fusion-studio 仪表盘
//
// 设计: CPU/内存本地采样 (sysinfo), GPU 数据由调用方注入 (executor 不跑模型,
// 不持有 GPU 句柄)。10Hz 采样 → mpsc<telemetry::TelemetrySample> 流。
// Executor 不跨请求累积状态: 每次 telemetry_stream() 返回独立流 + JoinHandle。

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// 单帧遥测样本 — CPU/内存本机采样, GPU 可选 (调用方注入)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySample {
    /// 采样时间戳 (毫秒, 调用方纪元)
    pub ts_ms: u64,
    /// 进程 CPU 占用百分比 (0-100, 单核倍数; sysinfo cpu_usage)
    pub cpu_pct: f32,
    /// 进程常驻内存 (MB)
    pub mem_mb: f64,
    /// GPU 占用百分比 (调用方注入; None = 本机不采样)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_pct: Option<f32>,
    /// GPU 显存占用 (MB, 调用方注入)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_mem_mb: Option<f64>,
    /// 关联任务 id (透传请求侧)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

impl TelemetrySample {
    /// M-11: GPU 注入字段 sanitize — NaN/Inf/负数 (serde_json 渲染 NaN→null 丢信息, 负数语义错)
    /// → None (告警系统读 null = "无 GPU 数据" 而非 "调用方传了脏数据", 宁静默丢坏值不留假信号)
    pub fn sanitize_gpu(&mut self) {
        if let Some(g) = self.gpu_pct {
            if !g.is_finite() || g < 0.0 {
                warn!(gpu_pct = g, "GPU pct 异常值 (NaN/Inf/负数), 置 None");
                self.gpu_pct = None;
            }
        }
        if let Some(g) = self.gpu_mem_mb {
            if !g.is_finite() || g < 0.0 {
                warn!(gpu_mem_mb = g, "GPU mem 异常值 (NaN/Inf/负数), 置 None");
                self.gpu_mem_mb = None;
            }
        }
    }
}

/// 遥测采样参数
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// 采样间隔 (默认 100ms = 10Hz)
    pub interval_ms: u64,
    /// 最大帧数 (默认 0 = 无限, 直至调用方丢弃 rx)
    pub max_samples: u64,
    /// 采样目标进程 PID (L-15) — None 时采样 executor 自身 (当前行为, 文档化)。
    /// 真实任务遥测: 调用方从 SandboxResult.pid 传入沙箱子进程 PID。
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

/// 启动遥测采样流 — 在指定 runtime handle 上 spawn, 返回 (Receiver, JoinHandle)。
/// spawn 任务按 interval 采样 CPU/内存 (sysinfo), GPU 字段由调用方在每次帧后
/// 通过 inject 路径填入 (此处仅产出 None; 注入由 fe-core 包装层完成)。
///
/// 停止契约 (A-9): 主导路径 = 调用方丢弃 receiver → send 失败 → 任务退出。
/// max_samples>0 达此值也结束。JoinHandle drop = detach (tokio 约定), 非僵尸
/// (receiver drop 即停)。缓冲 64 — 10Hz 下 6.4s stall 容忍。
///
/// PID 语义 (L-15): cfg.pid=None 采样 executor 自身 (默认, 当前行为);
/// 传入沙箱子进程 PID (从 SandboxResult.pid) 采样真实任务进程。
/// PID 消失 (子进程退出) → warn 跳帧, 不静默发 0 (P-7)。
pub fn start_stream(
    cfg: TelemetryConfig,
    rt: tokio::runtime::Handle,
) -> (mpsc::Receiver<TelemetrySample>, JoinHandle<()>) {
    // A-9: 缓冲 64 — 10Hz 下 6.4s 消费者 stall 才阻塞 send, ts_ms 漂移容忍窗口宽于旧 16
    let (tx, rx) = mpsc::channel(64);
    let handle = rt.spawn(async move {
        // P-7: new_all 建全进程表基线 (单 PID refresh 在全新 System 上 mem 可能 0);
        // 循环内再窄到单 PID refresh 省 CPU。macOS libproc 怪癖: 全表建内存基线稳。
        let mut sys = sysinfo::System::new_all();
        // L-15: pid=None (默认) 采样 executor 自身 (当前行为, 文档化); 传入则采样沙箱子进程
        let raw_pid = cfg.pid.unwrap_or_else(std::process::id);
        let pid = sysinfo::Pid::from_u32(raw_pid);
        info!(interval_ms = cfg.interval_ms, pid = raw_pid, "遥测采样启动");
        // L-TEL-03: 0 = 未指定用默认 100ms; <10 提至 10ms 防 CPU 霸占 (warn 显式, 非静默夹紧)
        let interval_ms = if cfg.interval_ms == 0 {
            100
        } else if cfg.interval_ms < 10 {
            warn!(
                requested = cfg.interval_ms,
                "interval_ms < 10, 提升至 10ms 防 CPU 霸占"
            );
            10
        } else {
            cfg.interval_ms
        };
        let interval = Duration::from_millis(interval_ms);
        let mut count: u64 = 0;
        let kind = sysinfo::ProcessRefreshKind::new().with_memory().with_cpu();
        // L-TEL-02: 命令前先刷新一次建基线, 首帧 sleep+刷新即得真实 delta
        // (旧版无基线刷新, 首帧 cpu_usage 恒 0.0 — sysinfo 需两次刷新间隔才准)
        sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::Some(&[pid]), false, kind);
        loop {
            tokio::time::sleep(interval).await;
            sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::Some(&[pid]), false, kind);
            let proc = sys.process(pid);
            // P-7: 进程消失 (子进程已退出或 executor PID 异常) — 非静默发 0, warn fail-loud 后跳帧
            let (cpu_pct, mem_mb) = match proc {
                Some(p) => (p.cpu_usage(), (p.memory() as f64) / (1024.0 * 1024.0)),
                None => {
                    // P-7: 进程消失 (子进程已退出或 executor PID 异常) — 非静默发 0, warn 后跳帧
                    warn!(pid = raw_pid, "采样进程消失, 跳帧 (子进程已退出?)");
                    if tx.is_closed() {
                        info!("遥测通道关闭 (调用方丢弃), 停止采样");
                        break;
                    }
                    continue;
                }
            };
            // L-TEL-01: 墙钟时间戳 (旧版 interval_ms*count 假计数, 非真实时刻)
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
            // M-11: GPU 注入字段 sanitize (此处恒 None, 留边界给 fe-core 注入路径)
            sample.sanitize_gpu();
            count += 1;
            if tx.send(sample).await.is_err() {
                info!("遥测通道关闭 (调用方丢弃), 停止采样");
                break;
            }
            if cfg.max_samples > 0 && count >= cfg.max_samples {
                info!(count, "遥测达 max_samples, 结束");
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
        assert_eq!(samples.len(), 3, "应产出 3 帧");
        assert!(samples[0].cpu_pct >= 0.0);
        assert!(samples[0].mem_mb > 0.0, "本进程内存非零");
        // L-TEL-01: ts_ms 墙钟 (非假计数); 单调递增, 末帧 > 首帧 (≈2*20ms 间隔)
        assert!(samples[0].ts_ms > 0, "墙钟时间戳非零");
        assert!(
            samples[2].ts_ms > samples[0].ts_ms,
            "末帧 ts > 首帧 (单调递增)"
        );
        assert!(samples[0].gpu_pct.is_none(), "默认 GPU 不注入");
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

    // M-11: GPU sanitize — NaN/Inf/负数 → None, 正常值保留
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
        assert!(neg.gpu_pct.is_none(), "负数 gpu_pct → None");
        assert!(neg.gpu_mem_mb.is_none(), "负数 gpu_mem → None");

        let mut ok = TelemetrySample {
            ts_ms: 1,
            cpu_pct: 0.0,
            mem_mb: 0.0,
            gpu_pct: Some(50.0),
            gpu_mem_mb: Some(2048.0),
            task_id: None,
        };
        ok.sanitize_gpu();
        assert_eq!(ok.gpu_pct, Some(50.0), "正常值保留");
        assert_eq!(ok.gpu_mem_mb, Some(2048.0), "正常值保留");
    }

    // L-15 + P-7: 指定不存在 PID — 进程消失跳帧, 不静默发 0, 通道空
    #[tokio::test]
    async fn pid_gone_skips_frames() {
        let cfg = TelemetryConfig {
            interval_ms: 10,
            max_samples: 5,
            pid: Some(u32::MAX), // 几乎肯定无此 PID
        };
        let (mut rx, handle) = start_stream(cfg, tokio::runtime::Handle::current());
        // 短超时: 应无帧 (进程消失跳帧), max_samples 永远不达 → 依赖超时证空
        let got = tokio::time::timeout(Duration::from_millis(80), rx.recv()).await;
        drop(rx);
        let _ = handle.await;
        assert!(
            got.is_err() || got.unwrap().is_none(),
            "不存在 PID 应跳帧, 通道空 (无 0 帧)"
        );
    }
}
