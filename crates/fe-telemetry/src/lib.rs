// fe-telemetry — 实时遥测采样 (GPU/CPU/内存), UDS 广播给 fusion-studio 仪表盘
//
// 设计: CPU/内存本地采样 (sysinfo), GPU 数据由调用方注入 (executor 不跑模型,
// 不持有 GPU 句柄)。10Hz 采样 → mpsc<telemetry::TelemetrySample> 流。
// Executor 不跨请求累积状态: 每次 telemetry_stream() 返回独立流 + JoinHandle。

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::info;

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

/// 遥测采样参数
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// 采样间隔 (默认 100ms = 10Hz)
    pub interval_ms: u64,
    /// 最大帧数 (默认 0 = 无限, 直至调用方丢弃 rx)
    pub max_samples: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            interval_ms: 100,
            max_samples: 0,
        }
    }
}

/// 启动遥测采样流 — 在指定 runtime handle 上 spawn, 返回 (Receiver, JoinHandle)。
/// spawn 任务按 interval 采样 CPU/内存 (sysinfo), GPU 字段由调用方在每次帧后
/// 通过 inject 路径填入 (此处仅产出 None; 注入由 fe-core 包装层完成)。
/// max_samples 达到后自动结束并关闭通道。
pub fn start_stream(
    cfg: TelemetryConfig,
    rt: tokio::runtime::Handle,
) -> (mpsc::Receiver<TelemetrySample>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(16);
    let handle = rt.spawn(async move {
        let mut sys = sysinfo::System::new();
        let pid = sysinfo::Pid::from_u32(std::process::id());
        let interval = Duration::from_millis(cfg.interval_ms.max(10));
        let mut count: u64 = 0;
        info!(interval_ms = cfg.interval_ms, "遥测采样启动");
        let kind = sysinfo::ProcessRefreshKind::new().with_memory().with_cpu();
        loop {
            // sysinfo cpu_usage 需两次刷新间隔才准; 首帧先 sleep 再采
            tokio::time::sleep(interval).await;
            sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::Some(&[pid]), false, kind);
            let cpu_pct = sys.process(pid).map(|p| p.cpu_usage()).unwrap_or(0.0);
            let mem_bytes = sys.process(pid).map(|p| p.memory()).unwrap_or(0);
            let mem_mb = (mem_bytes as f64) / (1024.0 * 1024.0);
            let ts_ms = cfg.interval_ms.saturating_mul(count);
            let sample = TelemetrySample {
                ts_ms,
                cpu_pct,
                mem_mb,
                gpu_pct: None,
                gpu_mem_mb: None,
                task_id: None,
            };
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
        assert_eq!(samples[0].ts_ms, 0);
        assert_eq!(samples[2].ts_ms, 40, "第三帧 ts = 2*20");
        assert!(samples[0].gpu_pct.is_none(), "默认 GPU 不注入");
    }

    #[tokio::test]
    async fn stream_stops_on_rx_drop() {
        let cfg = TelemetryConfig {
            interval_ms: 20,
            max_samples: 0,
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
}
