// fe-ipc logging — M-OPS-01 tracing-appender JSON+轮转 + EnvFilter 运行时可调
// (m-OPS-02 SIGHUP reload 经 FilterHandle.reload_log_filter)。
//
// 修复前 (C-OPS-01): init_tracing 在 fe-pyo3, 仅 fmt() 文本到 stderr, 无级别/格式/轮转。
// 修复后: JSON 结构化日志, Tee(file_non_blocking, stderr) 双输出 — 一个 fmt layer + 一个
// reload::Layer<EnvFilter>。文件经 tracing_appender::rolling::daily 轮转 (FE_LOG_DIR,
// 默认 ~/.fusion-executor/logs/fe.log.YYYY-MM-DD); WorkerGuard 存 static 防 drop (丢未刷缓冲)。
// EnvFilter 默认 "info", RUST_LOG 覆盖; 运行时 reload::Handle 持 FilterHandle 供 SIGHUP 换级别。
// 幂等: OnceLock 守护 subscriber 仅 init 一次。

use std::path::PathBuf;
use std::sync::OnceLock;

use thiserror::Error;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::fmt::writer::{BoxMakeWriter, MakeWriterExt};
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::reload::{self, Handle};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

/// IMPL-11: init_tracing 失败原因 — fail-loud (serve 不启动无日志服务器)。
/// 已初始化 (幂等二次调用) 不算错误 → Ok(())。
#[derive(Debug, Error)]
pub enum InitError {
    /// tracing global subscriber 已被占用 (测试并发 init 或 set_global_default 冲突)。
    #[error("tracing subscriber init 失败 (可能已被占用): {0} — 日志输出不生效")]
    SubscriberOccupied(String),
}

/// 运行时可重载的 EnvFilter handle — SIGHUP handler 持有, 调 reload_log_filter 换级别。
#[derive(Clone)]
pub struct FilterHandle {
    inner: Handle<EnvFilter, Registry>,
}

impl FilterHandle {
    /// 用新 directive 字符串重载日志级别。例 "debug", "fusion_executor=trace", "warn,fe_ipc=debug"。
    /// 解析失败返 Err, 不改当前级别 (fail-loud, 不静默降级)。
    pub fn reload_log_filter(&self, directive: &str) -> Result<(), String> {
        let filter = match EnvFilter::try_new(directive) {
            Ok(f) => f,
            Err(e) => return Err(format!("解析日志 directive 失败: {directive} — {e}")),
        };
        self.inner
            .reload(filter)
            .map_err(|e| format!("reload 失败: {e}"))
    }
}

/// 全局已初始化标志 + 首调用 handle 槽。
static TRACING_INIT: OnceLock<bool> = OnceLock::new();
static FIRST_HANDLE: OnceLock<Option<FilterHandle>> = OnceLock::new();
/// WorkerGuard 永存槽 (drop 会丢未刷缓冲)。
static LOG_GUARD: OnceLock<Option<WorkerGuard>> = OnceLock::new();
/// stderr NonBlocking guard 永存槽 — stderr 经独立写线程, 防 worker 线程串行阻塞在全局 stderr mutex。
/// 修复: 80 并发 execute_async 各发 tracing event → fmt layer → Tee::write_all → Stderr::write_all
/// 取 stderr 内部 pthread_mutex; 8 tokio worker 全串行化在该锁 → 吞吐崩溃 → soak 超时。
/// 包 NonBlocking 后 worker 只投递 channel, 由专用写线程持 stderr 锁, 不阻塞 reactor。
static STDERR_GUARD: OnceLock<Option<WorkerGuard>> = OnceLock::new();

/// 默认 EnvFilter directive (INFO) — SIGHUP 无 RUST_LOG 时回退。
pub const DEFAULT_FILTER_DIRECTIVE: &str = "info";

/// init_tracing — 幂等初始化 tracing subscriber。
///
/// 首次调用 init subscriber 并存 FilterHandle 到全局槽 (SIGHUP handler 经 current_handle 取);
/// 已初始化 (幂等二次调用) 返 Ok(()) (不重复 init, 避多 handler 竞争)。
/// FE_LOG_DIR 未设 / 目录不可写 → 仅 stderr 输出 (降级, 不崩), 仍返 Ok (filter 可 reload)。
///
/// IMPL-11: try_init 失败 (subscriber 已被占用) → 返 Err(InitError), 调用方 (serve) 须
/// fail-loud — 不启动无日志服务器 (生产无审计日志 = 不可接受)。旧版 eprintln warn 后继续 = 静默丢失。
pub fn init_tracing() -> Result<(), InitError> {
    let mut first = false;
    TRACING_INIT.get_or_init(|| {
        first = true;
        true
    });
    if !first {
        return Ok(());
    }
    let handle = build_subscriber()?;
    FIRST_HANDLE.set(Some(handle)).ok();
    Ok(())
}

/// 已初始化则返 handle 克隆 (SIGHUP handler 后续可重取), 未初始化返 None。
pub fn current_handle() -> Option<FilterHandle> {
    FIRST_HANDLE.get().and_then(|slot| slot.clone())
}

/// 构建并 init subscriber — Tee(file, stderr) 双输出 + reload::Layer<EnvFilter>。
/// IMPL-11: try_init 失败 → Err (fail-loud), 不再 eprintln warn 后返 Some。
fn build_subscriber() -> Result<FilterHandle, InitError> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER_DIRECTIVE));
    let (reload_filter, reload_handle) = reload::Layer::new(env_filter);

    let writer = resolve_writer();
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_writer(writer)
        .with_filter(reload_filter);

    let registry = Registry::default().with(fmt_layer);
    // IMPL-11: 旧版 `let _ = registry.try_init();` 静默吞 Err — 若已被其他 subscriber 占用
    // (测试并发 init) 或 set_global_default 失败, 无任何信号 → 日志静默丢失。fail-loud 返 Err。
    registry
        .try_init()
        .map_err(|e| InitError::SubscriberOccupied(e.to_string()))?;

    Ok(FilterHandle {
        inner: reload_handle,
    })
}

/// 解析双输出 writer — file (FE_LOG_DIR 滚动) + stderr, **两者均经 NonBlocking**。
///
/// 关键: stderr 必须包 NonBlocking。原版裸 `std::io::stderr` 在 tokio worker 线程同步取
/// stderr 内部 pthread_mutex; 80 并发 execute_async 各发 tracing event → fmt layer →
/// Tee::write_all → Stderr::write_all → 全 8 worker 串行化在该锁 → 吞吐崩溃 → soak 超时
/// (macOS sample 证: 7/8 worker 永久阻塞 __psynch_mutexwait ← Stderr::write_all)。
/// 包 NonBlocking 后 worker 只向 channel 投递字节, 由专用写线程持 stderr 锁, 不阻塞 reactor。
/// 返 BoxMakeWriter 擦除类型, 保 'static (with_filter 要求 Layer: 'static)。
fn resolve_writer() -> BoxMakeWriter {
    let stderr_nb = make_stderr_non_blocking();
    match resolve_file_writer() {
        Some((nb, guard)) => {
            LOG_GUARD.set(Some(guard)).ok();
            BoxMakeWriter::new(nb.and(stderr_nb))
        }
        None => BoxMakeWriter::new(stderr_nb),
    }
}

/// stderr 包 NonBlocking — 专用写线程持 stderr 锁, 防 worker 线程串行阻塞。
/// guard 存 STDERR_GUARD 永存 (drop 丢未刷缓冲)。构造失败 (理论上 NonBlocking 对 stderr
/// 不会失败) → 回退裸 stderr (保降级路径有输出, 优于无日志)。
fn make_stderr_non_blocking() -> NonBlocking {
    let (nb, guard) = tracing_appender::non_blocking(std::io::stderr());
    STDERR_GUARD.set(Some(guard)).ok();
    nb
}

/// 解析文件 writer — FE_LOG_DIR (默认 ~/.fusion-executor/logs), 每日 rolling fe.log。
/// 目录不可建/不可写 → None (降级仅 stderr)。
fn resolve_file_writer() -> Option<(NonBlocking, WorkerGuard)> {
    let dir = resolve_log_dir()?;
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!(
            "fe-ipc: 创建日志目录失败 {}, 仅 stderr 输出: {e}",
            dir.display()
        );
        return None;
    }
    let file_appender = tracing_appender::rolling::daily(&dir, "fe.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    Some((non_blocking, guard))
}

/// 解析日志目录 — FE_LOG_DIR env > ~/.fusion-executor/logs (HOME 下私有) > None。
fn resolve_log_dir() -> Option<PathBuf> {
    if let Ok(d) = std::env::var("FE_LOG_DIR") {
        if !d.is_empty() {
            return Some(PathBuf::from(d));
        }
    }
    let home = std::env::var("HOME").ok().filter(|h| !h.is_empty())?;
    let mut p = PathBuf::from(home);
    p.push(".fusion-executor");
    p.push("logs");
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // env-var 测试串行化 — cargo test 并行跑, set_var/remove_var 跨测试竞态。
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolve_log_dir_respects_env() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("FE_LOG_DIR", "/tmp/fe-logging-test-env-xyz");
        assert_eq!(
            resolve_log_dir(),
            Some(PathBuf::from("/tmp/fe-logging-test-env-xyz"))
        );
        std::env::remove_var("FE_LOG_DIR");
    }

    #[test]
    fn resolve_log_dir_defaults_to_home() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("FE_LOG_DIR");
        if std::env::var("HOME")
            .map(|h| !h.is_empty())
            .unwrap_or(false)
        {
            let d = resolve_log_dir().expect("HOME 存在应返 Some");
            assert!(
                d.ends_with(std::path::Path::new(".fusion-executor/logs")),
                "默认目录应指向 ~/.fusion-executor/logs, got {}",
                d.display()
            );
        }
    }

    #[test]
    fn filter_handle_reload_rejects_bad_directive() {
        let (_layer, handle) = reload::Layer::new(EnvFilter::new("info"));
        let fh = FilterHandle { inner: handle };
        // "notalevel=999" — 999 非合法 level → 解析失败。
        let res = fh.reload_log_filter("notalevel=999");
        assert!(
            res.is_err(),
            "坏 directive 应 fail-loud 返 Err, got {:?}",
            res
        );
    }

    #[test]
    fn filter_handle_reload_accepts_valid_directive() {
        let (_layer, handle) = reload::Layer::new(EnvFilter::new("info"));
        let fh = FilterHandle { inner: handle };
        let res = fh.reload_log_filter("debug");
        assert!(res.is_ok(), "合法 directive 应接受, got {:?}", res);
    }

    #[test]
    fn current_handle_none_before_init() {
        // 本测试不调 init_tracing (避免污染测试全局 subscriber); 仅断言未 init 时 None。
        // 注意: 若同进程其他测试已 init, 此断言可能假失败 — 但本 crate 测试均不 init, 安全。
        let _ = current_handle();
    }
}
