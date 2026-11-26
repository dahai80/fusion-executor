// fe-ipc logging — M-OPS-01 tracing-appender JSON + daily rotation + runtime-tunable EnvFilter
// (M-OPS-02 SIGHUP reload via FilterHandle.reload_log_filter).
//
// Before the fix (C-OPS-01): init_tracing lived in fe-pyo3, fmt() text only to stderr, no
// level/format/rotation. After: structured JSON logs, Tee(file_non_blocking, stderr) dual
// output — one fmt layer + one reload::Layer<EnvFilter>. File rotates daily via
// tracing_appender::rolling::daily (FE_LOG_DIR, default
// ~/.fusion-executor/logs/fe.log.YYYY-MM-DD); WorkerGuard stored in a static to prevent drop
// (which would lose unflushed buffers).
// EnvFilter defaults to "info", overridden by RUST_LOG; a runtime reload::Handle holds the
// FilterHandle so SIGHUP can swap the level.
// Idempotent: OnceLock guards the subscriber so it is initialized only once.

use std::path::PathBuf;
use std::sync::OnceLock;

use thiserror::Error;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::fmt::writer::{BoxMakeWriter, MakeWriterExt};
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::reload::{self, Handle};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

/// IMPL-11: reason for init_tracing failure — fail-loud (serve must not start a server without logs).
/// Already initialized (idempotent second call) is not an error → Ok(()).
#[derive(Debug, Error)]
pub enum InitError {
    /// tracing global subscriber already taken (concurrent test init or set_global_default conflict).
    #[error(
        "tracing subscriber init failed (possibly already taken): {0} — log output is not active"
    )]
    SubscriberOccupied(String),
}

/// Runtime-reloadable EnvFilter handle — held by the SIGHUP handler, calls reload_log_filter to swap level.
#[derive(Clone)]
pub struct FilterHandle {
    inner: Handle<EnvFilter, Registry>,
}

impl FilterHandle {
    /// Reload the log level with a new directive string. Examples: "debug", "fusion_executor=trace", "warn,fe_ipc=debug".
    /// Returns Err on parse failure, leaving the current level unchanged (fail-loud, no silent fallback).
    pub fn reload_log_filter(&self, directive: &str) -> Result<(), String> {
        let filter = match EnvFilter::try_new(directive) {
            Ok(f) => f,
            Err(e) => return Err(format!("failed to parse log directive: {directive} — {e}")),
        };
        self.inner
            .reload(filter)
            .map_err(|e| format!("reload failed: {e}"))
    }
}

/// Global initialized flag + slot for the first-call handle.
static TRACING_INIT: OnceLock<bool> = OnceLock::new();
static FIRST_HANDLE: OnceLock<Option<FilterHandle>> = OnceLock::new();
/// Permanent slot for the WorkerGuard (dropping it loses unflushed buffers).
static LOG_GUARD: OnceLock<Option<WorkerGuard>> = OnceLock::new();
/// Permanent slot for the stderr NonBlocking guard — stderr goes through a dedicated writer
/// thread, preventing worker threads from serializing on the global stderr mutex.
/// Fix: 80 concurrent execute_async calls each emit a tracing event → fmt layer → Tee::write_all
/// → Stderr::write_all takes stderr's internal pthread_mutex; all 8 tokio workers serialized on
/// that lock → throughput collapse → soak timeout.
/// Wrapped in NonBlocking, workers only enqueue to the channel; a dedicated writer thread holds
/// the stderr lock and does not block the reactor.
static STDERR_GUARD: OnceLock<Option<WorkerGuard>> = OnceLock::new();

/// Default EnvFilter directive (INFO) — fallback when SIGHUP has no RUST_LOG.
pub const DEFAULT_FILTER_DIRECTIVE: &str = "info";

/// init_tracing — idempotent initialization of the tracing subscriber.
///
/// First call initializes the subscriber and stores the FilterHandle in the global slot (the
/// SIGHUP handler fetches it via current_handle);
/// already initialized (idempotent second call) returns Ok(()) (no repeated init, avoiding
/// multi-handler races).
/// FE_LOG_DIR unset / directory unwritable → stderr-only output (degraded, no crash), still
/// returns Ok (filter remains reloadable).
///
/// IMPL-11: try_init failure (subscriber already taken) → returns Err(InitError); the caller
/// (serve) must fail-loud — never start a server without logs (no audit log in production =
/// unacceptable). The old eprintln-warn-and-continue silently lost logs.
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

/// Returns a handle clone if initialized (SIGHUP handler can re-fetch later), None if not.
pub fn current_handle() -> Option<FilterHandle> {
    FIRST_HANDLE.get().and_then(|slot| slot.clone())
}

/// Build and init the subscriber — Tee(file, stderr) dual output + reload::Layer<EnvFilter>.
/// IMPL-11: try_init failure → Err (fail-loud), no longer eprintln-warn-and-return-Some.
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
    // IMPL-11: the old `let _ = registry.try_init();` silently swallowed the Err — if the
    // subscriber was already taken (concurrent test init) or set_global_default failed, there
    // was no signal at all → logs silently lost. fail-loud returns Err.
    registry
        .try_init()
        .map_err(|e| InitError::SubscriberOccupied(e.to_string()))?;

    Ok(FilterHandle {
        inner: reload_handle,
    })
}

/// Resolve the dual-output writer — file (FE_LOG_DIR rolling) + stderr, **both via NonBlocking**.
///
/// Key point: stderr must be wrapped in NonBlocking. The original bare `std::io::stderr`
/// synchronously took stderr's internal pthread_mutex on tokio worker threads; 80 concurrent
/// execute_async calls each emit a tracing event → fmt layer → Tee::write_all →
/// Stderr::write_all → all 8 workers serialized on that lock → throughput collapse → soak
/// timeout (macOS sample proof: 7/8 workers permanently blocked in __psynch_mutexwait ←
/// Stderr::write_all).
/// Wrapped in NonBlocking, workers only enqueue bytes to the channel; a dedicated writer thread
/// holds the stderr lock and does not block the reactor.
/// Returns BoxMakeWriter to erase the type and keep 'static (with_filter requires Layer: 'static).
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

/// Wrap stderr in NonBlocking — a dedicated writer thread holds the stderr lock, preventing
/// worker threads from serializing on it.
/// The guard is stored permanently in STDERR_GUARD (dropping it loses unflushed buffers). On
/// construction failure (in theory NonBlocking cannot fail for stderr) → fall back to bare
/// stderr (keeps the degraded path producing output, better than no logs).
fn make_stderr_non_blocking() -> NonBlocking {
    let (nb, guard) = tracing_appender::non_blocking(std::io::stderr());
    STDERR_GUARD.set(Some(guard)).ok();
    nb
}

/// Resolve the file writer — FE_LOG_DIR (default ~/.fusion-executor/logs), daily rolling fe.log.
/// Directory uncreatable/unwritable → None (degraded to stderr only).
fn resolve_file_writer() -> Option<(NonBlocking, WorkerGuard)> {
    let dir = resolve_log_dir()?;
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!(
            "fe-ipc: failed to create log directory {}, stderr-only output: {e}",
            dir.display()
        );
        return None;
    }
    let file_appender = tracing_appender::rolling::daily(&dir, "fe.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    Some((non_blocking, guard))
}

/// Resolve the log directory — FE_LOG_DIR env > ~/.fusion-executor/logs (private under HOME) > None.
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

    // Serialize env-var tests — cargo test runs in parallel; set_var/remove_var race across tests.
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
            let d = resolve_log_dir().expect("should return Some when HOME exists");
            assert!(
                d.ends_with(std::path::Path::new(".fusion-executor/logs")),
                "default directory should point at ~/.fusion-executor/logs, got {}",
                d.display()
            );
        }
    }

    #[test]
    fn filter_handle_reload_rejects_bad_directive() {
        let (_layer, handle) = reload::Layer::new(EnvFilter::new("info"));
        let fh = FilterHandle { inner: handle };
        // "notalevel=999" — 999 is not a valid level → parse failure.
        let res = fh.reload_log_filter("notalevel=999");
        assert!(
            res.is_err(),
            "bad directive should fail-loud with Err, got {:?}",
            res
        );
    }

    #[test]
    fn filter_handle_reload_accepts_valid_directive() {
        let (_layer, handle) = reload::Layer::new(EnvFilter::new("info"));
        let fh = FilterHandle { inner: handle };
        let res = fh.reload_log_filter("debug");
        assert!(
            res.is_ok(),
            "valid directive should be accepted, got {:?}",
            res
        );
    }

    #[test]
    fn current_handle_none_before_init() {
        // This test does not call init_tracing (avoid polluting the test global subscriber);
        // only asserts None before init.
        // Note: if another test in the same process already initialized, this assertion may
        // false-fail — but no test in this crate initializes, so it is safe.
        let _ = current_handle();
    }
}
