// fe-shell — background persistent shell registry (Issue #1, Claude Code run_in_background/BashOutput/KillShell parity)
//
// ShellRegistry = Arc<Mutex<HashMap<shell_id, ShellHandle>>>. shell_start reuses fe-sandbox::spawn_pty
// (proven env/seatbelt/PTY setup) with self-managed std::thread reader (accumulates tail) + std::thread waiter (child.wait)
// shell_output polls the tail snapshot + running/exit_code; kill_shell reuses fe_sandbox::kill_tree; list_shells
// is poll-only: no BroadcastHub server-push wiring — live-tail deferred to a follow-up issue
//
// Safety: fe-shell does not validate commands — fe-core intercepts via self.security.validate before shell_start (fail-closed)
// fe-shell only spawns allowed commands. 0 new unsafe (reuses fe-sandbox safe wrappers + portable-pty)

use std::collections::HashMap;
use std::io::Read;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use fe_sandbox::{kill_process_group, spawn_pty, SpawnedPty};

/// Tail output cap — prevents OOM (same semantics as fe-sandbox DEFAULT_MAX_OUTPUT/HARD_CEILING)
const TAIL_CAP: usize = 100_000;

/// Registry cap — when MAX_SHELLS is exceeded, exited shells are auto-reaped (oldest first), preventing
/// monotonic memory growth in a long-lived serve(). pub: the M-OPS-05 health alert threshold reads this value (fe-ipc probe_health_depth).
pub const MAX_SHELLS: usize = 256;

/// m-SEC-02: exited-shell retention cap — each shell_start/list_shells reaps exited shells beyond this count (oldest first),
/// preventing 256 exited shells each holding a 100KB tail (worst case 25MB). Keeps up to MAX_FINISHED_RETAINED for callers to read exit_code.
const MAX_FINISHED_RETAINED: usize = 32;

/// m-SEC-01: default idle timeout (seconds) — background shells with no output beyond this are auto-killed (a caller that forgets kill does not run forever). 0 = unlimited.
pub const DEFAULT_MAX_IDLE_SEC: u64 = 3600;

/// M-9: default kill grace period (ms) — the SIGINT→grace→SIGKILL interval for kill_process_group.
/// kill_shell/expire_idle/Drop use this by default; ShellStartParams.kill_grace_ms can override per shell.
/// The production default 500 is passed in by the fe-pyo3/fe-ipc layers; this constant is for building default ShellStartParams in tests.
#[allow(dead_code)]
const DEFAULT_KILL_GRACE_MS: u64 = 500;

/// Background shell start result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellStartResult {
    pub ok: bool,
    pub shell_id: Option<String>,
    /// Already validated by fe-core, always false here — reserved field to align with the wire schema
    pub blocked_by_security: bool,
    pub security_reason: Option<String>,
    pub error: Option<String>,
}

/// shell_output poll result — output = accumulated tail snapshot (not incremental; caller deduplicates)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellOutput {
    pub shell_id: String,
    pub output: String,
    pub running: bool,
    pub exit_code: Option<i32>,
}

/// list_shells entry
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

/// shell_start parameter aggregate (assembled by fe-core; fe-shell does not take SecurityGuard)
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
    /// RUN-10 (audit 0827): file descriptor limit (RLIMIT_NOFILE). Default 1024, 0=unlimited. Passed through to SandboxConfig.
    pub max_nofile: u32,
    /// m-SEC-01: idle timeout (seconds) — shells with no output beyond this are auto-killed. 0 = unlimited (backward compatible).
    pub max_idle_sec: u64,
    /// M-9: kill grace period (ms) — kill_shell/expire_idle/Drop use this as the SIGINT→grace→SIGKILL interval.
    /// 0 = immediate SIGKILL; default DEFAULT_KILL_GRACE_MS (500).
    pub kill_grace_ms: u64,
    /// Issue #64: optional per-shell seatbelt profile (passed through to SandboxConfig.sandbox_profile).
    /// None = keep the seatbelt-bool fixed profile (backward compatible, byte-identical); Some = parameterized profile.
    pub sandbox_profile: Option<fe_sandbox::seatbelt::SandboxProfile>,
}

struct ShellHandle {
    pid: Option<u32>,
    tail: Arc<Mutex<String>>,
    exit: Arc<OnceLock<i32>>,
    task_id: Option<String>,
    command: String,
    started_at_ms: u128,
    finished: Arc<std::sync::atomic::AtomicBool>,
    /// m-SEC-01: last output/start time (ms since epoch). Idle-timeout check = now - last_output_ms > max_idle_sec*1000.
    last_output_ms: Arc<std::sync::atomic::AtomicU64>,
    /// m-SEC-01: this shell's idle timeout (seconds); 0 = unlimited. Stored on the handle so list_shells/Drop can expire without args.
    max_idle_sec: u64,
    /// M-9: this shell's kill grace period (ms); kill_shell/expire_idle/Drop read this instead of hardcoding 500.
    kill_grace_ms: u64,
    // m-PERF-02: holds reader/waiter thread handles, joined on Drop (prevents detached thread leaks)
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

    /// Start a background shell — reuses fe-sandbox::spawn_pty with self-managed reader + waiter threads
    pub fn shell_start(&self, p: ShellStartParams) -> ShellStartResult {
        if p.command.trim().is_empty() {
            return ShellStartResult {
                ok: false,
                shell_id: None,
                blocked_by_security: false,
                security_reason: None,
                error: Some("empty command".to_string()),
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
            max_nofile: p.max_nofile,
            rss_limit_mb: 0, // D3-4: no RSS cap for background shells — long-lived poll-model tasks, caller manages kill_shell itself
            sandbox_profile: p.sandbox_profile,
        };
        let spawned: SpawnedPty = match spawn_pty(&sb_cfg) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, command = %p.command, "shell_start spawn failed");
                return ShellStartResult {
                    ok: false,
                    shell_id: None,
                    blocked_by_security: false,
                    security_reason: None,
                    error: Some(format!("spawn failed: {e}")),
                };
            }
        };
        let pid = spawned.pid;
        let shell_id = format!("sh-{}", self.counter.fetch_add(1, Ordering::Relaxed));
        let tail = Arc::new(Mutex::new(String::new()));
        let exit = Arc::new(OnceLock::new());
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // m-SEC-01: idle clock starts at launch time (elapsed idle counts even with no output)
        let started_at_ms = now_ms() as u128;
        let last_output = Arc::new(std::sync::atomic::AtomicU64::new(started_at_ms as u64));
        info!(%shell_id, ?pid, command = %p.command, max_idle_sec = p.max_idle_sec, "background shell started");

        // reader thread — accumulates the tail (keeps the tail beyond TAIL_CAP), drops master on EOF, then marks finished
        // finished is set by the reader (not the waiter) — guarantees the tail has fully landed when running=false, so caller polls lose no final segment
        let tail_r = Arc::clone(&tail);
        let finished_r = Arc::clone(&finished);
        // M-8: on reader panic record exit=-1 fail-loud (on the normal path exit is set by the waiter thread)
        let exit_r = Arc::clone(&exit);
        // m-SEC-01: refresh last_output_ms on every output, for the idle-timeout check (now - last_output_ms > max_idle_sec*1000)
        let last_output_r = Arc::clone(&last_output);
        let mut reader = spawned.reader;
        let master = spawned.master;
        let reader_thread = std::thread::spawn(move || {
            // M-8: catch_unwind prevents a reader panic from being silently swallowed — a PTY read/utf8 panic must not leave finished unset forever
            // (the old version skipped finished.store on panic → running=true hung forever, tail truncated with no error indication).
            // AssertUnwindSafe: the reader (portable-pty MasterReader) is not UnwindSafe; Arc clones can cross the unwind.
            let mut tmp = [0u8; 4096];
            let mut pending: Vec<u8> = Vec::new();
            let panicked = std::panic::catch_unwind(AssertUnwindSafe(move || {
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
                                // m-SEC-01: refresh the idle clock as soon as output arrives
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
                            warn!(error = %e, "shell reader read failed");
                            break;
                        }
                    }
                }
            }));
            drop(master);
            if let Err(payload) = panicked {
                // M-8: reader panic — fail-loud: record exit=-1 + finished, prevents running=true hanging forever with no indication
                error!(error = ?payload, "shell reader thread panicked; set finished + exit=-1 fail-loud");
                let _ = exit_r.set(-1);
            } else {
                debug!("shell reader thread ended (finished set)");
            }
            // EOF and panic both set finished (running=false always implies the tail landed or a panic truncation marker)
            finished_r.store(true, Ordering::Release);
        });

        // waiter thread — only blocks on child.wait → records exit_code (finished is set by the reader, not here)
        let exit_w = Arc::clone(&exit);
        let child = spawned.child;
        let waiter_thread = std::thread::spawn(move || {
            let mut child = child;
            let status = child.wait();
            let code = match status {
                Ok(s) => s.exit_code() as i32,
                Err(e) => {
                    warn!(error = %e, "shell waiter child.wait failed");
                    -1
                }
            };
            let _ = exit_w.set(code);
            debug!(
                exit_code = code,
                "shell waiter: child process exited (exit_code recorded)"
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
            kill_grace_ms: p.kill_grace_ms,
            reader_thread: Some(reader_thread),
            waiter_thread: Some(waiter_thread),
        };
        // P-4/P-5: reap_finished/expire_idle only collect while holding the lock; join/kill happen outside after the guard is released (prevents in-lock blocking/deadlock)
        let (reaped, expired) = {
            let mut g = self.shells.lock().unwrap_or_else(|e| e.into_inner());
            // m-SEC-02: reap exited shells beyond MAX_FINISHED_RETAINED before each registration (not just above the 256 ceiling)
            let reaped = reap_finished(&mut g);
            // m-SEC-01: auto-kill idle-timed-out shells (idle > max_idle_sec), checked per shell (0=unlimited skips)
            let expired = expire_idle(&mut g);
            g.insert(shell_id.clone(), handle);
            (reaped, expired)
        };
        join_reaped(reaped);
        kill_expired(expired);
        ShellStartResult {
            ok: true,
            shell_id: Some(shell_id),
            blocked_by_security: false,
            security_reason: None,
            error: None,
        }
    }

    /// Poll the tail snapshot + running/exit status
    pub fn shell_output(&self, shell_id: &str) -> Result<ShellOutput> {
        let g = self.shells.lock().unwrap_or_else(|e| e.into_inner());
        let h = g
            .get(shell_id)
            .with_context(|| format!("shell not found: {shell_id}"))?;
        let output = match h.tail.lock() {
            Ok(s) => s.clone(),
            Err(e) => {
                warn!(error = %e, %shell_id, "shell_output tail lock poisoned, returning sentinel marker (data may be lost)");
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

    /// Kill the process group — reuses fe_sandbox::kill_process_group (SIGINT→grace→SIGKILL)
    /// finished is normally set by reader EOF; kill force-sets finished so the reader does not block forever on a dead PTY
    /// (in the kill scenario the caller expects termination, not the final output segment; losing it is acceptable)
    /// reap=false: fe-shell's own waiter thread reaps via child.wait, avoiding the L-13 double-waitpid race
    pub fn kill_shell(&self, shell_id: &str) -> Result<bool> {
        // M-9: read kill_grace_ms (per-shell override) + pid, take them under the lock then release; kill happens outside the lock (P-5)
        let (pid, grace_ms) = {
            let g = self.shells.lock().unwrap_or_else(|e| e.into_inner());
            let h = g
                .get(shell_id)
                .with_context(|| format!("shell not found: {shell_id}"))?;
            (h.pid, h.kill_grace_ms)
        };
        let res = kill_process_group(pid, false, grace_ms);
        let exit = res.exit_code;
        let g = self.shells.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = g.get(shell_id) {
            h.finished.store(true, Ordering::Release);
            let _ = h.exit.set(exit);
        }
        info!(%shell_id, ?pid, grace_ms, kill_exit = exit, "kill_shell done");
        Ok(true)
    }

    /// List all shells (including exited) — reaps exited shells beyond MAX_FINISHED_RETAINED (oldest first) + kills idle-timed-out ones
    /// P-4/P-5: reap_finished/expire_idle only collect while holding the lock; join/kill happen outside after the guard is released (prevents in-lock blocking/deadlock)
    pub fn list_shells(&self) -> Vec<ShellInfo> {
        let (reaped, expired, infos) = {
            let mut g = self.shells.lock().unwrap_or_else(|e| e.into_inner());
            let reaped = reap_finished(&mut g);
            let expired = expire_idle(&mut g);
            let infos: Vec<ShellInfo> = g
                .iter()
                .map(|(id, h)| ShellInfo {
                    shell_id: id.clone(),
                    pid: h.pid,
                    task_id: h.task_id.clone(),
                    command: h.command.clone(),
                    started_at_ms: h.started_at_ms,
                    finished: h.finished.load(Ordering::Acquire),
                    exit_code: h.exit.get().copied(),
                })
                .collect();
            (reaped, expired, infos)
        };
        join_reaped(reaped);
        kill_expired(expired);
        infos
    }
}

/// C-OPS-02: kill all active shells when the ShellRegistry drops, preventing orphan-process leaks on serve() exit.
/// On process exit (signal/crash) the registry drops → iterate shells with finished==false and kill_process_group,
/// reader/waiter threads exit naturally as the PTYs close. Fail-loud: record kill failures, never swallow silently.
/// reap=false: at drop time the waiter threads exit and reap quickly as the PTYs close; here we only signal, no double reap.
impl Drop for ShellRegistry {
    fn drop(&mut self) {
        // D5-5: process cleanup + thread reclamation (m-PERF-02 already implements kill+join; this Drop verifies no leaks:
        //   active shells kill_process_group → reader/waiter threads exit quickly after the PTY closes → joined).
        //   P-5: collect only (id, pid, grace) under the lock + take all handles for out-of-lock join; kill+join happen outside after the guard is released
        let (active, all_handles) = {
            let mut g = self.shells.lock().unwrap_or_else(|e| e.into_inner());
            let active: Vec<(String, Option<u32>, u64)> = g
                .iter()
                .filter(|(_, h)| !h.finished.load(Ordering::Acquire))
                .map(|(id, h)| (id.clone(), h.pid, h.kill_grace_ms))
                .collect();
            // P-5: move all handles out of the map, join outside the lock (prevents join blocking inside the lock)
            let all_handles: Vec<(String, ShellHandle)> = g.drain().collect();
            (active, all_handles)
        };
        if active.is_empty() && all_handles.is_empty() {
            return;
        }
        info!(
            count = active.len(),
            "ShellRegistry drop: draining active shells"
        );
        // M-9: use per-shell kill_grace_ms instead of a hardcoded 500
        for (shell_id, pid, grace_ms) in active {
            if let Some(pid) = pid {
                let res = kill_process_group(Some(pid), false, grace_ms);
                info!(%shell_id, pid, grace_ms, kill_exit = res.exit_code, "drop drain kill done");
            } else {
                warn!(%shell_id, "drop drain: shell has no pid, skipping kill");
            }
        }
        // m-PERF-02: after kill, join all shells' reader/waiter threads to reclaim them (threads exit quickly after the PTY closes), outside the lock (P-5)
        for (id, mut h) in all_handles {
            join_handle_threads(&mut h, &id);
        }
    }
}

impl Default for ShellRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Reap exited shells (m-SEC-02) — triggered on every shell_start/list_shells (no longer only above MAX_SHELLS):
/// 1. above the MAX_SHELLS ceiling always reaps (prevents unbounded registration);
/// 2. when exited entries exceed MAX_FINISHED_RETAINED, reap oldest-first by started_at_ms (prevents 256×100KB=25MB tail accumulation).
///
/// Only removes entries that are finished with a known exit_code (a running=false-without-exit_code transition state is kept, preventing premature removal while the waiter lags).
/// P-5: under the lock only remove the handle (returned to the caller), **do not join here** — join moves outside the lock so a reader panic cannot block the whole registry forever.
/// Returns the removed ShellHandles so the caller can join their threads outside the lock.
fn reap_finished(shells: &mut HashMap<String, ShellHandle>) -> Vec<(String, ShellHandle)> {
    let finished_count = shells
        .values()
        .filter(|h| h.finished.load(Ordering::Acquire) && h.exit.get().is_some())
        .count();
    if shells.len() <= MAX_SHELLS && finished_count <= MAX_FINISHED_RETAINED {
        return Vec::new();
    }
    let mut finished: Vec<(String, u128)> = shells
        .iter()
        .filter(|(_, h)| h.finished.load(Ordering::Acquire) && h.exit.get().is_some())
        .map(|(id, h)| (id.clone(), h.started_at_ms))
        .collect();
    if finished.is_empty() {
        return Vec::new();
    }
    finished.sort_unstable_by_key(|(_, t)| *t);
    // Reap down to under the ceiling with exited retention <= MAX_FINISHED_RETAINED: reap at least (total-cap) or (exited-retention)
    let over_ceiling = shells.len().saturating_sub(MAX_SHELLS);
    let over_retained = finished_count.saturating_sub(MAX_FINISHED_RETAINED);
    let remove_count = over_ceiling.max(over_retained);
    let mut reaped = Vec::new();
    for (id, _) in finished.into_iter().take(remove_count) {
        if let Some(h) = shells.remove(&id) {
            debug!(%id, "reap_finished: exited shell removed (threads joined outside the lock)");
            reaped.push((id, h));
        }
    }
    reaped
}

/// m-SEC-01: idle-timeout reap — auto kill_process_group for active shells with no output beyond max_idle_sec.
/// Reads each shell's own max_idle_sec (0=unlimited skips); exited shells are not handled here (reap_finished owns that).
/// P-4: under the lock only collect (id, pid, grace_ms) and mark finished/exit, **kill moves outside the lock** —
/// the old version blocked all shell_output/list_shells with kill_process_group 500ms×N inside the lock.
/// Returns (shell_id, pid, grace_ms) pending kill for the caller to execute outside the lock.
/// reap=false: the waiter thread reaps itself, avoiding the L-13 double-waitpid race.
fn expire_idle(shells: &mut HashMap<String, ShellHandle>) -> Vec<(String, Option<u32>, u64)> {
    let now = now_ms();
    let expired: Vec<(String, Option<u32>, u64)> = shells
        .iter()
        .filter_map(|(id, h)| {
            if h.finished.load(Ordering::Acquire) || h.max_idle_sec == 0 {
                return None;
            }
            let last = h.last_output_ms.load(Ordering::Acquire);
            if now.saturating_sub(last) > h.max_idle_sec * 1000 {
                Some((id.clone(), h.pid, h.kill_grace_ms))
            } else {
                None
            }
        })
        .collect();
    // Under the lock only set finished + a placeholder exit (prevents double expiration); the real kill + exit overwrite happen outside the lock
    for (id, _, _) in &expired {
        if let Some(h) = shells.get(id) {
            h.finished.store(true, Ordering::Release);
            let _ = h.exit.set(-124);
        }
    }
    expired
}

/// P-4/P-5: execute the kills collected by expire outside the lock (caller has already dropped the Mutex guard).
fn kill_expired(expired: Vec<(String, Option<u32>, u64)>) {
    for (id, pid, grace_ms) in expired {
        let res = kill_process_group(pid, false, grace_ms);
        let exit = res.exit_code;
        warn!(%id, ?pid, grace_ms, kill_exit = exit,
            "m-SEC-01: idle-timed-out shell auto-killed (a caller that forgets kill does not run forever)");
    }
}

/// P-5: join the removed handles' reader/waiter threads outside the lock (caller has already dropped the Mutex guard).
fn join_reaped(reaped: Vec<(String, ShellHandle)>) {
    for (id, mut h) in reaped {
        join_handle_threads(&mut h, &id);
    }
}

/// Drop join timeout cap (ms) — the waiter thread blocks on child.wait(); when kill fails (pid reuse/zombie/setsid escape)
/// child.wait() never returns → an unbounded join would block serve() exit. Detach on timeout (the OS kills the thread at process exit, Drop not blocked).
const DROP_JOIN_TIMEOUT_MS: u64 = 2000;
const DROP_JOIN_POLL_MS: u64 = 50;

/// C-OPS-fix: bounded join — is_finished() polling, detach on timeout (prevents serve() exit hang).
fn join_thread_bounded(t: Option<std::thread::JoinHandle<()>>, shell_id: &str, label: &str) {
    let Some(t) = t else {
        return;
    };
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(DROP_JOIN_TIMEOUT_MS);
    while std::time::Instant::now() < deadline {
        if t.is_finished() {
            if let Err(e) = t.join() {
                warn!(%shell_id, label, error = ?e, "{label} thread join failed (panic?)");
            }
            debug!(%shell_id, label, "{label} thread join reclaimed");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(DROP_JOIN_POLL_MS));
    }
    warn!(
        %shell_id, label, timeout_ms = DROP_JOIN_TIMEOUT_MS,
        "{label} thread join timed out — detach (the OS reclaims it at process exit, prevents serve() hang)"
    );
    drop(t);
}

/// m-SEC-01: current ms since epoch (reader thread refreshes last_output_ms + idle check uses this)
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// m-PERF-02: join one shell's reader/waiter threads to reclaim them (prevents detached thread leaks).
/// Exited shells return from join immediately; for active shells the caller should kill first (threads exit quickly after the PTY closes).
/// P-5: must be called after the Mutex guard is released (out-of-lock join prevents a reader panic from deadlocking everything).
fn join_handle_threads(h: &mut ShellHandle, shell_id: &str) {
    join_thread_bounded(h.reader_thread.take(), shell_id, "reader");
    join_thread_bounded(h.waiter_thread.take(), shell_id, "waiter");
}

/// Multi-byte UTF-8 across chunk boundaries — preserve trailing incomplete bytes (same as fe-sandbox L-SB-02)
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
            max_nofile: 0,
            max_idle_sec: 0,
            kill_grace_ms: DEFAULT_KILL_GRACE_MS,
            sandbox_profile: None,
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

    /// Issue #64: Some(sandbox_profile) passes through to SandboxConfig — the command still runs normally under a
    /// parameterized profile (excluded_commands denying a binary that is never invoked); when seatbelt is unavailable
    /// (non-macOS / CI without sandbox-exec) it silently degrades (fail_if_unavailable=false default), so only ok is asserted.
    #[test]
    fn shell_start_with_sandbox_profile() {
        let reg = ShellRegistry::new();
        let mut p = params("echo profiled", None);
        p.sandbox_profile = Some(fe_sandbox::seatbelt::SandboxProfile {
            excluded_commands: vec!["definitely-not-invoked-bin".to_string()],
            ..Default::default()
        });
        let r = reg.shell_start(p);
        assert!(r.ok, "error: {:?}", r.error);
        let id = r.shell_id.unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let out = reg.shell_output(&id).unwrap();
        assert!(out.output.contains("profiled"), "output: {}", out.output);
    }

    #[test]
    fn shell_output_running_then_finished() {
        let reg = ShellRegistry::new();
        let id = reg.shell_start(params("echo done", None)).shell_id.unwrap();
        std::thread::sleep(Duration::from_millis(800));
        let out = reg.shell_output(&id).unwrap();
        assert!(!out.running, "should have finished");
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
        assert!(mid.running, "long task should still be running");
        let ok = reg.kill_shell(&id).unwrap();
        assert!(ok);
        std::thread::sleep(Duration::from_millis(800));
        let after = reg.shell_output(&id).unwrap();
        assert!(!after.running, "should have finished after kill");
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
        assert!(r.error.unwrap().contains("empty"));
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
                "missing {i}: {}",
                out.output
            );
        }
    }

    #[test]
    fn utf8_safe_prefix_len_handles_multibyte() {
        // Full 3-byte CJK character
        let full = "中".as_bytes(); // i18n: user-facing
        assert_eq!(utf8_safe_prefix_len(full), 3);
        // Truncated first byte — should fall back to 0 (keep the whole char for the next chunk)
        let partial = &"中".as_bytes()[..1]; // i18n: user-facing
        assert_eq!(utf8_safe_prefix_len(partial), 0);
    }

    // reader-sets-finished guarantee: when finished=true the final output segment has landed, no tail loss
    #[test]
    fn finished_implies_final_output_drained() {
        let reg = ShellRegistry::new();
        let id = reg
            .shell_start(params("echo final_marker_xyz", None))
            .shell_id
            .unwrap();
        // Poll until running=false, then read output immediately — the final segment must be present
        let mut out = reg.shell_output(&id).unwrap();
        let mut waited = 0;
        while out.running && waited < 2000 {
            std::thread::sleep(Duration::from_millis(50));
            out = reg.shell_output(&id).unwrap();
            waited += 50;
        }
        assert!(!out.running, "should have finished (waited={}ms)", waited);
        assert!(
            out.output.contains("final_marker_xyz"),
            "final segment should have landed when finished=true: {}",
            out.output
        );
    }

    // Auto-reap: when over MAX_SHELLS, list_shells triggers reap_finished to remove the oldest exited shells
    #[test]
    fn reap_finished_drops_oldest_when_over_ceiling() {
        let reg = ShellRegistry::new();
        // Start more than MAX_SHELLS fast-exiting shells to trigger the reap inside shell_start
        for _ in 0..(MAX_SHELLS + 10) {
            let _ = reg.shell_start(params("echo x", None)).shell_id.unwrap();
        }
        std::thread::sleep(Duration::from_millis(600));
        // list_shells reaps once more; the total should fall back to <= MAX_SHELLS
        let list = reg.list_shells();
        assert!(
            list.len() <= MAX_SHELLS,
            "after reap should be <= {} entries, got {}",
            MAX_SHELLS,
            list.len()
        );
    }

    /// C-OPS-02: ShellRegistry drop must kill active shells, preventing orphan processes.
    /// Start a long sleep task, drop the registry, then confirm the child is no longer alive (kill -0 exit code non-zero).
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
            assert!(out.running, "long task should still be running before drop");
            // pid is in ShellInfo (list_shells), not in ShellOutput
            reg.list_shells()
                .into_iter()
                .find(|i| i.shell_id == id)
                .and_then(|i| i.pid)
                .expect("shell should have a pid")
        };
        // reg leaves scope → Drop triggers kill_tree; wait for the kill to take effect
        std::thread::sleep(Duration::from_millis(1500));
        // kill -0 probes process liveness: alive returns exit 0, gone returns non-zero (no unsafe, via a child process)
        let status = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .expect("kill command should be executable");
        assert!(
            !status.success(),
            "after drop child pid={} should be killed; kill -0 still succeeding = orphan process",
            pid
        );
    }

    /// m-SEC-01: idle-timeout auto-kill — max_idle_sec=1, a 30s sleep task with no output,
    /// starting another shell triggers expire_idle; the timed-out shell should be killed (running=false).
    /// exit_code may be kill_tree's -124 or a signal-kill code recorded first by the waiter thread racing (OnceLock first-wins);
    /// the key assertion = no longer running (kill took effect), not the specific code value.
    #[test]
    fn msec01_idle_timeout_kills_silent_shell() {
        let reg = ShellRegistry::new();
        let mut p = params("python3 -c 'import time; time.sleep(30)'", None);
        p.max_idle_sec = 1;
        let id = reg.shell_start(p).shell_id.unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let mid = reg.shell_output(&id).unwrap();
        assert!(
            mid.running,
            "long task should still be running before trigger"
        );
        // Wait for idle > 1s, then start another shell to trigger expire_idle inside shell_start
        std::thread::sleep(Duration::from_millis(1500));
        let _trigger = reg.shell_start(params("echo trigger", None));
        std::thread::sleep(Duration::from_millis(500));
        let out = reg.shell_output(&id).unwrap();
        assert!(
            !out.running,
            "m-SEC-01: idle-timed-out shell should be auto-killed, still running = {}",
            out.running
        );
    }

    /// m-SEC-01: max_idle_sec=0 (default) unlimited — a shell with continuous output is not mistakenly killed by the idle check.
    #[test]
    fn msec01_zero_idle_no_kill() {
        let reg = ShellRegistry::new();
        let id = reg
            .shell_start(params("python3 -c 'import time; time.sleep(2)'", None))
            .shell_id
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        // Trigger expire_idle (max_idle_sec=0 → skipped)
        let _ = reg.list_shells();
        std::thread::sleep(Duration::from_millis(200));
        let out = reg.shell_output(&id).unwrap();
        assert!(
            out.running,
            "m-SEC-01: max_idle_sec=0 should not kill an active shell"
        );
    }

    /// m-SEC-02: each shell_start reaps exited shells beyond MAX_FINISHED_RETAINED (no 25MB accumulation).
    /// Start MAX_FINISHED_RETAINED+N fast-exiting shells; after the last shell_start the exited count should be <= MAX_FINISHED_RETAINED.
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
            "m-SEC-02: exited shells should be <= retention cap {}, got {}",
            MAX_FINISHED_RETAINED,
            finished_count
        );
    }

    /// P-4: expire_idle does not kill inside the lock. Mixing an idle timeout with new shell_starts must not deadlock/block.
    /// (The old version blocked inside the lock with kill_tree 500ms×N; this test uses the timeout window to prove out-of-lock kill does not stall list_shells)
    #[test]
    fn p4_expire_idle_kills_outside_lock() {
        let reg = ShellRegistry::new();
        let mut idle = params("python3 -c 'import time; time.sleep(30)'", None);
        idle.max_idle_sec = 1;
        let idle_id = reg.shell_start(idle).shell_id.unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(reg.shell_output(&idle_id).unwrap().running);
        // Wait for idle > 1s, start 5 trigger shells + concurrent list_shells — proves expire's out-of-lock kill does not serialize/block
        std::thread::sleep(Duration::from_millis(1500));
        for _ in 0..5 {
            let _ = reg.shell_start(params("echo t", None));
        }
        let list = reg.list_shells();
        // list returning = no deadlock; the idle shell should already be marked finished by expire_idle
        let idle_info = list.iter().find(|i| i.shell_id == idle_id);
        assert!(
            idle_info.map(|i| i.finished).unwrap_or(true),
            "P-4: idle-timed-out shell should be finished (out-of-lock kill done)"
        );
    }

    /// P-5: reap_finished removes handles then joins outside the lock. Many exited shells + list_shells must not deadlock.
    #[test]
    fn p5_reap_finished_joins_outside_lock() {
        let reg = ShellRegistry::new();
        // Start MAX_FINISHED_RETAINED + extra fast-exiting shells → triggers reap + join
        for _ in 0..(MAX_FINISHED_RETAINED + 5) {
            let _ = reg.shell_start(params("echo gone", None)).shell_id.unwrap();
        }
        std::thread::sleep(Duration::from_millis(800));
        // Consecutive list_shells trigger reap (joining threads) — proves out-of-lock join does not block map borrows
        for _ in 0..3 {
            let list = reg.list_shells();
            assert!(list.iter().all(|i| !i.shell_id.is_empty()));
        }
    }

    /// M-9: kill_grace_ms passthrough. Start a long shell; after kill_shell it should finish within the grace window.
    /// (grace is stored on ShellHandle; kill_shell reads handle.kill_grace_ms and passes it to kill_process_group)
    #[test]
    fn m9_kill_grace_ms_stored_and_used() {
        let reg = ShellRegistry::new();
        let mut p = params("python3 -c 'import time; time.sleep(30)'", None);
        p.kill_grace_ms = 200;
        let id = reg.shell_start(p).shell_id.unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(reg.shell_output(&id).unwrap().running);
        let t0 = std::time::Instant::now();
        assert!(reg.kill_shell(&id).unwrap());
        // kill + 200ms grace + cleanup — should finish within 5s (proves grace is used, not an infinite hang)
        std::thread::sleep(Duration::from_millis(1000));
        let after = reg.shell_output(&id).unwrap();
        assert!(
            !after.running,
            "M-9: kill_grace_ms effective, shell should finish"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "kill should not hang"
        );
    }

    /// C-OPS-fix: join_thread_bounded detaches on timeout — a forever-blocking thread returns after DROP_JOIN_TIMEOUT_MS,
    /// not hanging the caller (prevents serve() exit hang). Finished threads are reclaimed immediately (is_finished=true).
    #[test]
    fn join_thread_bounded_detaches_blocking_thread() {
        let blocking = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(30));
        });
        let t0 = std::time::Instant::now();
        join_thread_bounded(Some(blocking), "sh-test", "waiter");
        assert!(
            t0.elapsed() >= Duration::from_millis(DROP_JOIN_TIMEOUT_MS)
                && t0.elapsed() < Duration::from_millis(DROP_JOIN_TIMEOUT_MS + 1000),
            "blocking thread should detach after ~{}ms, actual {:?}",
            DROP_JOIN_TIMEOUT_MS,
            t0.elapsed()
        );
    }

    #[test]
    fn join_thread_bounded_reclaims_finished_thread() {
        let done = std::thread::spawn(|| {});
        std::thread::sleep(Duration::from_millis(50));
        let t0 = std::time::Instant::now();
        join_thread_bounded(Some(done), "sh-test", "reader");
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "finished thread should reclaim immediately, actual {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn join_thread_bounded_none_noop() {
        let t0 = std::time::Instant::now();
        join_thread_bounded(None, "sh-test", "reader");
        assert!(t0.elapsed() < Duration::from_millis(10));
    }
}
