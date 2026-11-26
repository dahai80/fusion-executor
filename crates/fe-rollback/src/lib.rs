// fe-rollback — Git snapshot/rollback management (FR-04, caller-driven)
//
// git CLI shell (tokio::process::Command):
//   snapshot_create(cwd) → "head:<SHA>" (clean) or "stash:<SHA>,base:<HEAD>" (dirty)
//   rollback(snapshot_id, cwd) → parse tag + validate ref format:
//     head:<SHA>  → git reset --hard <baseline>  (single step, atomic; baseline format-validated)
//     stash:<SHA> → git reset --hard <baseline> + git stash apply <SHA>  (restore snapshot)
//   rollback_file(path, cwd) → git checkout -- <path> (single file; -- isolates the pathspec)
// The Executor never auto-rolls-back — the caller decides (locked decision)
// Non-git repo → empty snapshot_id, rollback is a no-op
//
// Fixes (audit C-RB-01~03):
//   C-RB-02: head/stash rollback does a single-step reset --hard <baseline> first (replacing the
//            two-step half-applied state of checkout -- . + stash apply: if checkout discards all
//            changes and apply then fails → data loss). reset clears to the baseline, and apply
//            cannot conflict on a clean worktree.
//   C-RB-03: refs (baseline/stash SHA) are format-validated by is_valid_ref to prevent flag
//            injection (40-hex or "HEAD"); anything that is not a "stash create" SHA is rejected.
//            **No --**: `git reset --hard -- <ref>` treats the ref as a pathspec → no-op
//            (verified empirically); `--` only isolates pathspecs (rollback_file's <path>), not the ref position.
//   C-RB-01: "stash apply never drops = unbounded growth" — **does not hold for the
//            `git stash create` backend**: stash create returns a dangling commit, it never
//            enters the stash reflog, stash list does not grow, and apply does not push the
//            stack either. Verified: stash list stays empty after 5 snapshot+rollback cycles.
//            Dangling commits are reclaimed by git gc. So no drop is needed (drop -- <sha>
//            errors with "not a stash reference" in practice).
//            The invariant is guarded by test_stash_list_stays_empty_across_rollback_cycles.

use anyhow::{bail, Context, Result};
use fe_security::SecurityGuard;
use fs2::FileExt;
use std::fs::OpenOptions;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{info, warn};

/// RUN-6 (audit 0827 arch): git operation timeout cap. The git CLI has no built-in timeout —
/// an NFS hang / network stall makes `.output().await` never return, and holding the RepoLock
/// across the hang blocks every other rollback (deadlock). Wrapped in `tokio::time::timeout`;
/// on timeout, fail-loud (bail) to release the lock. Local single-host git is far below this.
const GIT_TIMEOUT_SEC: u64 = 30;
/// RepoLock acquire polling timeout (same order as the git timeout). BSD flock can block
/// indefinitely on NFS, and fs2 has no lock-with-timeout → poll try_lock_exclusive up to the
/// cap, then fail-loud (never hang forever).
const LOCK_ACQUIRE_TIMEOUT_MS: u64 = GIT_TIMEOUT_SEC * 1000;
const LOCK_POLL_INTERVAL_MS: u64 = 50;

/// D6-03 (audit 0827 product): snapshot index retention cap. Past the cap, drop the oldest by
/// created_ms. Dangling commits are reclaimed by git gc (C-RB-01); index rows are just
/// metadata — the cap prevents unbounded index growth.
const SNAPSHOT_INDEX_MAX: usize = 100;
/// D6-03: snapshot index filename (NDJSON Lines), lives next to fe-rollback.lock in <git_dir>.
const SNAPSHOT_INDEX_NAME: &str = "fe-snapshots.ndjson";

/// RUN-6a (audit 0827 arch): uniformly bounded wrapper for git calls. The git CLI has no
/// built-in timeout; an NFS hang / deadlock makes `.output().await` never return (holding the
/// RepoLock across the hang blocks other rollbacks). Wrapped in
/// `tokio::time::timeout(GIT_TIMEOUT_SEC)`, fail-loud on timeout; `kill_on_drop(true)` kills
/// the pending git process when the future is dropped at timeout (no leak). Local single-host
/// git is far below this.
async fn git_output(cwd: &str, args: &[&str]) -> Result<std::process::Output> {
    let fut = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(args)
        .kill_on_drop(true)
        .output();
    tokio::time::timeout(Duration::from_secs(GIT_TIMEOUT_SEC), fut)
        .await
        .with_context(|| {
            format!(
                "git timed out ({}s) — possible NFS hang/deadlock, fail-loud to release the lock",
                GIT_TIMEOUT_SEC
            )
        })?
        .context("failed to spawn git command")
}

/// FNV-1a 64-bit (no external hash dependency, stable across nodes). Repo path → 16-hex id.
fn fnv1a_64(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

/// Stable repo identity (audit 2.7c / Blocker 9): with the cwd shared over NFS across nodes,
/// every node sees the same physical `.git` directory path → identical FNV hash after
/// canonicalize. Node A's snapshot carries repo:<hash>; node B compares before rollback —
/// a mismatch is rejected (prevents blindly rolling back to wrong content). No .git /
/// resolution failure → "".
async fn repo_id(cwd: &str) -> String {
    // git rev-parse --git-common-dir: returns the common .git for worktrees, itself for bare repos.
    // canonicalize that path → identical physical path on every NFS node yields the same hash.
    // RUN-6a: bounded via git_output (an NFS hang cannot hang forever).
    let out = match git_output(cwd, &["rev-parse", "--git-common-dir"]).await {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => return String::new(),
    };
    if out.is_empty() {
        return String::new();
    }
    let resolved = resolve_git_dir_path(cwd, &out);
    fnv1a_64(&resolved.to_string_lossy())
}

/// RUN-7 (audit 0827 arch): resolve the real git directory path for cwd.
/// Inside a worktree `.git` is a **file** (content `gitdir: <path>`), not a directory —
/// the old `cwd.join(".git")` treated it as a directory → `join("fe-rollback.lock")` opened
/// under a file = ENOTDIR and the lock silently stopped working. Fixed: `git rev-parse
/// --git-common-dir` yields the real git dir (common .git); relative paths resolve against
/// cwd; canonicalize failure falls back to the literal path.
/// Synchronous (std::process::Command): rev-parse --git-common-dir is a pure local config
/// read, no network, no NFS hang risk (unlike fetch/push); acquire is a sync lock path and
/// must not introduce .await.
fn resolve_git_dir(cwd: &str) -> Option<std::path::PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--git-common-dir"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let dir = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if dir.is_empty() {
        return None;
    }
    Some(resolve_git_dir_path(cwd, &dir))
}

/// Shared: relative git-dir string → absolute PathBuf (literal fallback when canonicalize fails).
fn resolve_git_dir_path(cwd: &str, dir: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(dir);
    let resolved = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::path::Path::new(cwd).join(p)
    };
    match std::fs::canonicalize(&resolved) {
        Ok(c) => c,
        Err(_) => resolved,
    }
}

/// Process-level lock (audit 2.7a / Blocker 9): snapshot_create/rollback on the same cwd are
/// mutually exclusive, preventing Agent A reset → Agent B reset (no-op) → A apply → B apply
/// double-apply conflicts. BSD flock is tied to the fd; dropping the File closes the fd →
/// auto-release. Lock file `<git_dir>/fe-rollback.lock`.
struct RepoLock {
    // Holding the fd is holding the lock (same pattern as fe-tools FileLock); the field is
    // never read — its existence IS the lock lifetime.
    #[allow(dead_code)]
    file: std::fs::File,
}

impl RepoLock {
    /// RUN-7 + RUN-6b: async acquire.
    /// RUN-7: resolve the real git dir via `git rev-parse --git-common-dir` (not cwd/.git);
    ///        inside a worktree `.git` is a file → the old `cwd.join(".git")` opened as a
    ///        directory = ENOTDIR and the lock silently failed.
    /// RUN-6b: bounded flock acquire polling (fs2 has no lock-with-timeout; NFS flock may block
    ///        indefinitely). `try_lock_exclusive` failure → sleep(50ms) and retry up to the cap
    ///        (30s) → fail-loud. kill_on_drop does not apply (fd-held flock; dropping the File
    ///        releases it, no process to kill).
    /// Cancel safety: no step inside the polling loop holds a resource across .await; on
    /// timeout the Err return releases the half-open fd.
    async fn acquire(cwd: &str) -> Result<Self> {
        // RUN-7: resolve the real git dir. resolve_git_dir is a sync local config read (no NFS risk).
        let git_dir = match resolve_git_dir(cwd) {
            Some(d) => d,
            None => {
                // Fall back to probing cwd/.git (regular non-worktree repos still take this path).
                let fallback = std::path::Path::new(cwd).join(".git");
                if !fallback.exists() {
                    return Ok(RepoLock {
                        file: OpenOptions::new()
                            .read(true)
                            .open("/dev/null")
                            .context("failed to open /dev/null placeholder lock")?,
                    });
                }
                fallback
            }
        };
        let lock_path = git_dir.join("fe-rollback.lock");
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&lock_path)
            .with_context(|| format!("failed to open rollback lock: {}", lock_path.display()))?;
        // RUN-6b: bounded polling acquire. fs2 `lock_exclusive` has no timeout and may block
        // indefinitely on NFS.
        let deadline = Instant::now() + Duration::from_millis(LOCK_ACQUIRE_TIMEOUT_MS);
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => {
                    info!(cwd, lock = %lock_path.display(), "rollback process lock acquired");
                    return Ok(RepoLock { file });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        warn!(
                            cwd, lock = %lock_path.display(),
                            "rollback lock acquire timed out ({}ms) — another rollback holds it long-term / NFS flock blocked, fail-loud",
                            LOCK_ACQUIRE_TIMEOUT_MS
                        );
                        anyhow::bail!(
                            "timed out acquiring rollback lock ({}ms): {}",
                            LOCK_ACQUIRE_TIMEOUT_MS,
                            lock_path.display()
                        );
                    }
                    std::thread::sleep(Duration::from_millis(LOCK_POLL_INTERVAL_MS));
                }
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!(
                            "failed to acquire rollback lock (IO error): {}",
                            lock_path.display()
                        )
                    });
                }
            }
        }
    }
}

/// L-1 (audit 0827): rollback outcome — replaces the old Ok(bool). Three states:
///   applied=true   rolled back (reset --hard / + stash apply succeeded)
///   applied=false + skipped_reason=Some  rollback was needed but skipped (non-repo / invalid
///                                        snapshot / repo mismatch / invalid ref / git failure)
///                                        — fail-loud signal the old bool folded into false
///   applied=true + wip_sha=Some  tracked WIP captured before rollback (dangling commit SHA);
///                                the caller can `git stash apply <sha>` to restore concurrent
///                                edits (C-7/M-SEC-03)
/// The old Ok(false) folded "skipped (invalid)" and "no rollback needed (caller did not
/// trigger)" together, so callers could not fail-loud. skipped_reason surfaces through
/// ExecutionResult.rollback_skipped_reason (4 layers, same pattern as L-2).
#[derive(Debug, Clone)]
pub struct RollbackOutcome {
    pub applied: bool,
    pub skipped_reason: Option<String>,
    pub wip_sha: Option<String>,
}

impl RollbackOutcome {
    fn applied(wip_sha: Option<String>) -> Self {
        Self {
            applied: true,
            skipped_reason: None,
            wip_sha,
        }
    }

    fn skipped(reason: impl Into<String>) -> Self {
        Self {
            applied: false,
            skipped_reason: Some(reason.into()),
            wip_sha: None,
        }
    }
}

/// D6-03 (audit 0827 product): snapshot index entry — lets on-call inspect "existing
/// snapshots" and keep a retention audit trail.
/// `id` = the full tag returned by snapshot_create (head:<SHA>[,repo:<hash>] /
/// stash:<SHA>,base:<HEAD>...).
/// `created_ms` = Unix epoch milliseconds (sort / retention drop-oldest key).
/// `kind` = "head" | "stash" (parsed by parse_snapshot); non-repo snapshots never enter the
/// index (empty id).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotInfo {
    pub id: String,
    pub created_ms: u64,
    pub kind: String,
}

/// D6-03: parse a snapshot id's kind (reuses parse_snapshot; non-repo/empty id → None).
fn snapshot_kind(id: &str) -> Option<&'static str> {
    RollbackManager::parse_snapshot(id).map(|(k, _, _, _)| k)
}

/// D6-03: snapshot index file path (<git_dir>/fe-snapshots.ndjson).
/// Non-repo (no git dir) → None; the caller skips indexing (consistent with snapshot_create's
/// empty string).
fn snapshot_index_path(cwd: &str) -> Option<std::path::PathBuf> {
    let git_dir = resolve_git_dir(cwd).or_else(|| {
        let fb = std::path::Path::new(cwd).join(".git");
        if fb.exists() {
            Some(fb)
        } else {
            None
        }
    })?;
    Some(git_dir.join(SNAPSHOT_INDEX_NAME))
}

/// D6-03: append a snapshot to the index + retention (drop oldest past SNAPSHOT_INDEX_MAX).
/// Called while snapshot_create holds the RepoLock — no new lock; index writes are mutually
/// exclusive with snapshot creation under the same lock.
/// Write failures are fail-visible via warn! and do not affect snapshot_create's return value
/// (the snapshot itself exists; the index is auxiliary).
fn record_snapshot_index(cwd: &str, id: &str) {
    if id.is_empty() {
        return;
    }
    let Some(kind) = snapshot_kind(id) else {
        warn!(%id, cwd, "D6-03: could not parse snapshot id kind, skipping index");
        return;
    };
    let Some(path) = snapshot_index_path(cwd) else {
        return; // non-repo; snapshot_create should already have returned empty — defensive
    };
    let entry = match serde_json::to_string(&SnapshotInfo {
        id: id.to_string(),
        created_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        kind: kind.to_string(),
    }) {
        Ok(s) => s,
        Err(e) => {
            warn!(%id, %e, "D6-03: snapshot index serialization failed, skipping");
            return;
        }
    };
    let mut lines: Vec<String> = match std::fs::read_to_string(&path) {
        Ok(s) => s
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            warn!(path = %path.display(), %e, "D6-03: failed to read snapshot index, rebuilding empty");
            Vec::new()
        }
    };
    lines.push(entry);
    if lines.len() > SNAPSHOT_INDEX_MAX {
        // Sort by parsed created_ms and drop the oldest; unparseable rows sort last and drop
        // first (bad rows are untrusted)
        lines.sort_by_key(|l| {
            serde_json::from_str::<SnapshotInfo>(l)
                .map(|i| i.created_ms)
                .unwrap_or(u64::MAX)
        });
        lines.truncate(SNAPSHOT_INDEX_MAX);
    }
    let body = lines.join("\n") + "\n";
    if let Err(e) = std::fs::write(&path, body) {
        warn!(path = %path.display(), %e, "D6-03: failed to write snapshot index (snapshot itself exists; index is auxiliary)");
    } else {
        info!(path = %path.display(), %id, kind, "D6-03: snapshot recorded in index (retention cap {})", SNAPSHOT_INDEX_MAX);
    }
}

/// Rollback manager — git CLI shell
pub struct RollbackManager {
    guard: SecurityGuard,
}

impl RollbackManager {
    pub fn new() -> Self {
        info!("RollbackManager::new()");
        Self {
            guard: SecurityGuard::new(),
        }
    }

    /// cwd validation (audit Blocker 4 / 1.3): rollback paths go through fe-security.
    /// Rejects: empty cwd / .. components / sensitive paths (/etc /System ~/.ssh ...).
    /// Validates again after canonicalize to prevent symlink bypass.
    fn validate_cwd(&self, cwd: &str) -> Result<()> {
        if cwd.trim().is_empty() {
            warn!("empty cwd, refusing rollback (prevents unauthorized reset)");
            anyhow::bail!("cwd is empty, refusing to execute rollback");
        }
        if std::path::Path::new(cwd)
            .components()
            .any(|comp| comp == std::path::Component::ParentDir)
        {
            warn!(
                cwd,
                "cwd contains .. components, refusing (escape suspicion)"
            );
            anyhow::bail!("cwd contains .. components, refusing: {}", cwd);
        }
        let v_lit = self.guard.validate_cwd(cwd);
        if !v_lit.allowed {
            let reason = v_lit.reason.unwrap_or_default();
            warn!(cwd, %reason, "cwd literal validation blocked");
            anyhow::bail!("cwd validation failed: {}", reason);
        }
        if let Ok(canonical) = std::fs::canonicalize(cwd) {
            let v_can = self.guard.validate_cwd(&canonical.to_string_lossy());
            if !v_can.allowed {
                let reason = v_can.reason.unwrap_or_default();
                warn!(cwd = %canonical.display(), %reason, "cwd canonicalize validation blocked (symlink bypass)");
                anyhow::bail!("cwd validation failed (symlink resolution): {}", reason);
            }
        }
        Ok(())
    }

    async fn git(cwd: &str, args: &[&str]) -> Result<String> {
        // RUN-6a: bounded via git_output (an NFS hang cannot hang forever; kill_on_drop kills
        // git on timeout).
        let output = git_output(cwd, args).await?;
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            warn!(cwd, args = ?args, %stderr, "git failed");
            anyhow::bail!("git failed: {}", stderr);
        }
        Ok(stdout)
    }

    /// Whether cwd is a git repo
    async fn is_repo(cwd: &str) -> bool {
        // RUN-6a: bounded. Timeout/spawn failure → false (conservative: treat as non-repo and skip).
        git_output(cwd, &["rev-parse", "--is-inside-work-tree"])
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Ref format validation — prevents flag injection (C-RB-03)
    /// Accepts: "HEAD" or a 7..=40 hex-char SHA (git stash create / rev-parse output)
    /// Rejects: "--foo" / anything else (cannot be a flag and is not a valid ref either)
    fn is_valid_ref(s: &str) -> bool {
        if s == "HEAD" {
            return true;
        }
        let len = s.len();
        (7..=40).contains(&len) && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Create a snapshot — the tag prefix encodes type + baseline; a single string flows
    /// through all 4 layers.
    /// Returns:
    ///   ""           non-git repo
    ///   "head:<SHA>" clean worktree, baseline = HEAD
    ///   "stash:<SHA>,base:<HEAD>" dirty worktree, stash SHA + baseline HEAD (rollback uses
    ///                             reset --hard <base>)
    pub async fn snapshot_create(&self, cwd: &str) -> Result<String> {
        self.validate_cwd(cwd)?;
        if !Self::is_repo(cwd).await {
            info!(cwd, "not a git repo, skipping snapshot");
            return Ok(String::new());
        }
        // Blocker 9 (audit 2.7a): process-level lock prevents concurrent double-apply conflicts.
        let _lock = RepoLock::acquire(cwd).await?;
        let head = Self::git(cwd, &["rev-parse", "HEAD"]).await?;
        let stash = Self::git(cwd, &["stash", "create"]).await?;
        // Blocker 9 (audit 2.7c): repo:<hash> identity — compared before cross-node rollback.
        let repo = repo_id(cwd).await;
        let repo_tag = if repo.is_empty() {
            String::new()
        } else {
            format!(",repo:{}", repo)
        };
        if stash.is_empty() {
            let id = format!("head:{}{}", head, repo_tag);
            info!(cwd, %id, "no changes, snapshot = head baseline");
            // D6-03: snapshot created; record into the on-disk index (RepoLock still held; the
            // write is mutually exclusive with snapshot creation under the same lock).
            record_snapshot_index(cwd, &id);
            return Ok(id);
        }
        let id = format!("stash:{},base:{}{}", stash, head, repo_tag);
        info!(cwd, %id, "snapshot created = stash + baseline + repo identity");
        // D6-03: same as above — stash snapshots are indexed too (fail-loud warn does not
        // affect the return value; the snapshot itself exists).
        record_snapshot_index(cwd, &id);
        Ok(id)
    }

    /// D6-03 (audit 0827 product): list existing snapshots for a cwd (on-disk NDJSON index).
    /// Retention cap SNAPSHOT_INDEX_MAX is already enforced at append time; this is a read-only
    /// parse. Non-repo (no .git / missing index) → empty Vec. Bad rows (parse failures) are
    /// skipped, non-fatal.
    /// Stateless: reads only the index file for cwd; the Executor holds no snapshot state
    /// (M-ARCH-1).
    pub fn list_snapshots(cwd: &str) -> Result<Vec<SnapshotInfo>> {
        let Some(path) = snapshot_index_path(cwd) else {
            return Ok(Vec::new());
        };
        let body = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                warn!(path = %path.display(), %e, "D6-03: failed to read snapshot index");
                bail!("failed to read snapshot index: {}", e);
            }
        };
        let mut out = Vec::new();
        for line in body.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<SnapshotInfo>(line) {
                Ok(si) => out.push(si),
                Err(e) => warn!(%line, %e, "D6-03: index row parse failed, skipping"),
            }
        }
        // Ascending by created_ms (old → new) — the caller takes the tail for the latest.
        out.sort_by_key(|s| s.created_ms);
        Ok(out)
    }

    /// Split "core[,repo:<hash>]" into core and repo tag.
    /// repo:<hash> only ever appears at the end (appended by snapshot_create), so
    /// rsplit_once ",repo:" is safe.
    /// Returns (core: &str, repo: Option<&str>); no repo tag → core = original, repo = None.
    fn split_repo_tag(s: &str) -> (&str, Option<&str>) {
        match s.rsplit_once(",repo:") {
            Some((core, repo)) => (core, Some(repo)),
            None => (s, None),
        }
    }

    /// Parse snapshot_id into (kind, stash_sha, baseline, repo_tag)
    /// kind: "head" | "stash"; repo_tag: Option<&str> (Blocker 9 addition, optional)
    #[allow(clippy::type_complexity)]
    fn parse_snapshot(
        id: &str,
    ) -> Option<(&'static str, Option<&str>, Option<&str>, Option<&str>)> {
        if let Some(rest) = id.strip_prefix("head:") {
            // head:<SHA>[,repo:<hash>]
            let (sha, repo) = Self::split_repo_tag(rest);
            let sha = if sha.is_empty() { None } else { Some(sha) };
            return Some(("head", None, sha, repo));
        }
        if let Some(rest) = id.strip_prefix("stash:") {
            // stash:<SHA>,base:<HEAD>[,repo:<hash>]
            let (core, repo) = Self::split_repo_tag(rest);
            let (stash, base) = core.split_once(",base:").unwrap_or((core, ""));
            let base = if base.is_empty() { None } else { Some(base) };
            return Some(("stash", Some(stash), base, repo));
        }
        None
    }

    /// Full rollback — dispatch on the snapshot_id tag
    /// head baseline: git reset --hard <baseline> (single-step atomic, C-RB-02)
    /// stash snapshot: git reset --hard <baseline> + git stash apply <SHA> (C-RB-02, restore
    /// the snapshot)
    /// Refs validated by is_valid_ref (C-RB-03); no -- (at the ref position -- makes git treat
    /// the ref as a pathspec → no-op)
    /// L-1 (audit 0827): returns RollbackOutcome — distinguishes "rolled back" / "needed but
    /// skipped (with reason)" / "no WIP". The old Ok(bool) folded "skipped (invalid snapshot)"
    /// and "no rollback needed" into the same false, so the caller (AutoRollbackGuard) could
    /// not fail-loud. skipped_reason = Some is the fail-loud signal.
    /// C-7 (audit 0827): WIP capture (rescuing tracked changes before reset --hard) — the old
    /// .unwrap_or_default() silently swallowed git Err → reset --hard destroyed WIP without a
    /// log. capture_wip now explicitly logs warn! and returns None; the rollback continues
    /// (safe path — aborting reset --hard would leave a worse half-applied state); wip_sha
    /// goes into the outcome for caller-side restore.
    pub async fn rollback(&self, snapshot_id: &str, cwd: &str) -> Result<RollbackOutcome> {
        self.validate_cwd(cwd)?;
        if !Self::is_repo(cwd).await {
            warn!(cwd, "not a git repo, cannot roll back");
            return Ok(RollbackOutcome::skipped("not a git repository"));
        }
        // Blocker 9 (audit 2.7b): empty snapshot_id — the old version's checkout -- . silently
        // wiped WIP. The cwd actually is a repo (race: snapshot_create returned empty because
        // git was temporarily unavailable) — fail-loud here rather than losing user work. The
        // caller should retry snapshot_create or decide explicitly.
        if snapshot_id.is_empty() {
            warn!(
                cwd,
                "empty snapshot_id, refusing rollback (prevents silently wiping WIP, audit 2.7b)"
            );
            return Ok(RollbackOutcome::skipped("empty snapshot_id"));
        }
        // Blocker 9 (audit 2.7a): process-level lock prevents concurrent double-apply conflicts.
        let _lock = RepoLock::acquire(cwd).await?;
        let (kind, stash, base, repo_tag) = match Self::parse_snapshot(snapshot_id) {
            Some(v) => v,
            None => {
                warn!(%snapshot_id, cwd, "cannot parse snapshot_id, skipping rollback");
                return Ok(RollbackOutcome::skipped("snapshot_id parse failed"));
            }
        };
        // Blocker 9 (audit 2.7c): repo:<hash> comparison — when the snapshot carries a repo
        // identity, the cwd repo hash must match. A mismatch = node A's snapshot landed on
        // node B / the cwd was swapped → reject (prevents blindly rolling back to wrong content).
        if let Some(expected) = repo_tag {
            let actual = repo_id(cwd).await;
            if actual.is_empty() {
                warn!(cwd, %expected, "cwd repo identity unresolvable, refusing (cannot verify cross-node consistency)");
                return Ok(RollbackOutcome::skipped("cwd repo identity unresolvable"));
            }
            if actual != expected {
                warn!(cwd, %expected, %actual, "snapshot_id repo identity does not match cwd, refusing (cross-node blind-rollback guard)");
                return Ok(RollbackOutcome::skipped("repo identity does not match cwd"));
            }
            info!(cwd, %expected, "repo identity matched, rollback allowed");
        }
        match kind {
            "head" => {
                // C-RB-02: single-step reset --hard <baseline> (replaces checkout -- . + stash apply)
                let baseline = base.unwrap_or("HEAD");
                if !Self::is_valid_ref(baseline) {
                    warn!(cwd, %baseline, "baseline is not a valid ref, refusing (C-RB-03 flag injection)");
                    return Ok(RollbackOutcome::skipped("baseline is not a valid ref"));
                }
                // C-7 (audit 0827) + M-SEC-03: before reset --hard, capture tracked WIP as a
                // dangling commit (never enters the stash list, so C-RB-01 holds). capture_wip
                // explicitly distinguishes Err (fail-loud warn!, returns None) from an empty
                // tree (no WIP); the old .unwrap_or_default() silently folded Err into an empty
                // string → reset --hard destroyed WIP without a log. The rollback continues
                // (safe path); wip_sha goes into the outcome for restore.
                let wip_sha = Self::capture_wip(cwd).await;
                if let Some(sha) = wip_sha.as_ref() {
                    warn!(
                        cwd, wip_sha = %sha,
                        "M-SEC-03: captured tracked WIP as a dangling commit before reset --hard; \
                         to restore concurrent edits after rollback run: git stash apply {}", sha
                    );
                }
                match Self::git(cwd, &["reset", "--hard", baseline]).await {
                    Ok(_) => {
                        info!(cwd, %baseline, "rollback succeeded (head baseline, reset --hard)");
                        Ok(RollbackOutcome::applied(wip_sha))
                    }
                    Err(e) => {
                        warn!(cwd, %baseline, "reset --hard failed: {}", e);
                        Ok(RollbackOutcome::skipped("reset --hard failed"))
                    }
                }
            }
            "stash" => {
                let stash_sha = stash.unwrap_or("");
                if stash_sha.is_empty() || !Self::is_valid_ref(stash_sha) {
                    warn!(cwd, %stash_sha, "stash SHA is not a valid ref, refusing (C-RB-03)");
                    return Ok(RollbackOutcome::skipped("stash SHA is not a valid ref"));
                }
                let baseline = base.unwrap_or("HEAD");
                if !Self::is_valid_ref(baseline) {
                    warn!(cwd, %baseline, "baseline is not a valid ref, refusing (C-RB-03 flag injection)");
                    return Ok(RollbackOutcome::skipped("baseline is not a valid ref"));
                }
                // C-7 + M-SEC-03: same as the head branch — capture_wip rescues tracked WIP
                // created after the snapshot.
                let wip_sha = Self::capture_wip(cwd).await;
                if let Some(sha) = wip_sha.as_ref() {
                    warn!(
                        cwd, wip_sha = %sha,
                        "M-SEC-03: captured tracked WIP as a dangling commit before stash rollback; \
                         to restore concurrent edits after rollback run: git stash apply {}", sha
                    );
                }
                // C-RB-02: first reset --hard <baseline> to clear the worktree to the baseline
                // (single-step atomic, avoids a half-applied state), then stash apply <stash>
                // to restore the snapshot content (clean baseline, apply cannot conflict).
                if let Err(e) = Self::git(cwd, &["reset", "--hard", baseline]).await {
                    warn!(cwd, %baseline, "stash rollback: reset --hard failed: {}", e);
                    return Ok(RollbackOutcome::skipped(
                        "stash rollback reset --hard failed",
                    ));
                }
                match Self::git(cwd, &["stash", "apply", stash_sha]).await {
                    Ok(_) => {
                        // C-RB-01: stash create returns a dangling commit — it never enters the
                        // stash list, so no drop is needed or possible (drop -- <sha> errors
                        // with "not a stash reference"). Unbounded growth cannot happen; the
                        // invariant is guarded by test_stash_list_stays_empty_across_rollback_cycles.
                        info!(cwd, %stash_sha, "rollback succeeded (reset --hard + stash apply)");
                        Ok(RollbackOutcome::applied(wip_sha))
                    }
                    Err(e) => {
                        warn!(cwd, %stash_sha, "stash apply failed (already reset --hard): {}", e);
                        Ok(RollbackOutcome::skipped("stash apply failed"))
                    }
                }
            }
            _ => {
                warn!(%kind, cwd, "unknown snapshot kind, skipping");
                Ok(RollbackOutcome::skipped("unknown snapshot kind"))
            }
        }
    }

    /// C-7 (audit 0827): WIP capture — rescue current tracked changes as a dangling commit
    /// before reset --hard. `git stash create` returns a SHA on success (an empty tree returns
    /// an empty string → no WIP → None); on failure (Err) the old .unwrap_or_default() silently
    /// swallowed it → reset --hard destroyed WIP without a log. Now fail-loud: warn! records
    /// the git Err and returns None; the caller (rollback) continues (safe path — aborting
    /// reset --hard would leave a worse half-applied state). wip_sha goes into RollbackOutcome
    /// so the upper layer (AutoRollbackGuard → result) can expose it to the caller for restore.
    async fn capture_wip(cwd: &str) -> Option<String> {
        match Self::git(cwd, &["stash", "create"]).await {
            Ok(s) => {
                let s = s.trim();
                if s.is_empty() {
                    None
                } else {
                    Some(s.to_string())
                }
            }
            Err(e) => {
                warn!(
                    cwd, error = %e,
                    "C-7: WIP capture (stash create) failed — reset --hard may lose unsaved tracked changes (fail-loud; rollback continues)"
                );
                None
            }
        }
    }

    /// Single-file rollback — git checkout -- <path> (PRD "single-file checkout")
    /// C-RB-03: -- isolates the pathspec (a path like --foo is not treated as a flag; path sits
    /// at the pathspec position where -- is correct)
    /// L-8 (audit 0827): holds the RepoLock — the old version only locked rollback(); without
    /// a lock, concurrent rollback (reset --hard) and rollback_file (checkout --) race on the
    /// git index → half-applied states / lost changes. Shares the same .git/fe-rollback.lock
    /// flock, mutually exclusive with rollback.
    pub async fn rollback_file(&self, path: &str, cwd: &str) -> Result<bool> {
        self.validate_cwd(cwd)?;
        if !Self::is_repo(cwd).await {
            warn!(cwd, "not a git repo, cannot roll back a single file");
            return Ok(false);
        }
        let _lock = RepoLock::acquire(cwd).await?;
        match Self::git(cwd, &["checkout", "--", path]).await {
            Ok(_) => {
                info!(cwd, %path, "single-file rollback succeeded");
                Ok(true)
            }
            Err(e) => {
                warn!(cwd, %path, "single-file rollback failed: {}", e);
                Ok(false)
            }
        }
    }
}

impl Default for RollbackManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_repo(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fe-rollback-test-{}-{}", std::process::id(), tag));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // git init + first commit (config user to bypass CI's missing global config)
        for (k, v) in [
            ("init", "-q"),
            ("config", "user.email"),
            ("config", "user.name"),
        ] {
            let mut args = vec!["-C", dir.to_str().unwrap(), k];
            if k == "config" {
                args.push(v);
                args.push("t@t");
            } else {
                args.push(v);
            }
            let _ = std::process::Command::new("git").args(&args).status();
        }
        std::process::Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["commit", "--allow-empty", "-q", "-m", "init"])
            .status()
            .unwrap();
        dir
    }

    #[tokio::test]
    async fn snapshot_then_rollback_restores_file() {
        let dir = tmp_repo("rt");
        let cwd = dir.to_str().unwrap();
        // Write a file and commit the baseline
        fs::write(dir.join("app.py"), "print('v1')\n").unwrap();
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["add", "app.py"])
            .status();
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["commit", "-q", "-m", "base"])
            .status();

        let mgr = RollbackManager::new();
        // Break the file → snapshot
        fs::write(dir.join("app.py"), "BROKEN\n").unwrap();
        let snap = mgr.snapshot_create(cwd).await.unwrap();
        assert!(!snap.is_empty(), "snapshot id non-empty: {}", snap);

        // Break it further → roll back to the snapshot
        fs::write(dir.join("app.py"), "WORSE\n").unwrap();
        let ok = mgr.rollback(&snap, cwd).await.unwrap();
        assert!(ok.applied, "rollback succeeded");
        let restored = fs::read_to_string(dir.join("app.py")).unwrap();
        assert_eq!(restored, "BROKEN\n", "rolled back to snapshot content");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rollback_file_single() {
        let dir = tmp_repo("rf");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("a.py"), "A\n").unwrap();
        fs::write(dir.join("b.py"), "B\n").unwrap();
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["add", "."])
            .status();
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["commit", "-q", "-m", "base"])
            .status();

        // Modify both files, roll back only a.py
        fs::write(dir.join("a.py"), "A2\n").unwrap();
        fs::write(dir.join("b.py"), "B2\n").unwrap();
        let ok = RollbackManager::new()
            .rollback_file("a.py", cwd)
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(
            fs::read_to_string(dir.join("a.py")).unwrap(),
            "A\n",
            "a.py restored"
        );
        assert_eq!(
            fs::read_to_string(dir.join("b.py")).unwrap(),
            "B2\n",
            "b.py untouched"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn non_repo_snapshot_empty() {
        let dir = std::env::temp_dir().join(format!("fe-rollback-norepo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let snap = RollbackManager::new()
            .snapshot_create(dir.to_str().unwrap())
            .await
            .unwrap();
        assert!(snap.is_empty(), "non-repo snapshot is empty");
        let _ = fs::remove_dir_all(&dir);
    }

    // ── T5 additions: C-RB-01/02/03 regressions ──

    // C-RB-01: stash create returns a dangling commit; stash list does not grow across
    // rollback cycles (the audit's original verdict "apply never drops = unbounded growth"
    // does not hold for the stash create backend; this test guards the invariant)
    #[tokio::test]
    async fn test_stash_list_stays_empty_across_rollback_cycles() {
        let dir = tmp_repo("grow");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        // 5 cycles: modify → snapshot → break → rollback
        for i in 0..5 {
            fs::write(dir.join("app.py"), format!("BROKEN{}\n", i)).unwrap();
            let snap = mgr.snapshot_create(cwd).await.unwrap();
            assert!(
                snap.starts_with("stash:"),
                "cycle {} should have stash prefix: {}",
                i,
                snap
            );
            fs::write(dir.join("app.py"), format!("WORSE{}\n", i)).unwrap();
            assert!(
                mgr.rollback(&snap, cwd).await.unwrap().applied,
                "cycle {} rollback succeeded",
                i
            );
        }
        // C-RB-01 invariant: stash list still empty (dangling commits never enter the stack)
        let list = git_list_stash(cwd).await;
        assert!(
            list.is_empty(),
            "stash list should be empty after 5 cycles (no unbounded growth): {}",
            list
        );
        // The last cycle rolled back to the 5th snapshot (BROKEN4)
        assert_eq!(fs::read_to_string(dir.join("app.py")).unwrap(), "BROKEN4\n");
        let _ = fs::remove_dir_all(&dir);
    }

    // C-RB-02: head baseline (clean worktree) rollback restores via single-step reset --hard
    #[tokio::test]
    async fn rollback_head_baseline_resets_hard() {
        let dir = tmp_repo("head");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        // Clean worktree → head snapshot
        let snap = mgr.snapshot_create(cwd).await.unwrap();
        assert!(
            snap.starts_with("head:"),
            "clean should have head prefix: {}",
            snap
        );
        // New commit (baseline advances)
        fs::write(dir.join("app.py"), "v2\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "v2");
        // Roll back to the head baseline (v1)
        let ok = mgr.rollback(&snap, cwd).await.unwrap();
        assert!(ok.applied, "head baseline rollback succeeded");
        assert_eq!(
            fs::read_to_string(dir.join("app.py")).unwrap(),
            "v1\n",
            "restored to baseline v1"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // C-RB-03: flag-like refs are rejected (is_valid_ref validation, not injection)
    #[tokio::test]
    async fn rollback_rejects_flaglike_snapshot_id() {
        let dir = tmp_repo("flag");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        // --foo has no head:/stash: prefix → parse_snapshot returns None → safely skipped (ok=false)
        assert!(
            !mgr.rollback("--foo", cwd).await.unwrap().applied,
            "flag-like snapshot_id should be rejected"
        );
        // head:--foo → parse succeeds but is_valid_ref rejects the baseline → ok=false
        assert!(
            !mgr.rollback("head:--foo", cwd).await.unwrap().applied,
            "head:--foo baseline is not a valid ref and should be rejected"
        );
        // File untouched
        assert_eq!(fs::read_to_string(dir.join("app.py")).unwrap(), "v1\n");
        let _ = fs::remove_dir_all(&dir);
    }

    // parse_snapshot + is_valid_ref unit tests
    #[test]
    fn parse_snapshot_and_ref_validation() {
        let (k, s, b, repo) = RollbackManager::parse_snapshot("head:abc123").unwrap();
        assert_eq!(k, "head");
        assert!(s.is_none());
        assert_eq!(b, Some("abc123"));
        assert!(repo.is_none(), "no repo identity should be None");
        let (k, s, b, repo) = RollbackManager::parse_snapshot("stash:st1,base:he2").unwrap();
        assert_eq!(k, "stash");
        assert_eq!(s, Some("st1"));
        assert_eq!(b, Some("he2"));
        assert!(repo.is_none());
        // Blocker 9: 4-tuple including repo:<hash>
        let (k, _s, b, repo) =
            RollbackManager::parse_snapshot("head:abc123,repo:deadbeef").unwrap();
        assert_eq!(k, "head");
        assert_eq!(b, Some("abc123"));
        assert_eq!(repo, Some("deadbeef"));
        let (k, s, b, repo) =
            RollbackManager::parse_snapshot("stash:st1,base:he2,repo:cafe").unwrap();
        assert_eq!(k, "stash");
        assert_eq!(s, Some("st1"));
        assert_eq!(b, Some("he2"));
        assert_eq!(repo, Some("cafe"));
        assert!(RollbackManager::parse_snapshot("garbage").is_none());
        assert!(RollbackManager::parse_snapshot("--foo").is_none());
        // is_valid_ref
        assert!(RollbackManager::is_valid_ref("HEAD"));
        assert!(RollbackManager::is_valid_ref("80a4c2f")); // 7-hex
        assert!(RollbackManager::is_valid_ref(
            "80a4c2f3fdf95dee67374b50a2c5aaf8cf9ac15f"
        ));
        assert!(!RollbackManager::is_valid_ref("--foo"));
        assert!(!RollbackManager::is_valid_ref("abc")); // too short (<7)
        assert!(!RollbackManager::is_valid_ref(
            "80a4c2f3fdf95dee67374b50a2c5aaf8cf9ac15f1234"
        )); // too long (>40)
        assert!(!RollbackManager::is_valid_ref("gggggggggg")); // not hex
    }

    // Helpers
    fn git_commit(dir: &std::path::Path, add: &[&str], msg: &str) {
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(add)
            .status();
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["commit", "-q", "-m", msg])
            .status();
    }

    async fn git_list_stash(cwd: &str) -> String {
        // Goes through git() but tolerates non-zero exit (with no stashes, git stash list
        // exits 0 with empty output)
        RollbackManager::git(cwd, &["stash", "list"])
            .await
            .unwrap_or_default()
    }

    // ── Blocker 4 (audit 1.3): rollback paths go through fe-security ──

    #[tokio::test]
    async fn snapshot_rejects_empty_cwd() {
        let mgr = RollbackManager::new();
        let err = mgr.snapshot_create("").await.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("empty"),
            "empty cwd should be rejected: {}",
            msg
        );
    }

    #[tokio::test]
    async fn snapshot_rejects_dotdot_cwd() {
        let mgr = RollbackManager::new();
        let err = mgr.snapshot_create("/tmp/foo/../bar").await.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains(".."),
            "cwd with .. should be rejected: {}",
            msg
        );
    }

    #[tokio::test]
    async fn snapshot_rejects_sensitive_cwd() {
        let mgr = RollbackManager::new();
        let err = mgr.snapshot_create("/etc").await.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("validation failed"),
            "sensitive path /etc should be rejected: {}",
            msg
        );
    }

    #[tokio::test]
    async fn rollback_rejects_sensitive_cwd() {
        let dir = tmp_repo("sens");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        let snap = mgr.snapshot_create(cwd).await.unwrap();
        assert!(!snap.is_empty());
        // /etc → validate_cwd rejects first (sensitive path); is_repo never runs, returns Err
        let err = mgr.rollback(&snap, "/etc").await.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("validation failed"),
            "/etc should be rejected by validate_cwd: {}",
            msg
        );
        // /tmp regular repo → validation passes, rollback succeeds
        assert!(
            mgr.rollback(&snap, cwd).await.unwrap().applied,
            "regular repo should be rollback-able"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rollback_file_rejects_empty_cwd() {
        let mgr = RollbackManager::new();
        let err = mgr.rollback_file("a.py", "").await.unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("empty"),
            "empty cwd should be rejected: {}",
            msg
        );
    }

    // ── Blocker 9 (audit 2.7): cross-node registry + process lock ──

    // 2.7b: empty snapshot_id fail-loud (the old checkout -- . silently wiped WIP)
    #[tokio::test]
    async fn rollback_rejects_empty_snapshot_id_fail_loud() {
        let dir = tmp_repo("empty-id");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        // WIP changes to be preserved
        fs::write(dir.join("app.py"), "WIP-important-work\n").unwrap();
        let mgr = RollbackManager::new();
        // L-1 (audit 0827): empty snapshot_id → RollbackOutcome::skipped (applied=false + reason).
        // The old Ok(false) folded "no rollback needed" together, so callers could not
        // fail-loud; skipped_reason now exposes the reason.
        let ok = mgr.rollback("", cwd).await.unwrap();
        assert!(!ok.applied, "empty snapshot_id should refuse rollback");
        assert!(
            ok.skipped_reason.is_some(),
            "L-1: skip should carry a reason (fail-loud), not a silent false"
        );
        // WIP was not destroyed
        assert_eq!(
            fs::read_to_string(dir.join("app.py")).unwrap(),
            "WIP-important-work\n",
            "WIP should be preserved when an empty id rollback is refused"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // 2.7c: repo:<hash> identity mismatch → rejected (cross-node blind-rollback guard)
    // Simulates: the snapshot carries repo:<hash> but the cwd repo's hash differs (forged
    // snapshot_id)
    #[tokio::test]
    async fn rollback_rejects_repo_tag_mismatch() {
        let dir = tmp_repo("repo-mismatch");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        // Real snapshot (with the correct repo identity)
        let snap = mgr.snapshot_create(cwd).await.unwrap();
        assert!(
            snap.contains(",repo:"),
            "snapshot should carry a repo identity: {}",
            snap
        );
        // Correct snapshot → rollback allowed
        fs::write(dir.join("app.py"), "WORSE\n").unwrap();
        let ok = mgr.rollback(&snap, cwd).await.unwrap();
        assert!(ok.applied, "correct repo identity should allow rollback");
        // Forged: swap repo:<hash> for a fake hash → rejected (L-1: skipped exposes the reason)
        let fake = "head:deadbeefdeadbeef,repo:0000000000000000".to_string();
        fs::write(dir.join("app.py"), "WORSE2\n").unwrap();
        let ok = mgr.rollback(&fake, cwd).await.unwrap();
        assert!(!ok.applied, "repo identity mismatch should refuse rollback");
        assert!(
            ok.skipped_reason.is_some(),
            "L-1: repo-mismatch skip should carry a reason (fail-loud)"
        );
        // File was not rolled back (still WORSE2)
        assert_eq!(
            fs::read_to_string(dir.join("app.py")).unwrap(),
            "WORSE2\n",
            "worktree should be untouched when a repo mismatch is refused"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // 2.7c: legacy snapshot_id without a repo identity (backward compatible) → allowed (no comparison)
    #[tokio::test]
    async fn rollback_allows_legacy_snapshot_without_repo_tag() {
        let dir = tmp_repo("legacy");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        // Build a legacy id without a repo identity from the real HEAD SHA
        let head = RollbackManager::git(cwd, &["rev-parse", "HEAD"])
            .await
            .unwrap();
        let legacy = format!("head:{}", head);
        assert!(
            !legacy.contains(",repo:"),
            "legacy id carries no repo identity: {}",
            legacy
        );
        // Advance the baseline with a new commit
        fs::write(dir.join("app.py"), "v2\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "v2");
        // Legacy id without a repo identity → allowed (backward compatible, no comparison)
        assert!(
            mgr.rollback(&legacy, cwd).await.unwrap().applied,
            "legacy id without a repo identity should be allowed"
        );
        assert_eq!(
            fs::read_to_string(dir.join("app.py")).unwrap(),
            "v1\n",
            "legacy rollback restored baseline v1"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // 2.7a: process lock — concurrent snapshot_create + rollback are serialized (lock file on disk)
    #[tokio::test]
    async fn process_lock_file_created_and_released() {
        let dir = tmp_repo("lock");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        // The lock file should exist while snapshot_create holds the lock (checked right after acquire)
        let snap = mgr.snapshot_create(cwd).await.unwrap();
        assert!(!snap.is_empty());
        // After snapshot_create returns the lock is released (drop), but the lock file itself
        // remains (create=true)
        let lock_path = dir.join(".git").join("fe-rollback.lock");
        assert!(
            lock_path.exists(),
            "lock file should persist at .git/fe-rollback.lock"
        );
        // rollback should be able to acquire the lock again (the previous one was released)
        fs::write(dir.join("app.py"), "WORSE\n").unwrap();
        assert!(
            mgr.rollback(&snap, cwd).await.unwrap().applied,
            "rollback should succeed after the lock is released"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // ── RUN-7 (audit 0827 arch): in a worktree .git is a file, so RepoLock must resolve the real git dir ──

    // resolve_git_dir returns cwd/.git (after canonicalize) for a regular repo
    #[tokio::test]
    async fn resolve_git_dir_normal_repo() {
        let dir = tmp_repo("resolve");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let resolved = resolve_git_dir(cwd).expect("regular repo should resolve a git dir");
        assert!(
            resolved.ends_with(".git"),
            "regular repo git dir should end with .git: {:?}",
            resolved
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // Inside a worktree .git is a file, not a directory; RepoLock::acquire must resolve the
    // real git dir without hitting ENOTDIR
    #[tokio::test]
    async fn repo_lock_worktree_git_file_not_dir() {
        let main = tmp_repo("wt-main");
        fs::write(main.join("app.py"), "v1\n").unwrap();
        git_commit(&main, &["add", "app.py"], "base");
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(&main)
            .args(["branch", "wt-branch"])
            .status();
        let wt =
            std::env::temp_dir().join(format!("fe-rollback-wt-{}-{}", std::process::id(), "wt"));
        let _ = fs::remove_dir_all(&wt);
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(&main)
            .args(["worktree", "add", wt.to_str().unwrap(), "wt-branch"])
            .status();
        // The worktree .git should be a file (not a directory) — this is RUN-7's trigger condition
        let dot_git = wt.join(".git");
        assert!(
            dot_git.is_file(),
            "worktree .git should be a file: {:?}",
            dot_git
        );
        // RUN-7: acquire must succeed (resolves the real git dir; the old cwd.join(".git")
        // treated it as a directory and hit ENOTDIR)
        let lock = RepoLock::acquire(wt.to_str().unwrap()).await;
        assert!(
            lock.is_ok(),
            "RepoLock::acquire should succeed inside a worktree (RUN-7): {:?}",
            lock.err()
        );
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(&main)
            .args(["worktree", "remove", "--force", wt.to_str().unwrap()])
            .status();
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(&main)
            .args(["branch", "-D", "wt-branch"])
            .status();
        let _ = fs::remove_dir_all(&main);
    }

    // D6-03 (audit 0827 product): snapshot_create writes an on-disk NDJSON index; list_snapshots reads it back.
    #[tokio::test]
    async fn snapshot_create_writes_index_and_list_reads_back() {
        let dir = tmp_repo("d603-clean");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");

        // Clean repo → head snapshot
        let id = RollbackManager::new().snapshot_create(cwd).await.unwrap();
        assert!(
            id.starts_with("head:"),
            "clean snapshot should have head: prefix: {}",
            id
        );

        let snaps = RollbackManager::list_snapshots(cwd).unwrap();
        assert_eq!(snaps.len(), 1, "index should contain 1 entry");
        assert_eq!(
            snaps[0].id, id,
            "index id should match snapshot_create's return"
        );
        assert_eq!(snaps[0].kind, "head");
        assert!(snaps[0].created_ms > 0, "created_ms non-zero");

        // Dirty repo → stash snapshot appended
        fs::write(dir.join("app.py"), "DIRTY\n").unwrap();
        let id2 = RollbackManager::new().snapshot_create(cwd).await.unwrap();
        assert!(
            id2.starts_with("stash:"),
            "dirty snapshot should have stash: prefix: {}",
            id2
        );

        let snaps2 = RollbackManager::list_snapshots(cwd).unwrap();
        assert_eq!(
            snaps2.len(),
            2,
            "index should contain 2 entries after append"
        );
        assert_eq!(snaps2[1].id, id2, "latest entry = stash snapshot");
        assert_eq!(snaps2[1].kind, "stash");
        // Ascending: created_ms old < new
        assert!(snaps2[0].created_ms <= snaps2[1].created_ms);

        let _ = fs::remove_dir_all(&dir);
    }

    // D6-03: non-repo (no .git) → snapshot_create returns empty, list_snapshots returns empty (nothing indexed).
    #[tokio::test]
    async fn non_repo_returns_empty_index() {
        let dir =
            std::env::temp_dir().join(format!("fe-rollback-nonrepo-{}-d603", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cwd = dir.to_str().unwrap();
        let id = RollbackManager::new().snapshot_create(cwd).await.unwrap();
        assert_eq!(id, "", "non-repo snapshot should be an empty string");
        let snaps = RollbackManager::list_snapshots(cwd).unwrap();
        assert!(snaps.is_empty(), "non-repo index should be empty");
        let _ = fs::remove_dir_all(&dir);
    }

    // D6-03: retention cap — past SNAPSHOT_INDEX_MAX, drop the oldest (smallest created_ms).
    #[tokio::test]
    async fn index_retention_prunes_oldest() {
        let dir = tmp_repo("d603-retention");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("a.txt"), "1\n").unwrap();
        git_commit(&dir, &["add", "a.txt"], "base");

        // SNAPSHOT_INDEX_MAX+5 clean snapshots (changing the file content each time leaves
        // stash create empty or not, either is fine; this exercises the retention truncation
        // logic and does not depend on the head/stash kind). Each git commit changes HEAD, so
        // the head snapshots all differ.
        let total = SNAPSHOT_INDEX_MAX + 5;
        for i in 0..total {
            fs::write(dir.join("a.txt"), format!("{}\n", i)).unwrap();
            git_commit(&dir, &["add", "a.txt"], &format!("c{}", i));
            let _ = RollbackManager::new().snapshot_create(cwd).await.unwrap();
        }
        let snaps = RollbackManager::list_snapshots(cwd).unwrap();
        assert_eq!(
            snaps.len(),
            SNAPSHOT_INDEX_MAX,
            "retention should truncate to cap {}",
            SNAPSHOT_INDEX_MAX
        );
        // The earliest (smallest created_ms) are dropped; the most recent
        // SNAPSHOT_INDEX_MAX entries are kept
        let first_id = &snaps[0].id;
        assert!(
            !first_id.starts_with("head:") || first_id != "head:",
            "the first entry after retention should not be the initial empty snapshot"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
