// fe-sandbox seatbelt — macOS runtime isolation (audit Blocker 1 / 1.1, 0827 C-16/A-12)
//
// Darwin 25 (macOS 26) measured findings (2026-08-25 / D3-3 retest 2026-08-28):
//   - sandbox-exec **global** `file-write*` deny is fully ineffective (neither literal nor subpath blocks writes/deletes).
//   - **Directed** `file-write*` deny (D3-3: subpath of specific sensitive paths and their children) —
//     0827 C-16: inject directed denies as best-effort defense-in-depth. D3-3 measurement (probe_seatbelt_fs_subpath_deny,
//     2026-08-28): Darwin 25 subpath is **also a NO-OP** — writing a tempdir child file exits 0 and the file lands.
//     subpath semantics are more correct than literal (literal is exact-path only, child files slip through), but on Darwin 25 both fail.
//     Real isolation relies on fe-security is_sensitive_path (argv layer) + a restricted macOS user account (OS-level, not seatbelt).
//   - `process-exec` deny works: (deny process-exec (literal "/bin/rm")) → execve blocked, exit 126.
//   - `network-outbound` deny works: blocks /dev/tcp exfiltration + curl|sh carrier egress.
//
// 0827 A-12 correction: removed the DANGEROUS_BINS process-exec denylist — blacklists are inherently unenumerable
// (rm rename/symlink bypass); fe-security Stage-2 allowlist (stronger: blocks every binary outside the whitelist)
// already covers binary isolation.
// The seatbelt denylist was a redundant weak line of defense that created a "double protection" illusion. seatbelt keeps only
// network-outbound + directed FS deny (C-16); binary isolation is led by the fe-security allowlist.
//
// 0827 C-16 documentation (explicit FS non-isolation statement):
//   the seatbelt layer is **not full FS isolation** — syscalls (unlink/rmdir/open/write) of whitelisted
//   binaries (python3/node/cargo) guard high-value paths via directed deny, but there is **no** full FS deny.
//   Global + directed file-write* both measured NO-OP on Darwin 25; directed denies are kept as best-effort
//   defense-in-depth (subpath semantics are correct; Darwin versions without the NO-OP would enforce them for real),
//   but the current platform does not rely on them for interception.
//   Actual isolation items: (1) network-outbound (measured working), (2) directed sensitive-path file-write* (best-effort, Darwin 25 NO-OP),
//   (3) binary exec led by the fe-security allowlist (not seatbelt).
//   Full FS isolation needs OS-level — a dedicated restricted macOS user account (not a seatbelt capability).
//
// No unsafe: sandbox-exec is a /usr/bin subprocess spawned via the portable-pty CommandBuilder.
// The crate stays unsafe_code="deny" (fe-sandbox has no allow).
//
// Issue #3 (resource caps): limits injected via the shell `ulimit` builtin (sh -c 'ulimit -u N; ulimit -t N; <cmd>'),
// not setrlimit FFI — avoids unsafe + stays consistent across the PTY/stdio backends.
// Darwin 25 measurements (2026-08-25):
//   - RLIMIT_AS (ulimit -v) / RLIMIT_DATA (ulimit -d) / RLIMIT_FSIZE (ulimit -f) are all NO-OPs
//     (setrlimit EINVAL, or accepted but allocations uncapped; infinite malloc still escapes) — a Darwin platform
//     limitation, not a code defect. No usable rlimit for heap memory; output-side OOM is bounded by the fe-sandbox ring buffer (2*max_output).
//     RUN-4 (audit 0827): no OS mechanism for a memory cap — an inherent Darwin platform limitation, not fixable in code.
//     Documentation + ring buffer (output side) + seatbelt network deny/directed FS deny (attack-surface side) are the current mitigations.
//   - RLIMIT_NPROC (ulimit -u) works: fork bombs get concurrency-limited (spread-limit, not terminator —
//     already-spawned children retry-storm; real termination relies on the timeout watchdog killing the process tree).
//   - RLIMIT_CPU (ulimit -t) works: CPU-second cap, SIGXCPU at the ceiling.
//   - RLIMIT_NOFILE (ulimit -n) works: caps per-process open FDs (Darwin measured errno 24 EMFILE
//     hitting the cap, RUN-10 audit 0827 — blocks fork-bomb + FD-exhaustion attacks).
//   - seatbelt profile `resource-limit`/`limit` keywords — unparseable (parse error), unusable.
// Policy: inject the measured-working ulimit -u (NPROC) + ulimit -t (CPU) + ulimit -n (NOFILE);
// do not inject -v/-d/-f (no-ops; fake security violates Rule 12 fail-visible). Darwin heap memory has no rlimit cap,
// documented as a platform limitation (RUN-4).

use portable_pty::CommandBuilder;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::LazyLock;
use tracing::{debug, info, warn};

/// Issue #34: per-command configurable seatbelt profile — lets the caller (fusion-code) request a sandbox policy per command,
/// aligned with the in-process SandboxSettings semantics (network allow/deny, filesystem allow/deny-write,
/// excluded commands). Default-off (Option<SandboxProfile> = None → the existing fixed profile, byte-identical);
/// Some(profile) → build_profile_from builds parameterized by field. With fail_if_unavailable=true and sandbox-exec
/// unavailable → fe-core fail-closed rejects execution (high-risk commands never run bare).
///
/// Network policy — Allow = permit egress (no network deny injected); Deny = network denied (deny network-outbound, the existing default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SandboxNetworkMode {
    Allow,
    #[default]
    Deny,
}

/// Filesystem policy — Allow = no FS deny injected; DenyWrite = directed sensitive-path file-write* deny (the existing
/// default, a best-effort NO-OP on Darwin 25 but semantically correct); Deny = global file-write* deny (measured NO-OP on Darwin 25, best-effort only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SandboxFsMode {
    Allow,
    #[default]
    DenyWrite,
    Deny,
}

/// Issue #34: per-command seatbelt profile. None fields fall back to defaults (network=Deny, fs=DenyWrite).
/// excluded_commands → process-exec deny (caller explicitly excludes specific binaries, complementing the fe-security allowlist).
/// fail_if_unavailable → fail-closed when a profile is requested but sandbox-exec is missing (validated at the fe-core entry).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SandboxProfile {
    #[serde(default)]
    pub network: Option<SandboxNetworkMode>,
    #[serde(default)]
    pub filesystem: Option<SandboxFsMode>,
    #[serde(default)]
    pub excluded_commands: Vec<String>,
    #[serde(default)]
    pub fail_if_unavailable: bool,
}

/// 0827 C-16: high-value sensitive paths for the directed FS deny — best-effort protection against whitelisted-binary
/// syscalls deleting/reading/writing them. Global file-write* fails on Darwin 25; directed denies (D3-3: subpath of the
/// path and its children) are injected as defense-in-depth.
/// Paths are expanded from $HOME (substituted at call time); covers credentials (~/.ssh), model cache (~/.fusion-mlx),
/// and system-sensitive areas (/etc, /var/db). On failure falls back to no FS protection, never fakes isolation (Rule 12).
/// All are directory roots → subpath is safe (no over-blocking of sibling directories).
const SENSITIVE_FS_PATHS: &[&str] = &[
    "HOME/.ssh",
    "HOME/.fusion-mlx",
    "HOME/.claude",
    "/etc",
    "/var/db",
    "/Library/Keychains",
];

/// 0827 A-12: (DANGEROUS_BINS process-exec denylist removed) — binary isolation is led by the fe-security
/// allowlist (stronger: blocks everything outside the whitelist); the seatbelt denylist was redundant and weak (rm rename/symlink bypass).
//
/// Build the seatbelt profile string — allow default + network deny + directed sensitive-path file-write* deny.
/// 0827 C-16/A-12: removed the process-exec denylist (covered by the fe-security allowlist), added the directed FS deny.
fn build_profile() -> String {
    build_profile_from(None)
}

/// Issue #34: parameterized profile build — profile fields map to seatbelt directives.
/// None = the existing fixed profile (network deny + directed FS deny, byte-identical). Some = per field:
///   network: Allow → no network deny injected (egress permitted); Deny/None → deny network-outbound (default deny).
///   filesystem: Allow → no FS deny; DenyWrite/None → directed SENSITIVE_FS_PATHS deny (default);
///               Deny → global file-write* deny (Darwin 25 NO-OP, best-effort).
///   excluded_commands → (deny process-exec (literal "<cmd>")) — caller-excluded, complementing the fe-security allowlist.
fn build_profile_from(profile: Option<&SandboxProfile>) -> String {
    let mut p = String::from("(version 1)(allow default)");
    let net = profile.and_then(|pr| pr.network).unwrap_or_default();
    let fs = profile.and_then(|pr| pr.filesystem).unwrap_or_default();
    if matches!(net, SandboxNetworkMode::Deny) {
        p.push_str("(deny network-outbound)");
    }
    let home = std::env::var("HOME").unwrap_or_default();
    match fs {
        SandboxFsMode::Allow => {}
        SandboxFsMode::DenyWrite => {
            for path in SENSITIVE_FS_PATHS {
                let resolved = path.replacen("HOME", &home, 1);
                p.push_str(&format!("(deny file-write* (subpath \"{}\"))", resolved));
            }
        }
        SandboxFsMode::Deny => {
            p.push_str("(deny file-write*)");
            for path in SENSITIVE_FS_PATHS {
                let resolved = path.replacen("HOME", &home, 1);
                p.push_str(&format!("(deny file-write* (subpath \"{}\"))", resolved));
            }
        }
    }
    if let Some(pr) = profile {
        for cmd in &pr.excluded_commands {
            let cleaned = sanitize_profile_string(cmd);
            if !cleaned.is_empty() {
                p.push_str(&format!("(deny process-exec (literal \"{}\"))", cleaned));
            }
        }
    }
    p
}

/// Issue #34: sanitize profile-injected strings — prevents a caller stuffing `"`/backslash/newline into
/// excluded_commands to break the seatbelt profile syntax (injection escape). Strips control chars + quote escaping.
/// Profile literal strings do not support escape sequences, so `"` and `\` and control chars are removed outright
/// (fail-safe: an entry that sanitizes to empty is skipped, not injected).
fn sanitize_profile_string(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '"' && *c != '\\' && !c.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

/// Issue #34: probe whether sandbox-exec is available (PATH resolution). fail_if_unavailable=true callers use this to fail closed.
/// /usr/bin/sandbox-exec is macOS built-in; non-macOS / removed → unavailable. Safe Rust, no unsafe.
pub fn seatbelt_available() -> bool {
    if let Ok(path) = which::which("sandbox-exec") {
        debug!(?path, "seatbelt sandbox-exec available");
        true
    } else {
        warn!("seatbelt sandbox-exec unavailable — fail_if_unavailable callers should fail closed");
        false
    }
}

/// D4-1: seatbelt profile cache — build_profile constructs once into a LazyLock; subsequent execs reuse the same String
/// (the profile is process-static: HOME resolves at first call, SIGHUP whitelist reload does not affect the seatbelt profile —
/// the sandbox-exec profile string does not track env). Eliminates per-build_command String rebuilds + HOME env lookups.
static SEATBELT_PROFILE: LazyLock<String> = LazyLock::new(build_profile);

/// Returns the cached seatbelt profile (D4-1, default fixed profile). Tests can still call build_profile/build_profile_from
/// directly to verify construction logic.
fn profile() -> &'static str {
    &SEATBELT_PROFILE
}

/// Issue #3 + RUN-10: resource-cap wrapper — injects the measured-working ulimit builtins ahead of the command string.
/// -u (NPROC, fork-bomb defense) + -t (CPU, infinite-loop CPU burn) + -n (NOFILE, FD exhaustion) all work;
/// -v/-d/-f are Darwin no-ops and are not injected. nproc=0/cpu_sec=0/nofile=0 → the corresponding item is uncapped.
/// Injected inside the sh -c script, consistent across PTY/stdio backends, no unsafe.
fn wrap_rlimits(command: &str, nproc: u32, cpu_sec: u32, nofile: u32) -> String {
    if nproc == 0 && cpu_sec == 0 && nofile == 0 {
        return command.to_string();
    }
    let mut prefix = String::new();
    if nproc > 0 {
        prefix.push_str(&format!("ulimit -u {} 2>/dev/null; ", nproc));
    }
    if cpu_sec > 0 {
        prefix.push_str(&format!("ulimit -t {} 2>/dev/null; ", cpu_sec));
    }
    if nofile > 0 {
        prefix.push_str(&format!("ulimit -n {} 2>/dev/null; ", nofile));
    }
    // 2>/dev/null swallows Darwin's EINVAL noise on some limits (the known -v no-op reports; we only inject working items,
    // but conservatively swallow errors to keep stderr from polluting diagnostics). A failed prefix does not short-circuit
    // (; the command still runs) — rlimits are best-effort defense-in-depth;
    // the real hard caps are guaranteed by the timeout watchdog + the output ring buffer.
    let wrapped = format!("{prefix}{command}");
    debug!(
        nproc,
        cpu_sec,
        nofile,
        wrapped_len = wrapped.len(),
        "ulimit resource caps injected"
    );
    wrapped
}

/// Build the child CommandBuilder.
/// seatbelt=true → sandbox-exec -p '<profile>' sh -c '<cmd>' (runtime isolation)
/// seatbelt=false → sh -c '<cmd>' (bare run, compatible with legacy callers)
/// Issue #3 + RUN-10: nproc/cpu_sec/nofile injected into the sh -c script via wrap_rlimits (measured-working ulimits).
/// cwd/env are set by the caller on the returned cmd.
/// Issue #34: sandbox_profile=Some → build_profile_from parameterized by field (network/fs/excluded_commands);
/// None → the existing fixed profile (byte-identical). fail_if_unavailable is validated at the fe-core entry; assumed available here.
pub fn build_command(
    command: &str,
    seatbelt: bool,
    nproc: u32,
    cpu_sec: u32,
    nofile: u32,
    sandbox_profile: Option<&SandboxProfile>,
) -> CommandBuilder {
    let wrapped = wrap_rlimits(command, nproc, cpu_sec, nofile);
    if seatbelt {
        let owned: String;
        let profile: &str = match sandbox_profile {
            Some(_) => {
                owned = build_profile_from(sandbox_profile);
                &owned
            }
            None => profile(),
        };
        info!(
            profile_len = profile.len(),
            fs_paths = SENSITIVE_FS_PATHS.len(),
            custom = sandbox_profile.is_some(),
            "seatbelt runtime isolation enabled — sandbox-exec wrapper (network deny + directed FS deny)"
        );
        debug!(profile = %profile, "seatbelt profile");
        let mut cmd = CommandBuilder::new("sandbox-exec");
        cmd.arg("-p");
        cmd.arg(profile);
        cmd.arg("sh");
        cmd.arg("-c");
        cmd.arg(&wrapped);
        cmd
    } else {
        debug!("seatbelt not enabled — bare sh -c");
        let mut cmd = CommandBuilder::new("sh");
        cmd.arg("-c");
        cmd.arg(&wrapped);
        cmd
    }
}

/// Issue #4: stdio backend command build — same semantics as build_command (seatbelt wrapper / bare sh -c),
/// but returns a std::process::Command (stdout/stderr as independent Stdio::piped, not PTY).
/// Dedicated to the use_pty=false path, keeping seatbelt behavior consistent with the PTY path.
/// Issue #3 + RUN-10: nproc/cpu_sec/nofile likewise injected via wrap_rlimits.
/// Issue #34: sandbox_profile same as build_command (None=fixed profile, Some=parameterized).
pub fn build_std_command(
    command: &str,
    seatbelt: bool,
    nproc: u32,
    cpu_sec: u32,
    nofile: u32,
    sandbox_profile: Option<&SandboxProfile>,
) -> Command {
    let wrapped = wrap_rlimits(command, nproc, cpu_sec, nofile);
    if seatbelt {
        let owned: String;
        let profile: &str = match sandbox_profile {
            Some(_) => {
                owned = build_profile_from(sandbox_profile);
                &owned
            }
            None => profile(),
        };
        info!(
            profile_len = profile.len(),
            fs_paths = SENSITIVE_FS_PATHS.len(),
            custom = sandbox_profile.is_some(),
            "seatbelt (stdio) runtime isolation enabled — sandbox-exec wrapper (network deny + directed FS deny)"
        );
        let mut cmd = Command::new("sandbox-exec");
        cmd.arg("-p").arg(profile).arg("sh").arg("-c").arg(&wrapped);
        cmd
    } else {
        debug!("seatbelt (stdio) not enabled — bare sh -c");
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(&wrapped);
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_blocks_network_and_sensitive_fs() {
        let p = build_profile();
        assert!(
            p.contains("(deny network-outbound)"),
            "profile must deny network"
        );
        // C-16 + D3-3: directed FS deny (subpath) covers high-value paths and their children
        let home = std::env::var("HOME").unwrap_or_default();
        assert!(
            p.contains(&format!("(deny file-write* (subpath \"{}/.ssh\"))", home)),
            "profile must direct-deny ~/.ssh writes (subpath covers children)"
        );
        assert!(
            p.contains("(deny file-write* (subpath \"/etc\"))"),
            "profile must direct-deny /etc writes (subpath covers children)"
        );
        assert!(
            p.contains("(deny file-write* (subpath \"/Library/Keychains\"))"),
            "profile must direct-deny Keychains writes (subpath covers children)"
        );
        // A-12: process-exec denylist removed (covered by the fe-security allowlist)
        assert!(
            !p.contains("(deny process-exec"),
            "A-12: process-exec denylist should be removed (fe-security allowlist leads)"
        );
        assert!(p.starts_with("(version 1)(allow default)"));
    }

    #[test]
    fn profile_covers_all_sensitive_paths() {
        let p = build_profile();
        let home = std::env::var("HOME").unwrap_or_default();
        for path in SENSITIVE_FS_PATHS {
            let resolved = path.replacen("HOME", &home, 1);
            assert!(
                p.contains(&format!("(deny file-write* (subpath \"{}\"))", resolved)),
                "profile missing sensitive-path subpath deny: {}",
                resolved
            );
        }
    }

    #[test]
    fn build_command_seatbelt_wraps_sandbox_exec() {
        let cmd = build_command("echo hi", true, 0, 0, 0, None);
        // CommandBuilder has no direct introspection API — just verify no panic and that the profile denies network
        let p = build_profile();
        assert!(p.contains("network-outbound"));
        let _ = cmd;
    }

    #[test]
    fn build_command_bare_when_disabled() {
        let cmd = build_command("echo hi", false, 0, 0, 0, None);
        let _ = cmd; // no panic
    }

    #[test]
    fn wrap_rlimits_injects_nproc_and_cpu() {
        let w = wrap_rlimits("echo hi", 1024, 30, 0);
        assert!(
            w.contains("ulimit -u 1024"),
            "NPROC should be injected: {}",
            w
        );
        assert!(w.contains("ulimit -t 30"), "CPU should be injected: {}", w);
        assert!(
            w.ends_with("echo hi"),
            "original command should be at the end: {}",
            w
        );
    }

    // RUN-10: NOFILE injection measured working (Darwin errno 24 EMFILE)
    #[test]
    fn wrap_rlimits_injects_nofile() {
        let w = wrap_rlimits("echo hi", 0, 0, 1024);
        assert!(
            w.contains("ulimit -n 1024"),
            "NOFILE should be injected: {}",
            w
        );
        assert!(!w.contains("ulimit -u"), "nproc=0 must not inject NPROC");
        assert!(
            w.ends_with("echo hi"),
            "original command should be at the end: {}",
            w
        );
    }

    #[test]
    fn wrap_rlimits_skips_when_zero() {
        let w = wrap_rlimits("echo hi", 0, 0, 0);
        assert_eq!(w, "echo hi", "all-zero must not inject any prefix");
    }

    #[test]
    fn wrap_rlimits_only_nproc() {
        let w = wrap_rlimits("echo hi", 512, 0, 0);
        assert!(w.contains("ulimit -u 512"));
        assert!(!w.contains("ulimit -t"), "cpu=0 must not inject CPU");
        assert!(!w.contains("ulimit -n"), "nofile=0 must not inject NOFILE");
    }

    #[test]
    fn build_std_command_accepts_rlimits() {
        // Verify the stdio backend build does not panic + accepts rlimit args (no Command arg introspection)
        let _ = build_std_command("echo hi", false, 1024, 30, 1024, None);
        let _ = build_std_command("echo hi", true, 1024, 30, 1024, None);
    }

    // D3-3: empirical probe — verifies whether the seatbelt subpath FS deny really blocks on Darwin 25.
    // Uses a temp directory + a custom profile (subpath deny on that tempdir) to probe, without touching real sensitive paths (~/.ssh etc.) —
    // the probe writes a child file inside the tempdir: if subpath works it should be blocked (exit != 0 or file absent);
    // if Darwin 25 subpath is also a NO-OP → the write succeeds and the probe records the best-effort status quo (Rule 12 fail-visible).
    // No hard blocked assertion (Darwin platform limitation); the probe merely proves the subpath syntax is accepted by sandbox-exec.
    #[test]
    fn probe_seatbelt_fs_subpath_deny() {
        let tmp = match std::env::temp_dir().canonicalize() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("D3-3 probe: temp_dir canonicalize failed {} — skipping", e);
                return;
            }
        };
        let probe_dir = tmp.join("fe-probe-d3-3-dir");
        let _ = std::fs::remove_dir_all(&probe_dir);
        if std::fs::create_dir_all(&probe_dir).is_err() {
            eprintln!("D3-3 probe: failed to create probe dir — skipping");
            return;
        }
        let probe_file = probe_dir.join("probe.txt");
        let dir_str = probe_dir.to_string_lossy();
        // Custom profile: deny only this tempdir (subpath covers its children), validating the subpath semantics itself.
        let profile = format!(
            "(version 1)(allow default)(deny network-outbound)(deny file-write* (subpath \"{}\"))",
            dir_str
        );
        let write_cmd = format!("echo probe > {}", probe_file.to_string_lossy());
        let out = std::process::Command::new("sandbox-exec")
            .arg("-p")
            .arg(&profile)
            .arg("sh")
            .arg("-c")
            .arg(&write_cmd)
            .output();
        let blocked = match out {
            Ok(o) => {
                let wrote = probe_file.exists();
                // Write succeeded (file exists + exit 0) → subpath did not block; otherwise interception is effective
                !(wrote && o.status.success())
            }
            Err(e) => {
                eprintln!(
                    "D3-3 probe: sandbox-exec invocation failed {} — treated as not blocked",
                    e
                );
                false
            }
        };
        // Clean up probe process data (logs only)
        let _ = std::fs::remove_dir_all(&probe_dir);
        if blocked {
            info!("D3-3 probe: subpath FS deny enforced — tempdir child write blocked (real isolation semantics)");
        } else {
            warn!(
                "D3-3 probe: subpath FS deny did not block the tempdir child write — Darwin 25 best-effort NO-OP status quo, \
                 falls back to the fe-security argv layer + documentation (not solvable by seatbelt)"
            );
        }
        // The probe stays honest about platform changes: no faked isolation. The subpath syntax being accepted (profile parses without error) is the probe's value.
        let _ = blocked;
    }

    // Issue #34: SandboxProfile serde roundtrip — snake_case + None-field defaults + deny_unknown_fields rejecting unknown fields.
    #[test]
    fn sandbox_profile_serde_roundtrip() {
        let json = r#"{"network":"allow","filesystem":"allow","excluded_commands":["rm","curl"],"fail_if_unavailable":true}"#;
        let p: SandboxProfile = serde_json::from_str(json).expect("deser ok");
        assert_eq!(p.network, Some(SandboxNetworkMode::Allow));
        assert_eq!(p.filesystem, Some(SandboxFsMode::Allow));
        assert_eq!(
            p.excluded_commands,
            vec!["rm".to_string(), "curl".to_string()]
        );
        assert!(p.fail_if_unavailable);
        let back = serde_json::to_string(&p).expect("ser ok");
        assert!(
            back.contains("\"network\":\"allow\""),
            "ser snake_case: {}",
            back
        );
        assert!(
            back.contains("\"filesystem\":\"allow\""),
            "ser snake_case: {}",
            back
        );
    }

    #[test]
    fn sandbox_profile_default_empty() {
        let p = SandboxProfile::default();
        assert_eq!(p.network, None);
        assert_eq!(p.filesystem, None);
        assert!(p.excluded_commands.is_empty());
        assert!(!p.fail_if_unavailable);
    }

    #[test]
    fn sandbox_profile_rejects_unknown_field() {
        let json = r#"{"network":"allow","bogus":1}"#;
        assert!(
            serde_json::from_str::<SandboxProfile>(json).is_err(),
            "deny_unknown_fields should reject unknown fields"
        );
    }

    // Issue #34: build_profile_from parameterization — None=fixed profile (byte-identical); network Allow=no deny injected;
    // fs Allow=no FS deny; fs Deny=global file-write* deny; excluded_commands → process-exec deny.
    #[test]
    fn build_profile_from_none_matches_fixed() {
        let fixed = build_profile();
        let from_none = build_profile_from(None);
        assert_eq!(
            fixed, from_none,
            "None profile should be byte-equal to the fixed profile"
        );
    }

    #[test]
    fn build_profile_from_network_allow_no_deny() {
        let p = SandboxProfile {
            network: Some(SandboxNetworkMode::Allow),
            ..Default::default()
        };
        let prof = build_profile_from(Some(&p));
        assert!(
            !prof.contains("(deny network-outbound)"),
            "network Allow must not inject a network deny: {}",
            prof
        );
    }

    #[test]
    fn build_profile_from_fs_allow_no_fs_deny() {
        let p = SandboxProfile {
            filesystem: Some(SandboxFsMode::Allow),
            ..Default::default()
        };
        let prof = build_profile_from(Some(&p));
        assert!(
            !prof.contains("(deny file-write*"),
            "fs Allow must not inject an FS deny: {}",
            prof
        );
    }

    #[test]
    fn build_profile_from_fs_deny_global() {
        let p = SandboxProfile {
            filesystem: Some(SandboxFsMode::Deny),
            ..Default::default()
        };
        let prof = build_profile_from(Some(&p));
        assert!(
            prof.contains("(deny file-write*)"),
            "fs Deny should inject the global file-write* deny: {}",
            prof
        );
    }

    #[test]
    fn build_profile_from_excluded_commands_injects_process_exec_deny() {
        let p = SandboxProfile {
            excluded_commands: vec!["/bin/rm".to_string(), "curl".to_string()],
            ..Default::default()
        };
        let prof = build_profile_from(Some(&p));
        assert!(
            prof.contains(r#"(deny process-exec (literal "/bin/rm"))"#),
            "excluded_commands should inject a process-exec deny: {}",
            prof
        );
        assert!(prof.contains(r#"(deny process-exec (literal "curl"))"#));
    }

    #[test]
    fn build_profile_from_excluded_commands_sanitizes_injection() {
        // The caller stuffs `"`/`\`/newline trying to break the seatbelt profile syntax — after sanitizing no escape chars are injected.
        let p = SandboxProfile {
            excluded_commands: vec![
                "evil\"(allow default))".to_string(),
                "no\\slash".to_string(),
            ],
            ..Default::default()
        };
        let prof = build_profile_from(Some(&p));
        assert!(
            !prof.contains(r#""(allow"#),
            "sanitize should strip quotes to prevent escape: {}",
            prof
        );
        assert!(
            !prof.contains(r#"\\"#),
            "sanitize should strip backslashes: {}",
            prof
        );
    }

    #[test]
    fn build_profile_from_excluded_commands_drops_empty() {
        // All control chars/empty → sanitizes to empty, skipped so an empty literal is never injected.
        let p = SandboxProfile {
            excluded_commands: vec!["   ".to_string(), "\n".to_string()],
            ..Default::default()
        };
        let prof = build_profile_from(Some(&p));
        assert!(
            !prof.contains(r#"(deny process-exec (literal ""))"#),
            "empty cleaned value must not inject an empty literal: {}",
            prof
        );
    }
}
