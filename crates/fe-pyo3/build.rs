// C-OPS-06: injects git_sha + build_time into compile-time env vars at build time
// fe-pyo3 reads them at runtime via env!, then exposes them to Python __version__ + IPC health
// git_sha: `git rev-parse --short=8 HEAD` (no git or failure → "unknown", never blocks the build)
// build_time: the build machine's current UTC time (RFC3339), injected because Date::now is unavailable in workflows — fine here in the build script
use std::process::Command;

fn main() {
    // Rerun when HEAD changes (git_sha changes)
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../Cargo.toml");

    let git_sha = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=FE_GIT_SHA={}", git_sha);

    let build_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string());
    println!("cargo:rustc-env=FE_BUILD_TIME={}", build_time);
}
