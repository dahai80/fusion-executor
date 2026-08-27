// C-OPS-06: 构建期注入 git_sha + build_time 到编译环境变量
// 供 fe-pyo3 运行时经 env! 读取, 再经 PyO3 暴露给 Python __version__ + IPC health
// git_sha: `git rev-parse --short=8 HEAD` (无 git 或失败 → "unknown", 不阻断构建)
// build_time: 编译机当前 UTC 时间 (RFC3339), 注入因 Date::now 在 workflow 不可用 — 此处构建脚本正常
use std::process::Command;

fn main() {
    // 重跑若 HEAD 变 (git_sha 变)
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
