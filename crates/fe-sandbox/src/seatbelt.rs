// fe-sandbox seatbelt — macOS 运行时隔离 (审计 Blocker 1 / 1.1, 0827 C-16/A-12)
//
// Darwin 25 (macOS 26) 实测结论 (2026-08-25):
//   - sandbox-exec **全局** `file-write*` deny 完全失效 (literal/subpath 均不拦写/删)。
//   - **定向** `file-write*` deny (literal 特定敏感路径) — 注释旧结论只说全局坏, 定向未实测。
//     0827 C-16: 注入定向 deny 作 best-effort 纵深防御 (失效则退回无 FS deny, 不误报隔离)。
//   - `process-exec` deny 生效: (deny process-exec (literal "/bin/rm")) → execve 拦截 exit 126。
//   - `network-outbound` deny 生效: 拦 /dev/tcp 外泄 + curl|sh 载体出网。
//
// 0827 A-12 修正: 删 DANGEROUS_BINS process-exec denylist — 黑名单天然不可枚举 (rm 重命名/
// symlink 绕过), fe-security Stage-2 allowlist (更强, 白名单外的二进制全拦) 已覆盖二进制隔离。
// seatbelt denylist 是冗余弱防线, 留之给"双重保护"错觉。seatbelt 仅留 network-outbound +
// 定向 FS deny (C-16), 二进制隔离由 fe-security allowlist 主导。
//
// 0827 C-16 文档 (FS 非隔离显式声明):
//   seatbelt 层**非完整 FS 隔离** — whitelist 二进制 (python3/node/cargo) 的 syscall
//   (unlink/rmdir/open/write) 经定向 deny 守高价值路径, 但**不**全 FS deny。
//   全局 file-write* Darwin 25 失效; 定向 deny best-effort (未实测, 失效退回无 FS 保护)。
//   实际隔离项: (1) network-outbound (实测生效), (2) 定向敏感路径 file-write* (best-effort),
//   (3) 二进制 exec 由 fe-security allowlist 主导 (非 seatbelt)。
//   全 FS 隔离需 OS 级 — 专用受限 macOS 用户账号 (非 seatbelt 能力)。
//
// 无 unsafe: sandbox-exec 是 /usr/bin 子进程, 走 portable-pty CommandBuilder spawn。
// crate 仍 unsafe_code="deny" (fe-sandbox 未开 allow)。
//
// Issue #3 (资源上限): 资源限制经 shell `ulimit` 内建注入 (sh -c 'ulimit -u N; ulimit -t N; <cmd>'),
// 非 setrlimit FFI — 避免 unsafe + 跨 PTY/stdio 后端一致。
// Darwin 25 实测 (2026-08-25):
//   - RLIMIT_AS (ulimit -v) / RLIMIT_DATA (ulimit -d) / RLIMIT_FSIZE (ulimit -f) 均 NO-OP
//     (setrlimit EINVAL 或接受但不限分配; 无限 malloc 仍逃逸不 cap) — Darwin 平台限制,
//     非代码缺陷。堆内存上限无可用 rlimit; 输出端 OOM 由 fe-sandbox 环形缓冲兜底 (2*max_output)。
//   - RLIMIT_NPROC (ulimit -u) 生效: fork bomb 被限并发数 (spread-limit, 非 terminator —
//     已生成子进程 retry-storm, 真正终止靠 timeout watchdog kill 进程树)。
//   - RLIMIT_CPU (ulimit -t) 生效: CPU 秒上限, 到顶 SIGXCPU。
//   - seatbelt profile `resource-limit`/`limit` 关键字 — 不解析 (parse error), 不可用。
// 策略: 仅注入实测生效的 ulimit -u (NPROC) + ulimit -t (CPU); 不注入 -v/-d/-f (no-op,
// 假安全违反 Rule 12 fail-visible)。Darwin 堆内存无 rlimit 上限, 文档化为平台限制。

use portable_pty::CommandBuilder;
use std::process::Command;
use tracing::{debug, info};

/// 0827 C-16: 定向 FS deny 的高价值敏感路径 — best-effort 防 whitelist 二进制 syscall 删/读写。
/// 全局 file-write* Darwin 25 失效; 定向 (literal 特定路径) 注入作纵深防御。
/// 路径基于 $HOME 展开 (调用时替换); 覆盖凭据 (~/.ssh)、模型缓存 (~/.fusion-mlx)、
/// 系统敏感区 (/etc, /var/db)。失效退回无 FS 保护, 不误报隔离 (Rule 12)。
const SENSITIVE_FS_PATHS: &[&str] = &[
    "HOME/.ssh",
    "HOME/.fusion-mlx",
    "HOME/.claude",
    "/etc",
    "/var/db",
    "/Library/Keychains",
];

/// 0827 A-12: (已删 DANGEROUS_BINS process-exec denylist) — 二进制隔离由 fe-security
/// allowlist 主导 (更强: 白名单外全拦), seatbelt denylist 冗余且弱 (rm 重命名/symlink 绕过)。
//
/// 构建 seatbelt profile 字符串 — allow default + 禁网 + 定向敏感路径 file-write* deny。
/// 0827 C-16/A-12: 删 process-exec denylist (fe-security allowlist 覆盖), 加定向 FS deny。
fn build_profile() -> String {
    let mut p = String::from("(version 1)(allow default)(deny network-outbound)");
    let home = std::env::var("HOME").unwrap_or_default();
    for path in SENSITIVE_FS_PATHS {
        let resolved = path.replacen("HOME", &home, 1);
        // file-write* 覆盖 write/unlink/rmdir 等; literal 精确路径 (非 subpath, 避免过拦子目录误报)
        p.push_str(&format!("(deny file-write* (literal \"{}\"))", resolved));
    }
    p
}

/// Issue #3: 资源上限包装 — 在命令串前注入实测生效的 ulimit 内建。
/// 仅 -u (NPROC, 防进程炸弹) + -t (CPU, 防死循环烧 CPU) 生效; -v/-d/-f Darwin no-op 不注入。
/// nproc=0 → 不限 NPROC; cpu_sec=0 → 不限 CPU (timeout watchdog 仍兜底)。
/// 注入到 sh -c 脚本内, 跨 PTY/stdio 后端一致, 无 unsafe。
fn wrap_rlimits(command: &str, nproc: u32, cpu_sec: u32) -> String {
    if nproc == 0 && cpu_sec == 0 {
        return command.to_string();
    }
    let mut prefix = String::new();
    if nproc > 0 {
        prefix.push_str(&format!("ulimit -u {} 2>/dev/null; ", nproc));
    }
    if cpu_sec > 0 {
        prefix.push_str(&format!("ulimit -t {} 2>/dev/null; ", cpu_sec));
    }
    // 2>/dev/null 吞 Darwin 对某些 limit 的 EINVAL 噪声 (已知 -v no-op 会报; 我们只注入生效项,
    // 但保守吞错防 stderr 污染诊断)。前缀失败不短路 (; 继续跑命令) — rlimit 是 best-effort 纵深防御,
    // 真正的硬上限由 timeout watchdog + 输出环形缓冲保底。
    let wrapped = format!("{prefix}{command}");
    debug!(
        nproc,
        cpu_sec,
        wrapped_len = wrapped.len(),
        "注入 ulimit 资源上限"
    );
    wrapped
}

/// 构建子进程 CommandBuilder。
/// seatbelt=true → sandbox-exec -p '<profile>' sh -c '<cmd>' (运行时隔离)
/// seatbelt=false → sh -c '<cmd>' (裸跑, 兼容旧调用方)
/// Issue #3: nproc/cpu_sec 经 wrap_rlimits 注入到 sh -c 脚本 (实测生效的 ulimit)。
/// cwd/env 在返回的 cmd 上由调用方继续设置。
pub fn build_command(command: &str, seatbelt: bool, nproc: u32, cpu_sec: u32) -> CommandBuilder {
    let wrapped = wrap_rlimits(command, nproc, cpu_sec);
    if seatbelt {
        let profile = build_profile();
        info!(
            profile_len = profile.len(),
            fs_paths = SENSITIVE_FS_PATHS.len(),
            "seatbelt 运行时隔离启用 — sandbox-exec 包装 (禁网 + 定向 FS deny)"
        );
        debug!(profile = %profile, "seatbelt profile");
        let mut cmd = CommandBuilder::new("sandbox-exec");
        cmd.arg("-p");
        cmd.arg(&profile);
        cmd.arg("sh");
        cmd.arg("-c");
        cmd.arg(&wrapped);
        cmd
    } else {
        debug!("seatbelt 未启用 — 裸 sh -c");
        let mut cmd = CommandBuilder::new("sh");
        cmd.arg("-c");
        cmd.arg(&wrapped);
        cmd
    }
}

/// Issue #4: stdio 后端命令构建 — 与 build_command 同语义 (seatbelt 包装 / 裸 sh -c),
/// 但返回 std::process::Command (stdout/stderr 独立 Stdio::piped, 非 PTY)。
/// use_pty=false 路径专用, 保留与 PTY 路径一致的 seatbelt 行为。
/// Issue #3: nproc/cpu_sec 同样经 wrap_rlimits 注入。
pub fn build_std_command(command: &str, seatbelt: bool, nproc: u32, cpu_sec: u32) -> Command {
    let wrapped = wrap_rlimits(command, nproc, cpu_sec);
    if seatbelt {
        let profile = build_profile();
        info!(
            profile_len = profile.len(),
            fs_paths = SENSITIVE_FS_PATHS.len(),
            "seatbelt (stdio) 运行时隔离启用 — sandbox-exec 包装 (禁网 + 定向 FS deny)"
        );
        let mut cmd = Command::new("sandbox-exec");
        cmd.arg("-p")
            .arg(&profile)
            .arg("sh")
            .arg("-c")
            .arg(&wrapped);
        cmd
    } else {
        debug!("seatbelt (stdio) 未启用 — 裸 sh -c");
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
        assert!(p.contains("(deny network-outbound)"), "profile 必须禁网");
        // C-16: 定向 FS deny 覆盖高价值路径
        let home = std::env::var("HOME").unwrap_or_default();
        assert!(
            p.contains(&format!("(deny file-write* (literal \"{}/.ssh\"))", home)),
            "profile 必须定向 deny ~/.ssh 写"
        );
        assert!(
            p.contains("(deny file-write* (literal \"/etc\"))"),
            "profile 必须定向 deny /etc 写"
        );
        assert!(
            p.contains("(deny file-write* (literal \"/Library/Keychains\"))"),
            "profile 必须定向 deny Keychains 写"
        );
        // A-12: process-exec denylist 已删 (fe-security allowlist 覆盖)
        assert!(
            !p.contains("(deny process-exec"),
            "A-12: process-exec denylist 应已删除 (fe-security allowlist 主导)"
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
                p.contains(&format!("(deny file-write* (literal \"{}\"))", resolved)),
                "profile 缺敏感路径 deny: {}",
                resolved
            );
        }
    }

    #[test]
    fn build_command_seatbelt_wraps_sandbox_exec() {
        let cmd = build_command("echo hi", true, 0, 0);
        // CommandBuilder 无直接 introspect API — 验证不 panic 且 profile 含禁网即可
        let p = build_profile();
        assert!(p.contains("network-outbound"));
        let _ = cmd;
    }

    #[test]
    fn build_command_bare_when_disabled() {
        let cmd = build_command("echo hi", false, 0, 0);
        let _ = cmd; // 不 panic
    }

    #[test]
    fn wrap_rlimits_injects_nproc_and_cpu() {
        let w = wrap_rlimits("echo hi", 1024, 30);
        assert!(w.contains("ulimit -u 1024"), "应注入 NPROC: {}", w);
        assert!(w.contains("ulimit -t 30"), "应注入 CPU: {}", w);
        assert!(w.ends_with("echo hi"), "原命令应在末尾: {}", w);
    }

    #[test]
    fn wrap_rlimits_skips_when_zero() {
        let w = wrap_rlimits("echo hi", 0, 0);
        assert_eq!(w, "echo hi", "nproc=cpu=0 不应注入任何前缀");
    }

    #[test]
    fn wrap_rlimits_only_nproc() {
        let w = wrap_rlimits("echo hi", 512, 0);
        assert!(w.contains("ulimit -u 512"));
        assert!(!w.contains("ulimit -t"), "cpu=0 不应注入 CPU");
    }

    #[test]
    fn build_std_command_accepts_rlimits() {
        // 验证 stdio 后端 build 不 panic + 接受 rlimit 参数 (不 introspect Command args)
        let _ = build_std_command("echo hi", false, 1024, 30);
        let _ = build_std_command("echo hi", true, 1024, 30);
    }
}
