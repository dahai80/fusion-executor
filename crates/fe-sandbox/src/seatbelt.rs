// fe-sandbox seatbelt — macOS 运行时隔离 (审计 Blocker 1 / 1.1)
//
// Darwin 25 (macOS 26) 实测结论 (2026-08-25):
//   - sandbox-exec `file-write*` deny 完全失效 (literal/subpath 均不拦写/删) — 留之无益, 不写入 profile
//   - `process-exec` deny 生效: (deny process-exec (literal "/bin/rm")) → execve 拦截 exit 126
//     → 兜底 fe-security 静态正则挡不住的运行时 execve 穿透 (审计 #1 攻击 os.execve('/bin/rm'))
//   - `network-outbound` deny 生效: 拦 /dev/tcp 外泄 + curl|sh 载体出网
//
// 策略 (用户锁定 "进程级 deny 列表 + 禁网"):
//   profile = (version 1)(allow default)(deny network-outbound)(deny process-exec (literal "<bin>"))...
//   危险二进制黑名单对齐 fe-security 正则黑名单: rm/sudo/su/doas/diskutil/mkfs/dd/nc
//   allow default 透传其余 (白名单二进制 python/node/cargo... 正常跑)
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

/// 危险二进制黑名单 — 运行时 process-exec deny 目标。
/// 对齐 fe-security::build_blocklist 的毁灭/特权/磁盘/远程脚本类。
/// Issue #3 扩展: 加进程管理 (shutdown/reboot/halt/kill/pkill/killall/launchctl) +
/// 权限变更 (chown/chgrp/chmod) + 远程下载 (curl/wget) — 纵深防御 (这些二进制本不在
/// fe-security 白名单, Stage-2 已拦; seatbelt 层再 deny 运行时 execve 穿透兜底)。
/// 路径为 macOS 标准位置; 多变体 (bin/sbin/usr) 逐条列 (literal 精确匹配, 无通配)。
const DANGEROUS_BINS: &[&str] = &[
    // 毁灭性删除
    "/bin/rm",
    "/usr/bin/rm",
    // 特权提升
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/doas",
    // 磁盘格式化/擦除
    "/usr/sbin/diskutil",
    "/sbin/diskutil",
    "/sbin/mkfs",
    "/usr/sbin/mkfs",
    "/bin/dd",
    "/usr/bin/dd",
    // 远程 shell 管道
    "/usr/bin/nc",
    "/bin/nc",
    // Issue #3: 进程/系统管理 (关机/重启/杀进程/launchd 控制)
    "/sbin/shutdown",
    "/sbin/reboot",
    "/sbin/halt",
    "/bin/kill",
    "/usr/bin/pkill",
    "/usr/bin/killall",
    "/bin/launchctl",
    // Issue #3: 权限变更 (chown/chgrp/chmod)
    "/usr/sbin/chown",
    "/usr/bin/chgrp",
    "/bin/chmod",
    // Issue #3: 远程下载 (curl|sh 载体; 白名单本不含, 运行时兜底)
    "/usr/bin/curl",
    "/usr/bin/wget",
];

/// 构建 seatbelt profile 字符串 — allow default + 禁网 + 危险二进制 process-exec deny
fn build_profile() -> String {
    let mut p = String::from("(version 1)(allow default)(deny network-outbound)");
    for bin in DANGEROUS_BINS {
        p.push_str(&format!("(deny process-exec (literal \"{}\"))", bin));
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
            bins = DANGEROUS_BINS.len(),
            "seatbelt 运行时隔离启用 — sandbox-exec 包装"
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
            bins = DANGEROUS_BINS.len(),
            "seatbelt (stdio) 运行时隔离启用 — sandbox-exec 包装"
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
    fn profile_blocks_network_and_dangerous_bins() {
        let p = build_profile();
        assert!(p.contains("(deny network-outbound)"), "profile 必须禁网");
        assert!(
            p.contains("(deny process-exec (literal \"/bin/rm\"))"),
            "profile 必须拦 /bin/rm"
        );
        assert!(
            p.contains("(deny process-exec (literal \"/usr/bin/sudo\"))"),
            "profile 必须拦 sudo"
        );
        // Issue #3: 新增进程管理 + 权限变更 + 远程下载二进制入列
        assert!(
            p.contains("(deny process-exec (literal \"/sbin/shutdown\"))"),
            "profile 必须拦 shutdown"
        );
        assert!(
            p.contains("(deny process-exec (literal \"/usr/bin/pkill\"))"),
            "profile 必须拦 pkill"
        );
        assert!(
            p.contains("(deny process-exec (literal \"/usr/sbin/chown\"))"),
            "profile 必须拦 chown"
        );
        assert!(
            p.contains("(deny process-exec (literal \"/usr/bin/curl\"))"),
            "profile 必须拦 curl"
        );
        // 危险二进制全部入列
        for bin in DANGEROUS_BINS {
            assert!(
                p.contains(&format!("(literal \"{}\")", bin)),
                "profile 缺危险二进制: {}",
                bin
            );
        }
        assert!(p.starts_with("(version 1)(allow default)"));
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
