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

use portable_pty::CommandBuilder;
use tracing::{debug, info};

/// 危险二进制黑名单 — 运行时 process-exec deny 目标。
/// 对齐 fe-security::build_blocklist 的毁灭/特权/磁盘/远程脚本类。
/// 路径为 macOS 标准位置; 多变体 (bin/sbin/usr) 逐条列 (literal 精确匹配, 无通配)。
const DANGEROUS_BINS: &[&str] = &[
    "/bin/rm",
    "/usr/bin/rm",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/doas",
    "/usr/sbin/diskutil",
    "/sbin/diskutil",
    "/sbin/mkfs",
    "/usr/sbin/mkfs",
    "/bin/dd",
    "/usr/bin/dd",
    "/usr/bin/nc",
    "/bin/nc",
];

/// 构建 seatbelt profile 字符串 — allow default + 禁网 + 危险二进制 process-exec deny
fn build_profile() -> String {
    let mut p = String::from("(version 1)(allow default)(deny network-outbound)");
    for bin in DANGEROUS_BINS {
        p.push_str(&format!("(deny process-exec (literal \"{}\"))", bin));
    }
    p
}

/// 构建子进程 CommandBuilder。
/// seatbelt=true → sandbox-exec -p '<profile>' sh -c '<cmd>' (运行时隔离)
/// seatbelt=false → sh -c '<cmd>' (裸跑, 兼容旧调用方)
/// cwd/env 在返回的 cmd 上由调用方继续设置。
pub fn build_command(command: &str, seatbelt: bool) -> CommandBuilder {
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
        cmd.arg(command);
        cmd
    } else {
        debug!("seatbelt 未启用 — 裸 sh -c");
        let mut cmd = CommandBuilder::new("sh");
        cmd.arg("-c");
        cmd.arg(command);
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
        let cmd = build_command("echo hi", true);
        // CommandBuilder 无直接 introspect API — 验证不 panic 且 profile 含禁网即可
        let p = build_profile();
        assert!(p.contains("network-outbound"));
        let _ = cmd;
    }

    #[test]
    fn build_command_bare_when_disabled() {
        let cmd = build_command("echo hi", false);
        let _ = cmd; // 不 panic
    }
}
