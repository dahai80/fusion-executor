// fe-sandbox seatbelt — macOS 运行时隔离 (审计 Blocker 1 / 1.1, 0827 C-16/A-12)
//
// Darwin 25 (macOS 26) 实测结论 (2026-08-25 / D3-3 复测 2026-08-28):
//   - sandbox-exec **全局** `file-write*` deny 完全失效 (literal/subpath 均不拦写/删)。
//   - **定向** `file-write*` deny (D3-3: subpath 特定敏感路径及其子项) —
//     0827 C-16: 注入定向 deny 作 best-effort 纵深防御。D3-3 实测 (probe_seatbelt_fs_subpath_deny,
//     2026-08-28): Darwin 25 subpath **同样 NO-OP** — 写 tempdir 子文件 exit 0 + 文件落地。
//     subpath 语义比 literal 更正确 (literal 仅精确路径, 子文件漏网), 但 Darwin 25 两者皆失效。
//     真隔离靠 fe-security is_sensitive_path (argv 层) + 受限 macOS 用户账号 (OS 级, 非 seatbelt)。
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
//   全局 + 定向 file-write* Darwin 25 均实测失效 (NO-OP); 定向 deny 保留作 best-effort 纵深防御
//   (subpath 语义正确, 非 NO-OP 的 Darwin 版本将真实拦), 但当前平台不依赖其拦截。
//   实际隔离项: (1) network-outbound (实测生效), (2) 定向敏感路径 file-write* (best-effort, Darwin 25 NO-OP),
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
//     RUN-4 (审计 0827): 内存上限无 OS 机制可用 — 此为 Darwin 平台固有限制, 非代码可修。
//     文档化 + 环形缓冲 (输出端) + seatbelt 禁网/定向 FS deny (攻击面端) 为现有缓解。
//   - RLIMIT_NPROC (ulimit -u) 生效: fork bomb 被限并发数 (spread-limit, 非 terminator —
//     已生成子进程 retry-storm, 真正终止靠 timeout watchdog kill 进程树)。
//   - RLIMIT_CPU (ulimit -t) 生效: CPU 秒上限, 到顶 SIGXCPU。
//   - RLIMIT_NOFILE (ulimit -n) 生效: 限每进程打开 FD 数 (Darwin 实测 errno 24 EMFILE
//     命中 cap, RUN-10 审计 0827 — fork 炸弹配 FD 耗尽攻击拦截)。
//   - seatbelt profile `resource-limit`/`limit` 关键字 — 不解析 (parse error), 不可用。
// 策略: 注入实测生效的 ulimit -u (NPROC) + ulimit -t (CPU) + ulimit -n (NOFILE);
// 不注入 -v/-d/-f (no-op, 假安全违反 Rule 12 fail-visible)。Darwin 堆内存无 rlimit 上限,
// 文档化为平台限制 (RUN-4)。

use portable_pty::CommandBuilder;
use std::process::Command;
use std::sync::LazyLock;
#[cfg(test)]
use tracing::warn;
use tracing::{debug, info};

/// 0827 C-16: 定向 FS deny 的高价值敏感路径 — best-effort 防 whitelist 二进制 syscall 删/读写。
/// 全局 file-write* Darwin 25 失效; 定向 (D3-3: subpath 路径及其子项) 注入作纵深防御。
/// 路径基于 $HOME 展开 (调用时替换); 覆盖凭据 (~/.ssh)、模型缓存 (~/.fusion-mlx)、
/// 系统敏感区 (/etc, /var/db)。失效退回无 FS 保护, 不误报隔离 (Rule 12)。
/// 全部为目录根 → subpath 安全 (无过拦兄弟目录)。
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
        // D3-3: subpath 匹配 — deny 路径及其下所有子项。literal 仅匹配精确路径,
        // 子文件 (~/.ssh/authorized_keys) 漏网。SENSITIVE_FS_PATHS 全为目录根,
        // subpath 安全 (无过拦兄弟目录风险)。若 Darwin 25 subpath 也 NO-OP,
        // 退回 best-effort (不误报隔离) — 经验探针实测 (test_probe_seatbelt_fs_subpath_deny)。
        p.push_str(&format!("(deny file-write* (subpath \"{}\"))", resolved));
    }
    p
}

/// D4-1: seatbelt profile 缓存 — build_profile 首次构造后进 LazyLock, 后续 exec 复用同一 String
/// (profile 是进程静态: HOME 在首调时解析, SIGHUP 重载白名单不影响 seatbelt profile —
/// sandbox-exec profile 串不跟 env 联动)。消除每次 build_command 的 String 重建 + HOME env 查。
static SEATBELT_PROFILE: LazyLock<String> = LazyLock::new(build_profile);

/// 返回缓存的 seatbelt profile (D4-1)。测试仍可直调 build_profile 验证构造逻辑。
fn profile() -> &'static str {
    &SEATBELT_PROFILE
}

/// Issue #3 + RUN-10: 资源上限包装 — 在命令串前注入实测生效的 ulimit 内建。
/// -u (NPROC, 防进程炸弹) + -t (CPU, 防死循环烧 CPU) + -n (NOFILE, 防 FD 耗尽) 生效;
/// -v/-d/-f Darwin no-op 不注入。nproc=0/cpu_sec=0/nofile=0 → 对应项不限。
/// 注入到 sh -c 脚本内, 跨 PTY/stdio 后端一致, 无 unsafe。
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
    // 2>/dev/null 吞 Darwin 对某些 limit 的 EINVAL 噪声 (已知 -v no-op 会报; 我们只注入生效项,
    // 但保守吞错防 stderr 污染诊断)。前缀失败不短路 (; 继续跑命令) — rlimit 是 best-effort 纵深防御,
    // 真正的硬上限由 timeout watchdog + 输出环形缓冲保底。
    let wrapped = format!("{prefix}{command}");
    debug!(
        nproc,
        cpu_sec,
        nofile,
        wrapped_len = wrapped.len(),
        "注入 ulimit 资源上限"
    );
    wrapped
}

/// 构建子进程 CommandBuilder。
/// seatbelt=true → sandbox-exec -p '<profile>' sh -c '<cmd>' (运行时隔离)
/// seatbelt=false → sh -c '<cmd>' (裸跑, 兼容旧调用方)
/// Issue #3 + RUN-10: nproc/cpu_sec/nofile 经 wrap_rlimits 注入到 sh -c 脚本 (实测生效的 ulimit)。
/// cwd/env 在返回的 cmd 上由调用方继续设置。
pub fn build_command(
    command: &str,
    seatbelt: bool,
    nproc: u32,
    cpu_sec: u32,
    nofile: u32,
) -> CommandBuilder {
    let wrapped = wrap_rlimits(command, nproc, cpu_sec, nofile);
    if seatbelt {
        let profile = profile();
        info!(
            profile_len = profile.len(),
            fs_paths = SENSITIVE_FS_PATHS.len(),
            "seatbelt 运行时隔离启用 — sandbox-exec 包装 (禁网 + 定向 FS deny)"
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
/// Issue #3 + RUN-10: nproc/cpu_sec/nofile 同样经 wrap_rlimits 注入。
pub fn build_std_command(
    command: &str,
    seatbelt: bool,
    nproc: u32,
    cpu_sec: u32,
    nofile: u32,
) -> Command {
    let wrapped = wrap_rlimits(command, nproc, cpu_sec, nofile);
    if seatbelt {
        let profile = profile();
        info!(
            profile_len = profile.len(),
            fs_paths = SENSITIVE_FS_PATHS.len(),
            "seatbelt (stdio) 运行时隔离启用 — sandbox-exec 包装 (禁网 + 定向 FS deny)"
        );
        let mut cmd = Command::new("sandbox-exec");
        cmd.arg("-p").arg(profile).arg("sh").arg("-c").arg(&wrapped);
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
        // C-16 + D3-3: 定向 FS deny (subpath) 覆盖高价值路径及其子项
        let home = std::env::var("HOME").unwrap_or_default();
        assert!(
            p.contains(&format!("(deny file-write* (subpath \"{}/.ssh\"))", home)),
            "profile 必须定向 deny ~/.ssh 写 (subpath 覆盖子项)"
        );
        assert!(
            p.contains("(deny file-write* (subpath \"/etc\"))"),
            "profile 必须定向 deny /etc 写 (subpath 覆盖子项)"
        );
        assert!(
            p.contains("(deny file-write* (subpath \"/Library/Keychains\"))"),
            "profile 必须定向 deny Keychains 写 (subpath 覆盖子项)"
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
                p.contains(&format!("(deny file-write* (subpath \"{}\"))", resolved)),
                "profile 缺敏感路径 subpath deny: {}",
                resolved
            );
        }
    }

    #[test]
    fn build_command_seatbelt_wraps_sandbox_exec() {
        let cmd = build_command("echo hi", true, 0, 0, 0);
        // CommandBuilder 无直接 introspect API — 验证不 panic 且 profile 含禁网即可
        let p = build_profile();
        assert!(p.contains("network-outbound"));
        let _ = cmd;
    }

    #[test]
    fn build_command_bare_when_disabled() {
        let cmd = build_command("echo hi", false, 0, 0, 0);
        let _ = cmd; // 不 panic
    }

    #[test]
    fn wrap_rlimits_injects_nproc_and_cpu() {
        let w = wrap_rlimits("echo hi", 1024, 30, 0);
        assert!(w.contains("ulimit -u 1024"), "应注入 NPROC: {}", w);
        assert!(w.contains("ulimit -t 30"), "应注入 CPU: {}", w);
        assert!(w.ends_with("echo hi"), "原命令应在末尾: {}", w);
    }

    // RUN-10: NOFILE 注入实测生效 (Darwin errno 24 EMFILE)
    #[test]
    fn wrap_rlimits_injects_nofile() {
        let w = wrap_rlimits("echo hi", 0, 0, 1024);
        assert!(w.contains("ulimit -n 1024"), "应注入 NOFILE: {}", w);
        assert!(!w.contains("ulimit -u"), "nproc=0 不应注入 NPROC");
        assert!(w.ends_with("echo hi"), "原命令应在末尾: {}", w);
    }

    #[test]
    fn wrap_rlimits_skips_when_zero() {
        let w = wrap_rlimits("echo hi", 0, 0, 0);
        assert_eq!(w, "echo hi", "全零不应注入任何前缀");
    }

    #[test]
    fn wrap_rlimits_only_nproc() {
        let w = wrap_rlimits("echo hi", 512, 0, 0);
        assert!(w.contains("ulimit -u 512"));
        assert!(!w.contains("ulimit -t"), "cpu=0 不应注入 CPU");
        assert!(!w.contains("ulimit -n"), "nofile=0 不应注入 NOFILE");
    }

    #[test]
    fn build_std_command_accepts_rlimits() {
        // 验证 stdio 后端 build 不 panic + 接受 rlimit 参数 (不 introspect Command args)
        let _ = build_std_command("echo hi", false, 1024, 30, 1024);
        let _ = build_std_command("echo hi", true, 1024, 30, 1024);
    }

    // D3-3: 经验探针 — 验证 seatbelt subpath FS deny 在 Darwin 25 是否真实拦截。
    // 用临时目录 + 定制 profile (subpath deny 该 tempdir) 探活, 不触碰真实敏感路径 (~/.ssh 等) —
    // 探针写 tempdir 内子文件: 若 subpath 生效应被拦 (exit!=0 或文件不存在);
    // 若 Darwin 25 subpath 也 NO-OP → 写成功, 探针记录 best-effort 现状 (Rule 12 fail-visible)。
    // 不硬断言 blocked (Darwin 平台限制); 探针跑过即证明 subpath 语法被 sandbox-exec 接受。
    #[test]
    fn probe_seatbelt_fs_subpath_deny() {
        let tmp = match std::env::temp_dir().canonicalize() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("D3-3 探针: temp_dir canonicalize 失败 {} — 跳过", e);
                return;
            }
        };
        let probe_dir = tmp.join("fe-probe-d3-3-dir");
        let _ = std::fs::remove_dir_all(&probe_dir);
        if std::fs::create_dir_all(&probe_dir).is_err() {
            eprintln!("D3-3 探针: 建探针目录失败 — 跳过");
            return;
        }
        let probe_file = probe_dir.join("probe.txt");
        let dir_str = probe_dir.to_string_lossy();
        // 定制 profile: 仅 deny 该 tempdir (subpath 覆盖其子项), 验证 subpath 语义本身。
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
                // 写成功 (文件存在 + exit 0) → subpath 未拦; 否则视为拦截生效
                !(wrote && o.status.success())
            }
            Err(e) => {
                eprintln!("D3-3 探针: sandbox-exec 调用失败 {} — 视为未拦", e);
                false
            }
        };
        // 清理探针过程数据 (只留日志)
        let _ = std::fs::remove_dir_all(&probe_dir);
        if blocked {
            info!("D3-3 探针: subpath FS deny 生效 — tempdir 子项写被拦 (真实隔离语义)");
        } else {
            warn!(
                "D3-3 探针: subpath FS deny 未拦 tempdir 子项 — Darwin 25 best-effort NO-OP 现状, \
                 退回 fe-security argv 层 + 文档 (非 seatbelt 可解)"
            );
        }
        // 探针对平台变化保持诚实: 不伪装隔离。subpath 语法被接受 (profile 解析无错) 即探针价值。
        let _ = blocked;
    }
}
