// fe-rollback — Git 快照/回滚管理 (FR-04, caller-driven)
//
// git CLI shell (tokio::process::Command):
//   snapshot_create(cwd) → "head:<SHA>" (干净) 或 "stash:<SHA>,base:<HEAD>" (有改动)
//   rollback(snapshot_id, cwd) → 解析 tag + 校验 ref 格式:
//     head:<SHA>  → git reset --hard <baseline>  (单步, 原子; baseline 经格式校验)
//     stash:<SHA> → git reset --hard <baseline> + git stash apply <SHA>  (恢复快照)
//   rollback_file(path, cwd) → git checkout -- <path> (单文件; -- 隔离 pathspec)
// Executor 不自动回滚 — 调用方决定 (锁定决策)
// 非 git repo → snapshot_id 空, rollback no-op
//
// 修复 (审计 C-RB-01~03):
//   C-RB-02: head/stash 回滚先 reset --hard <baseline> 单步 (替代 checkout -- . + stash apply
//            两步半截态: checkout 丢全部改动后若 apply 失败 → 数据丢失). reset 清到基线,
//            apply 在干净工作区不冲突.
//   C-RB-03: ref (baseline/stash SHA) 用 is_valid_ref 格式校验防 flag 注入 (40-hex 或 "HEAD"),
//            非 "stash create" SHA 拒绝. **不用 --**: `git reset --hard -- <ref>` 把 ref 当
//            pathspec → no-op (实测); `--` 仅隔离 pathspec (rollback_file 的 <path>), ref 位不适用.
//   C-RB-01: "stash apply 永不 drop = 无界增长" — **对 `git stash create` 后端不成立**:
//            stash create 返回 dangling commit, 不入 stash reflog, stash list 不增长,
//            apply 也不入栈. 实测 5 轮 snapshot+rollback 后 stash list 仍空. dangling commit
//            由 git gc 回收. 故无需 drop (drop -- <sha> 实测报 "不是一个储藏引用").
//            不变量由 test_stash_list_stays_empty_across_rollback_cycles 守护.

use anyhow::{Context, Result};
use fe_security::SecurityGuard;
use fs2::FileExt;
use std::fs::OpenOptions;
use tokio::process::Command;
use tracing::{info, warn};

/// FNV-1a 64-bit (无外部 hash 依赖, 稳定跨节点)。repo 路径 → 16-hex 标识。
fn fnv1a_64(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

/// 仓库稳定标识 (审计 2.7c / Blocker 9): 跨节点 NFS 共享 cwd 时, 各节点看到的
/// `.git` 目录物理路径一致 → canonicalize 后 FNV 哈希一致。节点 A 快照含 repo:<hash>,
/// 节点 B 回滚前比对 — 不匹配则拒绝 (防盲回滚到错误内容)。无 .git / 解析失败 → ""。
async fn repo_id(cwd: &str) -> String {
    // git rev-parse --git-common-dir: 对 worktree 返公共 .git, 对 bare repo 返自身。
    // canonicalize 该路径 → NFS 各节点同物理路径得同哈希。
    let out = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--git-common-dir"])
        .output()
        .await;
    let git_dir = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => return String::new(),
    };
    if git_dir.is_empty() {
        return String::new();
    }
    // 相对路径 (worktree 内常见 "gitdir: ..." 或 ".git") → 以 cwd 为基解析
    let base = std::path::Path::new(cwd);
    let p = std::path::Path::new(&git_dir);
    let resolved = if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    };
    match std::fs::canonicalize(&resolved) {
        Ok(canonical) => fnv1a_64(&canonical.to_string_lossy()),
        Err(_) => fnv1a_64(&resolved.to_string_lossy()),
    }
}

/// 进程级锁 (审计 2.7a / Blocker 9): 同 cwd 的 snapshot_create/rollback 互斥,
/// 防 Agent A reset → Agent B reset(no-op) → A apply → B apply 双应用冲突。
/// BSD flock 关联 fd, drop File → close fd → 自动释放。锁文件 `<git_dir>/fe-rollback.lock`。
struct RepoLock {
    // 持 fd 即持锁 (同 fe-tools FileLock 模式); 字段不读, 存在 = 锁生命周期。
    #[allow(dead_code)]
    file: std::fs::File,
}

impl RepoLock {
    fn acquire(cwd: &str) -> Result<Self> {
        let git_dir = std::path::Path::new(cwd).join(".git");
        if !git_dir.exists() {
            // 非 worktree repo (bare) 或 .git 缺 — 锁无意义, 返空锁占位 (no-op)。
            // 调用方仅靠 is_repo 守卫; 此处不拦 (validate_cwd + is_repo 已前置于)。
            return Ok(RepoLock {
                file: OpenOptions::new()
                    .read(true)
                    .open("/dev/null")
                    .context("打开 /dev/null 占位锁失败")?,
            });
        }
        let lock_path = git_dir.join("fe-rollback.lock");
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&lock_path)
            .with_context(|| format!("打开回滚锁失败: {}", lock_path.display()))?;
        file.lock_exclusive()
            .with_context(|| format!("获取回滚锁失败 (另一回滚进行中): {}", lock_path.display()))?;
        info!(cwd, lock = %lock_path.display(), "回滚进程锁已获取");
        Ok(RepoLock { file })
    }
}

/// 回滚管理器 — git CLI shell
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

    /// cwd 校验 (审计 Blocker 4 / 1.3): 回滚路径接 fe-security
    /// 拒绝: 空 cwd / .. 组件 / 敏感路径 (/etc /System ~/.ssh ...)
    /// canonicalize 后再校验, 防符号链接旁路
    fn validate_cwd(&self, cwd: &str) -> Result<()> {
        if cwd.trim().is_empty() {
            warn!("空 cwd, 拒绝回滚 (防越权 reset)");
            anyhow::bail!("cwd 为空, 拒绝执行回滚操作");
        }
        if std::path::Path::new(cwd)
            .components()
            .any(|comp| comp == std::path::Component::ParentDir)
        {
            warn!(cwd, "cwd 含 .. 组件, 拒绝 (逃逸嫌疑)");
            anyhow::bail!("cwd 含 .. 组件, 拒绝: {}", cwd);
        }
        let v_lit = self.guard.validate_cwd(cwd);
        if !v_lit.allowed {
            let reason = v_lit.reason.unwrap_or_default();
            warn!(cwd, %reason, "cwd 字面量校验拦截");
            anyhow::bail!("cwd 校验失败: {}", reason);
        }
        if let Ok(canonical) = std::fs::canonicalize(cwd) {
            let v_can = self.guard.validate_cwd(&canonical.to_string_lossy());
            if !v_can.allowed {
                let reason = v_can.reason.unwrap_or_default();
                warn!(cwd = %canonical.display(), %reason, "cwd canonicalize 校验拦截 (符号链接旁路)");
                anyhow::bail!("cwd 校验失败 (符号链接解析): {}", reason);
            }
        }
        Ok(())
    }

    async fn git(cwd: &str, args: &[&str]) -> Result<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(cwd)
            .args(args)
            .output()
            .await
            .context("git 命令启动失败")?;
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            warn!(cwd, args = ?args, %stderr, "git 失败");
            anyhow::bail!("git 失败: {}", stderr);
        }
        Ok(stdout)
    }

    /// 判断 cwd 是否 git repo
    async fn is_repo(cwd: &str) -> bool {
        Command::new("git")
            .arg("-C")
            .arg(cwd)
            .args(["rev-parse", "--is-inside-work-tree"])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// ref 格式校验 — 防 flag 注入 (C-RB-03)
    /// 接受: "HEAD" 或 7..=40 位十六进制 SHA (git stash create / rev-parse 输出)
    /// 拒绝: "--foo" / 其他 (无法作 flag, 也不是合法 ref)
    fn is_valid_ref(s: &str) -> bool {
        if s == "HEAD" {
            return true;
        }
        let len = s.len();
        (7..=40).contains(&len) && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// 创建快照 — tag 前缀编码类型 + baseline, 单 string 透传 4 层
    /// 返回:
    ///   ""           非 git repo
    ///   "head:<SHA>" 工作区干净, 基线 = HEAD
    ///   "stash:<SHA>,base:<HEAD>" 有改动, stash SHA + 基线 HEAD (rollback 用 reset --hard <base>)
    pub async fn snapshot_create(&self, cwd: &str) -> Result<String> {
        self.validate_cwd(cwd)?;
        if !Self::is_repo(cwd).await {
            info!(cwd, "非 git repo, 跳过快照");
            return Ok(String::new());
        }
        // Blocker 9 (审计 2.7a): 进程级锁防并发双应用冲突。
        let _lock = RepoLock::acquire(cwd)?;
        let head = Self::git(cwd, &["rev-parse", "HEAD"]).await?;
        let stash = Self::git(cwd, &["stash", "create"]).await?;
        // Blocker 9 (审计 2.7c): repo:<hash> 标识 — 跨节点回滚前比对。
        let repo = repo_id(cwd).await;
        let repo_tag = if repo.is_empty() {
            String::new()
        } else {
            format!(",repo:{}", repo)
        };
        if stash.is_empty() {
            info!(cwd, %head, "无改动, 快照 = head 基线");
            return Ok(format!("head:{}{}", head, repo_tag));
        }
        let id = format!("stash:{},base:{}{}", stash, head, repo_tag);
        info!(cwd, %id, "快照创建 = stash + 基线 + repo 标识");
        Ok(id)
    }

    /// 从 "core[,repo:<hash>]" 分离 core 与 repo tag。
    /// repo:<hash> 仅出现在末尾 (snapshot_create 追加), 故 rsplit_once ",repo:" 安全。
    /// 返回 (core: &str, repo: Option<&str>); 无 repo tag → core=原串, repo=None。
    fn split_repo_tag(s: &str) -> (&str, Option<&str>) {
        match s.rsplit_once(",repo:") {
            Some((core, repo)) => (core, Some(repo)),
            None => (s, None),
        }
    }

    /// 解析 snapshot_id 为 (kind, stash_sha, baseline, repo_tag)
    /// kind: "head" | "stash"; repo_tag: Option<&str> (Blocker 9 新增, 可缺)
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

    /// 整体回滚 — 按 snapshot_id tag 分派
    /// head 基线: git reset --hard <baseline> (单步原子, C-RB-02)
    /// stash 快照: git reset --hard <baseline> + git stash apply <SHA> (C-RB-02, 恢复快照)
    /// ref 经 is_valid_ref 校验 (C-RB-03); 不用 -- (ref 位 -- 把 ref 当 pathspec → no-op)
    pub async fn rollback(&self, snapshot_id: &str, cwd: &str) -> Result<bool> {
        self.validate_cwd(cwd)?;
        if !Self::is_repo(cwd).await {
            warn!(cwd, "非 git repo, 无法回滚");
            return Ok(false);
        }
        // Blocker 9 (审计 2.7b): 空 snapshot_id — 旧版 checkout -- . 静默清空 WIP。
        // cwd 实是 repo (竞态: snapshot_create 返空因 git 临时不可用), 此处 fail-loud
        // 拒绝, 不丢用户工作。调用方应重试 snapshot_create 或显式决定。
        if snapshot_id.is_empty() {
            warn!(cwd, "空 snapshot_id, 拒绝回滚 (防静默清空 WIP, 审计 2.7b)");
            return Ok(false);
        }
        // Blocker 9 (审计 2.7a): 进程级锁防并发回滚双应用冲突。
        let _lock = RepoLock::acquire(cwd)?;
        let (kind, stash, base, repo_tag) = match Self::parse_snapshot(snapshot_id) {
            Some(v) => v,
            None => {
                warn!(%snapshot_id, cwd, "无法解析 snapshot_id, 跳过回滚");
                return Ok(false);
            }
        };
        // Blocker 9 (审计 2.7c): repo:<hash> 比对 — 快照含 repo 标识时, cwd 仓库哈希须匹配。
        // 不匹配 = 节点 A 快照传到节点 B / cwd 被换 → 拒绝 (防盲回滚到错误内容)。
        if let Some(expected) = repo_tag {
            let actual = repo_id(cwd).await;
            if actual.is_empty() {
                warn!(cwd, %expected, "cwd repo 标识不可解析, 拒绝 (无法验证跨节点一致性)");
                return Ok(false);
            }
            if actual != expected {
                warn!(cwd, %expected, %actual, "snapshot_id repo 标识不匹配 cwd, 拒绝 (跨节点防盲回滚)");
                return Ok(false);
            }
            info!(cwd, %expected, "repo 标识匹配, 允许回滚");
        }
        match kind {
            "head" => {
                // C-RB-02: 单步 reset --hard <baseline> (替代 checkout -- . + stash apply)
                let baseline = base.unwrap_or("HEAD");
                if !Self::is_valid_ref(baseline) {
                    warn!(cwd, %baseline, "baseline 非合法 ref, 拒绝 (C-RB-03 flag 注入)");
                    return Ok(false);
                }
                match Self::git(cwd, &["reset", "--hard", baseline]).await {
                    Ok(_) => {
                        info!(cwd, %baseline, "回滚成功 (head 基线, reset --hard)");
                        Ok(true)
                    }
                    Err(e) => {
                        warn!(cwd, %baseline, "reset --hard 失败: {}", e);
                        Ok(false)
                    }
                }
            }
            "stash" => {
                let stash_sha = stash.unwrap_or("");
                if stash_sha.is_empty() || !Self::is_valid_ref(stash_sha) {
                    warn!(cwd, %stash_sha, "stash SHA 非合法 ref, 拒绝 (C-RB-03)");
                    return Ok(false);
                }
                let baseline = base.unwrap_or("HEAD");
                if !Self::is_valid_ref(baseline) {
                    warn!(cwd, %baseline, "baseline 非合法 ref, 拒绝 (C-RB-03 flag 注入)");
                    return Ok(false);
                }
                // C-RB-02: 先 reset --hard <baseline> 清工作区到基线 (单步原子, 避半截态)
                // 然后 stash apply <stash> 恢复快照内容 (基线干净, apply 不冲突)
                if let Err(e) = Self::git(cwd, &["reset", "--hard", baseline]).await {
                    warn!(cwd, %baseline, "stash 回滚: reset --hard 失败: {}", e);
                    return Ok(false);
                }
                match Self::git(cwd, &["stash", "apply", stash_sha]).await {
                    Ok(_) => {
                        // C-RB-01: stash create 返回 dangling commit, 不入 stash list, 无需
                        // 也无法 drop (drop -- <sha> 报 "不是一个储藏引用"). 无界增长不发生,
                        // 由 test_stash_list_stays_empty_across_rollback_cycles 守护.
                        info!(cwd, %stash_sha, "回滚成功 (reset --hard + stash apply)");
                        Ok(true)
                    }
                    Err(e) => {
                        warn!(cwd, %stash_sha, "stash apply 失败 (已 reset --hard): {}", e);
                        Ok(false)
                    }
                }
            }
            _ => {
                warn!(%kind, cwd, "未知快照类型, 跳过");
                Ok(false)
            }
        }
    }

    /// 单文件回滚 — git checkout -- <path> (PRD "单文件 checkout")
    /// C-RB-03: -- 隔离 pathspec (path 形如 --foo 不被当 flag; path 是 pathspec 位, -- 正确)
    pub async fn rollback_file(&self, path: &str, cwd: &str) -> Result<bool> {
        self.validate_cwd(cwd)?;
        if !Self::is_repo(cwd).await {
            warn!(cwd, "非 git repo, 无法回滚单文件");
            return Ok(false);
        }
        match Self::git(cwd, &["checkout", "--", path]).await {
            Ok(_) => {
                info!(cwd, %path, "单文件回滚成功");
                Ok(true)
            }
            Err(e) => {
                warn!(cwd, %path, "单文件回滚失败: {}", e);
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
        // git init + 首次提交 (配置 user 绕开 CI 无全局 config)
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
        // 写文件并提交基线
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
        // 搞坏文件 → 快照
        fs::write(dir.join("app.py"), "BROKEN\n").unwrap();
        let snap = mgr.snapshot_create(cwd).await.unwrap();
        assert!(!snap.is_empty(), "快照 id 非空: {}", snap);

        // 进一步破坏 → 回滚到快照
        fs::write(dir.join("app.py"), "WORSE\n").unwrap();
        let ok = mgr.rollback(&snap, cwd).await.unwrap();
        assert!(ok, "回滚成功");
        let restored = fs::read_to_string(dir.join("app.py")).unwrap();
        assert_eq!(restored, "BROKEN\n", "回滚到快照内容");
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

        // 改两文件, 单文件回滚 a.py
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
            "a.py 已恢复"
        );
        assert_eq!(
            fs::read_to_string(dir.join("b.py")).unwrap(),
            "B2\n",
            "b.py 未动"
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
        assert!(snap.is_empty(), "非 repo 快照为空");
        let _ = fs::remove_dir_all(&dir);
    }

    // ── T5 新增: C-RB-01/02/03 回归 ──

    // C-RB-01: stash create 返回 dangling commit, 多轮回滚 stash list 不增长
    // (审计原判 "apply 永不 drop = 无界增长" 对 stash create 后端不成立, 此测试守护不变量)
    #[tokio::test]
    async fn test_stash_list_stays_empty_across_rollback_cycles() {
        let dir = tmp_repo("grow");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        // 5 轮: 改动 → 快照 → 破坏 → 回滚
        for i in 0..5 {
            fs::write(dir.join("app.py"), format!("BROKEN{}\n", i)).unwrap();
            let snap = mgr.snapshot_create(cwd).await.unwrap();
            assert!(
                snap.starts_with("stash:"),
                "轮 {} 应 stash 前缀: {}",
                i,
                snap
            );
            fs::write(dir.join("app.py"), format!("WORSE{}\n", i)).unwrap();
            assert!(mgr.rollback(&snap, cwd).await.unwrap(), "轮 {} 回滚成功", i);
        }
        // C-RB-01 不变量: stash list 仍空 (dangling commit 不入栈)
        let list = git_list_stash(cwd).await;
        assert!(
            list.is_empty(),
            "5 轮后 stash list 应空 (无界增长未发生): {}",
            list
        );
        // 末轮回滚到第 5 个快照 (BROKEN4)
        assert_eq!(fs::read_to_string(dir.join("app.py")).unwrap(), "BROKEN4\n");
        let _ = fs::remove_dir_all(&dir);
    }

    // C-RB-02: head 基线 (工作区干净) rollback 用 reset --hard 单步恢复
    #[tokio::test]
    async fn rollback_head_baseline_resets_hard() {
        let dir = tmp_repo("head");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        // 工作区干净 → head 快照
        let snap = mgr.snapshot_create(cwd).await.unwrap();
        assert!(snap.starts_with("head:"), "干净应 head 前缀: {}", snap);
        // 新提交 (基线前进)
        fs::write(dir.join("app.py"), "v2\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "v2");
        // 回滚到 head 基线 (v1)
        let ok = mgr.rollback(&snap, cwd).await.unwrap();
        assert!(ok, "head 基线回滚成功");
        assert_eq!(
            fs::read_to_string(dir.join("app.py")).unwrap(),
            "v1\n",
            "恢复到基线 v1"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // C-RB-03: flag-like ref 被拒 (is_valid_ref 校验, 非注入)
    #[tokio::test]
    async fn rollback_rejects_flaglike_snapshot_id() {
        let dir = tmp_repo("flag");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        // --foo 非 head:/stash: 前缀 → parse_snapshot 返回 None → 安全跳过 (ok=false)
        assert!(
            !mgr.rollback("--foo", cwd).await.unwrap(),
            "flag-like snapshot_id 应被拒"
        );
        // head:--foo → parse 成功但 is_valid_ref 拒 baseline → ok=false
        assert!(
            !mgr.rollback("head:--foo", cwd).await.unwrap(),
            "head:--foo baseline 非合法 ref 应拒"
        );
        // 文件未动
        assert_eq!(fs::read_to_string(dir.join("app.py")).unwrap(), "v1\n");
        let _ = fs::remove_dir_all(&dir);
    }

    // parse_snapshot + is_valid_ref 单元
    #[test]
    fn parse_snapshot_and_ref_validation() {
        let (k, s, b, repo) = RollbackManager::parse_snapshot("head:abc123").unwrap();
        assert_eq!(k, "head");
        assert!(s.is_none());
        assert_eq!(b, Some("abc123"));
        assert!(repo.is_none(), "无 repo 标识应 None");
        let (k, s, b, repo) = RollbackManager::parse_snapshot("stash:st1,base:he2").unwrap();
        assert_eq!(k, "stash");
        assert_eq!(s, Some("st1"));
        assert_eq!(b, Some("he2"));
        assert!(repo.is_none());
        // Blocker 9: 含 repo:<hash> 四元组
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
        assert!(!RollbackManager::is_valid_ref("abc")); // 太短 (<7)
        assert!(!RollbackManager::is_valid_ref(
            "80a4c2f3fdf95dee67374b50a2c5aaf8cf9ac15f1234"
        )); // 太长 (>40)
        assert!(!RollbackManager::is_valid_ref("gggggggggg")); // 非十六进制
    }

    // 辅助
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
        // 走 git() 但允许非零退出 (无 stash 时 git stash list 退出 0 但空)
        RollbackManager::git(cwd, &["stash", "list"])
            .await
            .unwrap_or_default()
    }

    // ── Blocker 4 (审计 1.3): 回滚路径接 fe-security ──

    #[tokio::test]
    async fn snapshot_rejects_empty_cwd() {
        let mgr = RollbackManager::new();
        let err = mgr.snapshot_create("").await.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("空"), "空 cwd 应拒: {}", msg);
    }

    #[tokio::test]
    async fn snapshot_rejects_dotdot_cwd() {
        let mgr = RollbackManager::new();
        let err = mgr.snapshot_create("/tmp/foo/../bar").await.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains(".."), "含 .. 的 cwd 应拒: {}", msg);
    }

    #[tokio::test]
    async fn snapshot_rejects_sensitive_cwd() {
        let mgr = RollbackManager::new();
        let err = mgr.snapshot_create("/etc").await.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("敏感"), "敏感路径 /etc 应拒: {}", msg);
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
        // /etc → validate_cwd 先拒 (敏感路径), is_repo 不会执行, 返回 Err
        let err = mgr.rollback(&snap, "/etc").await.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("敏感"), "/etc 应被 validate_cwd 拒: {}", msg);
        // /tmp/正常 repo → validate 通过, 回滚成功
        assert!(
            mgr.rollback(&snap, cwd).await.unwrap(),
            "正常 repo 应可回滚"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rollback_file_rejects_empty_cwd() {
        let mgr = RollbackManager::new();
        let err = mgr.rollback_file("a.py", "").await.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("空"), "空 cwd 应拒: {}", msg);
    }

    // ── Blocker 9 (审计 2.7): 跨节点 registry + 进程锁 ──

    // 2.7b: 空 snapshot_id fail-loud (旧版 checkout -- . 静默清空 WIP)
    #[tokio::test]
    async fn rollback_rejects_empty_snapshot_id_fail_loud() {
        let dir = tmp_repo("empty-id");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        // WIP 改动待保留
        fs::write(dir.join("app.py"), "WIP-重要工作\n").unwrap();
        let mgr = RollbackManager::new();
        // 空 snapshot_id → 拒绝 (返 false), 不静默清空 WIP
        let ok = mgr.rollback("", cwd).await.unwrap();
        assert!(!ok, "空 snapshot_id 应拒绝回滚");
        // WIP 未被破坏
        assert_eq!(
            fs::read_to_string(dir.join("app.py")).unwrap(),
            "WIP-重要工作\n",
            "空 id 回滚拒绝时 WIP 应保留"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // 2.7c: repo:<hash> 标识不匹配 → 拒绝 (跨节点防盲回滚)
    // 模拟: snapshot 含 repo:<hash> 但 cwd 仓库的 hash 不同 (伪造 snapshot_id)
    #[tokio::test]
    async fn rollback_rejects_repo_tag_mismatch() {
        let dir = tmp_repo("repo-mismatch");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        // 真 snapshot (含正确 repo 标识)
        let snap = mgr.snapshot_create(cwd).await.unwrap();
        assert!(snap.contains(",repo:"), "snapshot 应含 repo 标识: {}", snap);
        // 正确 snapshot → 可回滚
        fs::write(dir.join("app.py"), "WORSE\n").unwrap();
        assert!(
            mgr.rollback(&snap, cwd).await.unwrap(),
            "正确 repo 标识应可回滚"
        );
        // 伪造: 替换 repo:<hash> 为假哈希 → 拒绝
        let fake = "head:deadbeefdeadbeef,repo:0000000000000000".to_string();
        fs::write(dir.join("app.py"), "WORSE2\n").unwrap();
        let ok = mgr.rollback(&fake, cwd).await.unwrap();
        assert!(!ok, "repo 标识不匹配应拒绝回滚");
        // 文件未被回滚 (仍是 WORSE2)
        assert_eq!(
            fs::read_to_string(dir.join("app.py")).unwrap(),
            "WORSE2\n",
            "repo 不匹配拒绝时工作区应不动"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // 2.7c: 无 repo 标识的旧 snapshot_id (向后兼容) → 放行 (不比对)
    #[tokio::test]
    async fn rollback_allows_legacy_snapshot_without_repo_tag() {
        let dir = tmp_repo("legacy");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        // 取真实 HEAD SHA 构造无 repo 标识的 legacy id
        let head = RollbackManager::git(cwd, &["rev-parse", "HEAD"])
            .await
            .unwrap();
        let legacy = format!("head:{}", head);
        assert!(
            !legacy.contains(",repo:"),
            "legacy id 无 repo 标识: {}",
            legacy
        );
        // 新提交前进基线
        fs::write(dir.join("app.py"), "v2\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "v2");
        // legacy id 无 repo 标识 → 放行 (向后兼容, 不比对)
        assert!(
            mgr.rollback(&legacy, cwd).await.unwrap(),
            "无 repo 标识的 legacy id 应放行"
        );
        assert_eq!(
            fs::read_to_string(dir.join("app.py")).unwrap(),
            "v1\n",
            "legacy 回滚恢复到基线 v1"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // 2.7a: 进程锁 — 并发 snapshot_create + rollback 串行化 (锁文件落盘)
    #[tokio::test]
    async fn process_lock_file_created_and_released() {
        let dir = tmp_repo("lock");
        let cwd = dir.to_str().unwrap();
        fs::write(dir.join("app.py"), "v1\n").unwrap();
        git_commit(&dir, &["add", "app.py"], "base");
        let mgr = RollbackManager::new();
        // snapshot_create 持锁期间锁文件应存在 (acquire 后立即检查)
        let snap = mgr.snapshot_create(cwd).await.unwrap();
        assert!(!snap.is_empty());
        // snapshot_create 返回后锁已释放 (drop), 但锁文件本身保留 (create=true)
        let lock_path = dir.join(".git").join("fe-rollback.lock");
        assert!(lock_path.exists(), "锁文件应保留在 .git/fe-rollback.lock");
        // rollback 应能再次获取锁 (前次已释放)
        fs::write(dir.join("app.py"), "WORSE\n").unwrap();
        assert!(
            mgr.rollback(&snap, cwd).await.unwrap(),
            "锁释放后 rollback 应成功"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
