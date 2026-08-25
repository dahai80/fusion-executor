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
use tokio::process::Command;
use tracing::{info, warn};

/// 回滚管理器 — git CLI shell
pub struct RollbackManager;

impl RollbackManager {
    pub fn new() -> Self {
        info!("RollbackManager::new()");
        Self
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
        if !Self::is_repo(cwd).await {
            info!(cwd, "非 git repo, 跳过快照");
            return Ok(String::new());
        }
        let head = Self::git(cwd, &["rev-parse", "HEAD"]).await?;
        let stash = Self::git(cwd, &["stash", "create"]).await?;
        if stash.is_empty() {
            info!(cwd, %head, "无改动, 快照 = head 基线");
            return Ok(format!("head:{}", head));
        }
        let id = format!("stash:{},base:{}", stash, head);
        info!(cwd, %id, "快照创建 = stash + 基线");
        Ok(id)
    }

    /// 解析 snapshot_id 为 (kind, stash_sha, baseline)
    /// kind: "head" | "stash"
    fn parse_snapshot(id: &str) -> Option<(&'static str, Option<&str>, Option<&str>)> {
        if let Some(rest) = id.strip_prefix("head:") {
            return Some(("head", None, Some(rest)));
        }
        if let Some(rest) = id.strip_prefix("stash:") {
            // stash:<SHA>,base:<HEAD>
            let (stash, base) = rest.split_once(",base:").unwrap_or((rest, ""));
            let base = if base.is_empty() { None } else { Some(base) };
            return Some(("stash", Some(stash), base));
        }
        None
    }

    /// 整体回滚 — 按 snapshot_id tag 分派
    /// head 基线: git reset --hard <baseline> (单步原子, C-RB-02)
    /// stash 快照: git reset --hard <baseline> + git stash apply <SHA> (C-RB-02, 恢复快照)
    /// ref 经 is_valid_ref 校验 (C-RB-03); 不用 -- (ref 位 -- 把 ref 当 pathspec → no-op)
    pub async fn rollback(&self, snapshot_id: &str, cwd: &str) -> Result<bool> {
        if !Self::is_repo(cwd).await {
            warn!(cwd, "非 git repo, 无法回滚");
            return Ok(false);
        }
        if snapshot_id.is_empty() {
            warn!(cwd, "空 snapshot_id, 仅 reset 工作区");
            // 无基线 → 仅丢弃工作区改动 (保守: 不 reset --hard HEAD 避误删已暂存)
            Self::git(cwd, &["checkout", "--", "."]).await?;
            return Ok(true);
        }
        let (kind, stash, base) = match Self::parse_snapshot(snapshot_id) {
            Some(v) => v,
            None => {
                warn!(%snapshot_id, cwd, "无法解析 snapshot_id, 跳过回滚");
                return Ok(false);
            }
        };
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
        let (k, s, b) = RollbackManager::parse_snapshot("head:abc123").unwrap();
        assert_eq!(k, "head");
        assert!(s.is_none());
        assert_eq!(b, Some("abc123"));
        let (k, s, b) = RollbackManager::parse_snapshot("stash:st1,base:he2").unwrap();
        assert_eq!(k, "stash");
        assert_eq!(s, Some("st1"));
        assert_eq!(b, Some("he2"));
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
}
