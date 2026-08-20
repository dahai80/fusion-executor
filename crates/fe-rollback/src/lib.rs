// fe-rollback — Git 快照/回滚管理 (FR-04, caller-driven)
//
// git CLI shell (tokio::process::Command):
//   snapshot_create(cwd) → git stash create → SHA (空则 rev-parse HEAD)
//   rollback(snapshot_id, cwd) → git checkout -- . && git stash apply <id>
//   rollback_file(path, cwd) → git checkout -- <path> (单文件, 不破坏其他模块)
// Executor 不自动回滚 — 调用方决定 (锁定决策)
// 非 git repo → snapshot_id 空, rollback no-op

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

    /// 创建快照 — git stash create 返回 stash SHA; 无改动则返回 HEAD SHA
    pub async fn snapshot_create(&self, cwd: &str) -> Result<String> {
        if !Self::is_repo(cwd).await {
            info!(cwd, "非 git repo, 跳过快照");
            return Ok(String::new());
        }
        let stash = Self::git(cwd, &["stash", "create"]).await?;
        if stash.is_empty() {
            let head = Self::git(cwd, &["rev-parse", "HEAD"]).await?;
            info!(cwd, %head, "无改动, 快照 = HEAD");
            return Ok(head);
        }
        info!(cwd, %stash, "快照创建 = stash SHA");
        Ok(stash)
    }

    /// 整体回滚 — checkout 工作区 + 应用快照
    pub async fn rollback(&self, snapshot_id: &str, cwd: &str) -> Result<bool> {
        if !Self::is_repo(cwd).await {
            warn!(cwd, "非 git repo, 无法回滚");
            return Ok(false);
        }
        if snapshot_id.is_empty() {
            warn!(cwd, "空 snapshot_id, 仅 checkout 工作区");
            Self::git(cwd, &["checkout", "--", "."]).await?;
            return Ok(true);
        }
        Self::git(cwd, &["checkout", "--", "."]).await?;
        match Self::git(cwd, &["stash", "apply", snapshot_id]).await {
            Ok(_) => {
                info!(cwd, %snapshot_id, "回滚成功");
                Ok(true)
            }
            Err(e) => {
                warn!(cwd, %snapshot_id, "stash apply 失败: {}", e);
                Ok(false)
            }
        }
    }

    /// 单文件回滚 — git checkout -- <path> (PRD "单文件 checkout")
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
}
