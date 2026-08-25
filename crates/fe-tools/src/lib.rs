// fe-tools — 原生文件工具 (PRD §Claude-SDK 对比: 本地化 BashTool/FileEdit/GlobTool/GrepTool)
//             + 外科补丁引擎 (PRD §DeepSeek 对比: Unified Diff 应用 + 函数级替换, 禁全文件重写)
//
// 工具:
//   file_edit(path, old, new, cwd)  — 唯一匹配精确替换, 原子写
//   glob(pattern, cwd)              — 递归 glob 模式匹配, 返回相对路径
//   grep(pattern, paths, cwd)       — 正则逐行搜索, 返回 file/line/content
//   apply_patch(diff, cwd)          — Unified Diff 解析 + 应用 (diffy), 禁全文件清空
//   replace_function(path, fn_name, new_body, cwd) — tree-sitter 函数定位, 字节切片替换
//
// 安全: 所有路径经 fe_security::SecurityGuard::validate_path 校验敏感路径 + 逃逸防护

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

use fe_security::SecurityGuard;

#[derive(Debug, Error)]
pub enum ToolsError {
    #[error("路径安全校验失败: {0}")]
    PathBlocked(String),
    #[error("文件未找到: {0}")]
    NotFound(String),
    #[error("old_string 非唯一匹配 (命中 {0} 处), 拒绝模糊编辑")]
    Ambiguous(usize),
    #[error("old_string 未匹配")]
    NoMatch,
    #[error("禁止全文件重写 (diff 清空原内容) — 仅允许外科补丁")]
    FullRewriteForbidden,
    #[error("函数 {0} 未找到")]
    FunctionNotFound(String),
    #[error("正则编译失败: {0}")]
    Regex(#[from] regex::Error),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

// ── 结果类型 (serde, 4 层透传) ──

/// file_edit / apply_patch / replace_function 通用结果
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EditResult {
    pub ok: bool,
    pub path: Option<String>,
    pub error: Option<String>,
    /// 匹配/替换的行数 (file_edit=替换次数, apply_patch=hunk 数, replace_function=1/0)
    pub matches: u32,
}

/// glob 单条命中
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobEntry {
    pub path: String,
    pub is_dir: bool,
}

/// grep 单条命中
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrepMatch {
    pub path: String,
    pub line_number: u32,
    pub content: String,
}

/// Tools 控制器 — 持有 SecurityGuard 复用, 无状态
pub struct Tools {
    guard: SecurityGuard,
}

impl Default for Tools {
    fn default() -> Self {
        Self::new()
    }
}

impl Tools {
    pub fn new() -> Self {
        info!("Tools::new() — 原生文件工具就绪 (复用 SecurityGuard)");
        Self {
            guard: SecurityGuard::new(),
        }
    }

    /// file_edit — 唯一匹配 old_string → new_string 精确替换, 原子写
    /// (PRD FileEdit: 拒绝模糊编辑, old 必须全文唯一)
    pub fn file_edit(
        &self,
        path: &str,
        old_string: &str,
        new_string: &str,
        cwd: Option<&str>,
    ) -> Result<EditResult> {
        let abs = guard_path(&self.guard, path, cwd).map_err(|e| anyhow::anyhow!(e))?;
        if !abs.exists() {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(format!("文件未找到: {}", path)),
                matches: 0,
            });
        }
        // L-TOOLS-02: 空 old_string 在空文件上 matches().count()==1 误判唯一 → 提前拒绝
        if old_string.is_empty() {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some("old_string 不能为空".to_string()),
                matches: 0,
            });
        }
        let content = std::fs::read_to_string(&abs)
            .with_context(|| format!("读取 {} 失败", abs.display()))?;
        let count = content.matches(old_string).count();
        if count == 0 {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some("old_string 未匹配".to_string()),
                matches: 0,
            });
        }
        if count > 1 {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(format!("old_string 非唯一匹配 (命中 {} 处)", count)),
                matches: count as u32,
            });
        }
        let updated = content.replacen(old_string, new_string, 1);
        atomic_write(&abs, &updated)?;
        info!(path = %abs.display(), "file_edit 替换成功");
        Ok(EditResult {
            ok: true,
            path: Some(path.to_string()),
            error: None,
            matches: 1,
        })
    }

    /// glob — 递归 glob 模式匹配 (glob crate), 返回相对 cwd 的路径 + is_dir
    /// pattern 例: "**/*.py", "src/*.rs"
    pub fn glob(&self, pattern: &str, cwd: Option<&str>) -> Result<Vec<GlobEntry>> {
        let base = cwd.unwrap_or(".");
        // 安全校验 cwd
        let cwd_v = self.guard.validate_cwd(base);
        if !cwd_v.allowed {
            return Err(anyhow::anyhow!(ToolsError::PathBlocked(
                cwd_v.reason.unwrap_or_else(|| "cwd 敏感".to_string()),
            )));
        }
        let cwd_abs = std::fs::canonicalize(base).unwrap_or_else(|_| PathBuf::from(base));
        let full_pattern = if Path::new(pattern).is_absolute() {
            pattern.to_string()
        } else {
            format!(
                "{}/{}",
                cwd_abs.to_string_lossy().trim_end_matches('/'),
                pattern
            )
        };
        debug!(pattern = %full_pattern, "glob 匹配中");
        let mut out = Vec::new();
        for entry in
            glob::glob(&full_pattern).map_err(|e| anyhow::anyhow!("glob 模式无效: {}", e))?
        {
            let p = match entry {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "glob 单项读取失败, 跳过");
                    continue;
                }
            };
            // L-TOOLS-01: 绝对路径模式 (如 /etc/**, ~/.ssh/*) 可越过 cwd 落敏感区
            // 每条命中取父目录经 validate_cwd 校验敏感前缀, 命中则跳过
            let check_target = if p.is_dir() {
                p.to_string_lossy().into_owned()
            } else {
                p.parent()
                    .map(|d| d.to_string_lossy().into_owned())
                    .unwrap_or_else(|| p.to_string_lossy().into_owned())
            };
            let v = self.guard.validate_cwd(&check_target);
            if !v.allowed {
                warn!(path = %p.display(), reason = v.reason, "glob 命中敏感路径, 跳过");
                continue;
            }
            let is_dir = p.is_dir();
            // 相对 cwd 的路径 (无 cwd 则相对 ".")
            let rel = p
                .strip_prefix(&cwd_abs)
                .map(|r| r.to_string_lossy().into_owned())
                .unwrap_or_else(|_| p.to_string_lossy().into_owned());
            out.push(GlobEntry { path: rel, is_dir });
        }
        info!(count = out.len(), "glob 完成");
        Ok(out)
    }

    /// grep — 正则逐行搜索, paths 为文件或目录列表 (目录则 walkdir 递归)
    /// 返回每条命中 (相对路径, 行号, 内容); 限制单文件 1000 行命中防爆
    pub fn grep(
        &self,
        pattern: &str,
        paths: &[String],
        cwd: Option<&str>,
    ) -> Result<Vec<GrepMatch>> {
        let re = Regex::new(pattern)?;
        let base = cwd.unwrap_or(".");
        let cwd_v = self.guard.validate_cwd(base);
        if !cwd_v.allowed {
            return Err(anyhow::anyhow!(ToolsError::PathBlocked(
                cwd_v.reason.unwrap_or_else(|| "cwd 敏感".to_string()),
            )));
        }
        let cwd_abs = std::fs::canonicalize(base).unwrap_or_else(|_| PathBuf::from(base));
        let mut out = Vec::new();
        for raw in paths {
            let abs = guard_path(&self.guard, raw, cwd).map_err(|e| anyhow::anyhow!(e))?;
            if abs.is_file() {
                grep_file(&abs, &abs, &cwd_abs, &re, &mut out)?;
            } else if abs.is_dir() {
                for ent in walkdir::WalkDir::new(&abs)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                {
                    let fp = ent.path();
                    // 跳过隐藏目录/文件 + 二进制嫌疑 (含 \0)
                    if fp
                        .file_name()
                        .map(|n| n.to_string_lossy().starts_with('.'))
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    grep_file(fp, &abs, &cwd_abs, &re, &mut out)?;
                }
            } else {
                warn!(path = %abs.display(), "grep 路径不存在, 跳过");
            }
        }
        info!(matches = out.len(), "grep 完成");
        Ok(out)
    }

    /// apply_patch — Unified Diff 解析 + 应用 (diffy crate)
    /// 禁全文件重写: 若 patch 的某 hunk 删除原文件全部行且无新增 → 拒绝 (FullRewriteForbidden)
    /// diff 文本含 --- /+++ 头, 多文件 patch: 逐文件解析, 仅应用 cwd 内文件
    pub fn apply_patch(&self, diff: &str, cwd: Option<&str>) -> Result<EditResult> {
        let base = cwd.unwrap_or(".");
        let cwd_v = self.guard.validate_cwd(base);
        if !cwd_v.allowed {
            return Err(anyhow::anyhow!(ToolsError::PathBlocked(
                cwd_v.reason.unwrap_or_else(|| "cwd 敏感".to_string()),
            )));
        }
        let cwd_abs = std::fs::canonicalize(base).unwrap_or_else(|_| PathBuf::from(base));
        let patch =
            diffy::Patch::from_str(diff).map_err(|e| anyhow::anyhow!("diff 解析失败: {}", e))?;

        // diffy apply 需原文件; 从 patch 头取目标路径
        // diffy Patch 无 path() — 用 modified()(+++ 头) 优先, 回退 original()(--- 头)
        let target = patch
            .modified()
            .or_else(|| patch.original())
            .map(|p| p.to_string())
            .unwrap_or_else(|| "patch-target".to_string());
        let target_path = target
            .strip_prefix("b/")
            .or_else(|| target.strip_prefix("a/"))
            .unwrap_or(&target)
            .to_string();
        let abs = guard_path(&self.guard, &target_path, cwd).map_err(|e| anyhow::anyhow!(e))?;
        if !abs.exists() {
            return Ok(EditResult {
                ok: false,
                path: Some(target_path.clone()),
                error: Some(format!("文件未找到: {}", target_path)),
                matches: 0,
            });
        }
        let original = std::fs::read_to_string(&abs)
            .with_context(|| format!("读取 {} 失败", abs.display()))?;

        // C-TOOLS-02: 旧启发式只拦 "删全部 + 新增 0"; "删全部 + 新增全部" 绕过
        // 新判据: hunk new 范围从 0 起, end >= 原文件行数 → 该 hunk 重写整文件 → 拒绝
        let original_lines = original.lines().count();

        // 多文件 patch: 逐 hunk-file 处理
        // C-TOOLS-02: 全文件重写判据 — hunk 删除行数 >= 原文件总行数 即重写整文件 → 拒绝
        // (外科补丁必留 context 行, removed < original_lines; 删全部无论新增 0 或 N 都是重写)
        // 旧版只拦 "删全部+新增0" 且依赖 new_range().start()==0 (diffy 1-based, 永假) → 漏判
        let mut total_hunks = 0u32;
        for (idx, pf) in patch.hunks().iter().enumerate() {
            let (_added, removed) = count_hunk_lines(pf);
            if removed > 0 && (removed as usize) >= original_lines {
                return Ok(EditResult {
                    ok: false,
                    path: Some(target_path.clone()),
                    error: Some(
                        "禁止全文件重写 (hunk 删除原文件全部行) — 仅允许外科补丁".to_string(),
                    ),
                    matches: idx as u32,
                });
            }
            total_hunks += 1;
        }

        let updated = diffy::apply(&original, &patch)
            .map_err(|e| anyhow::anyhow!("patch 应用失败: {}", e))?;
        // 安全校验: 确认输出文件仍 cwd 内 (防止 patch 改路径)
        if let Ok(canonical) = abs.canonicalize() {
            if !canonical.starts_with(&cwd_abs) {
                return Ok(EditResult {
                    ok: false,
                    path: Some(target_path),
                    error: Some("patch 目标逃逸 cwd".to_string()),
                    matches: total_hunks,
                });
            }
        }
        atomic_write(&abs, &updated)?;
        info!(path = %abs.display(), hunks = total_hunks, "apply_patch 成功");
        Ok(EditResult {
            ok: true,
            path: Some(target_path),
            error: None,
            matches: total_hunks,
        })
    }

    /// replace_function — tree-sitter 定位函数定义, 用 new_body 整体替换该函数
    /// (PRD §DeepSeek 外科补丁: 函数级替换, 避免全文件重写)
    /// new_body 为完整函数定义文本 (含签名 + 体), 替换原同函数名的定义
    /// 支持语言: py/js/ts/rs; 按扩展选 grammar
    pub fn replace_function(
        &self,
        path: &str,
        fn_name: &str,
        new_body: &str,
        cwd: Option<&str>,
    ) -> Result<EditResult> {
        let abs = guard_path(&self.guard, path, cwd).map_err(|e| anyhow::anyhow!(e))?;
        if !abs.exists() {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(format!("文件未找到: {}", path)),
                matches: 0,
            });
        }
        let content = std::fs::read_to_string(&abs)
            .with_context(|| format!("读取 {} 失败", abs.display()))?;
        let ext = abs.extension().and_then(|e| e.to_str()).unwrap_or("");
        let span = locate_function(&content, ext, fn_name)?;
        let span = match span {
            Some(s) => s,
            None => {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("函数 {} 未找到", fn_name)),
                    matches: 0,
                });
            }
        };
        // 字节切片替换 (tree-sitter 给字节范围, content 是 String 但通常 utf8 对齐)
        let mut updated = String::with_capacity(content.len() + new_body.len());
        updated.push_str(&content[..span.start]);
        updated.push_str(new_body);
        updated.push_str(&content[span.end..]);
        atomic_write(&abs, &updated)?;
        info!(path = %abs.display(), fn = fn_name, "replace_function 成功");
        Ok(EditResult {
            ok: true,
            path: Some(path.to_string()),
            error: None,
            matches: 1,
        })
    }

    // PLACEHOLDER: path helpers
}

/// 校验路径不落敏感区 + 不通过 .. 逃逸 cwd
/// (复用 fe_security::SecurityGuard 的敏感路径集, 经 validate_cwd 做前缀匹配)
fn guard_path(
    guard: &SecurityGuard,
    raw: &str,
    cwd: Option<&str>,
) -> std::result::Result<PathBuf, ToolsError> {
    let expanded = expand_tilde(raw);
    let p = Path::new(&expanded);
    // 绝对路径直接校验; 相对路径接 cwd 后校验
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        match cwd {
            Some(c) => Path::new(c).join(p),
            None => p.to_path_buf(),
        }
    };
    // 拒绝 .. 逃逸 (相对路径越过 cwd)
    // L-TOOLS-03: 旧版 canonicalize 失败则静默放行 (fail-open) — 中间目录缺失即绕过
    // 改 fail-closed: 路径含 .. 组件即拒绝 (不依赖 canonicalize 成功)
    if let Some(c) = cwd {
        let cwd_abs = std::fs::canonicalize(c).unwrap_or_else(|_| PathBuf::from(c));
        // 路径含 .. 组件 → 可能逃逸, 拒绝 (不论 canonicalize 成败)
        if abs
            .components()
            .any(|comp| comp == std::path::Component::ParentDir)
        {
            return Err(ToolsError::PathBlocked(format!(
                "路径含 .. 组件, 拒绝逃逸嫌疑: {} (cwd={})",
                raw, c
            )));
        }
        // 无 .. 组件: canonicalize 成功则校验 starts_with, 失败 (文件/目录尚不存在) 放行
        // (新文件在 cwd 内创建合法, canonicalize 失败不代表逃逸)
        if let Ok(canonical) = abs.canonicalize() {
            if !canonical.starts_with(&cwd_abs) {
                return Err(ToolsError::PathBlocked(format!(
                    "路径逃逸 cwd: {} (cwd={})",
                    raw, c
                )));
            }
        }
    }
    // 敏感路径校验 — 复用 validate_cwd 做目录前缀匹配 (对文件取父目录)
    let check_target = if abs.is_dir() {
        abs.to_string_lossy().into_owned()
    } else {
        abs.parent()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_else(|| abs.to_string_lossy().into_owned())
    };
    let v = guard.validate_cwd(&check_target);
    if !v.allowed {
        return Err(ToolsError::PathBlocked(
            v.reason.unwrap_or_else(|| "敏感路径".to_string()),
        ));
    }
    Ok(abs)
}

fn expand_tilde(path: &str) -> String {
    if path == "~" {
        std::env::var("HOME").unwrap_or_else(|_| "~".to_string())
    } else if let Some(rest) = path.strip_prefix("~/") {
        format!("{}/{}", std::env::var("HOME").unwrap_or_default(), rest)
    } else {
        path.to_string()
    }
}

/// 原子写 — NamedTempFile 随机名 + persist 原子 rename
/// C-TOOLS-01: 旧版用固定名 .fe-tmp-{pid} — 同进程并发写同目录互踩; 且 rename 到符号链接可被劫持
/// tempfile::NamedTempFile::new_in(dir) 随机名避并发互踩; .persist() 原子 rename (同 FS)
/// 跨 FS (EXDEV) 降级 std::fs::write+rename (非原子, 记 warn)
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("无父目录: {}", path.display()))?;
    // NamedTempFile 随机名, 写后 persist 原子 rename 到 path
    let tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("创建临时文件失败 (dir={})", dir.display()))?;
    std::fs::write(tmp.path(), content)
        .with_context(|| format!("写临时文件 {} 失败", tmp.path().display()))?;
    match tmp.persist(path) {
        Ok(_) => Ok(()),
        Err(e) => {
            // persist 失败常因 EXDEV (跨文件系统); 降级非原子写
            warn!(error = %e, target = %path.display(), "persist 失败, 降级 rename");
            // NamedTempFile 已 drop; 重新走 std 写 (非原子, 兜底)
            let fallback = dir.join(format!(".fe-tmp-fb-{}", std::process::id()));
            std::fs::write(&fallback, content)
                .with_context(|| format!("降级写 {} 失败", fallback.display()))?;
            std::fs::rename(&fallback, path).with_context(|| {
                format!(
                    "降级 rename {} -> {} 失败",
                    fallback.display(),
                    path.display()
                )
            })?;
            Ok(())
        }
    }
}

/// tree-sitter 按扩展选 grammar
fn parser_for_ext(ext: &str) -> Option<tree_sitter::Parser> {
    let mut p = tree_sitter::Parser::new();
    let lang: tree_sitter::Language = match ext {
        "py" => tree_sitter_python::LANGUAGE.into(),
        "js" => tree_sitter_javascript::LANGUAGE.into(),
        "ts" | "tsx" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "rs" => tree_sitter_rust::LANGUAGE.into(),
        _ => return None,
    };
    p.set_language(&lang).ok()?;
    Some(p)
}

/// 函数定义节点类型 — 按扩展映射 (py: function_definition, js/ts: function_declaration, rs: function_item)
fn function_node_kind(ext: &str) -> Option<&'static str> {
    match ext {
        "py" => Some("function_definition"),
        "js" | "ts" | "tsx" => Some("function_declaration"),
        "rs" => Some("function_item"),
        _ => None,
    }
}

/// 函数名字段名 — py: name, js/ts: name, rs: name
const NAME_FIELD: &str = "name";

/// 在源码中定位函数定义, 返回字节范围 (start, end)
fn locate_function(content: &str, ext: &str, fn_name: &str) -> Result<Option<ByteSpan>> {
    let kind = match function_node_kind(ext) {
        Some(k) => k,
        None => {
            // 无 grammar — 回退正则 (def/fn 签名行起, 到下一同缩进定义前)
            return Ok(locate_function_regex(content, ext, fn_name));
        }
    };
    let mut parser = match parser_for_ext(ext) {
        Some(p) => p,
        None => return Ok(locate_function_regex(content, ext, fn_name)),
    };
    let tree = parser
        .parse(content, None)
        .context("tree-sitter 解析失败")?;
    let root = tree.root_node();

    // tree-sitter 0.25 无 descendants() — 栈式先序遍历
    // Node 是 Copy; 每节点用独立 cursor 收集子节点到 Vec 后释放 cursor, 避免借用冲突
    let mut found: Option<ByteSpan> = None;
    let mut stack: Vec<tree_sitter::Node> = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            if let Some(name_node) = node.child_by_field_name(NAME_FIELD) {
                let name_text = name_node.utf8_text(content.as_bytes()).unwrap_or("");
                if name_text == fn_name {
                    found = Some(ByteSpan {
                        start: node.start_byte(),
                        end: node.end_byte(),
                    });
                    break;
                }
            }
        }
        // 收集子节点入栈 (逆序, 保证先序访问)
        let mut cursor = node.walk();
        let children: Vec<tree_sitter::Node> = node.children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    Ok(found)
}

/// 无 grammar 回退: 正则定位函数起止 (粗略, 限 def/fn/function 关键字)
fn locate_function_regex(content: &str, ext: &str, fn_name: &str) -> Option<ByteSpan> {
    let pat = match ext {
        "py" => format!(r"(?m)^[ \t]*def\s+{}\b", regex::escape(fn_name)),
        "js" | "ts" | "tsx" => format!(
            r"(?m)^[ \t]*(?:export\s+)?(?:async\s+)?function\s+{}\b",
            regex::escape(fn_name)
        ),
        "rs" => format!(
            r"(?m)^[ \t]*(?:pub\s+)?(?:async\s+)?fn\s+{}\b",
            regex::escape(fn_name)
        ),
        _ => return None,
    };
    let re = Regex::new(&pat).ok()?;
    let m = re.find(content)?;
    let start = m.start();
    // 结束: 下一个同缩进顶层定义, 或文件尾 (粗略)
    let after = &content[m.end()..];
    let indent = content[start..m.start() + 1].matches(' ').count();
    let _ = indent;
    // 找下一个非空同级或更低缩进的定义行
    let end = after
        .lines()
        .skip(1)
        .find(|l| {
            let trimmed = l.trim_start();
            !trimmed.is_empty()
                && (trimmed.starts_with("def ")
                    || trimmed.starts_with("fn ")
                    || trimmed.starts_with("function ")
                    || trimmed.starts_with("export "))
        })
        .map(|l| m.end() + after[..after.find(l).unwrap_or(after.len())].len())
        .unwrap_or(content.len());
    Some(ByteSpan { start, end })
}

#[derive(Debug, Clone, Copy)]
struct ByteSpan {
    start: usize,
    end: usize,
}

/// 统计 hunk 新增/删除行数 (diffy Line 是枚举: Context/Delete/Insert, 各持 &T)
fn count_hunk_lines(hunk: &diffy::Hunk<'_, str>) -> (u32, u32) {
    let mut added = 0u32;
    let mut removed = 0u32;
    for line in hunk.lines() {
        match line {
            diffy::Line::Insert(_) => added += 1,
            diffy::Line::Delete(_) => removed += 1,
            diffy::Line::Context(_) => {}
        }
    }
    (added, removed)
}

/// grep 单文件 — 正则逐行, 跳过二进制 (含 \0), 单文件限 1000 命中
/// P-SB-01: 旧版 std::fs::read 整文件入内存 — 超大文件 (GB 级) OOM
/// 改用 metadata 先查大小, 超 64MB 跳过 (grep 非二进制探测工具, 大文件该用专用索引)
const GREP_FILE_MAX_BYTES: u64 = 64 * 1024 * 1024;
fn grep_file(
    fp: &Path,
    root: &Path,
    cwd_abs: &Path,
    re: &Regex,
    out: &mut Vec<GrepMatch>,
) -> Result<()> {
    // P-SB-01: metadata 限大小, 超限跳过 (避 OOM)
    if let Ok(meta) = std::fs::metadata(fp) {
        if meta.len() > GREP_FILE_MAX_BYTES {
            warn!(path = %fp.display(), size = meta.len(), "grep 文件超 64MB 上限, 跳过");
            return Ok(());
        }
    }
    let bytes = match std::fs::read(fp) {
        Ok(b) => b,
        Err(e) => {
            debug!(path = %fp.display(), error = %e, "grep 读文件失败, 跳过");
            return Ok(());
        }
    };
    // 二进制嫌疑 → 跳过 (限前 8KB 探测, 避全扫描)
    let probe = &bytes[..bytes.len().min(8192)];
    if probe.contains(&0u8) {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&bytes);
    let rel = fp
        .strip_prefix(cwd_abs)
        .or_else(|_| fp.strip_prefix(root))
        .map(|r| r.to_string_lossy().into_owned())
        .unwrap_or_else(|_| fp.to_string_lossy().into_owned());
    let mut hits = 0u32;
    for (i, line) in text.lines().enumerate() {
        if re.is_match(line) {
            out.push(GrepMatch {
                path: rel.clone(),
                line_number: (i + 1) as u32,
                content: line.to_string(),
            });
            hits += 1;
            if hits >= 1000 {
                warn!(path = %fp.display(), "grep 单文件命中超 1000, 截断");
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── file_edit ──

    #[test]
    fn test_file_edit_unique_replace() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("app.py");
        std::fs::write(&fp, "x = 1\ny = 2\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools
            .file_edit("app.py", "x = 1", "x = 99", Some(&cwd))
            .unwrap();
        assert!(r.ok);
        assert_eq!(r.matches, 1);
        assert_eq!(std::fs::read_to_string(&fp).unwrap(), "x = 99\ny = 2\n");
    }

    #[test]
    fn test_file_edit_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("a.txt");
        std::fs::write(&fp, "hello\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools
            .file_edit("a.txt", "missing", "x", Some(&cwd))
            .unwrap();
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("未匹配"));
    }

    #[test]
    fn test_file_edit_ambiguous_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("a.txt");
        std::fs::write(&fp, "dup\ndup\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.file_edit("a.txt", "dup", "one", Some(&cwd)).unwrap();
        assert!(!r.ok);
        assert_eq!(r.matches, 2);
        // 内容未变
        assert_eq!(std::fs::read_to_string(&fp).unwrap(), "dup\ndup\n");
    }

    #[test]
    fn test_file_edit_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.file_edit("nope.txt", "a", "b", Some(&cwd)).unwrap();
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("未找到"));
    }

    // ── glob ──

    #[test]
    fn test_glob_python_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "").unwrap();
        std::fs::write(dir.path().join("b.py"), "").unwrap();
        std::fs::write(dir.path().join("c.txt"), "").unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub").join("d.py"), "").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let mut paths: Vec<String> = tools
            .glob("**/*.py", Some(&cwd))
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        paths.sort();
        assert_eq!(paths, vec!["a.py", "b.py", "sub/d.py"]);
    }

    // ── grep ──

    #[test]
    fn test_grep_matches_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "import os\nx = 1\nimport sys\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let ms = tools
            .grep(r"^import\s", &["a.py".to_string()], Some(&cwd))
            .unwrap();
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].line_number, 1);
        assert_eq!(ms[0].content, "import os");
        assert_eq!(ms[1].line_number, 3);
    }

    #[test]
    fn test_grep_dir_recursive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "TODO fix\n").unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub").join("b.py"), "TODO more\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let ms = tools.grep("TODO", &[".".to_string()], Some(&cwd)).unwrap();
        assert_eq!(ms.len(), 2);
    }

    // ── apply_patch ──

    #[test]
    fn test_apply_patch_simple() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("app.py");
        std::fs::write(&fp, "line1\nline2\nline3\n").unwrap();
        let diff = "\
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 line1
 line2
+line2b
 line3
";
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.apply_patch(diff, Some(&cwd)).unwrap();
        assert!(r.ok, "apply_patch 应成功: {:?}", r.error);
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            "line1\nline2\nline2b\nline3\n"
        );
    }

    #[test]
    fn test_apply_patch_target_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let diff = "\
--- a/missing.py
+++ b/missing.py
@@ -1,1 +1,1 @@
-old
+new
";
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.apply_patch(diff, Some(&cwd)).unwrap();
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("未找到"));
    }

    // ── replace_function ──

    #[test]
    fn test_replace_function_python() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("mod.py");
        std::fs::write(
            &fp,
            "def old():\n    return 1\n\ndef keep():\n    return 2\n",
        )
        .unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools
            .replace_function("mod.py", "old", "def old():\n    return 99\n", Some(&cwd))
            .unwrap();
        assert!(r.ok, "replace_function 应成功: {:?}", r.error);
        let after = std::fs::read_to_string(&fp).unwrap();
        assert!(after.contains("return 99"));
        assert!(after.contains("return 2"), "keep 函数应保留");
        assert!(!after.contains("return 1"), "旧函数体应被替换");
    }

    #[test]
    fn test_replace_function_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("mod.py");
        std::fs::write(&fp, "def keep():\n    return 2\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools
            .replace_function("mod.py", "ghost", "def ghost():\n    pass\n", Some(&cwd))
            .unwrap();
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("未找到"));
    }

    #[test]
    fn test_replace_function_rust() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("lib.rs");
        std::fs::write(
            &fp,
            "fn old() -> i32 {\n    1\n}\n\nfn keep() -> i32 {\n    2\n}\n",
        )
        .unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools
            .replace_function(
                "lib.rs",
                "old",
                "fn old() -> i32 {\n    99\n}\n",
                Some(&cwd),
            )
            .unwrap();
        assert!(r.ok, "replace_function rs 应成功: {:?}", r.error);
        let after = std::fs::read_to_string(&fp).unwrap();
        assert!(after.contains("99"));
        assert!(after.contains("fn keep"));
    }

    // ── guard_path 逃逸防护 ──

    #[test]
    fn test_guard_path_rejects_escape() {
        let dir = tempfile::tempdir().unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        // .. 逃逸到 cwd 之外 (目标不存在, canonicalize 失败则放行 — 这里造一个真实逃逸目标)
        let outside = tempfile::tempdir().unwrap();
        let escape_target = outside.path().join("evil.txt");
        std::fs::write(&escape_target, "x").unwrap();
        let rel = format!("{}/evil.txt", outside.path().to_string_lossy());
        let res = guard_path(&guard, &rel, Some(&cwd));
        assert!(res.is_err(), "绝对路径逃逸 cwd 应被拒");
    }

    // ── T4 新增: 6 修复回归 ──

    // L-TOOLS-02: 空 old_string 应拒 (旧版空文件上 count==1 误判唯一)
    #[test]
    fn test_file_edit_empty_old_string_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("empty.txt");
        std::fs::write(&fp, "").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.file_edit("empty.txt", "", "x", Some(&cwd)).unwrap();
        assert!(!r.ok, "空 old_string 应被拒");
        assert!(r.error.unwrap().contains("不能为空"));
        // 非空文件空 old_string 也应拒
        std::fs::write(&fp, "content\n").unwrap();
        let r = tools.file_edit("empty.txt", "", "x", Some(&cwd)).unwrap();
        assert!(!r.ok, "空 old_string 应被拒 (非空文件同样)");
    }

    // L-TOOLS-01: 绝对路径模式命中敏感区应被过滤 (validate_cwd 拦 /etc)
    #[test]
    fn test_glob_filters_sensitive_absolute() {
        let tools = Tools::new();
        // /etc 在 SENSITIVE_PATHS 内 → validate_cwd 拒 → glob 返回空
        let r = tools.glob("/etc/passwd", Some("/tmp")).unwrap();
        assert!(r.is_empty(), "敏感路径 /etc/passwd 应被过滤: {:?}", r);
    }

    // C-TOOLS-02: 全文件重写 (删全部+加全部) 应被拒 (旧启发式漏判)
    #[test]
    fn test_apply_patch_full_rewrite_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("app.py");
        std::fs::write(&fp, "line1\nline2\nline3\n").unwrap();
        // 整文件删除 + 整文件新增 (新范围 1..3 覆盖原 3 行)
        let diff = "\
--- a/app.py
+++ b/app.py
@@ -1,3 +1,3 @@
-line1
-line2
-line3
+REPLACED1
+REPLACED2
+REPLACED3
";
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.apply_patch(diff, Some(&cwd)).unwrap();
        assert!(!r.ok, "全文件重写应被拒: {:?}", r.error);
        assert!(r.error.unwrap().contains("全文件重写"));
        // 文件未变
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            "line1\nline2\nline3\n"
        );
    }

    // C-TOOLS-02 对照: 外科补丁 (小 hunk 不覆盖全文件) 仍通过
    #[test]
    fn test_apply_patch_surgical_still_works() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("app.py");
        std::fs::write(&fp, "line1\nline2\nline3\n").unwrap();
        let diff = "\
--- a/app.py
+++ b/app.py
@@ -1,3 +1,3 @@
 line1
-line2
+LINE2
 line3
";
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.apply_patch(diff, Some(&cwd)).unwrap();
        assert!(r.ok, "外科补丁应通过: {:?}", r.error);
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            "line1\nLINE2\nline3\n"
        );
    }

    // L-TOOLS-03: 路径含 .. 组件应被拒 (旧版 canonicalize 失败 fail-open)
    #[test]
    fn test_guard_path_rejects_dotdot_component() {
        let dir = tempfile::tempdir().unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        // 相对路径含 .. (目标尚不存在, canonicalize 必失败 — 旧版 fail-open)
        let res = guard_path(&guard, "sub/../../etc/evil.txt", Some(&cwd));
        assert!(res.is_err(), "含 .. 组件应被拒 (fail-closed)");
        let err = res.unwrap_err().to_string();
        assert!(err.contains(".."), "错误应提及 .. 组件");
    }

    // P-SB-01: 超 64MB 文件 grep 应跳过 (避 OOM)
    #[test]
    fn test_grep_skips_oversize_file() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("big.txt");
        // 稀疏文件: set_len 设逻辑大小不实际写 (metadata.len() 报 65MB)
        {
            let f = std::fs::File::create(&fp).unwrap();
            f.set_len(GREP_FILE_MAX_BYTES + 1024).unwrap();
        }
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let ms = tools
            .grep("anything", &["big.txt".to_string()], Some(&cwd))
            .unwrap();
        assert!(ms.is_empty(), "超 64MB 文件应被跳过: {:?}", ms);
    }
}
