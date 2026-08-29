// fe-tools — 原生文件工具 (PRD §Claude-SDK 对比: 本地化 BashTool/FileEdit/GlobTool/GrepTool)
//             + 外科补丁引擎 (PRD §DeepSeek 对比: Unified Diff 应用 + 函数级替换, 禁全文件重写)
//
// 工具:
//   file_edit(path, old, new, cwd, replace_all)  — 唯一匹配精确替换 (replace_all 全量), 原子写
//   glob(pattern, cwd)              — 递归 glob 模式匹配, 返回相对路径
//   grep(pattern, paths, cwd)       — 正则逐行搜索, 返回 file/line/content
//   apply_patch(diff, cwd)          — Unified Diff 解析 + 应用 (diffy), 禁全文件清空
//   replace_function(path, fn_name, new_body, cwd) — tree-sitter 函数定位, 字节切片替换
//
// 安全: 所有路径经 fe_security::SecurityGuard::validate_path 校验敏感路径 + 逃逸防护

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fs2::FileExt;
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
    #[error("文件超大小上限 ({size} > {max} bytes) — 防 OOM, 拒绝整文件读")]
    Oversize { size: u64, max: u64 },
    #[error("函数 {0} 未找到")]
    FunctionNotFound(String),
    #[error("正则编译失败: {0}")]
    Regex(#[from] regex::Error),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("multi_edit 第 {index} 项: {reason}")]
    MultiEditItem { index: usize, reason: String },
    #[error("notebook 编辑失败: {0}")]
    Notebook(String),
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
/// #7: context_before/context_after (内容模式 -A/-B/-C 上下文行), 默认空 (无上下文)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrepMatch {
    pub path: String,
    pub line_number: u32,
    pub content: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_before: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_after: Vec<String>,
}

// ── #7: ripgrep parity — grep 输出模式 / 选项 / 结果 ──

/// grep 输出模式 (ripgrep parity)
/// content (默认): 逐行命中 + 可选上下文; files_with_matches (-l): 仅文件名; count (-c): 每文件命中数
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrepOutputMode {
    #[default]
    Content,
    FilesWithMatches,
    Count,
}

/// grep 文件命中计数 (count 模式)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrepFileCount {
    pub path: String,
    pub count: u32,
}

/// grep 选项 (#7 ripgrep parity)
/// output_mode: content|files_with_matches|count
/// after/before/context: -A/-B/-C 上下文行 (仅 content 模式生效)
/// multiline: 跨行匹配 (RegexBuilder multi_line + 整文件 buffer)
/// glob_include/glob_exclude: -g include/exclude glob 过滤文件路径 (globset)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrepOptions {
    #[serde(default)]
    pub output_mode: GrepOutputMode,
    #[serde(default)]
    pub after: u32,
    #[serde(default)]
    pub before: u32,
    #[serde(default)]
    pub context: u32,
    #[serde(default)]
    pub multiline: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub glob_include: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub glob_exclude: Vec<String>,
}

/// grep 聚合结果 (#7: 三种输出模式统一返回)
/// content 模式 → matches 有值, files/counts 空
/// files_with_matches 模式 → files 有值 (去重排序), matches/counts 空
/// count 模式 → counts 有值 (每文件命中数), matches/files 空
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrepOutput {
    pub output_mode: GrepOutputMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<GrepMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counts: Vec<GrepFileCount>,
}

// ── #6: replace_all / MultiEdit / NotebookEdit 扩展 ──

/// MultiEdit 单条编辑 (serde, IPC/PyO3 透传)
/// replace_all=false (默认): old_string 必须全文唯一 (Ambiguous 拒绝)
/// replace_all=true: 替换该条所有匹配
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiEditItem {
    pub old_string: String,
    pub new_string: String,
    #[serde(default)]
    pub replace_all: bool,
}

/// notebook 编辑模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NotebookEditMode {
    /// 替换目标 cell 源 (需 cell_id 或 cell_number 定位)
    #[default]
    Replace,
    /// 在目标 cell 后插入新 cell
    Insert,
    /// 删除目标 cell
    Delete,
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

    /// 复制 guard (SecurityGuard Clone) — 测试用, 生产单实例无状态共享
    #[cfg(test)]
    pub(crate) fn clone_guard(&self) -> Self {
        Self {
            guard: self.guard.clone(),
        }
    }

    /// file_edit — 唯一匹配 old_string → new_string 精确替换, 原子写
    /// (PRD FileEdit: 拒绝模糊编辑, old 必须全文唯一)
    /// #6: replace_all=true → 替换全部匹配 (Claude Code FileEdit parity); false (默认) → 唯一匹配
    pub fn file_edit(
        &self,
        path: &str,
        old_string: &str,
        new_string: &str,
        cwd: Option<&str>,
        replace_all: bool,
    ) -> Result<EditResult> {
        let abs = guard_path(&self.guard, path, cwd).map_err(|e| anyhow::anyhow!(e))?;
        // #2 create-on-empty: 路径不存在 + old_string 空 → 用 new_string 建文件 (Claude Code FileEdit parity)
        // 路径不存在 + old_string 非空 → 仍拒绝 (不能凭空匹配不存在的 old_string)
        if !abs.exists() {
            if old_string.is_empty() {
                return self.write_file(path, new_string, cwd);
            }
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(format!("文件未找到: {}", path)),
                matches: 0,
            });
        }
        // L-TOOLS-02: 已存在文件 + 空 old_string → matches().count()==1 误判唯一 → 拒绝 (create-on-empty 仅对缺失路径)
        if old_string.is_empty() {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some("old_string 不能为空".to_string()),
                matches: 0,
            });
        }
        // L-9: 先取锁再 check_size — 锁前查 metadata 留 TOCTOU 窗口 (并发方在 check→read 间扩文件过限,
        // check Ok 但 read OOM)。锁内查大小: 并发 RMW 方亦持同 sidecar 锁, check→read 间文件大小稳定。
        // Blocker 8 / 3.4: flock LOCK_EX 包 RMW, 防并发编辑静默丢改动
        let lock = match FileLock::exclusive(&abs) {
            Ok(l) => l,
            Err(e) => {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("获取文件锁失败: {}", e)),
                    matches: 0,
                });
            }
        };
        // Blocker 8 / 3.5: 锁内预检大小防 OOM
        if let Err(e) = check_size(&abs) {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(e.to_string()),
                matches: 0,
            });
        }
        let content = FileLock::read_data_to_string(&abs)
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
        // #6: replace_all=false → count>1 拒绝 (唯一匹配契约); true → 替换全部
        if !replace_all && count > 1 {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(format!("old_string 非唯一匹配 (命中 {} 处)", count)),
                matches: count as u32,
            });
        }
        let updated = if replace_all {
            content.replace(old_string, new_string)
        } else {
            content.replacen(old_string, new_string, 1)
        };
        // 锁内写完 (atomic_write rename 到目标, 锁仍持 file fd — 保证此 RMW 期间他 Agent 阻塞)
        atomic_write(&abs, &updated)?;
        drop(lock);
        info!(path = %abs.display(), replace_all, "file_edit 替换成功");
        Ok(EditResult {
            ok: true,
            path: Some(path.to_string()),
            error: None,
            matches: count as u32,
        })
    }

    /// write_file — 整文件创建/覆盖 (#2, Claude Code Write parity)
    /// 父目录不存在 → create_dir_all; 已存在 → 原子覆盖; 全程经 atomic_write (temp+persist rename)
    /// 内容经 guard_path (逃逸/敏感防护) + 大小上限 (WRITE_FILE_MAX_BYTES 防 OOM)
    pub fn write_file(&self, path: &str, content: &str, cwd: Option<&str>) -> Result<EditResult> {
        let abs = guard_path(&self.guard, path, cwd).map_err(|e| anyhow::anyhow!(e))?;
        // #2: 内容大小上限 — 防 1GB 生成文件整写 OOM (同 check_size 语义, 但新建文件无 metadata 可查, 校验 content.len)
        if content.len() as u64 > WRITE_FILE_MAX_BYTES {
            warn!(
                path = %abs.display(),
                size = content.len(),
                max = WRITE_FILE_MAX_BYTES,
                "write_file 内容超 64MB 上限, 拒绝"
            );
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(format!(
                    "文件超大小上限 ({} > {} bytes) — 防 OOM",
                    content.len(),
                    WRITE_FILE_MAX_BYTES
                )),
                matches: 0,
            });
        }
        // #2: 父目录不存在 → create_dir_all (Claude Code Write 建父目录语义)
        let parent = abs.parent().unwrap_or_else(|| Path::new("."));
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("创建父目录失败: {}", parent.display()))?;
            debug!(dir = %parent.display(), "write_file 建父目录");
        }
        // #2: 已存在文件取 flock LOCK_EX 防并发 (与 file_edit RMW 同锁语义; 不存在则跳过锁)
        let _lock = if abs.exists() {
            match FileLock::exclusive(&abs) {
                Ok(l) => Some(l),
                Err(e) => {
                    return Ok(EditResult {
                        ok: false,
                        path: Some(path.to_string()),
                        error: Some(format!("获取文件锁失败: {}", e)),
                        matches: 0,
                    });
                }
            }
        } else {
            None
        };
        atomic_write(&abs, content)?;
        info!(path = %abs.display(), bytes = content.len(), "write_file 写入成功 (建/覆盖)");
        Ok(EditResult {
            ok: true,
            path: Some(path.to_string()),
            error: None,
            matches: 1,
        })
    }

    /// multi_edit — 同一文件顺序批量编辑, 原子性 all-or-nothing (#6)
    /// 顺序对内存 buffer 应用每项 (old→new, 支持 replace_all), 任一项失败 → 丢弃 buffer 不写盘, 文件保持编辑前状态
    /// 单次 flock 包整个批次, 防并发编辑静默丢改动
    pub fn multi_edit(
        &self,
        path: &str,
        edits: &[MultiEditItem],
        cwd: Option<&str>,
    ) -> Result<EditResult> {
        if edits.is_empty() {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some("edits 列表不能为空".to_string()),
                matches: 0,
            });
        }
        let abs = guard_path(&self.guard, path, cwd).map_err(|e| anyhow::anyhow!(e))?;
        if !abs.exists() {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(format!("文件未找到: {}", path)),
                matches: 0,
            });
        }
        // L-9: 先取锁再 check_size (锁前查留 TOCTOU 窗口)
        let lock = match FileLock::exclusive(&abs) {
            Ok(l) => l,
            Err(e) => {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("获取文件锁失败: {}", e)),
                    matches: 0,
                });
            }
        };
        if let Err(e) = check_size(&abs) {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(e.to_string()),
                matches: 0,
            });
        }
        let mut buffer = FileLock::read_data_to_string(&abs)
            .with_context(|| format!("读取 {} 失败", abs.display()))?;
        let mut total_matches: u32 = 0;
        // 顺序应用每项编辑; 任一项失败 → 立即 return, 不写盘 (buffer 丢弃), lock drop 释放
        for (i, item) in edits.iter().enumerate() {
            if item.old_string.is_empty() {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("multi_edit 第 {} 项: old_string 不能为空", i)),
                    matches: total_matches,
                });
            }
            let count = buffer.matches(&item.old_string).count();
            if count == 0 {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("multi_edit 第 {} 项: old_string 未匹配", i)),
                    matches: total_matches,
                });
            }
            if !item.replace_all && count > 1 {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!(
                        "multi_edit 第 {} 项: old_string 非唯一匹配 (命中 {} 处)",
                        i, count
                    )),
                    matches: total_matches,
                });
            }
            buffer = if item.replace_all {
                buffer.replace(&item.old_string, &item.new_string)
            } else {
                buffer.replacen(&item.old_string, &item.new_string, 1)
            };
            total_matches += count as u32;
            // IMPL-10: 每项应用后检 buffer 膨胀 — 超 MULTI_EDIT_BUFFER_MAX fail-loud,
            // 文件不动 (未到 atomic_write, buffer 丢弃), 防大文件多 edit 累积膨胀 OOM。
            if buffer.len() > MULTI_EDIT_BUFFER_MAX {
                warn!(path = %abs.display(), idx = i, len = buffer.len(), max = MULTI_EDIT_BUFFER_MAX,
                    "multi_edit buffer 超上限, 拒绝写入 (防膨胀)");
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!(
                        "multi_edit 第 {} 项后 buffer 膨胀超上限 ({} > {} bytes), 拒绝写入",
                        i,
                        buffer.len(),
                        MULTI_EDIT_BUFFER_MAX
                    )),
                    matches: total_matches,
                });
            }
        }
        // 全部项成功 → 一次原子写盘
        atomic_write(&abs, &buffer)?;
        drop(lock);
        info!(path = %abs.display(), edits = edits.len(), "multi_edit 批量替换成功");
        Ok(EditResult {
            ok: true,
            path: Some(path.to_string()),
            error: None,
            matches: total_matches,
        })
    }

    /// notebook_edit — Jupyter .ipynb 单元格编辑 (#6)
    /// 按 cell_id (nbformat v4+) 或 cell_number (0-based 索引) 定位, edit_mode=replace/insert/delete
    /// serde_json 解析/回写, 保持 nbformat 4.x 合规; new_source 为替换/插入的新单元格源码
    pub fn notebook_edit(
        &self,
        path: &str,
        cell_id: Option<&str>,
        cell_number: Option<i64>,
        new_source: &str,
        edit_mode: NotebookEditMode,
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
        // 仅接受 .ipynb 扩展名
        if abs.extension().and_then(|e| e.to_str()) != Some("ipynb") {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some("notebook_edit 仅支持 .ipynb 文件".to_string()),
                matches: 0,
            });
        }
        // L-9: 先取锁再 check_size (锁前查留 TOCTOU 窗口)
        let lock = match FileLock::exclusive(&abs) {
            Ok(l) => l,
            Err(e) => {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("获取文件锁失败: {}", e)),
                    matches: 0,
                });
            }
        };
        if let Err(e) = check_size(&abs) {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(e.to_string()),
                matches: 0,
            });
        }
        let raw = FileLock::read_data_to_string(&abs)
            .with_context(|| format!("读取 {} 失败", abs.display()))?;
        let mut nb: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("notebook 解析失败: {}", e))?;
        let cells = nb
            .get_mut("cells")
            .and_then(|c| c.as_array_mut())
            .ok_or_else(|| anyhow::anyhow!("notebook 缺少 cells 数组"))?;

        let new_cell = serde_json::json!({
            "cell_type": "code",
            "metadata": {},
            "source": source_to_lines(new_source),
            "outputs": [],
            "execution_count": serde_json::Value::Null,
        });

        let locate = |cells: &Vec<serde_json::Value>| -> Result<usize> {
            if let Some(id) = cell_id {
                for (i, c) in cells.iter().enumerate() {
                    if c.get("id").and_then(|v| v.as_str()) == Some(id) {
                        return Ok(i);
                    }
                }
                return Err(anyhow::anyhow!("未找到 cell_id={}", id));
            }
            if let Some(num) = cell_number {
                if num < 0 || num as usize >= cells.len() {
                    return Err(anyhow::anyhow!(
                        "cell_number {} 越界 (共 {} 个单元格)",
                        num,
                        cells.len()
                    ));
                }
                return Ok(num as usize);
            }
            Err(anyhow::anyhow!("需提供 cell_id 或 cell_number"))
        };

        match edit_mode {
            NotebookEditMode::Replace => {
                let idx = match locate(cells) {
                    Ok(i) => i,
                    Err(e) => {
                        drop(lock);
                        return Ok(EditResult {
                            ok: false,
                            path: Some(path.to_string()),
                            error: Some(e.to_string()),
                            matches: 0,
                        });
                    }
                };
                cells[idx] = new_cell;
            }
            NotebookEditMode::Insert => {
                let idx = match cell_number {
                    Some(n) => {
                        if n < 0 || n as usize > cells.len() {
                            drop(lock);
                            return Ok(EditResult {
                                ok: false,
                                path: Some(path.to_string()),
                                error: Some(format!(
                                    "cell_number {} 越界 (共 {} 个单元格, 插入允许 0..={})",
                                    n,
                                    cells.len(),
                                    cells.len()
                                )),
                                matches: 0,
                            });
                        }
                        n as usize
                    }
                    None => {
                        // L-12: 无 cell_number 时按 cell_id 定位后插其后。
                        // 旧版 `Err(_) => cells.len()` 把 "cell_id 未找到" 与 "无 id 无 num" 合并静默 append —
                        // 调用方传 id="bad" 想插特定位置, id 不存在却被静默追加末尾, API 契约三态不一致
                        // (Replace/Delete 都报 missing-id)。修: cell_id 给了但没找到 → 报错 (同 Replace/Delete);
                        // 调用方要 "插入或 append" 应显式传 cell_number=Some(cells.len())。
                        if let Some(id) = cell_id {
                            match cells
                                .iter()
                                .position(|c| c.get("id").and_then(|v| v.as_str()) == Some(id))
                            {
                                Some(i) => i + 1,
                                None => {
                                    drop(lock);
                                    return Ok(EditResult {
                                        ok: false,
                                        path: Some(path.to_string()),
                                        error: Some(format!("cell_id={} 未找到 (Insert 模式)", id)),
                                        matches: 0,
                                    });
                                }
                            }
                        } else {
                            // 无 cell_id 无 cell_number → 追加末尾 (显式 append 语义)
                            cells.len()
                        }
                    }
                };
                cells.insert(idx, new_cell);
            }
            NotebookEditMode::Delete => {
                let idx = match locate(cells) {
                    Ok(i) => i,
                    Err(e) => {
                        drop(lock);
                        return Ok(EditResult {
                            ok: false,
                            path: Some(path.to_string()),
                            error: Some(e.to_string()),
                            matches: 0,
                        });
                    }
                };
                cells.remove(idx);
            }
        }

        // 确保 nbformat 元数据合规
        if nb.get("nbformat").is_none() {
            nb["nbformat"] = serde_json::json!(4);
        }
        if nb.get("nbformat_minor").is_none() {
            nb["nbformat_minor"] = serde_json::json!(5);
        }
        let out = serde_json::to_string_pretty(&nb)
            .map_err(|e| anyhow::anyhow!("notebook 序列化失败: {}", e))?;
        atomic_write(&abs, &out)?;
        drop(lock);
        info!(path = %abs.display(), mode = ?edit_mode, "notebook_edit 成功");
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
        // #7: gitignore-aware 遍历 — ignore::WalkBuilder 读 .gitignore + 隐藏文件 + IGNORED_DIRS 基线
        // 旧版 glob::glob 直接匹配文件系统, 不读 .gitignore → 命中 .gitignore'd 文件 (如 dist/产物)
        // #20: literal_separator(true) — `*`/`?` 不跨 `/`, `**` 仍跨目录。对齐 fusion-event E1 生态统一 glob 规范。
        //   globset 默认 `*` 跨 `/` (与 E1 冲突: `src/*.swift` 会误命中 src/sub/a.swift)。literal_separator 收紧至 E1。
        let pat = globset::GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .map_err(|e| anyhow::anyhow!("glob 模式无效: {}", e))?
            .compile_matcher();
        let mut out = Vec::new();
        let mut skipped_ignored = 0u32;
        let mut builder = ignore::WalkBuilder::new(&cwd_abs);
        builder
            .hidden(false) // 显式: 不自动跳隐藏 (旧版仅跳 IGNORED_DIRS, 调用方可能要 .github/...)
            .ignore(true) // 读 .gitignore
            .git_ignore(true)
            .git_exclude(true)
            .git_global(true)
            .parents(true)
            .follow_links(false)
            // 非 git 仓库也遵循 .gitignore (默认 require_git=true 仅 git 仓生效; fusion 子项目多为独立仓)
            .require_git(false);
        // IGNORED_DIRS 作硬基线 (即使无 .gitignore 也跳 .venv/node_modules — 防 10 万条目 OOM)
        builder.add_custom_ignore_filename(".venv");
        for entry in builder.build() {
            let ent = match entry {
                Ok(e) => e,
                Err(e) => {
                    debug!(error = %e, "glob 遍历单项失败, 跳过");
                    continue;
                }
            };
            let p = ent.path();
            // 跳 cwd 根自身 (WalkBuilder 含根)
            if p == cwd_abs.as_path() {
                continue;
            }
            // IGNORED_DIRS 硬基线 (add_custom_ignore_filename 仅按文件名, 此处兜底目录组件)
            if is_in_ignored_dir(p) {
                skipped_ignored += 1;
                continue;
            }
            let rel = p
                .strip_prefix(&cwd_abs)
                .map(|r| r.to_string_lossy().into_owned())
                .unwrap_or_else(|_| p.to_string_lossy().into_owned());
            // glob 模式匹配相对路径 (同旧版 **/*.py 语义)
            if !pat.is_match(&rel) {
                continue;
            }
            // L-TOOLS-01: 命中父目录经 validate_cwd 校验敏感前缀
            // D4-6 perf 评估 (2026-08-29): 此 per-entry validate_cwd 不能"只校验一次 cwd"省掉 —
            // cwd 根已校验 (line 655), 但敏感子目录 (cwd=/home/user 命中 /home/user/.ssh) 须逐项拦。
            // strip_prefix(cwd_abs) 只证命中在 cwd 下, 不证非敏感。validate_cwd 是 O(sensitive_paths)
            // 纯内存前缀比对 (无 fs syscall), 热路径成本微。保留逐项校验 = 正确性优先, 不降级。
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
            out.push(GlobEntry { path: rel, is_dir });
            if out.len() >= GLOB_RESULT_CAP {
                warn!(
                    cap = GLOB_RESULT_CAP,
                    skipped_ignored, "glob 命中超上限, 截断"
                );
                break;
            }
        }
        if skipped_ignored > 0 {
            debug!(skipped_ignored, "glob 跳过忽略目录内命中");
        }
        info!(count = out.len(), skipped_ignored, "glob 完成");
        Ok(out)
    }

    /// grep — 正则逐行搜索 (content 模式, 旧版兼容入口)
    /// paths 为文件或目录列表 (目录则递归); 返回每条命中 (相对路径, 行号, 内容)
    pub fn grep(
        &self,
        pattern: &str,
        paths: &[String],
        cwd: Option<&str>,
    ) -> Result<Vec<GrepMatch>> {
        let out = self.grep_run(pattern, paths, cwd, &GrepOptions::default())?;
        Ok(out.matches)
    }

    /// grep_with_opts — #7 ripgrep parity: 输出模式 / 上下文 / 多行 / glob 过滤
    pub fn grep_with_opts(
        &self,
        pattern: &str,
        paths: &[String],
        cwd: Option<&str>,
        opts: &GrepOptions,
    ) -> Result<GrepOutput> {
        self.grep_run(pattern, paths, cwd, opts)
    }

    /// grep 核心实现 — 统一 content/files_with_matches/count 三模式
    fn grep_run(
        &self,
        pattern: &str,
        paths: &[String],
        cwd: Option<&str>,
        opts: &GrepOptions,
    ) -> Result<GrepOutput> {
        // D4-7 (审计 0827 product): regex 每次 grep 调用重建 (RegexBuilder + opts.multiline 变体)。
        // regex crate 编译是 µs 级 (无 backtracking NFA, 单遍 DFA 构建), 远小于文件遍历/IO 主导耗时;
        // 缓存需 keyed by (pattern, multiline) 二元组, 增内存 + 并发锁, 收益 <1% (Rule 2 不投机)。
        // 调用方高频重复同 pattern 可自行缓存 Regex 传 pattern→但 API 收 &str, 不接受预编译 Regex;
        // 若未来 profiling 证编译占主耗时, 再加 LazyLock<HashMap<(String,bool), Regex>> (YAGNI now)。
        let re = regex::RegexBuilder::new(pattern)
            .multi_line(opts.multiline)
            // 多行模式: . 匹配换行 (ripgrep -U 语义, 跨行块匹配)
            .dot_matches_new_line(opts.multiline)
            .build()
            .map_err(|e| anyhow::anyhow!(ToolsError::Regex(e)))?;
        let base = cwd.unwrap_or(".");
        let cwd_v = self.guard.validate_cwd(base);
        if !cwd_v.allowed {
            return Err(anyhow::anyhow!(ToolsError::PathBlocked(
                cwd_v.reason.unwrap_or_else(|| "cwd 敏感".to_string()),
            )));
        }
        // #7 gap 5: glob include/exclude (-g) — globset 过滤文件路径
        let include_set = build_globset(&opts.glob_include)?;
        let exclude_set = build_globset(&opts.glob_exclude)?;
        let mut matches: Vec<GrepMatch> = Vec::new();
        let mut files_with_matches: Vec<String> = Vec::new();
        let mut counts: Vec<GrepFileCount> = Vec::new();
        // 全局命中计数 (content 模式用; files/count 模式按文件计, 不受此 cap)
        let mut global_hits = 0usize;
        for raw in paths {
            let abs = guard_path(&self.guard, raw, cwd).map_err(|e| anyhow::anyhow!(e))?;
            // 规范化遍历根 (解 ./ 尾缀 + 符号链接), 与 walkdir 产出的 entry 前缀一致
            let root = std::fs::canonicalize(&abs).unwrap_or_else(|_| abs.clone());
            if abs.is_file() {
                if !path_passes_glob(&abs, &root, &include_set, &exclude_set) {
                    continue;
                }
                let n = grep_file(
                    &abs,
                    &abs,
                    &root,
                    &re,
                    &mut matches,
                    GREP_GLOBAL_HIT_CAP - global_hits,
                    opts,
                )?;
                global_hits += n as usize;
                if n > 0 {
                    record_output(opts, &abs, &root, n, &mut files_with_matches, &mut counts);
                }
            } else if abs.is_dir() {
                // 审计 3.7: max_depth 防 .venv 深递归 + 跳过忽略目录 + 全局命中 cap
                // #7: glob include/exclude 过滤 + (默认 gitignore 由调用方传 .gitignore'd 外的目录)
                for ent in walkdir::WalkDir::new(&root)
                    .max_depth(GREP_MAX_DEPTH)
                    .into_iter()
                    .filter_entry(|e| !is_ignored_walkdir_entry(e))
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                {
                    let fp = ent.path();
                    if fp
                        .file_name()
                        .map(|n| n.to_string_lossy().starts_with('.'))
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    if !path_passes_glob(fp, &root, &include_set, &exclude_set) {
                        continue;
                    }
                    if opts.output_mode == GrepOutputMode::Content
                        && global_hits >= GREP_GLOBAL_HIT_CAP
                    {
                        warn!(cap = GREP_GLOBAL_HIT_CAP, "grep 全局命中超上限, 停扫");
                        break;
                    }
                    let remaining = GREP_GLOBAL_HIT_CAP.saturating_sub(global_hits);
                    let n = grep_file(fp, &root, &root, &re, &mut matches, remaining, opts)?;
                    global_hits += n as usize;
                    if n > 0 {
                        record_output(opts, fp, &root, n, &mut files_with_matches, &mut counts);
                    }
                }
            } else {
                warn!(path = %abs.display(), "grep 路径不存在, 跳过");
            }
        }
        files_with_matches.sort();
        files_with_matches.dedup();
        info!(
            mode = ?opts.output_mode,
            matches = matches.len(),
            files = files_with_matches.len(),
            count_files = counts.len(),
            "grep 完成"
        );
        Ok(GrepOutput {
            output_mode: opts.output_mode,
            matches,
            files: files_with_matches,
            counts,
        })
    }

    /// apply_patch — Unified Diff 解析 + 应用 (diffy crate)
    /// 禁全文件重写: 该文件全部 hunks 删除行数合计 >= 原文件总行数 → 拒绝 (FullRewriteForbidden)
    /// 审计 3.8: 多文件 diff 须按文件切分 (diffy 0.4 from_str 拒多文件 "multiple '---' lines"),
    ///   逐文件解析+应用, 否则第二文件 hunk 静默丢失; 全重写判据须聚合该文件全部 hunk 合计删除行
    ///   (旧版 per-hunk 判据可被拆 hunk 各删 original/2 绕过 → 聚合后合计 = original 仍拦)
    pub fn apply_patch(&self, diff: &str, cwd: Option<&str>) -> Result<EditResult> {
        let base = cwd.unwrap_or(".");
        let cwd_v = self.guard.validate_cwd(base);
        if !cwd_v.allowed {
            return Err(anyhow::anyhow!(ToolsError::PathBlocked(
                cwd_v.reason.unwrap_or_else(|| "cwd 敏感".to_string()),
            )));
        }
        let cwd_abs = std::fs::canonicalize(base).unwrap_or_else(|_| PathBuf::from(base));

        // 审计 3.8(a): diffy 0.4 Patch::from_str 拒多文件 (parse.rs "multiple '---' lines")。
        // 先按 --- 头切分为单文件 diff 片段, 再逐片段 from_str + apply, 否则第二文件丢失。
        let file_diffs = split_multi_file_diff(diff);
        if file_diffs.is_empty() {
            return Ok(EditResult {
                ok: false,
                path: None,
                error: Some("diff 为空或无有效 --- 文件头".to_string()),
                matches: 0,
            });
        }

        let mut total_hunks = 0u32;
        let mut first_path: Option<String> = None;
        for (file_idx, fd) in file_diffs.iter().enumerate() {
            let patch = match diffy::Patch::from_str(fd) {
                Ok(p) => p,
                Err(e) => {
                    return Ok(EditResult {
                        ok: false,
                        path: first_path.clone(),
                        error: Some(format!("diff 第 {} 文件解析失败: {}", file_idx + 1, e)),
                        matches: total_hunks,
                    });
                }
            };
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
            if first_path.is_none() {
                first_path = Some(target_path.clone());
            }
            let abs = guard_path(&self.guard, &target_path, cwd).map_err(|e| anyhow::anyhow!(e))?;
            if !abs.exists() {
                return Ok(EditResult {
                    ok: false,
                    path: Some(target_path.clone()),
                    error: Some(format!("文件未找到: {}", target_path)),
                    matches: total_hunks,
                });
            }
            // L-9: 先取锁再 check_size (锁前查留 TOCTOU 窗口)
            // Blocker 8 / 3.4: flock LOCK_EX 包 RMW
            let lock = match FileLock::exclusive(&abs) {
                Ok(l) => l,
                Err(e) => {
                    return Ok(EditResult {
                        ok: false,
                        path: Some(target_path.clone()),
                        error: Some(format!("获取文件锁失败: {}", e)),
                        matches: total_hunks,
                    });
                }
            };
            // Blocker 8 / 3.5: 锁内预检大小防 OOM
            if let Err(e) = check_size(&abs) {
                return Ok(EditResult {
                    ok: false,
                    path: Some(target_path.clone()),
                    error: Some(e.to_string()),
                    matches: total_hunks,
                });
            }
            let original = FileLock::read_data_to_string(&abs)
                .with_context(|| format!("读取 {} 失败", abs.display()))?;
            let original_lines = original.lines().count();

            // 审计 3.8(b): 全重写判据聚合该文件全部 hunk 合计删除行 —
            // 旧版 per-hunk (removed >= original_lines) 可被拆 2 hunk 各删 original/2 绕过;
            // 聚合后合计删除行 >= original_lines 即重写整文件 → 拒绝 (外科补丁留 context, 合计 < original)。
            let mut file_removed = 0u32;
            let mut file_hunks = 0u32;
            for pf in patch.hunks() {
                let (_added, removed) = count_hunk_lines(pf);
                file_removed += removed;
                file_hunks += 1;
            }
            if file_removed > 0 && (file_removed as usize) >= original_lines {
                return Ok(EditResult {
                    ok: false,
                    path: Some(target_path.clone()),
                    error: Some(
                        "禁止全文件重写 (该文件 hunk 合计删除原文件全部行) — 仅允许外科补丁"
                            .to_string(),
                    ),
                    matches: total_hunks,
                });
            }

            let updated = diffy::apply(&original, &patch)
                .map_err(|e| anyhow::anyhow!("patch 应用失败 ({}): {}", target_path, e))?;
            // L-10: 安全校验 fail-closed — 确认输出文件仍 cwd 内 (防止 patch 改路径)。
            // 旧版 `if let Ok(canonical)` 在 canonicalize 失败时静默跳过校验 (fail-open),
            // 文件 symlink/IO 异常时逃逸检测被绕过。canonicalize 失败即无法确认边界 → 显式拒。
            let canonical = abs
                .canonicalize()
                .with_context(|| format!("patch 目标路径解析失败: {}", abs.display()))?;
            if !canonical.starts_with(&cwd_abs) {
                return Ok(EditResult {
                    ok: false,
                    path: Some(target_path),
                    error: Some("patch 目标逃逸 cwd".to_string()),
                    matches: total_hunks,
                });
            }
            atomic_write(&abs, &updated)?;
            drop(lock);
            total_hunks += file_hunks;
            info!(path = %abs.display(), hunks = file_hunks, "apply_patch 文件成功");
        }
        info!(
            files = file_diffs.len(),
            hunks = total_hunks,
            "apply_patch 全部成功"
        );
        Ok(EditResult {
            ok: true,
            path: first_path,
            error: None,
            matches: total_hunks,
        })
    }

    /// replace_function — tree-sitter 定位函数定义, 用 new_body 整体替换该函数
    /// (PRD §DeepSeek 外科补丁: 函数级替换, 避免全文件重写)
    /// new_body 为完整函数定义文本 (含签名 + 体), 替换原同函数名的定义
    /// 支持语言: py/js/ts/rs; 按扩展选 grammar。
    /// M-12.1: 无 grammar 的扩展名 (go/sh/lua/...) **不回退正则** — 正则边界不可靠会误匹配同名
    /// 方法/嵌套函数 + 结束边界靠猜会损坏文件, 已 fail-loud 拒绝 (改用 file_edit/apply_patch)。
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
        // L-9: 先取锁再 check_size (锁前查留 TOCTOU 窗口)
        // Blocker 8 / 3.4: flock LOCK_EX 包 RMW
        let lock = match FileLock::exclusive(&abs) {
            Ok(l) => l,
            Err(e) => {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("获取文件锁失败: {}", e)),
                    matches: 0,
                });
            }
        };
        // Blocker 8 / 3.5: 锁内预检大小防 OOM (replace_function 尤甚: 读全文件 + 全量 parse)
        if let Err(e) = check_size(&abs) {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(e.to_string()),
                matches: 0,
            });
        }
        let content = FileLock::read_data_to_string(&abs)
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
        drop(lock);
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

/// source_to_lines — nbformat 单元格 source 规范: 字符串列表, 每行末尾含 \n (末行无)
/// 单行源码 → ["整行"]; 多行 → 按 \n split, 保留行尾 \n
fn source_to_lines(source: &str) -> Vec<String> {
    if source.is_empty() {
        return vec![];
    }
    let mut lines: Vec<String> = Vec::new();
    let mut start = 0usize;
    let bytes = source.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            lines.push(source[start..=i].to_string());
            start = i + 1;
        }
    }
    if start < source.len() {
        lines.push(source[start..].to_string());
    }
    lines
}

/// 校验路径不落敏感区 + 不通过 .. 逃逸 cwd + 符号链接旁路防护
/// (复用 fe_security::SecurityGuard 的敏感路径集)
///
/// Blocker 3 (finding 3.1/3.2) 修复:
/// - 旧版 .. 检查仅在 `if let Some(cwd)` 内 → cwd=None 全跳过, 可写任意文件
/// - 旧版敏感校验用字面 abs 字符串前缀匹配 → 符号链接 (cwd/symlink/evil 指向 /etc) 旁路
///
/// 新版: .. 组件无条件拒绝; 敏感 + 逃逸校验走 canonicalize (解符号链接) 后 starts_with
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
    // 3.1: .. 组件无条件拒绝 (cwd=None 也拦) — 不依赖 canonicalize, fail-closed
    if abs
        .components()
        .any(|comp| comp == std::path::Component::ParentDir)
    {
        return Err(ToolsError::PathBlocked(format!(
            "路径含 .. 组件, 拒绝逃逸嫌疑: {} (cwd={:?})",
            raw, cwd
        )));
    }
    // 3.2: 敏感路径 + cwd 逃逸校验走 canonicalize (解符号链接)
    // abs 本身存在 → canonicalize(abs) 校验 starts_with cwd (目录输入如 "." 或文件目标)
    // abs 不存在 → canonicalize(abs 的父目录) (新文件在 cwd 内创建合法)
    let cwd_abs = cwd.and_then(|c| std::fs::canonicalize(c).ok());
    let (escape_check, sensitive_check) = match abs.canonicalize() {
        Ok(canonical) => {
            // C-SEC-03: 文件已存在 = 读场景 (file_edit/grep 老文件), 拒读凭据文件名模式
            // (id_rsa* / *.pem / *.key 等) — 路径前缀已拦 ~/.ssh/*, 此处补 cwd 内/任意位置凭据文件。
            // 创建新文件 (cert.pem) 走 Err 分支不拦 — 仅阻读已有凭据。
            if guard.is_sensitive_filename(&canonical.to_string_lossy()) {
                return Err(ToolsError::PathBlocked(format!(
                    "拒绝读取凭据文件 (敏感文件名模式): {} (C-SEC-03)",
                    raw
                )));
            }
            (canonical.clone(), canonical)
        }
        Err(_) => {
            // abs 不存在 — 取父目录 canonicalize (符号链接在父段)
            match abs.parent().and_then(|p| p.canonicalize().ok()) {
                Some(canonical_parent) => (
                    canonical_parent.join(abs.file_name().unwrap_or_default()),
                    canonical_parent,
                ),
                None => {
                    // 父目录也不存在 — 字面校验 (.. 已拦, 无符号链接旁路)
                    // abs 由 raw cwd + p 构造, 故用 raw cwd (非 canonicalize) 校验 starts_with
                    // 避免 macOS tempdir 符号链接 (/var → /private/var) 导致字面 vs 规范化误判
                    let lit = abs.to_string_lossy().into_owned();
                    let lit_parent = abs
                        .parent()
                        .map(|d| d.to_string_lossy().into_owned())
                        .unwrap_or_else(|| lit.clone());
                    if let Some(c) = cwd {
                        if !Path::new(&lit).starts_with(Path::new(c))
                            && !Path::new(&lit_parent).starts_with(Path::new(c))
                        {
                            return Err(ToolsError::PathBlocked(format!(
                                "路径逃逸 cwd: {} (cwd={:?})",
                                raw, cwd
                            )));
                        }
                    }
                    let v = guard.validate_cwd(&lit_parent);
                    if !v.allowed {
                        return Err(ToolsError::PathBlocked(
                            v.reason.unwrap_or_else(|| "敏感路径".to_string()),
                        ));
                    }
                    return Ok(abs);
                }
            }
        }
    };
    // cwd 逃逸: canonicalize 后必须 starts_with cwd 规范化
    if let Some(cwd_abs) = &cwd_abs {
        if !escape_check.starts_with(cwd_abs) {
            return Err(ToolsError::PathBlocked(format!(
                "路径逃逸 cwd (符号链接解析): {} (cwd={:?})",
                raw, cwd
            )));
        }
    }
    // 敏感前缀: canonicalize 后是否落敏感区
    let check_target = sensitive_check.to_string_lossy().into_owned();
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

/// 写工具文件大小上限 (Blocker 8 / 3.5) — 64MB, 防 1GB 生成文件 read_to_string OOM
const WRITE_FILE_MAX_BYTES: u64 = 64 * 1024 * 1024;

// IMPL-10: multi_edit in-memory buffer 独立上限 — 文件 64MB check_size 只检原始大小,
// 多项 replace_all 叠加膨胀后 buffer 可远超。每项应用后检 buffer.len() 超 MULTI_EDIT_BUFFER_MAX
// → fail-loud Err, 文件不动 (buffer 丢弃, atomic_write 不触发, 原子回滚保留)。
// 256MB > 64MB 文件 cap 留叠加余量, 拦非合理膨胀 (调用方传过大 new_string)。
const MULTI_EDIT_BUFFER_MAX: usize = 256 * 1024 * 1024;

/// glob/grep 结果上限 — 防 .venv/node_modules 扫出 10 万条目 OOM (审计 3.6/3.7)
/// 5000 条够定位代码, 超限截断 + warn (调用方拉全量应走专用索引工具)
const GLOB_RESULT_CAP: usize = 5000;
const GREP_GLOBAL_HIT_CAP: usize = 2000;
/// grep 递归最大深度 (审计 3.7) — 防 .venv 深符号链接网无限递归; 20 层够覆盖任何源码树
const GREP_MAX_DEPTH: usize = 20;

/// 默认忽略目录名 (审计 3.6/3.7) — 同 .gitignore 常见项 + Apple Silicon 构建产物
/// glob/grep 递归时跳过这些目录, 避免扫 .venv site-packages (数万符号链接) / node_modules
const IGNORED_DIRS: &[&str] = &[
    ".venv",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    ".cache",
    "venv",
    ".tox",
    "site-packages",
];

/// 路径是否落在忽略目录内 (任一路径组件匹配 IGNORED_DIRS)
fn is_in_ignored_dir(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|n| IGNORED_DIRS.contains(&n))
            .unwrap_or(false)
    })
}

/// walkdir filter_entry 判定 — 目录名匹配 IGNORED_DIRS 则不递归进 (剪枝整棵子树)
fn is_ignored_walkdir_entry(entry: &walkdir::DirEntry) -> bool {
    entry.file_type().is_dir()
        && entry
            .file_name()
            .to_str()
            .map(|n| IGNORED_DIRS.contains(&n))
            .unwrap_or(false)
}

// ── #7 ripgrep parity helpers ──

/// 构建 globset (None = 不过滤); 空列表 → None (跳过编译, 全通过)
fn build_globset(patterns: &[String]) -> Result<Option<globset::GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut b = globset::GlobSetBuilder::new();
    for p in patterns {
        b.add(globset::Glob::new(p).map_err(|e| anyhow::anyhow!("glob 过滤模式无效: {}", e))?);
    }
    Ok(Some(
        b.build()
            .map_err(|e| anyhow::anyhow!("globset 构建失败: {}", e))?,
    ))
}

/// 文件路径是否通过 include/exclude glob 过滤 (#7 gap 5, -g)
/// include 非空: 必须匹配任一 include (白名单); exclude 非空: 匹配任一则排除
/// 匹配相对遍历根的路径 (同 glob 语义); 单文件输入 (rel 空) → 用 file_name 匹配
/// 无 include → 默认通过; 任一 exclude 命中 → 拒
fn path_passes_glob(
    fp: &Path,
    root: &Path,
    include: &Option<globset::GlobSet>,
    exclude: &Option<globset::GlobSet>,
) -> bool {
    let rel = rel_for_glob(fp, root);
    if let Some(ex) = exclude {
        if ex.is_match(&rel) {
            return false;
        }
    }
    if let Some(inc) = include {
        return inc.is_match(&rel);
    }
    true
}

/// 按输出模式记录命中文件 (#7 gap 2)
/// content 模式不调此 (matches 在 grep_file 内填); files/count 在此聚合
fn record_output(
    opts: &GrepOptions,
    fp: &Path,
    root: &Path,
    hits: u32,
    files: &mut Vec<String>,
    counts: &mut Vec<GrepFileCount>,
) {
    let rel = rel_for_record(fp, root);
    match opts.output_mode {
        GrepOutputMode::FilesWithMatches => files.push(rel),
        GrepOutputMode::Count => counts.push(GrepFileCount {
            path: rel,
            count: hits,
        }),
        GrepOutputMode::Content => {}
    }
}

/// glob 过滤用的相对路径: strip_prefix(root), 空/失败 → file_name (单文件语义)
fn rel_for_glob(fp: &Path, root: &Path) -> String {
    if let Ok(r) = fp.strip_prefix(root) {
        let s = r.to_string_lossy().into_owned();
        if !s.is_empty() {
            return s;
        }
    }
    fp.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| fp.to_string_lossy().into_owned())
}

/// 记录用的相对路径 (display): strip_prefix(root), 失败 → file_name (避绝对路径泄漏)
fn rel_for_record(fp: &Path, root: &Path) -> String {
    if let Ok(r) = fp.strip_prefix(root) {
        let s = r.to_string_lossy().into_owned();
        if !s.is_empty() {
            return s;
        }
    }
    fp.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| fp.to_string_lossy().into_owned())
}

/// 预检文件大小 — 超上限返 Oversize 错 (fail-loud), 不静默截断
/// (写工具需读全文件做 RMW, 超大文件该用专用 diff 工具, 非 LLM 整文件重写)
fn check_size(path: &Path) -> std::result::Result<(), ToolsError> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > WRITE_FILE_MAX_BYTES {
            warn!(path = %path.display(), size = meta.len(), max = WRITE_FILE_MAX_BYTES, "文件超 64MB 上限, 拒绝整文件读");
            return Err(ToolsError::Oversize {
                size: meta.len(),
                max: WRITE_FILE_MAX_BYTES,
            });
        }
    }
    Ok(())
}

/// RAII 排他锁 — 持 sidecar lockfile 的 fd (LOCK_EX), drop 自动 unlock (fs2 FileExt)
/// Blocker 8 / 3.4: file_edit/apply_patch/replace_function 全是 RMW, 无锁则两 Agent 并发改同文件后写覆盖前写, 静默丢改动
/// 关键: 锁 sidecar `<data>.fe-flock` (稳定 inode, 永不被 rename), 非锁 data 文件本身 —
///   atomic_write 用 temp+rename 换 data inode, 若锁 data 旧 inode 则并发方锁到新 inode → 形同未锁 (丢改动根因)
///   sidecar 永不 rename, 两方争同一锁 → 真·串行。lockfile 0 字节, create-if-absent, 永不删 (删亦生 inode-swap 竞态)
struct FileLock {
    // 持 fd 即持锁: BSD flock(2) 关联打开 fd, close 最后 fd 时内核自动释放。
    // 字段不被读 — 存在本身 = 锁的生命周期, drop FileLock → drop File → close fd → 解锁。
    #[allow(dead_code)]
    file: std::fs::File,
}

impl FileLock {
    /// 锁 `<data_path>.fe-flock` sidecar (data_path 为数据文件绝对路径)
    fn exclusive(data_path: &Path) -> std::result::Result<Self, ToolsError> {
        // RUN-5: BSD flock 跨主机不互斥 (NFS 本地只锁, 远端不知)。当前单机 UDS 部署无 NFS 场景,
        // 不引入分布式锁 (Rule 2 — 无需求过度工程)。仅检测 NFS mount → warn 提示限制, 不改锁机制。
        // stat -f -t <path> macOS 取 fstype (含 nfs → NFS); 失败静默 (非 macOS 或 stat 缺失, 不阻塞锁)。
        if is_nfs(data_path) {
            warn!(path = %data_path.display(),
                "NFS mount 检测到 — BSD flock 跨主机不互斥, 当前单机部署场景; \
                 多节点共享目录请改本地工作区 (flock 限制已知)");
        }
        let lock_path = sidecar_lock_path(data_path);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(ToolsError::Io)?;
        file.lock_exclusive().map_err(ToolsError::Io)?;
        debug!(lock = %lock_path.display(), data = %data_path.display(), "flock LOCK_EX 获取 (sidecar)");
        Ok(Self { file })
    }

    /// 从数据文件 (非锁文件) 读全内容 — 锁已持, 读 data_path 安全
    /// M-12.2: 旧版裸 `std::fs::read_to_string` 错误消息 (如 "stream did not contain valid UTF-8")
    /// 无文件名上下文 — 非 UTF-8 文件 (Latin-1/二进制配置) 失败时难定位。加文件名前缀到 io::Error。
    fn read_data_to_string(data_path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(data_path)
            .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {}", data_path.display(), e)))
    }
}

/// sidecar 锁文件路径: `<data>.fe-flock`
fn sidecar_lock_path(data_path: &Path) -> PathBuf {
    let mut s = data_path.to_string_lossy().into_owned();
    s.push_str(".fe-flock");
    PathBuf::from(s)
}

/// RUN-5: 检测路径所在文件系统是否 NFS — macOS `stat -f -t <path>` 取 fstype。
/// 输出形如 `/dev/disk1s1 apfs` 或 `host:/export nfs`; 含 `nfs` → true。
/// 失败 (非 macOS / stat 缺失 / 路径不存在) → false (静默, 不阻塞锁路径)。
/// 仅用于 warn 提示 BSD flock 跨主机限制, 不改变锁行为 (单机部署无 NFS 需求)。
fn is_nfs(path: &Path) -> bool {
    // 取父目录探测 (path 可能是不存在的待建文件, 父目录通常存在)
    let target = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => path,
    };
    let output = match std::process::Command::new("stat")
        .args(["-f", "-t", &target.to_string_lossy()])
        .output()
    {
        Ok(o) => o,
        Err(_) => return false,
    };
    if !output.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!(path = %target.display(), fstype = %stdout.trim(), "is_nfs stat 探测");
    stdout
        .split_whitespace()
        .any(|tok| tok.eq_ignore_ascii_case("nfs"))
}

/// 原子写 — NamedTempFile 随机名 + persist 原子 rename
/// C-TOOLS-01: 旧版用固定名 .fe-tmp-{pid} — 同进程并发写同目录互踩; 且 rename 到符号链接可被劫持
/// tempfile::NamedTempFile::new_in(dir) 随机名避并发互踩; .persist() 原子 rename (同 FS)
/// 跨 FS (EXDEV) 降级 std::fs::write+rename (非原子, 记 warn)
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("无父目录: {}", path.display()))?;
    // NamedTempFile 随机名 (避同进程并发互踩), 在目标同目录 (同 FS → rename 原子)
    let tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("创建临时文件失败 (dir={})", dir.display()))?;
    std::fs::write(tmp.path(), content)
        .with_context(|| format!("写临时文件 {} 失败", tmp.path().display()))?;
    match tmp.persist(path) {
        Ok(_) => Ok(()),
        Err(e) => {
            // m-SEC-03: persist 失败 — 复用同一随机名 NamedTempFile (非旧固定名 .fe-tmp-fb-{pid}
            // 会同进程并发互踩), 仍在目标同目录 (同 FS), 走 std::fs::rename (同 FS 原子)。
            // PersistError { file: NamedTempFile, error: io::Error } — 取出 file 重试 rename。
            let persist_err = e.error;
            let tmp_retry = e.file;
            warn!(
                error = %persist_err,
                target = %path.display(),
                "persist 失败, 重试 std::fs::rename (同目录, 同 FS 原子)"
            );
            let tmp_path = tmp_retry.path().to_path_buf();
            // std::fs::rename 同 FS 原子; 真 EXDEV (不同 FS) 则 fail-loud Err (不静默降级非原子写)
            if let Err(rename_err) = std::fs::rename(&tmp_path, path) {
                return Err(anyhow::anyhow!(
                    "atomic_write rename 失败 ({} -> {}): persist={}; rename={}",
                    tmp_path.display(),
                    path.display(),
                    persist_err,
                    rename_err
                )
                .context("m-SEC-03: 拒绝降级非原子写, fail-loud"));
            }
            // rename 成功 → forget 防 drop 删文件 (rename 后原路径已空, 但 NamedTempFile
            // drop 会尝试删旧 path; forget 仅清 handle 不动已 rename 走的文件)
            std::mem::forget(tmp_retry);
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

/// 函数定义节点类型候选 — 按扩展映射
/// IMPL-6: JS/TS 漏 arrow function — `const f = () => {}` 是 lexical_declaration >
/// variable_declarator(name: identifier, value: arrow_function)。arrow_function 节点本身
/// 无 name 字段, 须走 variable_declarator 路径。method_definition (类方法) 也补入。
/// py: function_definition; rs: function_item; js/ts: function_declaration + method_definition
/// + variable_declarator (arrow function 入口)。
fn function_node_kinds(ext: &str) -> Option<&'static [&'static str]> {
    match ext {
        "py" => Some(&["function_definition"]),
        "js" | "ts" | "tsx" => Some(&[
            "function_declaration",
            "method_definition",
            "generator_function_declaration",
            // arrow function: 名在 variable_declarator, 值为 arrow_function
            "variable_declarator",
        ]),
        "rs" => Some(&["function_item"]),
        _ => None,
    }
}

/// 函数名字段名 — py: name, js/ts: name, rs: name
const NAME_FIELD: &str = "name";

/// 在源码中定位函数定义, 返回字节范围 (start, end)
fn locate_function(content: &str, ext: &str, fn_name: &str) -> Result<Option<ByteSpan>> {
    let kinds = match function_node_kinds(ext) {
        Some(k) => k,
        None => {
            // 审计 3.12 / M-12.1: 无 grammar 时无正则回退 — 正则结束边界靠找下一行
            // def/fn/function/export, 命中目标函数内部嵌套定义 → span 提前结束, 只换前几行,
            // 余下旧函数体 + 嵌套定义残留 → 文件语法损坏。无 AST 边界不可靠, fail-loud 拒绝。
            warn!(ext = ext, fn_name = %fn_name, "replace_function 无 grammar (ext={ext}), 拒绝正则回退 (边界不可靠, 损坏文件)");
            return Err(anyhow::anyhow!(
                "replace_function 不支持 .{ext} 文件 — 无 tree-sitter grammar, \
                 正则回退边界不可靠会损坏文件; 改用 file_edit 或 apply_patch"
            ));
        }
    };
    let mut parser = match parser_for_ext(ext) {
        Some(p) => p,
        None => {
            // 同上: parser 构建失败 (set_language 失败) 也 fail-loud
            warn!(ext = ext, fn_name = %fn_name, "replace_function parser 构建失败, 拒绝回退");
            return Err(anyhow::anyhow!(
                "replace_function .{ext} parser 构建失败, 拒绝正则回退 (边界不可靠)"
            ));
        }
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
        if kinds.contains(&node.kind()) {
            // IMPL-6: variable_declarator 是 arrow function 入口 — 名在 name 字段,
            // 值须是 arrow_function 才算箭头函数 (普通 `const x = 1` 不该被替换函数体)。
            // 命中后替换整个声明语句 (parent lexical_declaration / variable_declaration),
            // 即 `const add = (...) => ...;` 整句 — 否则只换 declarator span 会残 `const ` 前缀
            // 与 `;` 后缀 → 损坏文件 (const + const + ;)。new_body 须自带完整声明。
            if node.kind() == "variable_declarator" {
                let is_arrow = node
                    .child_by_field_name("value")
                    .map(|v| v.kind() == "arrow_function")
                    .unwrap_or(false);
                if !is_arrow {
                    // 非 arrow function 的 declarator, 跳过 (继续遍历其子节点)
                } else if let Some(name_node) = node.child_by_field_name(NAME_FIELD) {
                    let name_text = name_node.utf8_text(content.as_bytes()).unwrap_or("");
                    if name_text == fn_name {
                        // 取 parent 整句声明 span (const/let → lexical_declaration, var → variable_declaration)
                        let span_node = match node.parent() {
                            Some(p)
                                if p.kind() == "lexical_declaration"
                                    || p.kind() == "variable_declaration" =>
                            {
                                p
                            }
                            _ => node,
                        };
                        found = Some(ByteSpan {
                            start: span_node.start_byte(),
                            end: span_node.end_byte(),
                        });
                        break;
                    }
                }
            } else if let Some(name_node) = node.child_by_field_name(NAME_FIELD) {
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

/// 按 `--- /+++ ` 文件头切分多文件 unified diff 为单文件 diff 片段 (审计 3.8)。
///
/// diffy 0.4 `Patch::from_str` 在第二个 `--- ` 行报 "multiple '---' lines" 拒多文件。
/// 真实 `git diff` 多文件工作流含多对 `--- /+++` 头, 须先切分再逐片段 from_str。
///
/// 切分规则: 按行扫描, 每个 `--- ` 行 (L-11: **且后跟 `+++ ` 行** 才算文件头) 起一个新文件片段
/// (含该 `--- ` 行 + 其后所有行, 直到下一个 `--- `+`+++ ` 头前)。跳过 `diff --git`/`index` 等
/// git 扩展头 (它们在首 `--- ` 前)。
///
/// L-11: 旧版仅 `starts_with("--- ")` 判头 — unified diff 删除行前缀 `-`, 若原源码行是 `-- foo`
/// (Lua/SQL 注释/printf 格式串), diff 删除行 `--- foo` 匹配 `starts_with("--- ")` 触发 hunk 中段
/// 误拆 → 两段皆畸形 → from_str 失败 → 合法 diff 被拒。修: peek ahead, 仅当 `--- ` 后跟 `+++ `
/// 才算文件头 (文件头必成对, 删除行后的行非 `+++ `)。
/// 单文件 diff (无第二个 `--- `+`+++ ` 头) → 返回 1 元素 Vec。
fn split_multi_file_diff(diff: &str) -> Vec<String> {
    let lines: Vec<&str> = diff.lines().collect();
    let mut segments: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    for i in 0..lines.len() {
        let line = lines[i];
        // L-11: 仅当 `--- ` 行后跟 `+++ ` 行才算新文件头 (成对出现),
        // 避免误判删除行 `--- foo` (原源码 `-- foo`) 为头, 防 hunk 中段误拆。
        let is_file_header =
            line.starts_with("--- ") && i + 1 < lines.len() && lines[i + 1].starts_with("+++ ");
        if is_file_header {
            // 新文件片段起点: 把已积累的片段推入, 开新片段
            if let Some(seg) = current.take() {
                segments.push(seg);
            }
            current = Some(String::new());
        }
        if let Some(seg) = current.as_mut() {
            seg.push_str(line);
            seg.push('\n');
        }
        // diff --git / index 等 git 扩展头在首个 --- 前, current=None 时被丢弃 (符合预期)
    }
    if let Some(seg) = current {
        segments.push(seg);
    }
    segments
}

/// grep 单文件 — 正则逐行, 跳过二进制 (含 \0), 单文件限 1000 命中 + 受全局余量约束
/// P-SB-01: 旧版 std::fs::read 整文件入内存 — 超大文件 (GB 级) OOM
/// 改用 metadata 先查大小, 超 64MB 跳过 (grep 非二进制探测工具, 大文件该用专用索引)
/// 审计 3.7: global_remaining = 全局命中余量 (GREP_GLOBAL_HIT_CAP - 已收), 取 min(单文件 1000, 余量)
const GREP_FILE_MAX_BYTES: u64 = 64 * 1024 * 1024;
const GREP_PER_FILE_CAP: usize = 1000;
/// 返回该文件命中数 (0 = 无命中); content 模式才填充 out (含上下文)
#[allow(clippy::too_many_arguments)]
fn grep_file(
    fp: &Path,
    root: &Path,
    cwd_abs: &Path,
    re: &Regex,
    out: &mut Vec<GrepMatch>,
    global_remaining: usize,
    opts: &GrepOptions,
) -> Result<u32> {
    // P-SB-01: metadata 限大小, 超限跳过 (避 OOM)
    if let Ok(meta) = std::fs::metadata(fp) {
        if meta.len() > GREP_FILE_MAX_BYTES {
            warn!(path = %fp.display(), size = meta.len(), "grep 文件超 64MB 上限, 跳过");
            return Ok(0);
        }
    }
    let bytes = match std::fs::read(fp) {
        Ok(b) => b,
        Err(e) => {
            debug!(path = %fp.display(), error = %e, "grep 读文件失败, 跳过");
            return Ok(0);
        }
    };
    // 二进制嫌疑 → 跳过 (限前 8KB 探测, 避全扫描)
    let probe = &bytes[..bytes.len().min(8192)];
    if probe.contains(&0u8) {
        return Ok(0);
    }
    let text = String::from_utf8_lossy(&bytes);
    let rel = fp
        .strip_prefix(cwd_abs)
        .or_else(|_| fp.strip_prefix(root))
        .map(|r| r.to_string_lossy().into_owned())
        .unwrap_or_else(|_| fp.to_string_lossy().into_owned());
    // #7 gap 4: 多行模式 — 整文件 buffer 匹配, 行号 = 匹配起点所在行
    if opts.multiline {
        let mut hits = 0u32;
        let file_cap = GREP_PER_FILE_CAP.min(global_remaining) as u32;
        for m in re.find_iter(&text) {
            if hits >= file_cap {
                warn!(path = %fp.display(), cap = file_cap, "grep 多行单文件命中超上限, 截断");
                break;
            }
            // 行号 = 匹配起点之前 '\n' 数 + 1
            let line_number = text[..m.start()].matches('\n').count() as u32 + 1;
            let content = m.as_str().to_string();
            if opts.output_mode == GrepOutputMode::Content {
                out.push(GrepMatch {
                    path: rel.clone(),
                    line_number,
                    content,
                    context_before: Vec::new(),
                    context_after: Vec::new(),
                });
            }
            hits += 1;
        }
        return Ok(hits);
    }
    // #7 gap 3: 上下文 -A/-B/-C (-C = min(A,B) 同时取 before/after)
    let lines: Vec<&str> = text.lines().collect();
    let before = opts.before.max(opts.context) as usize;
    let after = opts.after.max(opts.context) as usize;
    let file_cap = GREP_PER_FILE_CAP.min(global_remaining) as u32;
    let mut hits = 0u32;
    for (i, line) in lines.iter().enumerate() {
        if re.is_match(line) {
            hits += 1;
            if opts.output_mode == GrepOutputMode::Content {
                let cb: Vec<String> = if before > 0 {
                    lines[i.saturating_sub(before)..i]
                        .iter()
                        .map(|s| s.to_string())
                        .collect()
                } else {
                    Vec::new()
                };
                let ca: Vec<String> = if after > 0 {
                    let end = (i + 1 + after).min(lines.len());
                    lines[(i + 1)..end].iter().map(|s| s.to_string()).collect()
                } else {
                    Vec::new()
                };
                out.push(GrepMatch {
                    path: rel.clone(),
                    line_number: (i + 1) as u32,
                    content: line.to_string(),
                    context_before: cb,
                    context_after: ca,
                });
            }
            if hits >= file_cap {
                warn!(path = %fp.display(), cap = file_cap, "grep 单文件命中超上限, 截断");
                break;
            }
        }
    }
    Ok(hits)
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
            .file_edit("app.py", "x = 1", "x = 99", Some(&cwd), false)
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
            .file_edit("a.txt", "missing", "x", Some(&cwd), false)
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
        let r = tools
            .file_edit("a.txt", "dup", "one", Some(&cwd), false)
            .unwrap();
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
        let r = tools
            .file_edit("nope.txt", "a", "b", Some(&cwd), false)
            .unwrap();
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

    // ── #7 ripgrep parity ──

    #[test]
    fn test_grep_files_with_matches_mode() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "TODO fix\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "no match here\n").unwrap();
        std::fs::write(dir.path().join("c.py"), "TODO again\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let out = tools
            .grep_with_opts(
                "TODO",
                &[".".to_string()],
                Some(&cwd),
                &GrepOptions {
                    output_mode: GrepOutputMode::FilesWithMatches,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(out.output_mode, GrepOutputMode::FilesWithMatches);
        assert!(out.matches.is_empty());
        assert_eq!(out.files.len(), 2);
        assert!(out.files.contains(&"a.py".to_string()));
        assert!(out.files.contains(&"c.py".to_string()));
    }

    #[test]
    fn test_grep_count_mode() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "todo\ntodo\ntodo\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let out = tools
            .grep_with_opts(
                "todo",
                &["a.py".to_string()],
                Some(&cwd),
                &GrepOptions {
                    output_mode: GrepOutputMode::Count,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(out.counts.len(), 1);
        assert_eq!(out.counts[0].path, "a.py");
        assert_eq!(out.counts[0].count, 3);
    }

    #[test]
    fn test_grep_context_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "l1\nl2\nl3\nMARK\nl5\nl6\nl7\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let out = tools
            .grep_with_opts(
                "MARK",
                &["a.py".to_string()],
                Some(&cwd),
                &GrepOptions {
                    before: 2,
                    after: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(out.matches.len(), 1);
        let m = &out.matches[0];
        assert_eq!(m.line_number, 4);
        assert_eq!(m.content, "MARK");
        assert_eq!(m.context_before, vec!["l2".to_string(), "l3".to_string()]);
        assert_eq!(m.context_after, vec!["l5".to_string()]);
    }

    #[test]
    fn test_grep_multiline_mode() {
        let dir = tempfile::tempdir().unwrap();
        // 多行块匹配: foo ... bar 跨行
        std::fs::write(dir.path().join("a.py"), "foo\nmiddle\nbar\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let out = tools
            .grep_with_opts(
                "foo.*bar",
                &["a.py".to_string()],
                Some(&cwd),
                &GrepOptions {
                    multiline: true,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(out.matches.len(), 1);
        // 行号 = 匹配起点 (foo 所在行)
        assert_eq!(out.matches[0].line_number, 1);
        assert_eq!(out.matches[0].content, "foo\nmiddle\nbar");
    }

    #[test]
    fn test_grep_glob_include_exclude() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "MARK\n").unwrap();
        std::fs::write(dir.path().join("b.rs"), "MARK\n").unwrap();
        std::fs::write(dir.path().join("c.txt"), "MARK\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        // include *.py → 只 a.py
        let out = tools
            .grep_with_opts(
                "MARK",
                &[".".to_string()],
                Some(&cwd),
                &GrepOptions {
                    output_mode: GrepOutputMode::FilesWithMatches,
                    glob_include: vec!["*.py".to_string()],
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(out.files, vec!["a.py".to_string()]);
        // exclude *.rs → a.py + c.txt
        let out = tools
            .grep_with_opts(
                "MARK",
                &[".".to_string()],
                Some(&cwd),
                &GrepOptions {
                    output_mode: GrepOutputMode::FilesWithMatches,
                    glob_exclude: vec!["*.rs".to_string()],
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(out.files.len(), 2);
        assert!(out.files.contains(&"a.py".to_string()));
        assert!(out.files.contains(&"c.txt".to_string()));
    }

    #[test]
    fn test_glob_gitignore_aware() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        // 写 .gitignore 排除 ignored.py
        std::fs::write(dir.path().join(".gitignore"), "ignored.py\n").unwrap();
        std::fs::write(dir.path().join("ignored.py"), "x\n").unwrap();
        std::fs::write(dir.path().join("kept.py"), "y\n").unwrap();
        let tools = Tools::new();
        let entries = tools.glob("*.py", Some(&cwd)).unwrap();
        let paths: Vec<String> = entries.into_iter().map(|e| e.path).collect();
        assert!(paths.contains(&"kept.py".to_string()));
        assert!(
            !paths.contains(&"ignored.py".to_string()),
            "gitignore 应排除 ignored.py"
        );
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
        let r = tools
            .file_edit("empty.txt", "", "x", Some(&cwd), false)
            .unwrap();
        assert!(!r.ok, "空 old_string 应被拒");
        assert!(r.error.unwrap().contains("不能为空"));
        // 非空文件空 old_string 也应拒
        std::fs::write(&fp, "content\n").unwrap();
        let r = tools
            .file_edit("empty.txt", "", "x", Some(&cwd), false)
            .unwrap();
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

    // ── C-SEC-03: guard_path 拒读 cwd 内凭据文件名模式 ──

    #[test]
    fn guard_path_blocks_read_existing_pem() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("secrets.pem");
        std::fs::write(&fp, "PRIVATE\n").unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = guard_path(&guard, "secrets.pem", Some(&cwd));
        assert!(r.is_err(), "读已有 secrets.pem 应被拦截");
        let msg = format!("{:?}", r.unwrap_err());
        assert!(msg.contains("凭据文件"), "应含凭据文件提示: {}", msg);
    }

    #[test]
    fn guard_path_blocks_read_existing_id_rsa() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("id_rsa");
        std::fs::write(&fp, "KEY\n").unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = guard_path(&guard, "id_rsa", Some(&cwd));
        assert!(r.is_err(), "读已有 id_rsa 应被拦截");
    }

    #[test]
    fn guard_path_allows_read_id_rsa_pub() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("id_rsa.pub");
        std::fs::write(&fp, "PUBLIC\n").unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = guard_path(&guard, "id_rsa.pub", Some(&cwd));
        assert!(r.is_ok(), "读公钥 id_rsa.pub 不应被拦截");
    }

    #[test]
    fn guard_path_allows_create_new_pem() {
        // 创建新 cert.pem (文件不存在 → Err 分支) 不拦 — 仅阻读已有凭据
        let dir = tempfile::tempdir().unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = guard_path(&guard, "newcert.pem", Some(&cwd));
        assert!(r.is_ok(), "创建新 newcert.pem 不应被拦截");
    }

    #[test]
    fn file_edit_blocks_read_credential_filename() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("server.key");
        std::fs::write(&fp, "secret\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        // guard_path Err 经 anyhow 透传 (不降级为 EditResult) — 安全校验失败 fail-loud
        let r = tools.file_edit("server.key", "secret", "x", Some(&cwd), false);
        assert!(r.is_err(), "file_edit 读 server.key 应被拦截 (Err)");
        let msg = format!("{:?}", r.unwrap_err());
        assert!(msg.contains("凭据文件"), "应含凭据文件提示: {}", msg);
    }

    #[test]
    fn grep_blocks_read_credential_filename() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("agent.pem");
        std::fs::write(&fp, "data\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        // grep 走 guard_path → PathBlocked → Err (propagate), 不读文件
        let r = tools.grep("data", &["agent.pem".to_string()], Some(&cwd));
        assert!(r.is_err(), "grep agent.pem 应被拦截 (Err): {:?}", r);
        let msg = format!("{:?}", r.unwrap_err());
        assert!(msg.contains("凭据文件"), "应含凭据文件提示: {}", msg);
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

    // Blocker 3 finding 3.1: cwd=None 时 .. 检查不应跳过 (旧版在 if let Some(cwd) 内)
    #[test]
    fn test_guard_path_rejects_dotdot_no_cwd() {
        let guard = SecurityGuard::new();
        // 绝对路径含 .. (cwd=None, 旧版全跳过 .. 检查)
        let res = guard_path(&guard, "/tmp/../../etc/evil.txt", None);
        assert!(res.is_err(), "cwd=None 含 .. 组件也应被拒");
        assert!(res.unwrap_err().to_string().contains(".."));
    }

    // Blocker 3 finding 3.2: 符号链接旁路 — cwd 内符号链接指向敏感区应被 canonicalize 拦截
    #[test]
    fn test_guard_path_rejects_symlink_to_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        // 在 cwd 内造符号链接指向 /etc (敏感)
        #[cfg(unix)]
        {
            let link = dir.path().join("etc_link");
            std::os::unix::fs::symlink("/etc", &link).unwrap();
            let target = "etc_link/passwd";
            let res = guard_path(&guard, target, Some(&cwd));
            assert!(
                res.is_err(),
                "符号链接指向敏感区应被 canonicalize 拦截: {:?}",
                res
            );
        }
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

    // ── Blocker 8 / 3.5: 写工具大小上限 ──

    // file_edit 超 64MB 应被拒 (非 OOM, fail-loud)
    #[test]
    fn test_file_edit_rejects_oversize() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("big.txt");
        std::fs::write(&fp, "x = 1\n").unwrap();
        {
            let f = std::fs::OpenOptions::new().write(true).open(&fp).unwrap();
            f.set_len(WRITE_FILE_MAX_BYTES + 1024).unwrap();
        }
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools
            .file_edit("big.txt", "x = 1", "x = 2", Some(&cwd), false)
            .unwrap();
        assert!(!r.ok, "超 64MB 文件 file_edit 应被拒");
        assert!(r.error.unwrap().contains("超大小上限"), "应报 Oversize");
        // 内容未变 (x = 1 仍在, 末尾稀疏空洞)
        let s = std::fs::read_to_string(&fp).unwrap();
        assert!(s.starts_with("x = 1"), "拒绝时不应改动文件");
    }

    // replace_function 超 64MB 应被拒
    #[test]
    fn test_replace_function_rejects_oversize() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("big.py");
        std::fs::write(&fp, "def old():\n    return 1\n").unwrap();
        {
            let f = std::fs::OpenOptions::new().write(true).open(&fp).unwrap();
            f.set_len(WRITE_FILE_MAX_BYTES + 1024).unwrap();
        }
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools
            .replace_function("big.py", "old", "def old():\n    return 9\n", Some(&cwd))
            .unwrap();
        assert!(!r.ok, "超 64MB 文件 replace_function 应被拒");
        assert!(r.error.unwrap().contains("超大小上限"));
    }

    // apply_patch 超 64MB 应被拒
    #[test]
    fn test_apply_patch_rejects_oversize() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("big.py");
        std::fs::write(&fp, "line1\nline2\n").unwrap();
        {
            let f = std::fs::OpenOptions::new().write(true).open(&fp).unwrap();
            f.set_len(WRITE_FILE_MAX_BYTES + 1024).unwrap();
        }
        let diff = "--- a/big.py\n+++ b/big.py\n@@ -1,2 +1,2 @@\n line1\n-line2\n+LINE2\n";
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.apply_patch(diff, Some(&cwd)).unwrap();
        assert!(!r.ok, "超 64MB 文件 apply_patch 应被拒");
        assert!(r.error.unwrap().contains("超大小上限"));
    }

    // ── Blocker 8 / 3.4: flock RMW 串行化 ──

    // 并发两线程 file_edit 同文件 — flock 保证两改动都落地 (无静默丢)
    #[test]
    fn test_file_edit_flock_serializes_concurrent_edits() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("race.txt");
        // 两个唯一锚点, 各替换一处
        std::fs::write(&fp, "A1\nB1\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let tools_a = tools.clone_guard();
        let tools_b = tools.clone_guard();
        let cwd_a = cwd.clone();
        let cwd_b = cwd.clone();
        let h = std::thread::spawn(move || {
            tools_a
                .file_edit("race.txt", "A1", "A2", Some(&cwd_a), false)
                .unwrap()
        });
        let rb = tools_b
            .file_edit("race.txt", "B1", "B2", Some(&cwd_b), false)
            .unwrap();
        let ra = h.join().unwrap();
        assert!(ra.ok && rb.ok, "两并发 edit 都应成功: a={ra:?} b={rb:?}");
        let after = std::fs::read_to_string(&fp).unwrap();
        assert!(
            after.contains("A2") && after.contains("B2"),
            "两改动都应落地: {after}"
        );
    }

    // 持锁时他方阻塞 (非立即覆盖) — 模拟: 主线程持锁, 子线程 edit 应等到锁释放
    #[test]
    fn test_file_edit_blocks_until_lock_released() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("locked.txt");
        std::fs::write(&fp, "v1\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        // 主线程先持锁
        let _hold = FileLock::exclusive(&fp).unwrap();
        let tools = Tools::new();
        let fp2 = fp.clone();
        let cwd2 = cwd.clone();
        let start = std::time::Instant::now();
        let h = std::thread::spawn(move || {
            tools
                .file_edit("locked.txt", "v1", "v2", Some(&cwd2), false)
                .unwrap()
        });
        // 持锁 300ms 后释放
        std::thread::sleep(std::time::Duration::from_millis(300));
        drop(_hold);
        let r = h.join().unwrap();
        let elapsed = start.elapsed();
        assert!(r.ok, "锁释放后 edit 应成功: {r:?}");
        assert!(
            elapsed >= std::time::Duration::from_millis(250),
            "edit 应阻塞到锁释放 (实耗 {elapsed:?})"
        );
        let _ = fp2;
    }

    // ── 审计 3.6/3.7/3.8/3.12 回归 ──

    // 3.6: glob 应跳过忽略目录 (.venv/node_modules/...) — 旧版扫 .venv 10 万条目
    #[test]
    fn test_glob_skips_ignored_dirs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real.py"), "").unwrap();
        std::fs::create_dir_all(dir.path().join(".venv").join("lib")).unwrap();
        std::fs::write(dir.path().join(".venv").join("lib").join("fake.py"), "").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        std::fs::write(dir.path().join("node_modules").join("dep.py"), "").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let paths: Vec<String> = tools
            .glob("**/*.py", Some(&cwd))
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert_eq!(paths, vec!["real.py"], "glob 应只返忽略目录外的命中");
    }

    // 3.6: glob 结果上限 — 超 GLOB_RESULT_CAP 截断不 OOM
    #[test]
    fn test_glob_caps_results() {
        let dir = tempfile::tempdir().unwrap();
        // 造 GLOB_RESULT_CAP + 50 个文件
        for i in 0..(GLOB_RESULT_CAP + 50) {
            std::fs::write(dir.path().join(format!("f{i}.txt")), "").unwrap();
        }
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.glob("*.txt", Some(&cwd)).unwrap();
        assert_eq!(r.len(), GLOB_RESULT_CAP, "glob 应截断到上限");
    }

    // 3.7: grep 递归应跳过忽略目录 — 旧版扫 node_modules 百万命中
    #[test]
    fn test_grep_skips_ignored_dirs_recursive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "needle here\n").unwrap();
        std::fs::create_dir_all(dir.path().join(".venv").join("lib")).unwrap();
        std::fs::write(
            dir.path().join(".venv").join("lib").join("dep.py"),
            "needle venv\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        std::fs::write(dir.path().join("node_modules").join("x.py"), "needle nm\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let ms = tools
            .grep("needle", &[".".to_string()], Some(&cwd))
            .unwrap();
        // 仅 a.py 命中, .venv/node_modules 跳过
        assert_eq!(ms.len(), 1, "grep 应跳过忽略目录: {:?}", ms);
        assert!(ms[0].path.contains("a.py"));
    }

    // 3.7: grep 全局命中上限 — 多文件累计超 GREP_GLOBAL_HIT_CAP 停扫
    // (单文件先触 per-file cap GREP_PER_FILE_CAP=1000, 故须多文件累计触全局)
    #[test]
    fn test_grep_global_cap_stops_scan() {
        let dir = tempfile::tempdir().unwrap();
        // 3 文件各 GREP_PER_FILE_CAP(1000) 命中: 前 2 文件填满全局 2000, 第 3 跳过
        let content: String = (0..GREP_PER_FILE_CAP).map(|_| "hit hit\n").collect();
        for name in ["a.py", "b.py", "c.py"] {
            std::fs::write(dir.path().join(name), &content).unwrap();
        }
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let ms = tools.grep("hit", &[".".to_string()], Some(&cwd)).unwrap();
        assert_eq!(
            ms.len(),
            GREP_GLOBAL_HIT_CAP,
            "grep 多文件累计应截断到全局上限, 实得 {}",
            ms.len()
        );
    }

    // 3.8: 多文件 diff 两个文件都应应用 — 旧版 diffy from_str 拒多文件, 第二文件丢失
    #[test]
    fn test_apply_patch_multi_file() {
        let dir = tempfile::tempdir().unwrap();
        let f1 = dir.path().join("a.py");
        let f2 = dir.path().join("b.py");
        std::fs::write(&f1, "ctx1\nold1\nctx1b\n").unwrap();
        std::fs::write(&f2, "ctx2\nold2\nctx2b\n").unwrap();
        let diff = "--- a/a.py\n+++ b/a.py\n@@ -1,3 +1,3 @@\n ctx1\n-old1\n+new1\n ctx1b\n--- a/b.py\n+++ b/b.py\n@@ -1,3 +1,3 @@\n ctx2\n-old2\n+new2\n ctx2b\n";
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.apply_patch(diff, Some(&cwd)).unwrap();
        assert!(r.ok, "多文件 apply_patch 应成功: {:?}", r.error);
        assert_eq!(r.matches, 2, "两个文件各 1 hunk = 2 hunks");
        assert_eq!(std::fs::read_to_string(&f1).unwrap(), "ctx1\nnew1\nctx1b\n");
        assert_eq!(std::fs::read_to_string(&f2).unwrap(), "ctx2\nnew2\nctx2b\n");
    }

    // 3.8(b): 拆 2 hunk 各删 original/2 绕过 per-hunk 判据 — 聚合合计应拦
    #[test]
    fn test_apply_patch_split_hunk_full_rewrite_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("app.py");
        // 4 行文件: 2 hunk 各删 2 (合计 4 = original_lines=4)
        // 各 hunk removed(2) < 4 绕 per-hunk, 聚合 file_removed(4) >= 4 → 拒
        std::fs::write(&fp, "line1\nline2\nline3\nline4\n").unwrap();
        let diff = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,1 @@\n-line1\n-line2\n+X\n@@ -3,2 +2,1 @@\n-line3\n-line4\n+Y\n";
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.apply_patch(diff, Some(&cwd)).unwrap();
        assert!(!r.ok, "拆 hunk 全重写应被聚合判据拦: {:?}", r.error);
        assert!(r.error.unwrap().contains("全文件重写"));
        // 文件未变
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            "line1\nline2\nline3\nline4\n"
        );
    }

    // 3.12: replace_function 无 grammar (.go) 应 fail-loud 拒绝 (非破损正则回退)
    // locate_function 无 grammar → 返回 Err (非 Ok{ok:false}), 调用方见 Result
    #[test]
    fn test_replace_function_no_grammar_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("main.go");
        std::fs::write(&fp, "func foo() {\n    return 1\n}\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.replace_function(
            "main.go",
            "foo",
            "func foo() {\n    return 9\n}\n",
            Some(&cwd),
        );
        let err = r.err().unwrap().to_string();
        assert!(
            err.contains("不支持") || err.contains("grammar"),
            "应说明不支持/无 grammar: {err}"
        );
        // 文件未变 (未被破损正则损坏)
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            "func foo() {\n    return 1\n}\n"
        );
    }

    // split_multi_file_diff 单元: 单文件 → 1 元素; 多文件 → N 元素; git 扩展头丢弃
    #[test]
    fn test_split_multi_file_diff() {
        let single = "--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-x\n+y\n";
        assert_eq!(split_multi_file_diff(single).len(), 1);

        let multi = "--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-x\n+y\n--- a/b.py\n+++ b/b.py\n@@ -1,1 +1,1 @@\n-p\n+q\n";
        let segs = split_multi_file_diff(multi);
        assert_eq!(segs.len(), 2);
        assert!(segs[0].starts_with("--- a/a.py"));
        assert!(segs[1].starts_with("--- a/b.py"));

        // git 扩展头 (diff --git/index) 在首 --- 前 → 丢弃
        let with_git = "diff --git a/a.py b/a.py\nindex 123..456\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-x\n+y\n";
        let segs = split_multi_file_diff(with_git);
        assert_eq!(segs.len(), 1);
        assert!(segs[0].starts_with("--- a/a.py"), "git 扩展头应被丢弃");
    }

    // ── #6: file_edit replace_all ──

    #[test]
    fn test_file_edit_replace_all_replaces_every_occurrence() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("rep.py");
        std::fs::write(&fp, "foo\nfoo\nfoo\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .file_edit("rep.py", "foo", "bar", Some(&cwd), true)
            .unwrap();
        assert!(r.ok, "replace_all 应全量替换: {r:?}");
        assert_eq!(r.matches, 3);
        assert_eq!(std::fs::read_to_string(&fp).unwrap(), "bar\nbar\nbar\n");
    }

    #[test]
    fn test_file_edit_replace_all_false_still_rejects_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("rep.py");
        std::fs::write(&fp, "foo\nfoo\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .file_edit("rep.py", "foo", "bar", Some(&cwd), false)
            .unwrap();
        assert!(!r.ok, "replace_all=false 多匹配应拒绝");
        assert_eq!(r.matches, 2);
        // 文件未被改动
        assert_eq!(std::fs::read_to_string(&fp).unwrap(), "foo\nfoo\n");
    }

    #[test]
    fn test_file_edit_replace_all_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("rep.py");
        std::fs::write(&fp, "baz\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .file_edit("rep.py", "foo", "bar", Some(&cwd), true)
            .unwrap();
        assert!(!r.ok);
        assert_eq!(r.matches, 0);
    }

    // ── #2: write_file 整文件创建/覆盖 + create-on-empty ──

    #[test]
    fn test_write_file_creates_new_with_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        // 父目录不存在 → create_dir_all 建出
        let r = tools
            .write_file("nested/deep/new.py", "print('hi')\n", Some(&cwd))
            .unwrap();
        assert!(r.ok, "write_file 应建父目录并写入: {r:?}");
        assert_eq!(r.matches, 1);
        let fp = dir.path().join("nested/deep/new.py");
        assert!(fp.exists(), "新文件应存在");
        assert_eq!(std::fs::read_to_string(&fp).unwrap(), "print('hi')\n");
    }

    #[test]
    fn test_write_file_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("over.txt");
        std::fs::write(&fp, "old content\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .write_file("over.txt", "new content\n", Some(&cwd))
            .unwrap();
        assert!(r.ok, "write_file 覆盖应成功: {r:?}");
        assert_eq!(std::fs::read_to_string(&fp).unwrap(), "new content\n");
    }

    #[test]
    fn test_write_file_rejects_oversize_content() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let big = "x".repeat(WRITE_FILE_MAX_BYTES as usize + 1);
        let r = tools.write_file("big.txt", &big, Some(&cwd)).unwrap();
        assert!(!r.ok, "超 64MB 内容应被拒");
        assert!(r.error.unwrap().contains("超大小上限"));
    }

    #[test]
    fn test_file_edit_create_on_empty_missing_path() {
        // #2: file_edit 在缺失路径 + 空 old_string → 用 new_string 建文件 (Claude Code parity)
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .file_edit(
                "brand_new.py",
                "",
                "def f():\n    pass\n",
                Some(&cwd),
                false,
            )
            .unwrap();
        assert!(r.ok, "create-on-empty 缺失路径应建文件: {r:?}");
        let fp = dir.path().join("brand_new.py");
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            "def f():\n    pass\n"
        );
    }

    #[test]
    fn test_file_edit_existing_empty_old_string_still_rejected() {
        // #2: 已存在文件 + 空 old_string 仍拒 (L-TOOLS-02 保持; create-on-empty 仅对缺失路径)
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("exist.txt");
        std::fs::write(&fp, "data\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .file_edit("exist.txt", "", "new\n", Some(&cwd), false)
            .unwrap();
        assert!(!r.ok, "已存在文件 + 空 old_string 应拒");
        assert!(r.error.unwrap().contains("不能为空"));
        // 原文件未被改动
        assert_eq!(std::fs::read_to_string(&fp).unwrap(), "data\n");
    }

    #[test]
    fn test_file_edit_missing_path_nonempty_old_string_rejected() {
        // #2: 缺失路径 + 非空 old_string → 仍拒 (不能凭空匹配不存在的 old_string)
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .file_edit("ghost.py", "foo", "bar", Some(&cwd), false)
            .unwrap();
        assert!(!r.ok, "缺失路径 + 非空 old_string 应拒");
        assert!(r.error.unwrap().contains("文件未找到"));
    }

    // ── #6: multi_edit 原子 all-or-nothing ──

    #[test]
    fn test_multi_edit_all_succeed() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("me.py");
        std::fs::write(&fp, "a = 1\nb = 2\nc = 3\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let edits = vec![
            MultiEditItem {
                old_string: "a = 1".to_string(),
                new_string: "a = 10".to_string(),
                replace_all: false,
            },
            MultiEditItem {
                old_string: "c = 3".to_string(),
                new_string: "c = 30".to_string(),
                replace_all: false,
            },
        ];
        let r = tools.multi_edit("me.py", &edits, Some(&cwd)).unwrap();
        assert!(r.ok, "multi_edit 全成功: {r:?}");
        assert_eq!(r.matches, 2);
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            "a = 10\nb = 2\nc = 30\n"
        );
    }

    #[test]
    fn test_multi_edit_partial_failure_no_write() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("me.py");
        std::fs::write(&fp, "a = 1\nb = 2\n").unwrap();
        let original = std::fs::read_to_string(&fp).unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        // 第二项 old_string 不存在 → 整批失败, 文件保持原状
        let edits = vec![
            MultiEditItem {
                old_string: "a = 1".to_string(),
                new_string: "a = 10".to_string(),
                replace_all: false,
            },
            MultiEditItem {
                old_string: "MISSING".to_string(),
                new_string: "x".to_string(),
                replace_all: false,
            },
        ];
        let r = tools.multi_edit("me.py", &edits, Some(&cwd)).unwrap();
        assert!(!r.ok, "第二项未匹配应整批失败: {r:?}");
        assert!(r.error.unwrap().contains("第 1 项"));
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            original,
            "文件应保持编辑前状态"
        );
    }

    #[test]
    fn test_multi_edit_empty_list_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("me.py");
        std::fs::write(&fp, "a = 1\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools.multi_edit("me.py", &[], Some(&cwd)).unwrap();
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("不能为空"));
    }

    #[test]
    fn test_multi_edit_replace_all_per_item() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("me.py");
        std::fs::write(&fp, "x\nx\ny\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let edits = vec![
            MultiEditItem {
                old_string: "x".to_string(),
                new_string: "z".to_string(),
                replace_all: true,
            },
            MultiEditItem {
                old_string: "y".to_string(),
                new_string: "w".to_string(),
                replace_all: false,
            },
        ];
        let r = tools.multi_edit("me.py", &edits, Some(&cwd)).unwrap();
        assert!(r.ok);
        assert_eq!(r.matches, 3);
        assert_eq!(std::fs::read_to_string(&fp).unwrap(), "z\nz\nw\n");
    }

    // IMPL-10: buffer 膨胀超 MULTI_EDIT_BUFFER_MAX → fail-loud, 文件不动
    #[test]
    fn test_multi_edit_buffer_overflow_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("big.txt");
        // 用极小 old_string + 极大 new_string 触发膨胀 (单次 replace 即超 256MB)
        let seed = "MARKER\n".to_string();
        std::fs::write(&fp, &seed).unwrap();
        let original = std::fs::read_to_string(&fp).unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let huge = "x".repeat(MULTI_EDIT_BUFFER_MAX + 1);
        let edits = vec![MultiEditItem {
            old_string: "MARKER".to_string(),
            new_string: huge,
            replace_all: false,
        }];
        let r = tools.multi_edit("big.txt", &edits, Some(&cwd)).unwrap();
        assert!(!r.ok, "buffer 超限应 fail-loud: {r:?}");
        assert!(
            r.error.as_deref().unwrap().contains("膨胀超上限"),
            "缺膨胀错误: {:?}",
            r.error
        );
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            original,
            "文件应保持原状 (未写盘)"
        );
    }

    // IMPL-6: arrow function 替换 — `const add = (a, b) => a + b;`
    #[test]
    fn test_replace_function_arrow_js() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("arr.js");
        std::fs::write(
            &fp,
            "const add = (a, b) => a + b;\nconst sub = (a, b) => a - b;\n",
        )
        .unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        // 替换整个声明语句 (parent lexical_declaration, 含 const → ; 整句)
        let new_body = "const add = (a, b) => a + b + 100;";
        let r = tools
            .replace_function("arr.js", "add", new_body, Some(&cwd))
            .unwrap();
        assert!(r.ok, "arrow function 替换应成功: {r:?}");
        let after = std::fs::read_to_string(&fp).unwrap();
        // 整句等值断言 (防只换 declarator span 残 const 前缀 / ; 后缀 → 损坏)
        assert_eq!(
            after, "const add = (a, b) => a + b + 100;\nconst sub = (a, b) => a - b;\n",
            "arrow 替换应整句替换, 邻近函数不变: {after}"
        );
    }

    // IMPL-6: 非 arrow 的 declarator 不被误替换 — `const x = 1;` 不当函数
    #[test]
    fn test_replace_function_non_arrow_declarator_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("na.js");
        std::fs::write(&fp, "const x = 1;\nfunction real() { return 2; }\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        // x 非 arrow, real 是 function_declaration — 替换 real 应成功, 不碰 x
        let r = tools
            .replace_function("na.js", "real", "function real() { return 3; }", Some(&cwd))
            .unwrap();
        assert!(r.ok, "function_declaration 替换应成功: {r:?}");
        let after = std::fs::read_to_string(&fp).unwrap();
        assert!(after.contains("return 3"), "新体未写入: {after}");
        assert!(
            after.contains("const x = 1;"),
            "非 arrow declarator 受损: {after}"
        );
    }

    // IMPL-6: 类方法 method_definition 替换
    #[test]
    fn test_replace_function_method_definition_ts() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("cls.ts");
        std::fs::write(&fp, "class Foo {\n  bar(): number { return 1; }\n}\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .replace_function("cls.ts", "bar", "bar(): number { return 2; }", Some(&cwd))
            .unwrap();
        assert!(r.ok, "method_definition 替换应成功: {r:?}");
        let after = std::fs::read_to_string(&fp).unwrap();
        assert!(after.contains("return 2"), "新体未写入: {after}");
    }

    // RUN-5: is_nfs helper — 本地 tempdir 非 NFS (macOS apfs) → false
    #[test]
    fn test_is_nfs_local_false() {
        let dir = tempfile::tempdir().unwrap();
        // 本地 tempdir (apfs) 非 nfs
        assert!(!is_nfs(dir.path()), "本地 tempdir 不应判为 NFS");
    }

    // ── #6: notebook_edit ──

    fn write_minimal_nb(path: &Path) {
        let nb = serde_json::json!({
            "nbformat": 4,
            "nbformat_minor": 5,
            "metadata": {},
            "cells": [
                {"cell_type": "code", "metadata": {}, "source": ["print(1)\n"], "outputs": [], "execution_count": serde_json::Value::Null, "id": "cell-0"},
                {"cell_type": "code", "metadata": {}, "source": ["print(2)\n"], "outputs": [], "execution_count": serde_json::Value::Null, "id": "cell-1"},
            ],
        });
        std::fs::write(path, serde_json::to_string_pretty(&nb).unwrap()).unwrap();
    }

    #[test]
    fn test_notebook_edit_replace_by_number() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("nb.ipynb");
        write_minimal_nb(&fp);
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .notebook_edit(
                "nb.ipynb",
                None,
                Some(0),
                "print(99)\n",
                NotebookEditMode::Replace,
                Some(&cwd),
            )
            .unwrap();
        assert!(r.ok, "replace by number: {r:?}");
        let nb: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&fp).unwrap()).unwrap();
        let cells = nb["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 2);
        assert_eq!(cells[0]["source"][0].as_str().unwrap(), "print(99)\n");
        assert_eq!(cells[1]["source"][0].as_str().unwrap(), "print(2)\n");
    }

    #[test]
    fn test_notebook_edit_insert_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("nb.ipynb");
        write_minimal_nb(&fp);
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        // 在 cell-0 后插入新单元格
        let r = tools
            .notebook_edit(
                "nb.ipynb",
                Some("cell-0"),
                None,
                "import os\n",
                NotebookEditMode::Insert,
                Some(&cwd),
            )
            .unwrap();
        assert!(r.ok);
        let nb: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&fp).unwrap()).unwrap();
        let cells = nb["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 3);
        assert_eq!(cells[0]["id"].as_str().unwrap(), "cell-0");
        assert_eq!(cells[1]["source"][0].as_str().unwrap(), "import os\n");
        assert_eq!(cells[2]["id"].as_str().unwrap(), "cell-1");
    }

    #[test]
    fn test_notebook_edit_delete_by_number() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("nb.ipynb");
        write_minimal_nb(&fp);
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .notebook_edit(
                "nb.ipynb",
                None,
                Some(1),
                "",
                NotebookEditMode::Delete,
                Some(&cwd),
            )
            .unwrap();
        assert!(r.ok);
        let nb: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&fp).unwrap()).unwrap();
        let cells = nb["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0]["id"].as_str().unwrap(), "cell-0");
    }

    #[test]
    fn test_notebook_edit_missing_id() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("nb.ipynb");
        write_minimal_nb(&fp);
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .notebook_edit(
                "nb.ipynb",
                Some("no-such-id"),
                None,
                "x\n",
                NotebookEditMode::Replace,
                Some(&cwd),
            )
            .unwrap();
        assert!(!r.ok, "缺失 cell_id 应失败: {r:?}");
        assert!(r.error.unwrap().contains("未找到"));
    }

    #[test]
    fn test_notebook_edit_number_out_of_range() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("nb.ipynb");
        write_minimal_nb(&fp);
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .notebook_edit(
                "nb.ipynb",
                None,
                Some(99),
                "x\n",
                NotebookEditMode::Replace,
                Some(&cwd),
            )
            .unwrap();
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("越界"));
    }

    #[test]
    fn test_notebook_edit_rejects_non_ipynb() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("nb.txt");
        std::fs::write(&fp, "not a notebook").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .notebook_edit(
                "nb.txt",
                None,
                Some(0),
                "x\n",
                NotebookEditMode::Replace,
                Some(&cwd),
            )
            .unwrap();
        assert!(!r.ok);
        assert!(r.error.unwrap().contains(".ipynb"));
    }

    #[test]
    fn test_source_to_lines_handles_multiline() {
        assert!(source_to_lines("").is_empty());
        assert_eq!(source_to_lines("one"), vec!["one"]);
        assert_eq!(source_to_lines("a\nb\n"), vec!["a\n", "b\n"]);
        assert_eq!(source_to_lines("a\nb"), vec!["a\n", "b"]);
    }

    // ── E1 生态统一 glob 规范 (issue #20, fusion-event/docs/glob-spec.md) ──
    // `*` 不跨 `/`, `**` 跨目录, `?` 单个非 `/` 字符。glob 匹配相对 cwd 路径。

    // E1 例 1: `src/*.swift` 命中 src/a.swift, 不命中 src/sub/a.swift (* 不跨 /)
    #[test]
    fn test_glob_e1_star_within_segment() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::create_dir_all(dir.path().join("src").join("sub")).unwrap();
        std::fs::write(dir.path().join("src").join("a.swift"), "").unwrap();
        std::fs::write(dir.path().join("src").join("sub").join("a.swift"), "").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let mut paths: Vec<String> = tools
            .glob("src/*.swift", Some(&cwd))
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        paths.sort();
        assert_eq!(paths, vec!["src/a.swift"], "* 应仅命中同层, 不跨 /");
    }

    // E1 例 2: `src/**/*.swift` 命中 src/a.swift + src/x/y/a.swift (** 跨目录)
    #[test]
    fn test_glob_e1_doublestar_across_dirs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src").join("x").join("y")).unwrap();
        std::fs::write(dir.path().join("src").join("a.swift"), "").unwrap();
        std::fs::write(
            dir.path().join("src").join("x").join("y").join("a.swift"),
            "",
        )
        .unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let mut paths: Vec<String> = tools
            .glob("src/**/*.swift", Some(&cwd))
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            vec!["src/a.swift", "src/x/y/a.swift"],
            "** 应跨目录命中多层"
        );
    }

    // E1 例 3: `bin/?s` 命中 bin/ls, 不命中 bin/less (? 恰一非 / 字符)
    #[test]
    fn test_glob_e1_question_one_char() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        std::fs::write(dir.path().join("bin").join("ls"), "").unwrap();
        std::fs::write(dir.path().join("bin").join("less"), "").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let mut paths: Vec<String> = tools
            .glob("bin/?s", Some(&cwd))
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        paths.sort();
        assert_eq!(paths, vec!["bin/ls"], "? 应恰匹配一字符, 不匹配 less");
    }

    // ── 0827 审计 P1 回归 (L-9/L-10/L-11/L-12/M-12.2) ──

    // L-9: check_size 在锁内执行 — 超大文件 file_edit 仍被拒, 文件未变。
    // TOCTOU 直接复现难 (需并发方在 check→read 间扩文件), 测不变量: 锁内 check 路径与原行为等价 (超限拒, 内容不变)。
    #[test]
    fn l9_check_size_under_lock_rejects_oversize() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("big.txt");
        std::fs::write(&fp, "x = 1\n").unwrap();
        {
            let f = std::fs::OpenOptions::new().write(true).open(&fp).unwrap();
            f.set_len(WRITE_FILE_MAX_BYTES + 1024).unwrap();
        }
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools
            .file_edit("big.txt", "x = 1", "x = 2", Some(&cwd), false)
            .unwrap();
        assert!(!r.ok, "超 64MB 应被锁内 check_size 拒");
        assert!(r.error.unwrap().contains("超大小上限"));
        // 内容未变 — 锁内拒不写
        let s = std::fs::read_to_string(&fp).unwrap();
        assert!(s.starts_with("x = 1"), "拒绝时不应改动文件");
        // sidecar 锁文件残留 0 字节 (永不删), 但 data 文件未被 rename
        assert!(fp.exists(), "data 文件应仍在原处");
    }

    // L-9: multi_edit 锁内 check_size 拒超大文件
    #[test]
    fn l9_multi_edit_check_size_under_lock_rejects_oversize() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("big.txt");
        std::fs::write(&fp, "a\nb\n").unwrap();
        {
            let f = std::fs::OpenOptions::new().write(true).open(&fp).unwrap();
            f.set_len(WRITE_FILE_MAX_BYTES + 512).unwrap();
        }
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools
            .multi_edit(
                "big.txt",
                &[MultiEditItem {
                    old_string: "a".to_string(),
                    new_string: "A".to_string(),
                    replace_all: false,
                }],
                Some(&cwd),
            )
            .unwrap();
        assert!(!r.ok, "超 64MB multi_edit 应被锁内 check_size 拒");
        assert!(r.error.unwrap().contains("超大小上限"));
    }

    // L-10: apply_patch 旧版 `if let Ok(canonical)` 在 canonicalize 失败时静默跳过 cwd 校验 (fail-open)。
    // 现版 fail-closed (`with_context?`)。symlink 逃逸由 guard_path (第一道门, 见 line 1189) 拦截,
    // L-10 的 apply 后 canonicalize 是纵深冗余。测两路:
    //   (a) cwd 内正常文件 apply_patch 仍成功 (fail-closed 不破正常路径)
    //   (b) symlink 指向 cwd 外 → guard_path 拦 (纵深防御不漏)
    #[test]
    fn l10_apply_patch_normal_path_still_works_and_symlink_blocked() {
        // (a) 正常路径不破
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("app.py");
        std::fs::write(&fp, "ctx\nold\nctxb\n").unwrap();
        let diff = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n ctx\n-old\n+new\n ctxb\n";
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.apply_patch(diff, Some(&cwd)).unwrap();
        assert!(r.ok, "cwd 内正常 apply_patch 应成功: {:?}", r.error);
        assert_eq!(std::fs::read_to_string(&fp).unwrap(), "ctx\nnew\nctxb\n");

        // (b) symlink 逃逸 — guard_path 第一道门拦, apply_patch 返 Err (非 EditResult)
        let dir2 = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let real_file = outside.path().join("real.py");
        std::fs::write(&real_file, "ctx\nold\nctxb\n").unwrap();
        let link = dir2.path().join("link.py");
        std::os::unix::fs::symlink(&real_file, &link).unwrap();
        let diff2 = "--- a/link.py\n+++ b/link.py\n@@ -1,3 +1,3 @@\n ctx\n-old\n+new\n ctxb\n";
        let cwd2 = dir2.path().to_string_lossy().to_string();
        let res = tools.apply_patch(diff2, Some(&cwd2));
        assert!(
            res.is_err(),
            "symlink 逃逸应被 guard_path 拦 (Err 非 EditResult)"
        );
        // 真实文件未变
        assert_eq!(
            std::fs::read_to_string(&real_file).unwrap(),
            "ctx\nold\nctxb\n"
        );
    }

    // L-11: 删除行 `--- foo` (原源码 `-- foo` Lua/SQL 注释) 不应被误判为新文件头。
    // 旧版 starts_with("--- ") 误拆 hunk 中段 → 两片段均畸形 → Patch::from_str 拒。
    // 现版 peek-ahead: `--- ` 仅当后跟 `+++ ` 才算头 → 单文件单片段, 补丁成功。
    #[test]
    fn l11_split_no_misjudge_deletion_line_as_header() {
        // hunk 内含 `--- foo` 删除行 (后无 +++ ) — 应被当作删除行, 非新文件头
        let diff =
            "--- a/app.lua\n+++ b/app.lua\n@@ -1,3 +1,2 @@\n local x = 1\n--- foo\n+local x = 2\n";
        let segs = split_multi_file_diff(diff);
        assert_eq!(segs.len(), 1, "删除行 --- foo 不应误拆为新文件头");
        assert!(segs[0].contains("--- foo"), "删除行应留在片段内");
    }

    // L-11: 真实多文件补丁 (含 hunk 内删除行) 仍正确拆 N 段
    // 源码行 `-- c1` (注释) → diff 删除行 `--- c1` (diff 标记 - + 源码 -- c1) — 旧版误判此为头
    #[test]
    fn l11_multi_file_with_deletion_lines_still_splits() {
        let diff = "--- a/a.py\n+++ b/a.py\n@@ -1,3 +1,2 @@\n ctx\n--- c1\n+ctx\n--- a/b.py\n+++ b/b.py\n@@ -1,2 +1,1 @@\n--- c2\n+ok\n";
        let segs = split_multi_file_diff(diff);
        assert_eq!(segs.len(), 2, "两文件头各成一段 (删除行 --- c1 不误拆)");
        assert!(segs[0].starts_with("--- a/a.py"));
        assert!(segs[1].starts_with("--- a/b.py"));
        // 删除行 --- c1/--- c2 (源码 -- c1/-- c2 经 diff 编码) 留在各自片段
        assert!(segs[0].contains("--- c1"), "删除行应留在片段 0");
        assert!(segs[1].contains("--- c2"), "删除行应留在片段 1");
    }

    // L-12: Insert 模式 cell_id 不存在 → fail-loud 报错 (旧版静默 append 末尾)
    #[test]
    fn l12_insert_missing_cell_id_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("nb.ipynb");
        write_minimal_nb(&fp);
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .notebook_edit(
                "nb.ipynb",
                Some("no-such-id"),
                None,
                "import os\n",
                NotebookEditMode::Insert,
                Some(&cwd),
            )
            .unwrap();
        assert!(!r.ok, "Insert 缺失 cell_id 应失败, 非静默 append: {r:?}");
        let err = r.error.unwrap();
        assert!(
            err.contains("cell_id=no-such-id") && err.contains("未找到"),
            "应报 cell_id 未找到: {err}"
        );
        // 文件未变 (未静默 append)
        let nb: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&fp).unwrap()).unwrap();
        assert_eq!(
            nb["cells"].as_array().unwrap().len(),
            2,
            "不应静默追加单元格"
        );
    }

    // L-12: Insert 模式无 id 无 num → 追加末尾 (显式 append 语义保留)
    #[test]
    fn l12_insert_no_id_no_num_appends() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("nb.ipynb");
        write_minimal_nb(&fp);
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .notebook_edit(
                "nb.ipynb",
                None,
                None,
                "import os\n",
                NotebookEditMode::Insert,
                Some(&cwd),
            )
            .unwrap();
        assert!(r.ok, "无 id 无 num Insert 应 append 末尾: {r:?}");
        let nb: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&fp).unwrap()).unwrap();
        let cells = nb["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 3, "应追加一个单元格");
        assert_eq!(cells[2]["source"][0].as_str().unwrap(), "import os\n");
    }

    // M-12.2: read_data_to_string 非 UTF-8 文件错误含文件名
    #[test]
    fn m12_2_read_data_to_string_error_has_filename() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("latin1.txt");
        // 写入非 UTF-8 字节 (0xFF 非 ASCII 起始字节, 无效 UTF-8 序列)
        std::fs::write(&fp, b"before\xff\xfeafter").unwrap();
        let err = FileLock::read_data_to_string(&fp).err().unwrap();
        let msg = err.to_string();
        assert!(msg.contains("latin1.txt"), "错误消息应含文件名, got: {msg}");
        assert!(!msg.is_empty(), "应保留原始 UTF-8 错误描述, got: {msg}");
    }
}
