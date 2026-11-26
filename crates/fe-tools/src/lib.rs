// fe-tools — native file tools (PRD §Claude-SDK comparison: localized BashTool/FileEdit/GlobTool/GrepTool)
//             + surgical patch engine (PRD §DeepSeek comparison: Unified Diff application + function-level replacement, full-file rewrite forbidden)
//
// Tools:
//   file_edit(path, old, new, cwd, replace_all)  — unique-match exact replacement (replace_all = all), atomic write
//   glob(pattern, cwd)              — recursive glob pattern match, returns relative paths
//   grep(pattern, paths, cwd)       — regex per-line search, returns file/line/content
//   apply_patch(diff, cwd)          — Unified Diff parse + apply (diffy), full-file wipe forbidden
//   replace_function(path, fn_name, new_body, cwd) — tree-sitter function locate, byte-slice replace
//
// Security: all paths validated by fe_security::SecurityGuard::validate_path for sensitive paths + escape protection

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
    #[error("path security validation failed: {0}")]
    PathBlocked(String),
    #[error("file not found: {0}")]
    NotFound(String),
    #[error("old_string is not a unique match ({0} hits), ambiguous edit rejected")]
    Ambiguous(usize),
    #[error("old_string did not match")]
    NoMatch,
    #[error(
        "full-file rewrite forbidden (diff wipes original content) — only surgical patches allowed"
    )]
    FullRewriteForbidden,
    #[error("file exceeds size cap ({size} > {max} bytes) — OOM guard, whole-file read rejected")]
    Oversize { size: u64, max: u64 },
    #[error("function {0} not found")]
    FunctionNotFound(String),
    #[error("regex compile failed: {0}")]
    Regex(#[from] regex::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("multi_edit item {index}: {reason}")]
    MultiEditItem { index: usize, reason: String },
    #[error("notebook edit failed: {0}")]
    Notebook(String),
}

// ── Result types (serde, 4-layer passthrough) ──

/// Common result for file_edit / apply_patch / replace_function
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EditResult {
    pub ok: bool,
    pub path: Option<String>,
    pub error: Option<String>,
    /// Matched/replaced count (file_edit=replacement count, apply_patch=hunk count, replace_function=1/0)
    pub matches: u32,
}

/// Single glob hit
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobEntry {
    pub path: String,
    pub is_dir: bool,
}

/// Single grep hit
/// #7: context_before/context_after (content mode -A/-B/-C context lines), empty by default (no context)
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

// ── #7: ripgrep parity — grep output modes / options / results ──

/// grep output mode (ripgrep parity)
/// content (default): per-line hits + optional context; files_with_matches (-l): file names only; count (-c): per-file hit count
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrepOutputMode {
    #[default]
    Content,
    FilesWithMatches,
    Count,
}

/// grep per-file hit count (count mode)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrepFileCount {
    pub path: String,
    pub count: u32,
}

/// grep options (#7 ripgrep parity)
/// output_mode: content|files_with_matches|count
/// after/before/context: -A/-B/-C context lines (only effective in content mode)
/// multiline: cross-line matching (RegexBuilder multi_line + whole-file buffer)
/// glob_include/glob_exclude: -g include/exclude glob filters on file paths (globset)
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

/// grep aggregated output (#7: unified return for all three output modes)
/// content mode → matches populated, files/counts empty
/// files_with_matches mode → files populated (deduped + sorted), matches/counts empty
/// count mode → counts populated (per-file hit count), matches/files empty
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

// ── #6: replace_all / MultiEdit / NotebookEdit extensions ──

/// Single MultiEdit item (serde, IPC/PyO3 passthrough)
/// replace_all=false (default): old_string must be unique in the file (Ambiguous rejects)
/// replace_all=true: replace all occurrences for this item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiEditItem {
    pub old_string: String,
    pub new_string: String,
    #[serde(default)]
    pub replace_all: bool,
}

/// notebook edit mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NotebookEditMode {
    /// Replace target cell source (requires cell_id or cell_number to locate)
    #[default]
    Replace,
    /// Insert a new cell after the target cell
    Insert,
    /// Delete the target cell
    Delete,
}

/// Tools controller — holds a reused SecurityGuard, stateless
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
        info!("Tools::new() — native file tools ready (reuses SecurityGuard)");
        Self {
            guard: SecurityGuard::new(),
        }
    }

    /// Clone the guard (SecurityGuard Clone) — test helper, production shares a single stateless instance
    #[cfg(test)]
    pub(crate) fn clone_guard(&self) -> Self {
        Self {
            guard: self.guard.clone(),
        }
    }

    /// file_edit — unique-match old_string → new_string exact replacement, atomic write
    /// (PRD FileEdit: rejects ambiguous edits, old must be unique in the file)
    /// #6: replace_all=true → replace all matches (Claude Code FileEdit parity); false (default) → unique match
    pub fn file_edit(
        &self,
        path: &str,
        old_string: &str,
        new_string: &str,
        cwd: Option<&str>,
        replace_all: bool,
    ) -> Result<EditResult> {
        let abs = guard_path(&self.guard, path, cwd).map_err(|e| anyhow::anyhow!(e))?;
        // #2 create-on-empty: missing path + empty old_string → create the file with new_string (Claude Code FileEdit parity)
        // missing path + non-empty old_string → still rejected (cannot match an old_string that does not exist)
        if !abs.exists() {
            if old_string.is_empty() {
                return self.write_file(path, new_string, cwd);
            }
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(format!("file not found: {}", path)),
                matches: 0,
            });
        }
        // L-TOOLS-02: existing file + empty old_string → matches().count()==1 falsely unique → rejected (create-on-empty only for missing paths)
        if old_string.is_empty() {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some("old_string must not be empty".to_string()),
                matches: 0,
            });
        }
        // L-9: take the lock before check_size — checking metadata before the lock leaves a TOCTOU window (a concurrent writer
        // grows the file past the cap between check→read; check passes but read OOMs). Size checked under the lock: concurrent RMW
        // writers hold the same sidecar lock, so file size is stable across check→read.
        // Blocker 8 / 3.4: flock LOCK_EX wraps the RMW, preventing silent loss from concurrent edits
        let lock = match FileLock::exclusive(&abs) {
            Ok(l) => l,
            Err(e) => {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("failed to acquire file lock: {}", e)),
                    matches: 0,
                });
            }
        };
        // Blocker 8 / 3.5: pre-check size under lock to prevent OOM
        if let Err(e) = check_size(&abs) {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(e.to_string()),
                matches: 0,
            });
        }
        let content = FileLock::read_data_to_string(&abs)
            .with_context(|| format!("failed to read {}", abs.display()))?;
        let count = content.matches(old_string).count();
        if count == 0 {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some("old_string did not match".to_string()),
                matches: 0,
            });
        }
        // #6: replace_all=false → reject when count>1 (unique-match contract); true → replace all
        if !replace_all && count > 1 {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(format!("old_string is not a unique match ({} hits)", count)),
                matches: count as u32,
            });
        }
        let updated = if replace_all {
            content.replace(old_string, new_string)
        } else {
            content.replacen(old_string, new_string, 1)
        };
        // Write completes under the lock (atomic_write renames to target while the lock still holds the file fd — other agents block for the duration of this RMW)
        atomic_write(&abs, &updated)?;
        drop(lock);
        info!(path = %abs.display(), replace_all, "file_edit replacement succeeded");
        Ok(EditResult {
            ok: true,
            path: Some(path.to_string()),
            error: None,
            matches: count as u32,
        })
    }

    /// write_file — whole-file create/overwrite (#2, Claude Code Write parity)
    /// Missing parent dir → create_dir_all; existing file → atomic overwrite; always via atomic_write (temp+persist rename)
    /// Content passes guard_path (escape/sensitive protection) + size cap (WRITE_FILE_MAX_BYTES OOM guard)
    pub fn write_file(&self, path: &str, content: &str, cwd: Option<&str>) -> Result<EditResult> {
        let abs = guard_path(&self.guard, path, cwd).map_err(|e| anyhow::anyhow!(e))?;
        // #2: content size cap — guards against whole-write OOM on 1GB generated files (same semantics as check_size, but a new file has no metadata to check, so content.len is validated)
        if content.len() as u64 > WRITE_FILE_MAX_BYTES {
            warn!(
                path = %abs.display(),
                size = content.len(),
                max = WRITE_FILE_MAX_BYTES,
                "write_file content exceeds 64MB cap, rejected"
            );
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(format!(
                    "file exceeds size cap ({} > {} bytes) — OOM guard",
                    content.len(),
                    WRITE_FILE_MAX_BYTES
                )),
                matches: 0,
            });
        }
        // #2: missing parent dir → create_dir_all (Claude Code Write creates parent dirs)
        let parent = abs.parent().unwrap_or_else(|| Path::new("."));
        if !parent.exists() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create parent directory: {}", parent.display())
            })?;
            debug!(dir = %parent.display(), "write_file created parent directory");
        }
        // #2: existing file takes flock LOCK_EX against concurrency (same lock semantics as the file_edit RMW; skipped when the file does not exist)
        let _lock = if abs.exists() {
            match FileLock::exclusive(&abs) {
                Ok(l) => Some(l),
                Err(e) => {
                    return Ok(EditResult {
                        ok: false,
                        path: Some(path.to_string()),
                        error: Some(format!("failed to acquire file lock: {}", e)),
                        matches: 0,
                    });
                }
            }
        } else {
            None
        };
        atomic_write(&abs, content)?;
        info!(path = %abs.display(), bytes = content.len(), "write_file write succeeded (create/overwrite)");
        Ok(EditResult {
            ok: true,
            path: Some(path.to_string()),
            error: None,
            matches: 1,
        })
    }

    /// multi_edit — sequential batch edits on one file, atomic all-or-nothing (#6)
    /// Applies each item in order to an in-memory buffer (old→new, replace_all supported); any failure → buffer discarded, nothing written, file keeps its pre-edit state
    /// A single flock wraps the whole batch, preventing silent loss from concurrent edits
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
                error: Some("edits list must not be empty".to_string()),
                matches: 0,
            });
        }
        let abs = guard_path(&self.guard, path, cwd).map_err(|e| anyhow::anyhow!(e))?;
        if !abs.exists() {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(format!("file not found: {}", path)),
                matches: 0,
            });
        }
        // L-9: take the lock before check_size (pre-lock check leaves a TOCTOU window)
        let lock = match FileLock::exclusive(&abs) {
            Ok(l) => l,
            Err(e) => {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("failed to acquire file lock: {}", e)),
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
            .with_context(|| format!("failed to read {}", abs.display()))?;
        let mut total_matches: u32 = 0;
        // Apply each edit in order; any failure → immediate return, nothing written (buffer discarded), lock released on drop
        for (i, item) in edits.iter().enumerate() {
            if item.old_string.is_empty() {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!(
                        "multi_edit item {}: old_string must not be empty",
                        i
                    )),
                    matches: total_matches,
                });
            }
            let count = buffer.matches(&item.old_string).count();
            if count == 0 {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("multi_edit item {}: old_string did not match", i)),
                    matches: total_matches,
                });
            }
            if !item.replace_all && count > 1 {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!(
                        "multi_edit item {}: old_string is not a unique match ({} hits)",
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
            // IMPL-10: after each item, check buffer growth — exceeding MULTI_EDIT_BUFFER_MAX fails loud,
            // file untouched (atomic_write not reached, buffer discarded), preventing cumulative OOM from many edits on large files.
            if buffer.len() > MULTI_EDIT_BUFFER_MAX {
                warn!(path = %abs.display(), idx = i, len = buffer.len(), max = MULTI_EDIT_BUFFER_MAX,
                    "multi_edit buffer exceeds cap, write rejected (growth guard)");
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!(
                        "multi_edit buffer exceeds cap after item {} ({} > {} bytes), write rejected",
                        i,
                        buffer.len(),
                        MULTI_EDIT_BUFFER_MAX
                    )),
                    matches: total_matches,
                });
            }
        }
        // All items succeeded → single atomic write
        atomic_write(&abs, &buffer)?;
        drop(lock);
        info!(path = %abs.display(), edits = edits.len(), "multi_edit batch replacement succeeded");
        Ok(EditResult {
            ok: true,
            path: Some(path.to_string()),
            error: None,
            matches: total_matches,
        })
    }

    /// notebook_edit — Jupyter .ipynb cell editing (#6)
    /// Locates by cell_id (nbformat v4+) or cell_number (0-based index), edit_mode=replace/insert/delete
    /// serde_json parse/write-back, keeping nbformat 4.x compliance; new_source is the new cell source for replace/insert
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
                error: Some(format!("file not found: {}", path)),
                matches: 0,
            });
        }
        // Only the .ipynb extension is accepted
        if abs.extension().and_then(|e| e.to_str()) != Some("ipynb") {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some("notebook_edit only supports .ipynb files".to_string()),
                matches: 0,
            });
        }
        // L-9: take the lock before check_size (pre-lock check leaves a TOCTOU window)
        let lock = match FileLock::exclusive(&abs) {
            Ok(l) => l,
            Err(e) => {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("failed to acquire file lock: {}", e)),
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
            .with_context(|| format!("failed to read {}", abs.display()))?;
        let mut nb: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("notebook parse failed: {}", e))?;
        let cells = nb
            .get_mut("cells")
            .and_then(|c| c.as_array_mut())
            .ok_or_else(|| anyhow::anyhow!("notebook is missing the cells array"))?;

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
                return Err(anyhow::anyhow!("cell_id={} not found", id));
            }
            if let Some(num) = cell_number {
                if num < 0 || num as usize >= cells.len() {
                    return Err(anyhow::anyhow!(
                        "cell_number {} out of range ({} cells total)",
                        num,
                        cells.len()
                    ));
                }
                return Ok(num as usize);
            }
            Err(anyhow::anyhow!("cell_id or cell_number is required"))
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
                                    "cell_number {} out of range ({} cells total, insert allows 0..={})",
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
                        // L-12: without cell_number, locate by cell_id and insert after it.
                        // The old `Err(_) => cells.len()` merged "cell_id not found" with "no id and no num" into a silent append —
                        // a caller passing id="bad" to insert at a specific position got the cell silently appended at the end; the API contract was inconsistent across the three modes
                        // (Replace/Delete both report missing-id). Fix: cell_id given but not found → error (same as Replace/Delete);
                        // callers wanting "insert or append" must pass cell_number=Some(cells.len()) explicitly.
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
                                        error: Some(format!(
                                            "cell_id={} not found (Insert mode)",
                                            id
                                        )),
                                        matches: 0,
                                    });
                                }
                            }
                        } else {
                            // No cell_id and no cell_number → append at the end (explicit append semantics)
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

        // Ensure nbformat metadata compliance
        if nb.get("nbformat").is_none() {
            nb["nbformat"] = serde_json::json!(4);
        }
        if nb.get("nbformat_minor").is_none() {
            nb["nbformat_minor"] = serde_json::json!(5);
        }
        let out = serde_json::to_string_pretty(&nb)
            .map_err(|e| anyhow::anyhow!("notebook serialization failed: {}", e))?;
        atomic_write(&abs, &out)?;
        drop(lock);
        info!(path = %abs.display(), mode = ?edit_mode, "notebook_edit succeeded");
        Ok(EditResult {
            ok: true,
            path: Some(path.to_string()),
            error: None,
            matches: 1,
        })
    }

    /// glob — recursive glob pattern matching (glob crate), returns paths relative to cwd + is_dir
    /// pattern examples: "**/*.py", "src/*.rs"
    pub fn glob(&self, pattern: &str, cwd: Option<&str>) -> Result<Vec<GlobEntry>> {
        let base = cwd.unwrap_or(".");
        // Security-check cwd
        let cwd_v = self.guard.validate_cwd(base);
        if !cwd_v.allowed {
            return Err(anyhow::anyhow!(ToolsError::PathBlocked(
                cwd_v
                    .reason
                    .unwrap_or_else(|| "cwd is sensitive".to_string()),
            )));
        }
        let cwd_abs = std::fs::canonicalize(base).unwrap_or_else(|_| PathBuf::from(base));
        // #7: gitignore-aware traversal — ignore::WalkBuilder reads .gitignore + hidden files + IGNORED_DIRS baseline
        // Old glob::glob matched the filesystem directly without reading .gitignore → hits .gitignore'd files (e.g. dist/ artifacts)
        // #20: literal_separator(true) — `*`/`?` do not cross `/`, `**` still crosses directories. Aligns with the fusion-event E1 unified glob spec.
        //   globset by default lets `*` cross `/` (conflicts with E1: `src/*.swift` would wrongly match src/sub/a.swift). literal_separator tightens this to E1.
        let pat = globset::GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .map_err(|e| anyhow::anyhow!("invalid glob pattern: {}", e))?
            .compile_matcher();
        let mut out = Vec::new();
        let mut skipped_ignored = 0u32;
        let mut builder = ignore::WalkBuilder::new(&cwd_abs);
        builder
            .hidden(false) // explicit: do not auto-skip hidden files (the old version only skipped IGNORED_DIRS; callers may want .github/...)
            .ignore(true) // read .gitignore
            .git_ignore(true)
            .git_exclude(true)
            .git_global(true)
            .parents(true)
            .follow_links(false)
            // honor .gitignore even outside git repos (default require_git=true only applies inside git repos; fusion subprojects are mostly standalone repos)
            .require_git(false);
        // IGNORED_DIRS as a hard baseline (skip .venv/node_modules even without .gitignore — guards against 100k-entry OOM)
        builder.add_custom_ignore_filename(".venv");
        for entry in builder.build() {
            let ent = match entry {
                Ok(e) => e,
                Err(e) => {
                    debug!(error = %e, "glob traversal entry failed, skipping");
                    continue;
                }
            };
            let p = ent.path();
            // Skip the cwd root itself (WalkBuilder includes the root)
            if p == cwd_abs.as_path() {
                continue;
            }
            // IGNORED_DIRS hard baseline (add_custom_ignore_filename matches by file name only; this backs it up on directory components)
            if is_in_ignored_dir(p) {
                skipped_ignored += 1;
                continue;
            }
            let rel = p
                .strip_prefix(&cwd_abs)
                .map(|r| r.to_string_lossy().into_owned())
                .unwrap_or_else(|_| p.to_string_lossy().into_owned());
            // glob matches against the relative path (same semantics as the old **/*.py)
            if !pat.is_match(&rel) {
                continue;
            }
            // L-TOOLS-01: matched parent directories are validated for sensitive prefixes via validate_cwd
            // D4-6 perf evaluation (2026-08-29): this per-entry validate_cwd cannot be reduced to "validate cwd once" —
            // the cwd root is already validated (line 655), but sensitive subdirectories (cwd=/home/user hitting /home/user/.ssh) must be blocked per entry.
            // strip_prefix(cwd_abs) only proves the hit is under cwd, not that it is non-sensitive. validate_cwd is an O(sensitive_paths)
            // pure in-memory prefix comparison (no fs syscalls), negligible hot-path cost. Keeping per-entry validation = correctness first, no degradation.
            let check_target = if p.is_dir() {
                p.to_string_lossy().into_owned()
            } else {
                p.parent()
                    .map(|d| d.to_string_lossy().into_owned())
                    .unwrap_or_else(|| p.to_string_lossy().into_owned())
            };
            let v = self.guard.validate_cwd(&check_target);
            if !v.allowed {
                warn!(path = %p.display(), reason = v.reason, "glob hit a sensitive path, skipping");
                continue;
            }
            let is_dir = p.is_dir();
            out.push(GlobEntry { path: rel, is_dir });
            if out.len() >= GLOB_RESULT_CAP {
                warn!(
                    cap = GLOB_RESULT_CAP,
                    skipped_ignored, "glob hits exceed cap, truncated"
                );
                break;
            }
        }
        if skipped_ignored > 0 {
            debug!(
                skipped_ignored,
                "glob skipped hits inside ignored directories"
            );
        }
        info!(count = out.len(), skipped_ignored, "glob done");
        Ok(out)
    }

    /// grep — regex per-line search (content mode, legacy-compatible entry)
    /// paths is a list of files or directories (directories searched recursively); returns each hit (relative path, line number, content)
    pub fn grep(
        &self,
        pattern: &str,
        paths: &[String],
        cwd: Option<&str>,
    ) -> Result<Vec<GrepMatch>> {
        let out = self.grep_run(pattern, paths, cwd, &GrepOptions::default())?;
        Ok(out.matches)
    }

    /// grep_with_opts — #7 ripgrep parity: output mode / context / multiline / glob filtering
    pub fn grep_with_opts(
        &self,
        pattern: &str,
        paths: &[String],
        cwd: Option<&str>,
        opts: &GrepOptions,
    ) -> Result<GrepOutput> {
        self.grep_run(pattern, paths, cwd, opts)
    }

    /// grep core implementation — unified across content/files_with_matches/count modes
    fn grep_run(
        &self,
        pattern: &str,
        paths: &[String],
        cwd: Option<&str>,
        opts: &GrepOptions,
    ) -> Result<GrepOutput> {
        // D4-7 (audit 0827 product): regex is rebuilt on every grep call (RegexBuilder + opts.multiline variant).
        // regex crate compilation is microsecond-scale (no backtracking NFA, single-pass DFA construction), far below the traversal/IO-dominated cost;
        // caching would need keying by the (pattern, multiline) pair, adding memory + a concurrency lock for <1% gain (Rule 2, no speculation).
        // callers repeating the same pattern at high frequency could cache the Regex themselves → but the API takes &str, not a precompiled Regex;
        // if future profiling shows compilation dominates, add LazyLock<HashMap<(String,bool), Regex>> (YAGNI now).
        let re = regex::RegexBuilder::new(pattern)
            .multi_line(opts.multiline)
            // multiline mode: . matches newlines (ripgrep -U semantics, cross-line block matching)
            .dot_matches_new_line(opts.multiline)
            .build()
            .map_err(|e| anyhow::anyhow!(ToolsError::Regex(e)))?;
        let base = cwd.unwrap_or(".");
        let cwd_v = self.guard.validate_cwd(base);
        if !cwd_v.allowed {
            return Err(anyhow::anyhow!(ToolsError::PathBlocked(
                cwd_v
                    .reason
                    .unwrap_or_else(|| "cwd is sensitive".to_string()),
            )));
        }
        // #7 gap 5: glob include/exclude (-g) — globset filters on file paths
        let include_set = build_globset(&opts.glob_include)?;
        let exclude_set = build_globset(&opts.glob_exclude)?;
        let mut matches: Vec<GrepMatch> = Vec::new();
        let mut files_with_matches: Vec<String> = Vec::new();
        let mut counts: Vec<GrepFileCount> = Vec::new();
        // global hit counter (content mode; files/count modes count per file and are not capped by this)
        let mut global_hits = 0usize;
        for raw in paths {
            let abs = guard_path(&self.guard, raw, cwd).map_err(|e| anyhow::anyhow!(e))?;
            // Canonicalize the traversal root (resolve ./ suffix + symlinks) to match the entry prefix walkdir produces
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
                // audit 3.7: max_depth guards against deep .venv recursion + skips ignored dirs + global hit cap
                // #7: glob include/exclude filtering + (by default callers pass directories already outside .gitignore)
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
                        warn!(
                            cap = GREP_GLOBAL_HIT_CAP,
                            "grep global hits exceed cap, stopping scan"
                        );
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
                warn!(path = %abs.display(), "grep path does not exist, skipping");
            }
        }
        files_with_matches.sort();
        files_with_matches.dedup();
        info!(
            mode = ?opts.output_mode,
            matches = matches.len(),
            files = files_with_matches.len(),
            count_files = counts.len(),
            "grep done"
        );
        Ok(GrepOutput {
            output_mode: opts.output_mode,
            matches,
            files: files_with_matches,
            counts,
        })
    }

    /// apply_patch — Unified Diff parse + apply (diffy crate)
    /// Full-file rewrite forbidden: total removed lines across the file's hunks >= the original file's line count → rejected (FullRewriteForbidden)
    /// audit 3.8: multi-file diffs must be split per file (diffy 0.4 from_str rejects multi-file with "multiple '---' lines"),
    ///   parse+apply file by file, otherwise the second file's hunks are silently lost; the full-rewrite check must aggregate removed lines across all hunks of the file
    ///   (the old per-hunk check could be bypassed by splitting into hunks each deleting original/2 → the aggregated total = original is still caught)
    pub fn apply_patch(&self, diff: &str, cwd: Option<&str>) -> Result<EditResult> {
        let base = cwd.unwrap_or(".");
        let cwd_v = self.guard.validate_cwd(base);
        if !cwd_v.allowed {
            return Err(anyhow::anyhow!(ToolsError::PathBlocked(
                cwd_v
                    .reason
                    .unwrap_or_else(|| "cwd is sensitive".to_string()),
            )));
        }
        let cwd_abs = std::fs::canonicalize(base).unwrap_or_else(|_| PathBuf::from(base));

        // audit 3.8(a): diffy 0.4 Patch::from_str rejects multi-file (parse.rs "multiple '---' lines").
        // Split into single-file diff segments at the --- headers first, then from_str + apply each; otherwise the second file is lost.
        let file_diffs = split_multi_file_diff(diff);
        if file_diffs.is_empty() {
            return Ok(EditResult {
                ok: false,
                path: None,
                error: Some("diff is empty or has no valid --- file header".to_string()),
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
                        error: Some(format!(
                            "failed to parse file {} of the diff: {}",
                            file_idx + 1,
                            e
                        )),
                        matches: total_hunks,
                    });
                }
            };
            // diffy Patch has no path() — prefer modified() (+++ header), fall back to original() (--- header)
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
                    error: Some(format!("file not found: {}", target_path)),
                    matches: total_hunks,
                });
            }
            // L-9: take the lock before check_size (pre-lock check leaves a TOCTOU window)
            // Blocker 8 / 3.4: flock LOCK_EX wraps the RMW
            let lock = match FileLock::exclusive(&abs) {
                Ok(l) => l,
                Err(e) => {
                    return Ok(EditResult {
                        ok: false,
                        path: Some(target_path.clone()),
                        error: Some(format!("failed to acquire file lock: {}", e)),
                        matches: total_hunks,
                    });
                }
            };
            // Blocker 8 / 3.5: pre-check size under lock to prevent OOM
            if let Err(e) = check_size(&abs) {
                return Ok(EditResult {
                    ok: false,
                    path: Some(target_path.clone()),
                    error: Some(e.to_string()),
                    matches: total_hunks,
                });
            }
            let original = FileLock::read_data_to_string(&abs)
                .with_context(|| format!("failed to read {}", abs.display()))?;
            let original_lines = original.lines().count();

            // audit 3.8(b): the full-rewrite check aggregates removed lines across all hunks of the file —
            // the old per-hunk check (removed >= original_lines) could be bypassed by splitting into 2 hunks each deleting original/2;
            // when the aggregated removed total >= original_lines the whole file is being rewritten → rejected (a surgical patch keeps context, so the total < original).
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
                        "full-file rewrite forbidden (the file's hunks remove all original lines) — only surgical patches allowed"
                            .to_string(),
                    ),
                    matches: total_hunks,
                });
            }

            let updated = diffy::apply(&original, &patch)
                .map_err(|e| anyhow::anyhow!("patch apply failed ({}): {}", target_path, e))?;
            // L-10: security check fail-closed — confirm the output file is still inside cwd (guards against the patch changing the path).
            // The old `if let Ok(canonical)` silently skipped the check when canonicalize failed (fail-open),
            // letting escape detection be bypassed via file symlink/IO errors. A canonicalize failure means the boundary cannot be confirmed → reject explicitly.
            let canonical = abs.canonicalize().with_context(|| {
                format!("failed to resolve patch target path: {}", abs.display())
            })?;
            if !canonical.starts_with(&cwd_abs) {
                return Ok(EditResult {
                    ok: false,
                    path: Some(target_path),
                    error: Some("patch target escapes cwd".to_string()),
                    matches: total_hunks,
                });
            }
            atomic_write(&abs, &updated)?;
            drop(lock);
            total_hunks += file_hunks;
            info!(path = %abs.display(), hunks = file_hunks, "apply_patch file succeeded");
        }
        info!(
            files = file_diffs.len(),
            hunks = total_hunks,
            "apply_patch all files succeeded"
        );
        Ok(EditResult {
            ok: true,
            path: first_path,
            error: None,
            matches: total_hunks,
        })
    }

    /// replace_function — tree-sitter locates the function definition, replaced wholesale with new_body
    /// (PRD §DeepSeek surgical patch: function-level replacement, avoiding full-file rewrites)
    /// new_body is the complete function definition text (signature + body), replacing the definition with the same function name
    /// Supported languages: py/js/ts/rs; grammar chosen by extension.
    /// M-12.1: extensions without a grammar (go/sh/lua/...) do **not fall back to regex** — regex boundaries are unreliable,
    /// they can mis-match same-named methods/nested functions and guessed end boundaries corrupt the file; rejected fail-loud (use file_edit/apply_patch instead).
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
                error: Some(format!("file not found: {}", path)),
                matches: 0,
            });
        }
        // L-9: take the lock before check_size (pre-lock check leaves a TOCTOU window)
        // Blocker 8 / 3.4: flock LOCK_EX wraps the RMW
        let lock = match FileLock::exclusive(&abs) {
            Ok(l) => l,
            Err(e) => {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("failed to acquire file lock: {}", e)),
                    matches: 0,
                });
            }
        };
        // Blocker 8 / 3.5: pre-check size under lock to prevent OOM (worst for replace_function: full-file read + full parse)
        if let Err(e) = check_size(&abs) {
            return Ok(EditResult {
                ok: false,
                path: Some(path.to_string()),
                error: Some(e.to_string()),
                matches: 0,
            });
        }
        let content = FileLock::read_data_to_string(&abs)
            .with_context(|| format!("failed to read {}", abs.display()))?;
        let ext = abs.extension().and_then(|e| e.to_str()).unwrap_or("");
        let span = locate_function(&content, ext, fn_name)?;
        let span = match span {
            Some(s) => s,
            None => {
                return Ok(EditResult {
                    ok: false,
                    path: Some(path.to_string()),
                    error: Some(format!("function {} not found", fn_name)),
                    matches: 0,
                });
            }
        };
        // Byte-slice replacement (tree-sitter gives byte ranges; content is a String, usually utf8-aligned)
        let mut updated = String::with_capacity(content.len() + new_body.len());
        updated.push_str(&content[..span.start]);
        updated.push_str(new_body);
        updated.push_str(&content[span.end..]);
        atomic_write(&abs, &updated)?;
        drop(lock);
        info!(path = %abs.display(), fn = fn_name, "replace_function succeeded");
        Ok(EditResult {
            ok: true,
            path: Some(path.to_string()),
            error: None,
            matches: 1,
        })
    }

    // PLACEHOLDER: path helpers
}

/// source_to_lines — nbformat cell source spec: list of strings, each line ends with \n (except the last)
/// Single-line source → ["whole line"]; multi-line → split on \n, keeping the trailing \n
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

/// Validates that the path stays out of sensitive areas, does not escape cwd via .., and blocks symlink bypass
/// (reuses fe_security::SecurityGuard's sensitive path set)
///
/// Blocker 3 (findings 3.1/3.2) fix:
/// - the old .. check only ran inside `if let Some(cwd)` → cwd=None skipped it entirely, allowing arbitrary file writes
/// - the old sensitive check matched the literal abs string prefix → symlink bypass (cwd/symlink/evil pointing to /etc)
///
/// New version: .. components rejected unconditionally; sensitive + escape checks use canonicalize (resolves symlinks) then starts_with
fn guard_path(
    guard: &SecurityGuard,
    raw: &str,
    cwd: Option<&str>,
) -> std::result::Result<PathBuf, ToolsError> {
    let expanded = expand_tilde(raw);
    let p = Path::new(&expanded);
    // Absolute paths validated directly; relative paths joined with cwd first
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        match cwd {
            Some(c) => Path::new(c).join(p),
            None => p.to_path_buf(),
        }
    };
    // 3.1: .. components rejected unconditionally (also blocked when cwd=None) — does not rely on canonicalize, fail-closed
    if abs
        .components()
        .any(|comp| comp == std::path::Component::ParentDir)
    {
        return Err(ToolsError::PathBlocked(format!(
            "path contains .. components, suspected escape rejected: {} (cwd={:?})",
            raw, cwd
        )));
    }
    // 3.2: sensitive path + cwd escape checks via canonicalize (resolves symlinks)
    // abs exists → canonicalize(abs), check starts_with cwd (directory inputs like "." or file targets)
    // abs missing → canonicalize(abs's parent) (creating a new file inside cwd is legitimate)
    let cwd_abs = cwd.and_then(|c| std::fs::canonicalize(c).ok());
    let (escape_check, sensitive_check) = match abs.canonicalize() {
        Ok(canonical) => {
            // C-SEC-03: file exists = read scenario (file_edit/grep on existing files), reject credential filename patterns
            // (id_rsa* / *.pem / *.key etc.) — the path prefix already blocks ~/.ssh/*; this also covers credential files inside cwd or anywhere else.
            // Creating a new file (cert.pem) takes the Err branch and is not blocked — only reads of existing credentials are blocked.
            if guard.is_sensitive_filename(&canonical.to_string_lossy()) {
                return Err(ToolsError::PathBlocked(format!(
                    "reading credential files rejected (sensitive filename pattern): {} (C-SEC-03)",
                    raw
                )));
            }
            (canonical.clone(), canonical)
        }
        Err(_) => {
            // abs missing — canonicalize the parent directory (symlinks live in the parent segments)
            match abs.parent().and_then(|p| p.canonicalize().ok()) {
                Some(canonical_parent) => (
                    canonical_parent.join(abs.file_name().unwrap_or_default()),
                    canonical_parent,
                ),
                None => {
                    // Parent missing too — literal check (.. already blocked, no symlink bypass possible)
                    // abs is constructed from the raw cwd + p, so validate starts_with against the raw cwd (not canonicalized)
                    // to avoid macOS tempdir symlink (/var → /private/var) literal-vs-canonicalized mismatches
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
                                "path escapes cwd: {} (cwd={:?})",
                                raw, cwd
                            )));
                        }
                    }
                    let v = guard.validate_cwd(&lit_parent);
                    if !v.allowed {
                        return Err(ToolsError::PathBlocked(
                            v.reason.unwrap_or_else(|| "sensitive path".to_string()),
                        ));
                    }
                    return Ok(abs);
                }
            }
        }
    };
    // cwd escape: after canonicalize the path must start with the canonicalized cwd
    if let Some(cwd_abs) = &cwd_abs {
        if !escape_check.starts_with(cwd_abs) {
            return Err(ToolsError::PathBlocked(format!(
                "path escapes cwd (after symlink resolution): {} (cwd={:?})",
                raw, cwd
            )));
        }
    }
    // Sensitive prefix: whether the canonicalized path lands in a sensitive area
    let check_target = sensitive_check.to_string_lossy().into_owned();
    let v = guard.validate_cwd(&check_target);
    if !v.allowed {
        return Err(ToolsError::PathBlocked(
            v.reason.unwrap_or_else(|| "sensitive path".to_string()),
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

/// Write-tool file size cap (Blocker 8 / 3.5) — 64MB, guards against read_to_string OOM on 1GB generated files
const WRITE_FILE_MAX_BYTES: u64 = 64 * 1024 * 1024;

// IMPL-10: the multi_edit in-memory buffer has its own cap — the file 64MB check_size only checks the original size,
// with multiple replace_all items the buffer can grow far beyond it. After each item, buffer.len() is checked against MULTI_EDIT_BUFFER_MAX
// → fail-loud Err, file untouched (buffer discarded, atomic_write never triggered, atomic rollback preserved).
// 256MB > the 64MB file cap leaves stacking headroom, catching unreasonable growth (caller passing an oversized new_string).
const MULTI_EDIT_BUFFER_MAX: usize = 256 * 1024 * 1024;

/// glob/grep result caps — guards against .venv/node_modules scans producing 100k entries OOM (audit 3.6/3.7)
/// 5000 entries suffice to locate code; beyond that, truncate + warn (callers wanting the full set should use a dedicated index tool)
const GLOB_RESULT_CAP: usize = 5000;
const GREP_GLOBAL_HIT_CAP: usize = 2000;
/// grep max recursion depth (audit 3.7) — guards against infinite recursion in deep .venv symlink webs; 20 levels covers any source tree
const GREP_MAX_DEPTH: usize = 20;

/// Default ignored directory names (audit 3.6/3.7) — common .gitignore entries + Apple Silicon build artifacts
/// glob/grep recursion skips these directories, avoiding scans of .venv site-packages (tens of thousands of symlinks) / node_modules
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

/// Whether the path sits inside an ignored directory (any path component matches IGNORED_DIRS)
fn is_in_ignored_dir(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|n| IGNORED_DIRS.contains(&n))
            .unwrap_or(false)
    })
}

/// walkdir filter_entry predicate — directory names matching IGNORED_DIRS are not descended into (prunes the whole subtree)
fn is_ignored_walkdir_entry(entry: &walkdir::DirEntry) -> bool {
    entry.file_type().is_dir()
        && entry
            .file_name()
            .to_str()
            .map(|n| IGNORED_DIRS.contains(&n))
            .unwrap_or(false)
}

// ── #7 ripgrep parity helpers ──

/// Builds a globset (None = no filtering); empty list → None (skips compilation, everything passes)
fn build_globset(patterns: &[String]) -> Result<Option<globset::GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut b = globset::GlobSetBuilder::new();
    for p in patterns {
        b.add(
            globset::Glob::new(p)
                .map_err(|e| anyhow::anyhow!("invalid glob filter pattern: {}", e))?,
        );
    }
    Ok(Some(b.build().map_err(|e| {
        anyhow::anyhow!("globset build failed: {}", e)
    })?))
}

/// Whether a file path passes the include/exclude glob filters (#7 gap 5, -g)
/// Non-empty include: must match at least one include (allowlist); non-empty exclude: any match excludes
/// Matches the path relative to the traversal root (same semantics as glob); single-file input (empty rel) → matches on file_name
/// No include → passes by default; any exclude hit → rejected
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

/// Records hit files per output mode (#7 gap 2)
/// Not called in content mode (matches are filled inside grep_file); files/count aggregate here
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

/// Relative path for glob filtering: strip_prefix(root), empty/failed → file_name (single-file semantics)
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

/// Relative path for records (display): strip_prefix(root), failed → file_name (avoids leaking absolute paths)
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

/// Pre-checks file size — returns an Oversize error past the cap (fail-loud), never silently truncates
/// (write tools read the whole file for RMW; oversized files should use a dedicated diff tool, not LLM full-file rewrites)
fn check_size(path: &Path) -> std::result::Result<(), ToolsError> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > WRITE_FILE_MAX_BYTES {
            warn!(path = %path.display(), size = meta.len(), max = WRITE_FILE_MAX_BYTES, "file exceeds 64MB cap, whole-file read rejected");
            return Err(ToolsError::Oversize {
                size: meta.len(),
                max: WRITE_FILE_MAX_BYTES,
            });
        }
    }
    Ok(())
}

/// RAII exclusive lock — holds the sidecar lockfile's fd (LOCK_EX), drop unlocks automatically (fs2 FileExt)
/// Blocker 8 / 3.4: file_edit/apply_patch/replace_function are all RMW; without a lock two agents concurrently editing one file
/// have the later write overwrite the earlier one, silently losing changes
/// Key point: lock the sidecar `<data>.fe-flock` (stable inode, never renamed), not the data file itself —
///   atomic_write swaps the data inode via temp+rename; locking the data's old inode would let the concurrent party lock the new inode → effectively unlocked (root cause of lost changes)
///   the sidecar is never renamed, so both parties contend on the same lock → true serialization. Lockfile is 0 bytes, create-if-absent, never deleted (deleting would also create an inode-swap race)
struct FileLock {
    // Holding the fd holds the lock: BSD flock(2) is associated with the open fd; the kernel releases it when the last fd is closed.
    // The field is never read — its existence is the lock's lifetime; drop FileLock → drop File → close fd → unlock.
    #[allow(dead_code)]
    file: std::fs::File,
}

impl FileLock {
    /// Locks the `<data_path>.fe-flock` sidecar (data_path is the data file's absolute path)
    fn exclusive(data_path: &Path) -> std::result::Result<Self, ToolsError> {
        // RUN-5: BSD flock is not mutually exclusive across hosts (NFS locks locally only; remotes are unaware). The current single-machine UDS
        // deployment has no NFS scenario — no distributed lock (Rule 2 — no need, over-engineering). Only detect NFS mount → warn about the limitation, do not change the lock mechanism.
        // stat -f -t <path> reads the fstype on macOS (contains nfs → NFS); silent on failure (non-macOS or missing stat does not block locking).
        if is_nfs(data_path) {
            warn!(path = %data_path.display(),
                "NFS mount detected — BSD flock is not cross-host mutually exclusive; current deployment is single-machine; \
                 use a local workspace for multi-node shared directories (known flock limitation)");
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
        debug!(lock = %lock_path.display(), data = %data_path.display(), "flock LOCK_EX acquired (sidecar)");
        Ok(Self { file })
    }

    /// Reads the full content of the data file (not the lock file) — lock already held, reading data_path is safe
    /// M-12.2: the old bare `std::fs::read_to_string` error message (e.g. "stream did not contain valid UTF-8")
    /// lacks filename context — hard to locate the failure for non-UTF-8 files (Latin-1/binary configs). Prepends the filename to io::Error.
    fn read_data_to_string(data_path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(data_path)
            .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {}", data_path.display(), e)))
    }
}

/// Sidecar lockfile path: `<data>.fe-flock`
fn sidecar_lock_path(data_path: &Path) -> PathBuf {
    let mut s = data_path.to_string_lossy().into_owned();
    s.push_str(".fe-flock");
    PathBuf::from(s)
}

/// RUN-5: detects whether the path's filesystem is NFS — macOS `stat -f -t <path>` reads the fstype.
/// Output looks like `/dev/disk1s1 apfs` or `host:/export nfs`; contains `nfs` → true.
/// Failure (non-macOS / missing stat / missing path) → false (silent, does not block the lock path).
/// Only used to warn about the BSD flock cross-host limitation, never changes lock behavior (single-machine deployment, no NFS need).
fn is_nfs(path: &Path) -> bool {
    // Probe the parent directory (path may be a not-yet-created file; the parent usually exists)
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
    debug!(path = %target.display(), fstype = %stdout.trim(), "is_nfs stat probe");
    stdout
        .split_whitespace()
        .any(|tok| tok.eq_ignore_ascii_case("nfs"))
}

/// Atomic write — NamedTempFile random name + persist atomic rename
/// C-TOOLS-01: the old version used the fixed name .fe-tmp-{pid} — concurrent same-process writes to the same directory trampled each other; rename onto a symlink could also be hijacked
/// tempfile::NamedTempFile::new_in(dir) random name avoids concurrent trampling; .persist() is an atomic rename (same FS)
/// Cross-FS (EXDEV) falls back to std::fs::write+rename (non-atomic, logged with warn)
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("no parent directory: {}", path.display()))?;
    // NamedTempFile random name (avoids same-process concurrent trampling), in the target's directory (same FS → atomic rename)
    let tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("failed to create temp file (dir={})", dir.display()))?;
    std::fs::write(tmp.path(), content)
        .with_context(|| format!("failed to write temp file {}", tmp.path().display()))?;
    match tmp.persist(path) {
        Ok(_) => Ok(()),
        Err(e) => {
            // m-SEC-03: persist failed — reuse the same random-named NamedTempFile (the old fixed name .fe-tmp-fb-{pid}
            // would trample under same-process concurrency), still in the target's directory (same FS), via std::fs::rename (atomic on the same FS).
            // PersistError { file: NamedTempFile, error: io::Error } — take the file out and retry rename.
            let persist_err = e.error;
            let tmp_retry = e.file;
            warn!(
                error = %persist_err,
                target = %path.display(),
                "persist failed, retrying with std::fs::rename (same directory, atomic on the same FS)"
            );
            let tmp_path = tmp_retry.path().to_path_buf();
            // std::fs::rename is atomic on the same FS; a true EXDEV (different FS) fails loudly with Err (never silently degrades to a non-atomic write)
            if let Err(rename_err) = std::fs::rename(&tmp_path, path) {
                return Err(anyhow::anyhow!(
                    "atomic_write rename failed ({} -> {}): persist={}; rename={}",
                    tmp_path.display(),
                    path.display(),
                    persist_err,
                    rename_err
                )
                .context("m-SEC-03: refusing to degrade to a non-atomic write, fail-loud"));
            }
            // rename succeeded → forget so drop does not delete the file (after rename the old path is gone, but NamedTempFile
            // drop would still try to delete the old path; forget only clears the handle, never touches the already-renamed file)
            std::mem::forget(tmp_retry);
            Ok(())
        }
    }
}

/// tree-sitter grammar selection by extension
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

/// Function definition node type candidates — mapped by extension
/// IMPL-6: JS/TS missed arrow functions — `const f = () => {}` is a lexical_declaration >
/// variable_declarator(name: identifier, value: arrow_function). The arrow_function node itself
/// has no name field; it must go through the variable_declarator path. method_definition (class methods) also added.
/// py: function_definition; rs: function_item; js/ts: function_declaration + method_definition
/// + variable_declarator (arrow function entry).
fn function_node_kinds(ext: &str) -> Option<&'static [&'static str]> {
    match ext {
        "py" => Some(&["function_definition"]),
        "js" | "ts" | "tsx" => Some(&[
            "function_declaration",
            "method_definition",
            "generator_function_declaration",
            // arrow function: name lives in variable_declarator, value is arrow_function
            "variable_declarator",
        ]),
        "rs" => Some(&["function_item"]),
        _ => None,
    }
}

/// Function name field — py: name, js/ts: name, rs: name
const NAME_FIELD: &str = "name";

/// Locates a function definition in source, returns the byte range (start, end)
fn locate_function(content: &str, ext: &str, fn_name: &str) -> Result<Option<ByteSpan>> {
    let kinds = match function_node_kinds(ext) {
        Some(k) => k,
        None => {
            // Audit 3.12 / M-12.1: no regex fallback when there is no grammar — the regex end boundary
            // finds the next def/fn/function/export line; hitting a nested definition inside the target
            // function ends the span early, replacing only the first few lines while the rest of the old
            // body + nested definitions remain → corrupted file. Without AST boundaries it is unreliable, fail-loud.
            warn!(ext = ext, fn_name = %fn_name, "replace_function has no grammar (ext={ext}), regex fallback rejected (unreliable boundaries, corrupts files)");
            return Err(anyhow::anyhow!(
                "replace_function does not support .{ext} files — no tree-sitter grammar, \
                 regex fallback boundaries are unreliable and would corrupt the file; use file_edit or apply_patch instead"
            ));
        }
    };
    let mut parser = match parser_for_ext(ext) {
        Some(p) => p,
        None => {
            // Same as above: parser construction failure (set_language failed) is also fail-loud
            warn!(ext = ext, fn_name = %fn_name, "replace_function parser construction failed, fallback rejected");
            return Err(anyhow::anyhow!(
                "replace_function .{ext} parser construction failed, regex fallback rejected (unreliable boundaries)"
            ));
        }
    };
    let tree = parser
        .parse(content, None)
        .context("tree-sitter parse failed")?;
    let root = tree.root_node();

    // tree-sitter 0.25 has no descendants() — stack-based preorder traversal
    // Node is Copy; each node uses its own cursor to collect children into a Vec before releasing the cursor, avoiding borrow conflicts
    let mut found: Option<ByteSpan> = None;
    let mut stack: Vec<tree_sitter::Node> = vec![root];
    while let Some(node) = stack.pop() {
        if kinds.contains(&node.kind()) {
            // IMPL-6: variable_declarator is the arrow function entry — the name is in the name field,
            // and the value must be an arrow_function for it to count as an arrow function (a plain `const x = 1`
            // must not have its body replaced). On a hit, replace the whole declaration statement (parent
            // lexical_declaration / variable_declaration), i.e. the entire `const add = (...) => ...;` line —
            // otherwise replacing only the declarator span leaves the `const ` prefix and the `;` suffix,
            // corrupting the file (const + const + ;). new_body must carry the full declaration.
            if node.kind() == "variable_declarator" {
                let is_arrow = node
                    .child_by_field_name("value")
                    .map(|v| v.kind() == "arrow_function")
                    .unwrap_or(false);
                if !is_arrow {
                    // Non-arrow-function declarator, skip (keep traversing its children)
                } else if let Some(name_node) = node.child_by_field_name(NAME_FIELD) {
                    let name_text = name_node.utf8_text(content.as_bytes()).unwrap_or("");
                    if name_text == fn_name {
                        // Take the parent full-declaration span (const/let → lexical_declaration, var → variable_declaration)
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
        // Push children onto the stack (reversed, to preserve preorder access)
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

/// Counts hunk added/removed lines (diffy Line is an enum: Context/Delete/Insert, each holding &T)
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

/// Splits a multi-file unified diff into single-file diff segments on the `--- /+++ ` file headers (audit 3.8).
///
/// diffy 0.4 `Patch::from_str` rejects multi-file diffs with "multiple '---' lines" on the second `--- ` line.
/// Real `git diff` multi-file workflows contain multiple `--- /+++` header pairs; split first, then from_str per segment.
///
/// Split rule: scan line by line; each `--- ` line (L-11: **only when followed by a `+++ ` line** does it count as a file header)
/// starts a new file segment (that `--- ` line + all lines after it, until the next `--- `+`+++ ` header). Skips `diff --git`/`index`
/// git extended headers (they come before the first `--- `).
///
/// L-11: the old version judged headers only by `starts_with("--- ")` — unified diff removes lines with a `-` prefix; if the original
/// source line is `-- foo` (Lua/SQL comment/printf format string), the diff removal line `--- foo` matches `starts_with("--- ")` and
/// triggers a mid-hunk mis-split → both segments malformed → from_str fails → a valid diff rejected. Fix: peek ahead; only a `--- `
/// followed by `+++ ` counts as a file header (headers come in pairs; the line after a removal line is not `+++ `).
/// Single-file diff (no second `--- `+`+++ ` header) → returns a 1-element Vec.
fn split_multi_file_diff(diff: &str) -> Vec<String> {
    let lines: Vec<&str> = diff.lines().collect();
    let mut segments: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    for i in 0..lines.len() {
        let line = lines[i];
        // L-11: only a `--- ` line followed by a `+++ ` line counts as a new file header (they come in pairs),
        // avoiding misjudging the removal line `--- foo` (original source `-- foo`) as a header, preventing mid-hunk mis-splits.
        let is_file_header =
            line.starts_with("--- ") && i + 1 < lines.len() && lines[i + 1].starts_with("+++ ");
        if is_file_header {
            // New file segment start: push the accumulated segment, open a new one
            if let Some(seg) = current.take() {
                segments.push(seg);
            }
            current = Some(String::new());
        }
        if let Some(seg) = current.as_mut() {
            seg.push_str(line);
            seg.push('\n');
        }
        // git extended headers like diff --git / index come before the first ---; dropped while current=None (expected)
    }
    if let Some(seg) = current {
        segments.push(seg);
    }
    segments
}

/// grep single file — regex line by line, skip binaries (containing \0), 1000 hits per file cap + bounded by the global remainder
/// P-SB-01: the old version did std::fs::read of the whole file into memory — OOM on huge (GB-scale) files
/// Now checks size via metadata first, skips past 64MB (grep is not a binary probe tool; huge files need a dedicated index)
/// Audit 3.7: global_remaining = global hit remainder (GREP_GLOBAL_HIT_CAP - collected), take min(per-file 1000, remainder)
const GREP_FILE_MAX_BYTES: u64 = 64 * 1024 * 1024;
const GREP_PER_FILE_CAP: usize = 1000;
/// Returns this file's hit count (0 = no hits); out (with context) is filled only in content mode
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
    // P-SB-01: metadata size cap, skip past it (avoids OOM)
    if let Ok(meta) = std::fs::metadata(fp) {
        if meta.len() > GREP_FILE_MAX_BYTES {
            warn!(path = %fp.display(), size = meta.len(), "grep file exceeds 64MB cap, skipped");
            return Ok(0);
        }
    }
    let bytes = match std::fs::read(fp) {
        Ok(b) => b,
        Err(e) => {
            debug!(path = %fp.display(), error = %e, "grep failed to read file, skipping");
            return Ok(0);
        }
    };
    // Binary suspicion → skip (probe limited to the first 8KB, avoids a full scan)
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
    // #7 gap 4: multiline mode — match over the whole-file buffer, line number = line of the match start
    if opts.multiline {
        let mut hits = 0u32;
        let file_cap = GREP_PER_FILE_CAP.min(global_remaining) as u32;
        for m in re.find_iter(&text) {
            if hits >= file_cap {
                warn!(path = %fp.display(), cap = file_cap, "grep multiline per-file hits exceed cap, truncated");
                break;
            }
            // Line number = count of '\n' before the match start + 1
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
    // #7 gap 3: context -A/-B/-C (-C = min(A,B), takes both before/after)
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
                warn!(path = %fp.display(), cap = file_cap, "grep per-file hits exceed cap, truncated");
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
        assert!(r.error.unwrap().contains("did not match"));
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
        // Content unchanged
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
        assert!(r.error.unwrap().contains("not found"));
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
        // Multi-line block match: foo ... bar across lines
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
        // Line number = match start (the line foo is on)
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
        // include *.py → only a.py
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
        // Write a .gitignore excluding ignored.py
        std::fs::write(dir.path().join(".gitignore"), "ignored.py\n").unwrap();
        std::fs::write(dir.path().join("ignored.py"), "x\n").unwrap();
        std::fs::write(dir.path().join("kept.py"), "y\n").unwrap();
        let tools = Tools::new();
        let entries = tools.glob("*.py", Some(&cwd)).unwrap();
        let paths: Vec<String> = entries.into_iter().map(|e| e.path).collect();
        assert!(paths.contains(&"kept.py".to_string()));
        assert!(
            !paths.contains(&"ignored.py".to_string()),
            "gitignore should exclude ignored.py"
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
        assert!(r.ok, "apply_patch should succeed: {:?}", r.error);
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
        assert!(r.error.unwrap().contains("not found"));
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
        assert!(r.ok, "replace_function should succeed: {:?}", r.error);
        let after = std::fs::read_to_string(&fp).unwrap();
        assert!(after.contains("return 99"));
        assert!(
            after.contains("return 2"),
            "keep function should be preserved"
        );
        assert!(
            !after.contains("return 1"),
            "old function body should be replaced"
        );
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
        assert!(r.error.unwrap().contains("not found"));
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
        assert!(r.ok, "replace_function rs should succeed: {:?}", r.error);
        let after = std::fs::read_to_string(&fp).unwrap();
        assert!(after.contains("99"));
        assert!(after.contains("fn keep"));
    }

    // ── guard_path escape protection ──

    #[test]
    fn test_guard_path_rejects_escape() {
        let dir = tempfile::tempdir().unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        // .. escape outside cwd (target missing would pass via canonicalize failure — create a real escape target here)
        let outside = tempfile::tempdir().unwrap();
        let escape_target = outside.path().join("evil.txt");
        std::fs::write(&escape_target, "x").unwrap();
        let rel = format!("{}/evil.txt", outside.path().to_string_lossy());
        let res = guard_path(&guard, &rel, Some(&cwd));
        assert!(
            res.is_err(),
            "absolute path escaping cwd should be rejected"
        );
    }

    // ── T4 additions: 6-fix regression ──

    // L-TOOLS-02: empty old_string must be rejected (the old version misjudged count==1 as unique on empty files)
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
        assert!(!r.ok, "empty old_string should be rejected");
        assert!(r.error.unwrap().contains("must not be empty"));
        // Empty old_string on a non-empty file should also be rejected
        std::fs::write(&fp, "content\n").unwrap();
        let r = tools
            .file_edit("empty.txt", "", "x", Some(&cwd), false)
            .unwrap();
        assert!(
            !r.ok,
            "empty old_string should be rejected (non-empty file too)"
        );
    }

    // L-TOOLS-01: absolute path patterns hitting sensitive areas must be filtered (validate_cwd blocks /etc)
    #[test]
    fn test_glob_filters_sensitive_absolute() {
        let tools = Tools::new();
        // /etc is in SENSITIVE_PATHS → validate_cwd rejects → glob returns empty
        let r = tools.glob("/etc/passwd", Some("/tmp")).unwrap();
        assert!(
            r.is_empty(),
            "sensitive path /etc/passwd should be filtered: {:?}",
            r
        );
    }

    // ── C-SEC-03: guard_path rejects reading credential filename patterns inside cwd ──

    #[test]
    fn guard_path_blocks_read_existing_pem() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("secrets.pem");
        std::fs::write(&fp, "PRIVATE\n").unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = guard_path(&guard, "secrets.pem", Some(&cwd));
        assert!(r.is_err(), "reading existing secrets.pem should be blocked");
        let msg = format!("{:?}", r.unwrap_err());
        assert!(
            msg.contains("credential"),
            "should mention credential files: {}",
            msg
        );
    }

    #[test]
    fn guard_path_blocks_read_existing_id_rsa() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("id_rsa");
        std::fs::write(&fp, "KEY\n").unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = guard_path(&guard, "id_rsa", Some(&cwd));
        assert!(r.is_err(), "reading existing id_rsa should be blocked");
    }

    #[test]
    fn guard_path_allows_read_id_rsa_pub() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("id_rsa.pub");
        std::fs::write(&fp, "PUBLIC\n").unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = guard_path(&guard, "id_rsa.pub", Some(&cwd));
        assert!(
            r.is_ok(),
            "reading the public key id_rsa.pub should not be blocked"
        );
    }

    #[test]
    fn guard_path_allows_create_new_pem() {
        // Creating a new cert.pem (file missing → Err branch) is not blocked — only reads of existing credentials are
        let dir = tempfile::tempdir().unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = guard_path(&guard, "newcert.pem", Some(&cwd));
        assert!(
            r.is_ok(),
            "creating a new newcert.pem should not be blocked"
        );
    }

    #[test]
    fn file_edit_blocks_read_credential_filename() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("server.key");
        std::fs::write(&fp, "secret\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        // guard_path Err propagates via anyhow (not degraded to EditResult) — security validation failure is fail-loud
        let r = tools.file_edit("server.key", "secret", "x", Some(&cwd), false);
        assert!(
            r.is_err(),
            "file_edit reading server.key should be blocked (Err)"
        );
        let msg = format!("{:?}", r.unwrap_err());
        assert!(
            msg.contains("credential"),
            "should mention credential files: {}",
            msg
        );
    }

    #[test]
    fn grep_blocks_read_credential_filename() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("agent.pem");
        std::fs::write(&fp, "data\n").unwrap();
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        // grep goes through guard_path → PathBlocked → Err (propagated), file not read
        let r = tools.grep("data", &["agent.pem".to_string()], Some(&cwd));
        assert!(
            r.is_err(),
            "grep agent.pem should be blocked (Err): {:?}",
            r
        );
        let msg = format!("{:?}", r.unwrap_err());
        assert!(
            msg.contains("credential"),
            "should mention credential files: {}",
            msg
        );
    }

    // C-TOOLS-02: full-file rewrite (delete all + add all) must be rejected (the old heuristic missed it)
    #[test]
    fn test_apply_patch_full_rewrite_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("app.py");
        std::fs::write(&fp, "line1\nline2\nline3\n").unwrap();
        // Whole-file delete + whole-file add (new range 1..3 covers the original 3 lines)
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
        assert!(!r.ok, "full-file rewrite should be rejected: {:?}", r.error);
        assert!(r.error.unwrap().contains("full-file rewrite"));
        // File unchanged
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            "line1\nline2\nline3\n"
        );
    }

    // C-TOOLS-02 counterpart: surgical patch (small hunks not covering the whole file) still passes
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
        assert!(r.ok, "surgical patch should pass: {:?}", r.error);
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            "line1\nLINE2\nline3\n"
        );
    }

    // L-TOOLS-03: paths containing .. components must be rejected (the old version failed open when canonicalize failed)
    #[test]
    fn test_guard_path_rejects_dotdot_component() {
        let dir = tempfile::tempdir().unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        // Relative path containing .. (target does not exist yet, canonicalize will always fail — old version failed open)
        let res = guard_path(&guard, "sub/../../etc/evil.txt", Some(&cwd));
        assert!(
            res.is_err(),
            ".. components should be rejected (fail-closed)"
        );
        let err = res.unwrap_err().to_string();
        assert!(err.contains(".."), "error should mention .. components");
    }

    // Blocker 3 finding 3.1: the .. check must not be skipped when cwd=None (the old version kept it inside if let Some(cwd))
    #[test]
    fn test_guard_path_rejects_dotdot_no_cwd() {
        let guard = SecurityGuard::new();
        // Absolute path containing .. (cwd=None, the old version skipped the .. check entirely)
        let res = guard_path(&guard, "/tmp/../../etc/evil.txt", None);
        assert!(
            res.is_err(),
            ".. components must also be rejected when cwd=None"
        );
        assert!(res.unwrap_err().to_string().contains(".."));
    }

    // Blocker 3 finding 3.2: symlink bypass — a symlink inside cwd pointing to a sensitive area must be caught via canonicalize
    #[test]
    fn test_guard_path_rejects_symlink_to_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        let guard = SecurityGuard::new();
        let cwd = dir.path().to_string_lossy().to_string();
        // Create a symlink inside cwd pointing to /etc (sensitive)
        #[cfg(unix)]
        {
            let link = dir.path().join("etc_link");
            std::os::unix::fs::symlink("/etc", &link).unwrap();
            let target = "etc_link/passwd";
            let res = guard_path(&guard, target, Some(&cwd));
            assert!(
                res.is_err(),
                "symlink into a sensitive area should be caught via canonicalize: {:?}",
                res
            );
        }
    }

    // P-SB-01: grep should skip files over 64MB (avoids OOM)
    #[test]
    fn test_grep_skips_oversize_file() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("big.txt");
        // Sparse file: set_len sets the logical size without writing (metadata.len() reports 65MB)
        {
            let f = std::fs::File::create(&fp).unwrap();
            f.set_len(GREP_FILE_MAX_BYTES + 1024).unwrap();
        }
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let ms = tools
            .grep("anything", &["big.txt".to_string()], Some(&cwd))
            .unwrap();
        assert!(ms.is_empty(), "files over 64MB should be skipped: {:?}", ms);
    }

    // ── Blocker 8 / 3.5: write-tool size cap ──

    // file_edit should reject files over 64MB (not OOM, fail-loud)
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
        assert!(!r.ok, "file_edit on a file over 64MB should be rejected");
        assert!(
            r.error.unwrap().contains("exceeds size cap"),
            "should report Oversize"
        );
        // Content unchanged (x = 1 still present, trailing sparse hole)
        let s = std::fs::read_to_string(&fp).unwrap();
        assert!(
            s.starts_with("x = 1"),
            "the file must not be modified when rejected"
        );
    }

    // replace_function should reject files over 64MB
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
        assert!(
            !r.ok,
            "replace_function on a file over 64MB should be rejected"
        );
        assert!(r.error.unwrap().contains("exceeds size cap"));
    }

    // apply_patch should reject files over 64MB
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
        assert!(!r.ok, "apply_patch on a file over 64MB should be rejected");
        assert!(r.error.unwrap().contains("exceeds size cap"));
    }

    // ── Blocker 8 / 3.4: flock RMW serialization ──

    // Two threads concurrently file_edit the same file — flock guarantees both changes land (no silent loss)
    #[test]
    fn test_file_edit_flock_serializes_concurrent_edits() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("race.txt");
        // Two unique anchors, one replacement each
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
        assert!(
            ra.ok && rb.ok,
            "both concurrent edits should succeed: a={ra:?} b={rb:?}"
        );
        let after = std::fs::read_to_string(&fp).unwrap();
        assert!(
            after.contains("A2") && after.contains("B2"),
            "both changes should land: {after}"
        );
    }

    // Other parties block while the lock is held (not an immediate overwrite) — simulated: main thread holds the lock, child thread's edit must wait for release
    #[test]
    fn test_file_edit_blocks_until_lock_released() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("locked.txt");
        std::fs::write(&fp, "v1\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        // Main thread takes the lock first
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
        // Hold the lock for 300ms, then release
        std::thread::sleep(std::time::Duration::from_millis(300));
        drop(_hold);
        let r = h.join().unwrap();
        let elapsed = start.elapsed();
        assert!(
            r.ok,
            "edit should succeed after the lock is released: {r:?}"
        );
        assert!(
            elapsed >= std::time::Duration::from_millis(250),
            "edit should block until the lock is released (took {elapsed:?})"
        );
        let _ = fp2;
    }

    // ── Audit 3.6/3.7/3.8/3.12 regression ──

    // 3.6: glob should skip ignored dirs (.venv/node_modules/...) — the old version scanned 100k .venv entries
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
        assert_eq!(
            paths,
            vec!["real.py"],
            "glob should only return hits outside ignored dirs"
        );
    }

    // 3.6: glob result cap — truncate past GLOB_RESULT_CAP instead of OOM
    #[test]
    fn test_glob_caps_results() {
        let dir = tempfile::tempdir().unwrap();
        // Create GLOB_RESULT_CAP + 50 files
        for i in 0..(GLOB_RESULT_CAP + 50) {
            std::fs::write(dir.path().join(format!("f{i}.txt")), "").unwrap();
        }
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.glob("*.txt", Some(&cwd)).unwrap();
        assert_eq!(r.len(), GLOB_RESULT_CAP, "glob should truncate to the cap");
    }

    // 3.7: grep recursion should skip ignored dirs — the old version scanned node_modules for a million hits
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
        // Only a.py hits; .venv/node_modules skipped
        assert_eq!(ms.len(), 1, "grep should skip ignored dirs: {:?}", ms);
        assert!(ms[0].path.contains("a.py"));
    }

    // 3.7: grep global hit cap — stop scanning once the multi-file total passes GREP_GLOBAL_HIT_CAP
    // (a single file hits the per-file cap GREP_PER_FILE_CAP=1000 first, so multiple files are needed to hit the global cap)
    #[test]
    fn test_grep_global_cap_stops_scan() {
        let dir = tempfile::tempdir().unwrap();
        // 3 files each with GREP_PER_FILE_CAP(1000) hits: the first 2 fill the global 2000, the 3rd is skipped
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
            "grep multi-file totals should truncate to the global cap, got {}",
            ms.len()
        );
    }

    // 3.8: both files of a multi-file diff should be applied — the old diffy from_str rejected multi-file diffs, losing the second file
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
        assert!(r.ok, "multi-file apply_patch should succeed: {:?}", r.error);
        assert_eq!(r.matches, 2, "1 hunk per file = 2 hunks");
        assert_eq!(std::fs::read_to_string(&f1).unwrap(), "ctx1\nnew1\nctx1b\n");
        assert_eq!(std::fs::read_to_string(&f2).unwrap(), "ctx2\nnew2\nctx2b\n");
    }

    // 3.8(b): splitting into 2 hunks each removing original/2 bypasses the per-hunk check — the aggregate must block
    #[test]
    fn test_apply_patch_split_hunk_full_rewrite_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("app.py");
        // 4-line file: 2 hunks each removing 2 (total 4 = original_lines=4)
        // each hunk removed(2) < 4 bypasses per-hunk; the aggregate file_removed(4) >= 4 → reject
        std::fs::write(&fp, "line1\nline2\nline3\nline4\n").unwrap();
        let diff = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,1 @@\n-line1\n-line2\n+X\n@@ -3,2 +2,1 @@\n-line3\n-line4\n+Y\n";
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.apply_patch(diff, Some(&cwd)).unwrap();
        assert!(
            !r.ok,
            "split-hunk full rewrite should be caught by the aggregate check: {:?}",
            r.error
        );
        assert!(r.error.unwrap().contains("full-file rewrite"));
        // File unchanged
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            "line1\nline2\nline3\nline4\n"
        );
    }

    // 3.12: replace_function without a grammar (.go) must fail-loud (not a broken regex fallback)
    // locate_function without a grammar → returns Err (not Ok{ok:false}), callers see the Result
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
            err.contains("does not support") || err.contains("grammar"),
            "should state unsupported / no grammar: {err}"
        );
        // File unchanged (not corrupted by a broken regex)
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            "func foo() {\n    return 1\n}\n"
        );
    }

    // split_multi_file_diff unit: single file → 1 element; multi-file → N elements; git extended headers dropped
    #[test]
    fn test_split_multi_file_diff() {
        let single = "--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-x\n+y\n";
        assert_eq!(split_multi_file_diff(single).len(), 1);

        let multi = "--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-x\n+y\n--- a/b.py\n+++ b/b.py\n@@ -1,1 +1,1 @@\n-p\n+q\n";
        let segs = split_multi_file_diff(multi);
        assert_eq!(segs.len(), 2);
        assert!(segs[0].starts_with("--- a/a.py"));
        assert!(segs[1].starts_with("--- a/b.py"));

        // git extended headers (diff --git/index) come before the first --- → dropped
        let with_git = "diff --git a/a.py b/a.py\nindex 123..456\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-x\n+y\n";
        let segs = split_multi_file_diff(with_git);
        assert_eq!(segs.len(), 1);
        assert!(
            segs[0].starts_with("--- a/a.py"),
            "git extended headers should be dropped"
        );
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
        assert!(r.ok, "replace_all should replace every occurrence: {r:?}");
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
        assert!(!r.ok, "replace_all=false should reject multiple matches");
        assert_eq!(r.matches, 2);
        // File not modified
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

    // ── #2: write_file full-file create/overwrite + create-on-empty ──

    #[test]
    fn test_write_file_creates_new_with_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        // Parent dirs missing → created via create_dir_all
        let r = tools
            .write_file("nested/deep/new.py", "print('hi')\n", Some(&cwd))
            .unwrap();
        assert!(
            r.ok,
            "write_file should create parent dirs and write: {r:?}"
        );
        assert_eq!(r.matches, 1);
        let fp = dir.path().join("nested/deep/new.py");
        assert!(fp.exists(), "the new file should exist");
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
        assert!(r.ok, "write_file overwrite should succeed: {r:?}");
        assert_eq!(std::fs::read_to_string(&fp).unwrap(), "new content\n");
    }

    #[test]
    fn test_write_file_rejects_oversize_content() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let big = "x".repeat(WRITE_FILE_MAX_BYTES as usize + 1);
        let r = tools.write_file("big.txt", &big, Some(&cwd)).unwrap();
        assert!(!r.ok, "content over 64MB should be rejected");
        assert!(r.error.unwrap().contains("exceeds size cap"));
    }

    #[test]
    fn test_file_edit_create_on_empty_missing_path() {
        // #2: file_edit on a missing path + empty old_string → creates the file with new_string (Claude Code parity)
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
        assert!(
            r.ok,
            "create-on-empty should create the file for a missing path: {r:?}"
        );
        let fp = dir.path().join("brand_new.py");
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            "def f():\n    pass\n"
        );
    }

    #[test]
    fn test_file_edit_existing_empty_old_string_still_rejected() {
        // #2: existing file + empty old_string still rejected (L-TOOLS-02 kept; create-on-empty only applies to missing paths)
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("exist.txt");
        std::fs::write(&fp, "data\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .file_edit("exist.txt", "", "new\n", Some(&cwd), false)
            .unwrap();
        assert!(!r.ok, "existing file + empty old_string should be rejected");
        assert!(r.error.unwrap().contains("must not be empty"));
        // Original file not modified
        assert_eq!(std::fs::read_to_string(&fp).unwrap(), "data\n");
    }

    #[test]
    fn test_file_edit_missing_path_nonempty_old_string_rejected() {
        // #2: missing path + non-empty old_string → still rejected (cannot match an old_string that does not exist)
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        let r = tools
            .file_edit("ghost.py", "foo", "bar", Some(&cwd), false)
            .unwrap();
        assert!(
            !r.ok,
            "missing path + non-empty old_string should be rejected"
        );
        assert!(r.error.unwrap().contains("file not found"));
    }

    // ── #6: multi_edit atomic all-or-nothing ──

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
        assert!(r.ok, "multi_edit all succeed: {r:?}");
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
        // Second item's old_string missing → whole batch fails, file kept intact
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
        assert!(
            !r.ok,
            "a non-matching second item should fail the whole batch: {r:?}"
        );
        assert!(r.error.unwrap().contains("item 1"));
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            original,
            "the file should stay in its pre-edit state"
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
        assert!(r.error.unwrap().contains("must not be empty"));
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

    // IMPL-10: buffer growth past MULTI_EDIT_BUFFER_MAX → fail-loud, file untouched
    #[test]
    fn test_multi_edit_buffer_overflow_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("big.txt");
        // Tiny old_string + huge new_string triggers growth (a single replace already exceeds 256MB)
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
        assert!(!r.ok, "buffer over cap should fail-loud: {r:?}");
        assert!(
            r.error.as_deref().unwrap().contains("exceeds cap"),
            "missing buffer-growth error: {:?}",
            r.error
        );
        assert_eq!(
            std::fs::read_to_string(&fp).unwrap(),
            original,
            "the file should stay intact (nothing written)"
        );
    }

    // IMPL-6: arrow function replacement — `const add = (a, b) => a + b;`
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
        // Replace the whole declaration statement (parent lexical_declaration, the full const → ; line)
        let new_body = "const add = (a, b) => a + b + 100;";
        let r = tools
            .replace_function("arr.js", "add", new_body, Some(&cwd))
            .unwrap();
        assert!(r.ok, "arrow function replacement should succeed: {r:?}");
        let after = std::fs::read_to_string(&fp).unwrap();
        // Whole-statement equality assertion (guards against replacing only the declarator span, leaving a const prefix / ; suffix → corruption)
        assert_eq!(
            after, "const add = (a, b) => a + b + 100;\nconst sub = (a, b) => a - b;\n",
            "arrow replacement should swap the whole statement, adjacent functions untouched: {after}"
        );
    }

    // IMPL-6: non-arrow declarators must not be replaced — `const x = 1;` is not a function
    #[test]
    fn test_replace_function_non_arrow_declarator_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("na.js");
        std::fs::write(&fp, "const x = 1;\nfunction real() { return 2; }\n").unwrap();
        let cwd = dir.path().to_string_lossy().to_string();
        let tools = Tools::new();
        // x is not an arrow, real is a function_declaration — replacing real should succeed without touching x
        let r = tools
            .replace_function("na.js", "real", "function real() { return 3; }", Some(&cwd))
            .unwrap();
        assert!(
            r.ok,
            "function_declaration replacement should succeed: {r:?}"
        );
        let after = std::fs::read_to_string(&fp).unwrap();
        assert!(after.contains("return 3"), "new body not written: {after}");
        assert!(
            after.contains("const x = 1;"),
            "non-arrow declarator damaged: {after}"
        );
    }

    // IMPL-6: class method method_definition replacement
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
        assert!(r.ok, "method_definition replacement should succeed: {r:?}");
        let after = std::fs::read_to_string(&fp).unwrap();
        assert!(after.contains("return 2"), "new body not written: {after}");
    }

    // RUN-5: is_nfs helper — a local tempdir is not NFS (macOS apfs) → false
    #[test]
    fn test_is_nfs_local_false() {
        let dir = tempfile::tempdir().unwrap();
        // Local tempdir (apfs) is not nfs
        assert!(
            !is_nfs(dir.path()),
            "a local tempdir should not be detected as NFS"
        );
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
        // Insert a new cell after cell-0
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
        assert!(!r.ok, "a missing cell_id should fail: {r:?}");
        assert!(r.error.unwrap().contains("not found"));
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
        assert!(r.error.unwrap().contains("out of range"));
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

    // ── E1 ecosystem-wide glob spec (issue #20, fusion-event/docs/glob-spec.md) ──
    // `*` does not cross `/`, `**` crosses directories, `?` is one non-`/` character. Glob matches paths relative to cwd.

    // E1 example 1: `src/*.swift` matches src/a.swift, not src/sub/a.swift (* does not cross /)
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
        assert_eq!(
            paths,
            vec!["src/a.swift"],
            "* should only match the same level, not cross /"
        );
    }

    // E1 example 2: `src/**/*.swift` matches src/a.swift + src/x/y/a.swift (** crosses directories)
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
            "** should match across directory levels"
        );
    }

    // E1 example 3: `bin/?s` matches bin/ls, not bin/less (? is exactly one non-/ character)
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
        assert_eq!(
            paths,
            vec!["bin/ls"],
            "? should match exactly one character, not less"
        );
    }

    // ── 0827 audit P1 regression (L-9/L-10/L-11/L-12/M-12.2) ──

    // L-9: check_size runs under the lock — an oversized file_edit is still rejected, file unchanged.
    // The TOCTOU window is hard to reproduce directly (needs a concurrent party to grow the file between check→read);
    // this tests the invariant: the under-lock check path behaves identically to before (reject past the cap, content unchanged).
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
        assert!(
            !r.ok,
            "over 64MB should be rejected by the under-lock check_size"
        );
        assert!(r.error.unwrap().contains("exceeds size cap"));
        // Content unchanged — rejection under the lock writes nothing
        let s = std::fs::read_to_string(&fp).unwrap();
        assert!(
            s.starts_with("x = 1"),
            "the file must not be modified when rejected"
        );
        // The sidecar lockfile remains 0 bytes (never deleted), but the data file was not renamed
        assert!(fp.exists(), "the data file should still be in place");
    }

    // L-9: multi_edit under-lock check_size rejects oversized files
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
        assert!(
            !r.ok,
            "multi_edit over 64MB should be rejected by the under-lock check_size"
        );
        assert!(r.error.unwrap().contains("exceeds size cap"));
    }

    // L-10: the old apply_patch `if let Ok(canonical)` silently skipped the cwd check when canonicalize failed (fail-open).
    // The current version is fail-closed (`with_context?`). Symlink escapes are caught by guard_path (first gate, see line 1189);
    // L-10's post-apply canonicalize is defense-in-depth redundancy. Tests both paths:
    //   (a) a normal in-cwd file still applies successfully (fail-closed does not break the normal path)
    //   (b) a symlink pointing outside cwd → guard_path blocks (defense in depth does not leak)
    #[test]
    fn l10_apply_patch_normal_path_still_works_and_symlink_blocked() {
        // (a) Normal path not broken
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("app.py");
        std::fs::write(&fp, "ctx\nold\nctxb\n").unwrap();
        let diff = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n ctx\n-old\n+new\n ctxb\n";
        let tools = Tools::new();
        let cwd = dir.path().to_string_lossy().to_string();
        let r = tools.apply_patch(diff, Some(&cwd)).unwrap();
        assert!(
            r.ok,
            "a normal in-cwd apply_patch should succeed: {:?}",
            r.error
        );
        assert_eq!(std::fs::read_to_string(&fp).unwrap(), "ctx\nnew\nctxb\n");

        // (b) Symlink escape — caught by the guard_path first gate; apply_patch returns Err (not an EditResult)
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
            "symlink escape should be caught by guard_path (Err, not an EditResult)"
        );
        // Real file unchanged
        assert_eq!(
            std::fs::read_to_string(&real_file).unwrap(),
            "ctx\nold\nctxb\n"
        );
    }

    // L-11: the deletion line `--- foo` (original source `-- foo`, a Lua/SQL comment) must not be misjudged as a new file header.
    // The old starts_with("--- ") mis-split mid-hunk → both segments malformed → Patch::from_str rejected.
    // The current peek-ahead: `--- ` counts as a header only when followed by `+++ ` → single file, single segment, patch succeeds.
    #[test]
    fn l11_split_no_misjudge_deletion_line_as_header() {
        // A `--- foo` deletion line inside a hunk (no +++ after) — must be treated as a deletion line, not a new file header
        let diff =
            "--- a/app.lua\n+++ b/app.lua\n@@ -1,3 +1,2 @@\n local x = 1\n--- foo\n+local x = 2\n";
        let segs = split_multi_file_diff(diff);
        assert_eq!(
            segs.len(),
            1,
            "the deletion line --- foo must not be mis-split as a new file header"
        );
        assert!(
            segs[0].contains("--- foo"),
            "the deletion line should stay in the segment"
        );
    }

    // L-11: a real multi-file patch (with deletion lines inside hunks) still splits into N segments correctly
    // Source line `-- c1` (comment) → diff deletion line `--- c1` (diff marker - + source -- c1) — the old version misjudged this as a header
    #[test]
    fn l11_multi_file_with_deletion_lines_still_splits() {
        let diff = "--- a/a.py\n+++ b/a.py\n@@ -1,3 +1,2 @@\n ctx\n--- c1\n+ctx\n--- a/b.py\n+++ b/b.py\n@@ -1,2 +1,1 @@\n--- c2\n+ok\n";
        let segs = split_multi_file_diff(diff);
        assert_eq!(
            segs.len(),
            2,
            "each file header forms one segment (deletion line --- c1 is not mis-split)"
        );
        assert!(segs[0].starts_with("--- a/a.py"));
        assert!(segs[1].starts_with("--- a/b.py"));
        // Deletion lines --- c1/--- c2 (source -- c1/-- c2 diff-encoded) stay in their segments
        assert!(
            segs[0].contains("--- c1"),
            "the deletion line should stay in segment 0"
        );
        assert!(
            segs[1].contains("--- c2"),
            "the deletion line should stay in segment 1"
        );
    }

    // L-12: Insert mode with a missing cell_id → fail-loud error (the old version silently appended at the end)
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
        assert!(
            !r.ok,
            "Insert with a missing cell_id should fail, not silently append: {r:?}"
        );
        let err = r.error.unwrap();
        assert!(
            err.contains("cell_id=no-such-id") && err.contains("not found"),
            "should report cell_id not found: {err}"
        );
        // File unchanged (no silent append)
        let nb: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&fp).unwrap()).unwrap();
        assert_eq!(
            nb["cells"].as_array().unwrap().len(),
            2,
            "cells must not be silently appended"
        );
    }

    // L-12: Insert mode with no id and no num → appends at the end (explicit append semantics preserved)
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
        assert!(
            r.ok,
            "Insert with no id and no num should append at the end: {r:?}"
        );
        let nb: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&fp).unwrap()).unwrap();
        let cells = nb["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 3, "one cell should be appended");
        assert_eq!(cells[2]["source"][0].as_str().unwrap(), "import os\n");
    }

    // M-12.2: read_data_to_string errors on non-UTF-8 files include the filename
    #[test]
    fn m12_2_read_data_to_string_error_has_filename() {
        let dir = tempfile::tempdir().unwrap();
        let fp = dir.path().join("latin1.txt");
        // Write non-UTF-8 bytes (0xFF is not an ASCII/UTF-8 start byte, invalid UTF-8 sequence)
        std::fs::write(&fp, b"before\xff\xfeafter").unwrap();
        let err = FileLock::read_data_to_string(&fp).err().unwrap();
        let msg = err.to_string();
        assert!(
            msg.contains("latin1.txt"),
            "the error message should contain the filename, got: {msg}"
        );
        assert!(
            !msg.is_empty(),
            "the original UTF-8 error description should be preserved, got: {msg}"
        );
    }
}
