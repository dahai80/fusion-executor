// fe-diagnostics — Traceback 提取 + tree-sitter AST 切片 (PRD §4.2)
//
// Pipeline: 正则提取 4 语言 traceback → tree-sitter 定位行号 → 上下 20 行切片
// 输出 Diagnostics → ExecutionResult.diagnostics (exit_code != 0 时)
//
// 语言:
//   Python   Traceback (most recent call last): ... <type>Error: <msg>
//            File "path", line N
//   Node     Error: <msg> at <fn> (path:line:col)
//   Rust     thread 't' panicked at path:line:col
//   Swift    path:line:col: error: <msg>

use std::path::Path;

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use tree_sitter::Parser;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Diagnostics {
    pub error_type: Option<String>,
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
    pub code_snippet: Option<String>,
    pub raw_trace: Option<String>,
}

/// 诊断切片器 — 正则 traceback + tree-sitter 定位
#[derive(Clone)]
pub struct Slicer {
    python_re: Regex,
    node_re: Regex,
    rust_re: Regex,
    swift_re: Regex,
}

impl Slicer {
    pub fn new() -> Self {
        info!("Slicer::new() — 编译 4 语言 traceback 正则");
        Self {
            // Python: Traceback ... File "path", line N ... <Type>Error: msg
            // (?ms): m=^按行锚, s=.跨行 (.*? 跨过 "in forward\n return...\n" 到达错误行)
            python_re: Regex::new(
                r#"(?ms)Traceback \(most recent call last\):.*?File "([^"]+)", line (\d+).*?^(\w+(?:Error|Exception|Warning)):\s*([^\n]*)"#,
            )
            .expect("python_re 编译失败"),
            // Node: Error: msg ... at fn (path:line:col)
            node_re: Regex::new(r"Error:\s*(.*)\n\s+at\s+.*\(([^()]+):(\d+):\d+\)")
                .expect("node_re 编译失败"),
            // Rust: thread 't' panicked at path:line:col
            rust_re: Regex::new(r"thread '.*?' panicked at ([^:\n]+):(\d+):\d+")
                .expect("rust_re 编译失败"),
            // Swift: path:line:col: error: msg
            // (?m): ^按行锚; [^:\n]* 防跨行吞掉上一行
            swift_re: Regex::new(r"(?m)^([^:\s][^:\n]*):(\d+):\d+:\s*error:\s*([^\n]*)")
                .expect("swift_re 编译失败"),
        }
    }

    /// 切片 — output 是合并后的 stdio (PTY 合并, traceback 在 stdout)
    pub fn slice(&self, output: &str, cwd: Option<&str>) -> Diagnostics {
        // 取最后 30 行 (PRD "最后 30 行")
        let tail = tail_lines(output, 30);
        debug!(tail_len = tail.len(), "slice — 提取 traceback");

        if let Some(d) = self.extract_python(&tail) {
            return self.enrich(d, cwd);
        }
        if let Some(d) = self.extract_node(&tail) {
            return self.enrich(d, cwd);
        }
        if let Some(d) = self.extract_rust(&tail) {
            return self.enrich(d, cwd);
        }
        if let Some(d) = self.extract_swift(&tail) {
            return self.enrich(d, cwd);
        }
        // 无匹配 → 仅存原始 trace
        Diagnostics {
            raw_trace: Some(tail),
            ..Default::default()
        }
    }

    fn extract_python(&self, tail: &str) -> Option<Diagnostics> {
        let c = self.python_re.captures(tail)?;
        let file_path = c.get(1).map(|m| m.as_str().to_string());
        let line_number = c.get(2).and_then(|m| m.as_str().parse::<u32>().ok());
        let error_type = c.get(3).map(|m| m.as_str().to_string());
        let msg = c
            .get(4)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        let raw_trace = format!("{}: {}", error_type.as_deref().unwrap_or("Error"), msg);
        Some(Diagnostics {
            error_type,
            file_path,
            line_number,
            raw_trace: Some(raw_trace),
            code_snippet: None,
        })
    }

    fn extract_node(&self, tail: &str) -> Option<Diagnostics> {
        let c = self.node_re.captures(tail)?;
        let msg = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let file_path = c.get(2).map(|m| m.as_str().to_string());
        let line_number = c.get(3).and_then(|m| m.as_str().parse::<u32>().ok());
        Some(Diagnostics {
            error_type: Some("Error".to_string()),
            file_path,
            line_number,
            raw_trace: Some(format!("Error: {}", msg)),
            code_snippet: None,
        })
    }

    fn extract_rust(&self, tail: &str) -> Option<Diagnostics> {
        let c = self.rust_re.captures(tail)?;
        let file_path = c.get(1).map(|m| m.as_str().to_string());
        let line_number = c.get(2).and_then(|m| m.as_str().parse::<u32>().ok());
        let raw = c.get(0).map(|m| m.as_str().to_string()).unwrap_or_default();
        Some(Diagnostics {
            error_type: Some("panic".to_string()),
            file_path,
            line_number,
            raw_trace: Some(raw),
            code_snippet: None,
        })
    }

    fn extract_swift(&self, tail: &str) -> Option<Diagnostics> {
        let c = self.swift_re.captures(tail)?;
        let file_path = c.get(1).map(|m| m.as_str().to_string());
        let line_number = c.get(2).and_then(|m| m.as_str().parse::<u32>().ok());
        let msg = c.get(3).map(|m| m.as_str().to_string()).unwrap_or_default();
        Some(Diagnostics {
            error_type: Some("error".to_string()),
            file_path,
            line_number,
            raw_trace: Some(format!("error: {}", msg)),
            code_snippet: None,
        })
    }

    /// 填充 code_snippet — 读文件, 报错行上下 20 行, 报错行标 >
    fn enrich(&self, mut d: Diagnostics, cwd: Option<&str>) -> Diagnostics {
        let (Some(path), Some(line)) = (d.file_path.as_ref(), d.line_number) else {
            return d;
        };
        let abs = resolve_path(path, cwd);
        let snippet = read_snippet(&abs, line).unwrap_or_else(|e| {
            debug!(path = %abs, "snippet 读取失败: {}", e);
            String::new()
        });
        if !snippet.is_empty() {
            d.code_snippet = Some(snippet);
        }
        d
    }
}

impl Default for Slicer {
    fn default() -> Self {
        Self::new()
    }
}

/// tree-sitter 按文件扩展选 grammar (预留 — v1 snippet 用纯文本行, AST 定位 P5)
fn _parser_for_ext(ext: &str) -> Option<Parser> {
    let mut p = Parser::new();
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

/// 取文本末尾 N 行 (保留 traceback 尾部)
fn tail_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// 解析 file_path — 相对路径接 cwd, 绝对直接用
fn resolve_path(path: &str, cwd: Option<&str>) -> String {
    let p = Path::new(path);
    if p.is_absolute() {
        return path.to_string();
    }
    match cwd {
        Some(c) => Path::new(c).join(path).to_string_lossy().into_owned(),
        None => path.to_string(),
    }
}

/// 读文件, 报错行上下 20 行, 报错行前标 > (PRD 格式)
fn read_snippet(path: &str, err_line: u32) -> Result<String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("读取 {} 失败: {}", path, e))?;
    let lines: Vec<&str> = content.lines().collect();
    let err = err_line as usize;
    let start = err.saturating_sub(20).max(1);
    let end = (err + 20).min(lines.len());
    let mut out = String::new();
    for i in start..=end {
        if i > lines.len() {
            break;
        }
        let mark = if i == err { ">" } else { " " };
        // PRD 格式: "> 142:     return x + None"
        let line_content = lines.get(i - 1).copied().unwrap_or("");
        out.push_str(&format!("{} {}: {}\n", mark, i, line_content));
    }
    Ok(out.trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s() -> Slicer {
        Slicer::new()
    }

    #[test]
    fn extract_python_traceback() {
        let out = "running...\nTraceback (most recent call last):\n  File \"src/core/router.py\", line 142, in forward\n    return x + None\nTypeError: unsupported operand type(s) for +: 'int' and 'NoneType'";
        let d = s().slice(out, None);
        assert_eq!(d.error_type.as_deref(), Some("TypeError"));
        assert_eq!(d.file_path.as_deref(), Some("src/core/router.py"));
        assert_eq!(d.line_number, Some(142));
        assert!(d.raw_trace.as_deref().unwrap().contains("TypeError"));
    }

    #[test]
    fn extract_node_error() {
        let out = "node app.js\nError: Cannot find module 'foo'\n    at require (app.js:10:15)\n    at Object.<anonymous> (app.js:3:1)";
        let d = s().slice(out, None);
        assert_eq!(d.error_type.as_deref(), Some("Error"));
        assert_eq!(d.file_path.as_deref(), Some("app.js"));
        assert_eq!(d.line_number, Some(10));
        assert!(d
            .raw_trace
            .as_deref()
            .unwrap()
            .contains("Cannot find module"));
    }

    #[test]
    fn extract_rust_panic() {
        let out = "thread 'main' panicked at src/main.rs:42:10:\nindex out of bounds";
        let d = s().slice(out, None);
        assert_eq!(d.error_type.as_deref(), Some("panic"));
        assert_eq!(d.file_path.as_deref(), Some("src/main.rs"));
        assert_eq!(d.line_number, Some(42));
    }

    #[test]
    fn extract_swift_error() {
        let out =
            "swift build\nmain.swift:15:7: error: use of unresolved identifier 'foo'\nlet x = foo";
        let d = s().slice(out, None);
        assert_eq!(d.error_type.as_deref(), Some("error"));
        assert_eq!(d.file_path.as_deref(), Some("main.swift"));
        assert_eq!(d.line_number, Some(15));
    }

    #[test]
    fn no_match_keeps_raw_trace() {
        let out = "some random output\nno error here";
        let d = s().slice(out, None);
        assert!(d.error_type.is_none());
        assert!(d.raw_trace.is_some());
    }

    #[test]
    fn snippet_marks_error_line() {
        let dir = tempfile_dir();
        let p = dir.join("t.py");
        let body = "a = 1\nb = 2\nc = a + None\nd = 3\n";
        std::fs::write(&p, body).unwrap();
        let d = s().slice(
            &format!(
                "Traceback (most recent call last):\n  File \"{}\", line 3, in <module>\n    c = a + None\nTypeError: bad",
                p.display()
            ),
            None,
        );
        assert_eq!(d.line_number, Some(3));
        let snip = d.code_snippet.as_deref().unwrap();
        assert!(snip.contains("> 3: c = a + None"), "snippet={:?}", snip);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tail_lines_keeps_end() {
        let big = (0..100)
            .map(|i| format!("line {}", i))
            .collect::<Vec<_>>()
            .join("\n");
        let tail = tail_lines(&big, 5);
        assert!(tail.contains("line 99"));
        assert!(!tail.contains("line 0"));
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("fe-diag-test-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
