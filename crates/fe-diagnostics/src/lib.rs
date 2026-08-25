// fe-diagnostics — Traceback 提取 + tree-sitter AST 切片 (PRD §4.2)
//
// Pipeline: 正则提取 4 语言 traceback → tree-sitter 定位行号 → 上下 20 行切片
// 输出 Diagnostics → ExecutionResult.diagnostics (exit_code != 0 时)
//
// 语言:
//   Python   Traceback (most recent call last): ... <type>Error: <msg>
//            File "path", line N
//   Node     Error: <msg> at <fn> (path:line:col)
//   Bun      error: <msg> at path:line:col (小写, 裸 at 无括号)
//   TS       path.ts(l,c): error TSxxxx: <msg> (tsc 编译器; 兼容 :l:c 与 - 形式)
//   Rust     thread 't' panicked at path:line:col
//   Swift    path:line:col: error: <msg>
//   Go       panic: <msg> ... goroutine ... \tfile.go:line  /  file.go:line:col: <msg>

use std::path::Path;

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use tree_sitter::Parser;

use fe_security::SecurityGuard;

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
    ts_re: Regex,
    ts_dash_re: Regex,
    node_re: Regex,
    bun_re: Regex,
    rust_re: Regex,
    go_panic_re: Regex,
    swift_re: Regex,
    go_compile_re: Regex,
    guard: SecurityGuard,
}

impl Slicer {
    pub fn new() -> Self {
        info!("Slicer::new() — 编译 8 语言 traceback 正则");
        Self {
            guard: SecurityGuard::new(),
            // Python: Traceback ... File "path", line N ... <Type>Error: msg
            // (?ms): m=^按行锚, s=.跨行。.*File 贪心取最深 (最后) File 帧 — M-DIAG-01
            // 配合 tail_lines 保标记行后, 深 traceback 多帧保留时取最接近根因的栈帧。
            python_re: Regex::new(
                r#"(?ms)Traceback \(most recent call last\):.*File "([^"]+)", line (\d+).*?^(\w+(?:Error|Exception|Warning)):\s*([^\n]*)"#,
            )
            .expect("python_re 编译失败"),
            // TS: path.ts(l,c): error TSxxxx: msg (tsc 括号形式)
            // (?m): ^按行锚; group1=path(.ts/.tsx 等), group2=line, group3=TS 码, group4=msg
            ts_re: Regex::new(
                r#"(?m)^([^:\s][^:\n]*?)\((\d+),\d+\):\s+error\s+(TS\d+):\s*([^\n]*)"#,
            )
            .expect("ts_re 编译失败"),
            // TS watch: path.ts:l:c - error TSxxxx: msg (tsc watch 冒号-短横形式)
            ts_dash_re: Regex::new(
                r#"(?m)^([^:\s][^:\n]*?):(\d+):\d+\s+-\s+error\s+(TS\d+):\s*([^\n]*)"#,
            )
            .expect("ts_dash_re 编译失败"),
            // Node: Error: msg ... at fn (path:line:col)
            node_re: Regex::new(r"Error:\s*(.*)\n\s+at\s+.*\(([^()]+):(\d+):\d+\)")
                .expect("node_re 编译失败"),
            // Bun: error: msg ... at path:line:col (小写 error, 裸 at 无括号)
            bun_re: Regex::new(r"error:\s*(.*)\n\s+at\s+([^()]+):(\d+):\d+")
                .expect("bun_re 编译失败"),
            // Rust: thread 't' panicked at path:line:col
            rust_re: Regex::new(r"thread '.*?' panicked at ([^:\n]+):(\d+):\d+")
                .expect("rust_re 编译失败"),
            // Go panic: panic: msg ... goroutine N [running]: ... \tfile.go:line
            // (?s): .跨行; group1=panic msg, group2=file, group3=line (最后一栈帧)
            go_panic_re: Regex::new(
                r#"(?s)panic:\s*([^\n]*)\n.*?goroutine \d+ \[running\]:.*?\n\t([^:\n]+):(\d+)"#,
            )
            .expect("go_panic_re 编译失败"),
            // Swift: path:line:col: error: msg
            // (?m): ^按行锚; [^:\n]* 防跨行吞掉上一行
            swift_re: Regex::new(r"(?m)^([^:\s][^:\n]*):(\d+):\d+:\s*error:\s*([^\n]*)")
                .expect("swift_re 编译失败"),
            // Go compile: file.go:line:col: msg (无 error 关键字; swift_re 漏因无 "error:")
            // (?m): ^按行锚; group1=file(.go), group2=line, group3=msg
            go_compile_re: Regex::new(r"(?m)^([^:\s][^:\n]*\.go):(\d+):\d+:\s*([^\n]*)")
                .expect("go_compile_re 编译失败"),
        }
    }

    /// 切片 — output 是合并后的 stdio (PTY 合并, traceback 在 stdout)
    pub fn slice(&self, output: &str, cwd: Option<&str>) -> Diagnostics {
        // 取最后 30 行 (PRD "最后 30 行")
        let tail = tail_lines(output, 30);
        debug!(tail_len = tail.len(), "slice — 提取 traceback");

        if let Some(d) = self.extract_ts(&tail) {
            return self.enrich(d, cwd);
        }
        if let Some(d) = self.extract_python(&tail) {
            return self.enrich(d, cwd);
        }
        if let Some(d) = self.extract_node(&tail) {
            return self.enrich(d, cwd);
        }
        if let Some(d) = self.extract_bun(&tail) {
            return self.enrich(d, cwd);
        }
        if let Some(d) = self.extract_rust(&tail) {
            return self.enrich(d, cwd);
        }
        if let Some(d) = self.extract_go_panic(&tail) {
            return self.enrich(d, cwd);
        }
        if let Some(d) = self.extract_swift(&tail) {
            return self.enrich(d, cwd);
        }
        if let Some(d) = self.extract_go_compile(&tail) {
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

    fn extract_ts(&self, tail: &str) -> Option<Diagnostics> {
        if let Some(c) = self.ts_re.captures(tail) {
            return Some(self.build_ts_diag(c));
        }
        let c = self.ts_dash_re.captures(tail)?;
        Some(self.build_ts_diag(c))
    }

    fn build_ts_diag(&self, c: regex::Captures) -> Diagnostics {
        let file_path = c.get(1).map(|m| m.as_str().to_string());
        let line_number = c.get(2).and_then(|m| m.as_str().parse::<u32>().ok());
        let error_type = c.get(3).map(|m| m.as_str().to_string()).unwrap_or_default();
        let msg = c
            .get(4)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        Diagnostics {
            error_type: Some(error_type.clone()),
            file_path,
            line_number,
            raw_trace: Some(format!("{}: {}", error_type, msg)),
            code_snippet: None,
        }
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

    fn extract_bun(&self, tail: &str) -> Option<Diagnostics> {
        let c = self.bun_re.captures(tail)?;
        let msg = c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let file_path = c.get(2).map(|m| m.as_str().to_string());
        let line_number = c.get(3).and_then(|m| m.as_str().parse::<u32>().ok());
        Some(Diagnostics {
            error_type: Some("error".to_string()),
            file_path,
            line_number,
            raw_trace: Some(format!("error: {}", msg)),
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
        // M-DIAG-02: 扩展名隔离 — swift_re 仅锚 :l:c: error: 无扩展名约束,
        // go vet `file.go:l:c: error: msg` 同格式会误匹配 .go 为 swift。
        // 守 .swift 后缀, 确保只处理 Swift 文件 (go_compile 已锚 .go)。
        let file_path = c.get(1).map(|m| m.as_str().to_string());
        let is_swift = file_path
            .as_ref()
            .is_some_and(|p| Path::new(p).extension().is_some_and(|e| e == "swift"));
        if !is_swift {
            return None;
        }
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

    fn extract_go_panic(&self, tail: &str) -> Option<Diagnostics> {
        let c = self.go_panic_re.captures(tail)?;
        let msg = c
            .get(1)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        let file_path = c.get(2).map(|m| m.as_str().to_string());
        let line_number = c.get(3).and_then(|m| m.as_str().parse::<u32>().ok());
        Some(Diagnostics {
            error_type: Some("panic".to_string()),
            file_path,
            line_number,
            raw_trace: Some(format!("panic: {}", msg)),
            code_snippet: None,
        })
    }

    fn extract_go_compile(&self, tail: &str) -> Option<Diagnostics> {
        let c = self.go_compile_re.captures(tail)?;
        let file_path = c.get(1).map(|m| m.as_str().to_string());
        let line_number = c.get(2).and_then(|m| m.as_str().parse::<u32>().ok());
        let msg = c
            .get(3)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        Some(Diagnostics {
            error_type: Some("compile error".to_string()),
            file_path,
            line_number,
            raw_trace: Some(format!("compile error: {}", msg)),
            code_snippet: None,
        })
    }

    /// 填充 code_snippet — 读文件, 报错行上下 20 行, 报错行标 >
    /// Blocker 2 (finding 3.3): traceback file_path 经 SecurityGuard 校验敏感路径 + .. 逃逸
    /// 防止私钥经诊断通道泄 LLM (攻击者构造 traceback 引用 ~/.ssh/id_rsa → enrich 读取 → 入 prompt)
    fn enrich(&self, mut d: Diagnostics, cwd: Option<&str>) -> Diagnostics {
        let (Some(path), Some(line)) = (d.file_path.as_ref(), d.line_number) else {
            return d;
        };
        // 敏感路径 + .. 逃逸校验 (复用 fe-security)
        // is_sensitive_path 只检 / ~ 前缀; .. 相对逃逸单独拦
        if Path::new(path)
            .components()
            .any(|comp| comp == std::path::Component::ParentDir)
        {
            warn!(path = %path, "诊断 file_path 含 .. 组件, 拒绝读取");
            return d;
        }
        let abs = resolve_path(path, cwd);
        // 校验 abs 的父目录非敏感 (canonicalize 解符号链接)
        let check_dir = Path::new(&abs)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| abs.clone());
        // 先字面校验 (快速), 再 canonicalize 校验 (防符号链接旁路)
        let v_lit = self.guard.validate_cwd(&check_dir);
        if !v_lit.allowed {
            warn!(path = %abs, reason = v_lit.reason, "诊断 file_path 敏感 (字面), 拒绝读取");
            return d;
        }
        if let Ok(canonical) = Path::new(&check_dir).canonicalize() {
            let v_can = self.guard.validate_cwd(&canonical.to_string_lossy());
            if !v_can.allowed {
                warn!(path = %abs, reason = v_can.reason, "诊断 file_path 敏感 (符号链接解析), 拒绝读取");
                return d;
            }
        }
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

/// 取文本末尾 N 行 + 保根因标记行 (M-DIAG-01)
///
/// 纯末 N 行会丢深 traceback 前部的根因 `Error:`/`Exception:` 行 (诊断失效)。
/// 策略: 保 traceback 段头 (`Traceback (most recent call last):` / `panic:` /
/// `goroutine`) + 根因标记行 (Error/Exception/Warning 含子串覆盖 TypeError 等;
/// `error:` 行首锚) + 标记行的下一行 (Node/Bun `at` 邻接依赖) + 末 N 行,
/// 按原序去重合并。过保几行无害 (正则仍精确捕), 漏保根因行才有害 — 此处治漏保。
fn tail_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    if lines.len() <= n {
        return lines.join("\n");
    }
    let tail_start = lines.len() - n;
    let mut keep_idx: Vec<usize> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let is_header = l.starts_with("Traceback (most recent call last)")
            || l.starts_with("panic:")
            || l.starts_with("goroutine ");
        let is_marker = l.contains("Error:")
            || l.contains("Exception:")
            || l.contains("Warning:")
            || l.starts_with("error:");
        if is_header || is_marker {
            keep_idx.push(i);
            if is_marker && i + 1 < lines.len() {
                keep_idx.push(i + 1);
            }
        } else if i >= tail_start {
            keep_idx.push(i);
        }
    }
    keep_idx.sort();
    keep_idx.dedup();
    keep_idx
        .into_iter()
        .map(|i| lines[i])
        .collect::<Vec<_>>()
        .join("\n")
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
/// Blocker 8 (finding 3.5): 64MB 上限防爆 OOM
const SNIPPET_FILE_MAX_BYTES: u64 = 64 * 1024 * 1024;
fn read_snippet(path: &str, err_line: u32) -> Result<String> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > SNIPPET_FILE_MAX_BYTES {
            warn!(path = %path, size = meta.len(), "snippet 文件超 64MB 上限, 跳过");
            return Ok(String::new());
        }
    }
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
    fn extract_ts_compiler_error() {
        let out = "tsc\nsrc/router.ts(42,7): error TS2322: Type 'string' is not assignable to type 'number'.";
        let d = s().slice(out, None);
        assert_eq!(d.error_type.as_deref(), Some("TS2322"));
        assert_eq!(d.file_path.as_deref(), Some("src/router.ts"));
        assert_eq!(d.line_number, Some(42));
        assert!(d.raw_trace.as_deref().unwrap().contains("TS2322"));
    }

    #[test]
    fn extract_ts_watch_error() {
        let out =
            "tsc -w\nsrc/util.ts:10:5 - error TS7006: Parameter 'x' implicitly has an 'any' type.";
        let d = s().slice(out, None);
        assert_eq!(d.error_type.as_deref(), Some("TS7006"));
        assert_eq!(d.file_path.as_deref(), Some("src/util.ts"));
        assert_eq!(d.line_number, Some(10));
    }

    #[test]
    fn extract_bun_runtime_error() {
        let out = "bun run app.ts\nerror: Could not resolve: \"foo\"\n    at /Users/x/app.ts:5:18";
        let d = s().slice(out, None);
        assert_eq!(d.error_type.as_deref(), Some("error"));
        assert_eq!(d.file_path.as_deref(), Some("/Users/x/app.ts"));
        assert_eq!(d.line_number, Some(5));
        assert!(d
            .raw_trace
            .as_deref()
            .unwrap()
            .contains("Could not resolve"));
    }

    #[test]
    fn extract_go_panic() {
        let out = "go run main.go\npanic: runtime error: index out of range [1] with length 1\n\ngoroutine 1 [running]:\nmain.main()\n\t/Users/x/main.go:12 +0x1b4";
        let d = s().slice(out, None);
        assert_eq!(d.error_type.as_deref(), Some("panic"));
        assert_eq!(d.file_path.as_deref(), Some("/Users/x/main.go"));
        assert_eq!(d.line_number, Some(12));
        assert!(d.raw_trace.as_deref().unwrap().contains("runtime error"));
    }

    #[test]
    fn extract_go_compile_error() {
        let out = "go build ./...\n./main.go:8:7: undefined: foo";
        let d = s().slice(out, None);
        assert_eq!(d.error_type.as_deref(), Some("compile error"));
        assert_eq!(d.file_path.as_deref(), Some("./main.go"));
        assert_eq!(d.line_number, Some(8));
        assert!(d.raw_trace.as_deref().unwrap().contains("undefined"));
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

    #[test]
    fn tail_lines_keeps_error_marker_in_deep_traceback() {
        // M-DIAG-01: 根因 Error 行在 traceback 前部, 纯末 30 行会丢。
        // 造 40 行填充 + TypeError 行 + 5 行尾, tail_lines(20) 应保 TypeError。
        let mut lines: Vec<String> = (0..40).map(|i| format!("fill line {}", i)).collect();
        lines.push("ValueError: root cause here".to_string());
        lines.push("    at deep (x.py:99:5)".to_string());
        lines.extend((0..5).map(|i| format!("tail line {}", i)));
        let big = lines.join("\n");
        let tail = tail_lines(&big, 20);
        assert!(
            tail.contains("ValueError: root cause here"),
            "根因标记行应保, tail={:?}",
            tail
        );
        assert!(tail.contains("at deep (x.py:99:5)"), "标记行下一行应保");
        assert!(tail.contains("tail line 4"), "末行应保");
        // 中段填充行 (非标记非末尾) 应丢
        assert!(!tail.contains("fill line 10"), "中段非标记行应丢");
    }

    #[test]
    fn python_deep_traceback_keeps_root_error() {
        // M-DIAG-01 端到端: 深 traceback 超 30 行, slice 仍捕到根因 TypeError + 最深 File 帧。
        let mut frames: Vec<String> = Vec::new();
        for i in 0..40 {
            frames.push(format!(
                "  File \"mod{}.py\", line {}, in fn{}",
                i,
                i + 1,
                i
            ));
            frames.push(format!("    x{}()", i));
        }
        frames.push("  File \"src/real.py\", line 142, in forward".into());
        frames.push("    return x + None".into());
        frames.push("TypeError: unsupported operand type(s) for +: 'int' and 'NoneType'".into());
        let mut out = String::from("Traceback (most recent call last):\n");
        out.push_str(&frames.join("\n"));
        out.push_str("\ntail1\ntail2\ntail3");
        let d = s().slice(&out, None);
        assert_eq!(
            d.error_type.as_deref(),
            Some("TypeError"),
            "根因 error_type 应捕到"
        );
        assert_eq!(
            d.file_path.as_deref(),
            Some("src/real.py"),
            "最深 File 帧应取"
        );
        assert_eq!(d.line_number, Some(142));
    }

    #[test]
    fn swift_re_rejects_go_vet_error_format() {
        // M-DIAG-02: go vet 输出 `file.go:l:c: error: msg` 格式同 swift_re, 无扩展名
        // 守卫会误匹配 .go 为 swift。守 .swift 后应不匹配, 回退 go_compile 或 raw。
        let out = "go vet ./...\nmain.go:8:7: error: undefined: foo";
        let d = s().slice(out, None);
        // 不应是 swift (file_path .go 非 .swift); go_compile_re 锚 .go 应捕到
        assert_eq!(
            d.error_type.as_deref(),
            Some("compile error"),
            "go vet error 应走 go_compile 非 swift, got error_type={:?}",
            d.error_type
        );
        assert_eq!(d.file_path.as_deref(), Some("main.go"));
        assert_eq!(d.line_number, Some(8));
    }

    // Blocker 2 finding 3.3: 诊断通道敏感路径防护 — enrich 不读敏感文件
    #[test]
    fn enrich_rejects_sensitive_path() {
        // traceback 引用 /etc/shadow → enrich 应拒, code_snippet 不填
        let out = "Traceback (most recent call last):\n  File \"/etc/shadow\", line 3, in <module>\n    x = 1\nTypeError: bad";
        let d = s().slice(out, None);
        assert_eq!(d.error_type.as_deref(), Some("TypeError"));
        assert_eq!(d.file_path.as_deref(), Some("/etc/shadow"));
        // 敏感文件不读 — code_snippet 应为 None
        assert!(
            d.code_snippet.is_none() || d.code_snippet.as_deref().unwrap().is_empty(),
            "敏感文件 /etc/shadow 不应被读取: {:?}",
            d.code_snippet
        );
    }

    #[test]
    fn enrich_rejects_dotdot_escape() {
        // traceback file_path 含 .. → enrich 应拒
        let out = "Traceback (most recent call last):\n  File \"../../etc/shadow\", line 3, in <module>\n    x = 1\nTypeError: bad";
        let d = s().slice(out, None);
        assert!(
            d.code_snippet.is_none() || d.code_snippet.as_deref().unwrap().is_empty(),
            "含 .. 的 file_path 不应被读取: {:?}",
            d.code_snippet
        );
    }

    #[test]
    fn enrich_rejects_ssh_key() {
        let out = "Traceback (most recent call last):\n  File \"~/.ssh/id_rsa\", line 3, in <module>\n    x = 1\nTypeError: bad";
        let d = s().slice(out, None);
        assert!(
            d.code_snippet.is_none() || d.code_snippet.as_deref().unwrap().is_empty(),
            "私钥 ~/.ssh/id_rsa 不应被读取: {:?}",
            d.code_snippet
        );
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("fe-diag-test-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
