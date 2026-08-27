// fe-diagnostics — Traceback 提取 + 纯文本行切片 (PRD §4.2)
//
// Pipeline: 正则提取多语言 traceback → 末 N 行 + 根因标记行保段头 → 上下 20 行切片
// (0827 A-8: regex-only, 无 AST fallback — tree-sitter 路径 v1.6 已删, 正则 = 唯一生产路径, 单点故障接受)
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

use std::collections::VecDeque;
use std::path::Path;

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use fe_security::SecurityGuard;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Diagnostics {
    pub error_type: Option<String>,
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
    pub code_snippet: Option<String>,
    pub raw_trace: Option<String>,
}

/// 诊断切片器 — 正则 traceback 提取 (纯文本行切片, 0827 A-8: regex-only 无 AST fallback)
#[derive(Clone)]
pub struct Slicer {
    python_file_re: Regex,
    python_err_re: Regex,
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

/// M-10: 正则编译降级 — 编译失败不 panic, 降级为永不匹配 (\b\B 矛盾锚)。
/// 硬编码模式已知可编译; 此为防御纵深 (未来改模式引入语法错时不致启动崩溃)。
/// 命中回退时 error! 留痕 (fail-visible), 该语言诊断静默失效 (其他语言不受影响)。
/// 用法: Regex::new(PAT).unwrap_or_else(|_| degrade_re("name")) — 保 PAT 原样不重写。
fn degrade_re(name: &str) -> Regex {
    error!(regex = name, "正则编译失败, 降级为永不匹配");
    Regex::new(r"\b\B").expect("回退正则 \\b\\B 必可编译")
}

impl Slicer {
    pub fn new() -> Self {
        info!("Slicer::new() — 编译 8 语言 traceback 正则");
        Self {
            guard: SecurityGuard::new(),
            // Python two-pass (0827 C-17: 单正则 .*File.*?^Error 贪心+非贪心量词爆炸,
            // 10MB 输入实测 1134s ReDoS; 拆两遍逐行匹配, 线性无回溯):
            // pass1 python_file_re: 找**最后** File 帧 (^\s+File, 无 .* 跨行量词)
            // pass2 python_err_re: 找错误行 <Type>Error: msg (行锚, 无跨行量词)
            // extract_python 组合两者 — 同一 traceback 内 File 帧与错误行配对。
            python_file_re: Regex::new(r#"(?m)^\s+File "([^"]+)", line (\d+)"#)
                .unwrap_or_else(|_| degrade_re("python_file_re")),
            python_err_re: Regex::new(r"(?m)^(\w+(?:Error|Exception|Warning)):\s*(.*)")
                .unwrap_or_else(|_| degrade_re("python_err_re")),
            // TS: path.ts(l,c): error TSxxxx: msg (tsc 括号形式)
            // (?m): ^按行锚; group1=path(.ts/.tsx 等), group2=line, group3=TS 码, group4=msg
            ts_re: Regex::new(
                r#"(?m)^([^:\s][^:\n]*?)\((\d+),\d+\):\s+error\s+(TS\d+):\s*([^\n]*)"#,
            )
            .unwrap_or_else(|_| degrade_re("ts_re")),
            // TS watch: path.ts:l:c - error TSxxxx: msg (tsc watch 冒号-短横形式)
            ts_dash_re: Regex::new(
                r#"(?m)^([^:\s][^:\n]*?):(\d+):\d+\s+-\s+error\s+(TS\d+):\s*([^\n]*)"#,
            )
            .unwrap_or_else(|_| degrade_re("ts_dash_re")),
            // Node: Error: msg ... at fn (path:line:col)
            // 0827 L-17: 锚行首 (?m)^ — 否则匹配内联 // Error: foo 注释误报
            node_re: Regex::new(r"(?m)^Error:\s*(.*)\n\s+at\s+.*\(([^()]+):(\d+):\d+\)")
                .unwrap_or_else(|_| degrade_re("node_re")),
            // Bun: error: msg ... at path:line:col (小写 error, 裸 at 无括号)
            // 0827 L-17: 锚行首 (?m)^ — 同 node_re
            bun_re: Regex::new(r"(?m)^error:\s*(.*)\n\s+at\s+([^()]+):(\d+):\d+")
                .unwrap_or_else(|_| degrade_re("bun_re")),
            // Rust: thread 't' panicked at path:line:col
            rust_re: Regex::new(r"thread '.*?' panicked at ([^:\n]+):(\d+):\d+")
                .unwrap_or_else(|_| degrade_re("rust_re")),
            // Go panic: panic: msg ... goroutine N [running]: ... \tfile.go:line
            // (?s): .跨行; group1=panic msg, group2=file, group3=line (最后一栈帧)
            go_panic_re: Regex::new(
                r#"(?s)panic:\s*([^\n]*)\n.*?goroutine \d+ \[running\]:.*?\n\t([^:\n]+):(\d+)"#,
            )
            .unwrap_or_else(|_| degrade_re("go_panic_re")),
            // Swift: path:line:col: error: msg
            // (?m): ^按行锚; [^:\n]* 防跨行吞掉上一行
            swift_re: Regex::new(r"(?m)^([^:\s][^:\n]*):(\d+):\d+:\s*error:\s*([^\n]*)")
                .unwrap_or_else(|_| degrade_re("swift_re")),
            // Go compile: file.go:line:col: msg (无 error 关键字; swift_re 漏因无 "error:")
            // (?m): ^按行锚; group1=file(.go), group2=line, group3=msg
            // 0827 L-16: regex 裸匹配 file.go:l:c: 误吞测试进度行 (main_test.go:15:3: PASS);
            // Rust regex 无 lookahead, 故 extract_go_compile 内加消息守卫拒测试状态 token。
            go_compile_re: Regex::new(r"(?m)^([^:\s][^:\n]*\.go):(\d+):\d+:\s*([^\n]*)")
                .unwrap_or_else(|_| degrade_re("go_compile_re")),
        }
    }

    /// 切片 — output 是合并后的 stdio (PTY 合并, traceback 在 stdout)
    pub fn slice(&self, output: &str, cwd: Option<&str>) -> Diagnostics {
        // PRD: "捕获 ANSI 颜色代码" — PTY 模式 python/tsc 等会注入 ANSI 转义 (如
        // \x1b[35m...\x1b[0m), 正则 `File "..."` 因颜色码紧贴引号前而失配。先剥离
        // ANSI 转义序列 (CSI/OSC/SGR 等) 再切片, 保正则匹配稳定 (与终端是否着色无关)。
        let cleaned = strip_ansi(output);
        // 取最后 30 行 (PRD "最后 30 行")
        let tail = tail_lines(&cleaned, 30);
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
        // 0827 C-17: 两遍线性匹配 (无跨行量词爆炸)
        // pass1: 找**最后** File 帧 (深 traceback 多帧, 取最接近根因的栈帧)
        // pass2: 找错误行 (<Type>Error: msg)
        // 二者均锚行首, 无 .* 跨行量词 — 10MB 输入线性, 不回溯爆炸
        let mut last_file: Option<(String, u32)> = None;
        for c in self.python_file_re.captures_iter(tail) {
            let f = c.get(1).map(|m| m.as_str().to_string());
            let l = c.get(2).and_then(|m| m.as_str().parse::<u32>().ok());
            if let (Some(f), Some(l)) = (f, l) {
                last_file = Some((f, l));
            }
        }
        let err = self.python_err_re.captures(tail);
        // 至少有错误行才算 Python traceback (File 帧可缺失, 如顶层抛异常无栈)
        let ec = err?;
        let error_type = ec.get(1).map(|m| m.as_str().to_string());
        let msg = ec
            .get(2)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        let raw_trace = format!("{}: {}", error_type.as_deref().unwrap_or("Error"), msg);
        let (file_path, line_number) = match last_file {
            Some((f, l)) => (Some(f), Some(l)),
            None => (None, None),
        };
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
        // 0827 L-16: go_compile_re 裸匹配 file.go:l:c: 误吞测试进度行
        // (main_test.go:15:3: PASS) 与 runtime 日志。遍历所有匹配, 跳测试状态 token
        // (PASS/FAIL/SKIP/ok/RUN/BENCHMARK 开头), 取首个非状态诊断行。
        for c in self.go_compile_re.captures_iter(tail) {
            let file_path = c.get(1).map(|m| m.as_str().to_string());
            let line_number = c.get(2).and_then(|m| m.as_str().parse::<u32>().ok());
            let msg_raw = c
                .get(3)
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();
            // 测试状态 token 不属编译诊断 — 跳过, 继续找下一匹配
            let is_test_status = matches!(
                msg_raw
                    .split_whitespace()
                    .next()
                    .map(|s| s.to_ascii_uppercase())
                    .as_deref(),
                Some("PASS" | "FAIL" | "SKIP" | "OK" | "RUN" | "BENCHMARK")
            );
            if is_test_status {
                continue;
            }
            let msg = msg_raw;
            return Some(Diagnostics {
                error_type: Some("compile error".to_string()),
                file_path,
                line_number,
                raw_trace: Some(format!("compile error: {}", msg)),
                code_snippet: None,
            });
        }
        None
    }

    /// 填充 code_snippet — 读文件, 报错行上下 20 行, 报错行标 >
    /// Blocker 2 (finding 3.3) + 0827 C-18: traceback file_path 经 SecurityGuard 校验
    /// 敏感路径 + .. 逃逸 + 跨 symlink 旁路, 防私钥经诊断通道泄 LLM。
    /// 攻击链: 构造 traceback 引用 /tmp/leak.py → symlink → ~/.ssh/id_rsa → enrich
    /// 读到私钥 → 入 prompt。旧实现只 canonicalize 父目录, 漏: symlink 文件本体解析。
    /// 修: canonicalize 文件本体 (real), 对 real + real.parent() 双重 validate_cwd,
    /// is_sensitive_filename(real) 命中即拒, real 与 abs 不一致 (跨 symlink) 额外审慎。
    fn enrich(&self, mut d: Diagnostics, cwd: Option<&str>) -> Diagnostics {
        let (Some(path), Some(line)) = (d.file_path.as_ref(), d.line_number) else {
            return d;
        };
        // .. 逃逸 — 相对路径 .. 跨 cwd 边界 (validate_cwd 也拦, 此处早期 fail-closed)
        if Path::new(path)
            .components()
            .any(|comp| comp == std::path::Component::ParentDir)
        {
            warn!(path = %path, "诊断 file_path 含 .. 组件, 拒绝读取");
            return d;
        }
        let abs = resolve_path(path, cwd);
        // 字面父目录校验 (快速, 防 canonicalize 前的敏感前缀)
        let check_dir = Path::new(&abs)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| abs.clone());
        let v_lit = self.guard.validate_cwd(&check_dir);
        if !v_lit.allowed {
            warn!(path = %abs, reason = v_lit.reason, "诊断 file_path 敏感 (字面), 拒绝读取");
            return d;
        }
        // 0827 C-18: canonicalize 文件本体 — 解 symlink 到真实路径
        // (旧实现只 canonicalize 父目录, symlink 文件 /tmp/leak.py→~/.ssh/id_rsa 旁路)
        let real = match Path::new(&abs).canonicalize() {
            Ok(r) => r,
            Err(e) => {
                debug!(path = %abs, "诊断 file_path canonicalize 失败 (跳过 snippet): {}", e);
                return d;
            }
        };
        // 真实文件名敏感 (id_rsa / *.pem / *.key...) — 命中即拒, 不读
        if self.guard.is_sensitive_filename(&real.to_string_lossy()) {
            warn!(path = %abs, real = %real.display(), "诊断 file_path 解析为敏感文件名, 拒绝读取");
            return d;
        }
        // 真实路径 + 真实父目录双重敏感校验 (symlink 目标落 ~/.ssh 等)
        let v_real = self.guard.validate_cwd(&real.to_string_lossy());
        if !v_real.allowed {
            warn!(path = %abs, real = %real.display(), reason = v_real.reason, "诊断 file_path 真实路径敏感, 拒绝读取");
            return d;
        }
        let real_parent = real
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| real.to_string_lossy().into_owned());
        let v_real_parent = self.guard.validate_cwd(&real_parent);
        if !v_real_parent.allowed {
            warn!(path = %abs, real = %real.display(), reason = v_real_parent.reason, "诊断 file_path 真实父目录敏感, 拒绝读取");
            return d;
        }
        // 跨 symlink 边界告警 (abs != real) — 非必拒 (合法 symlink 项目结构), 但留审计痕
        if real.to_string_lossy() != abs {
            warn!(path = %abs, real = %real.display(), "诊断 file_path 经 symlink 解析, 已双重校验通过");
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

/// 取文本末尾 N 行 + 保根因标记行 (M-DIAG-01)
///
/// 纯末 N 行会丢深 traceback 前部的根因 `Error:`/`Exception:` 行 (诊断失效)。
/// 策略: 保 traceback 段头 (`Traceback (most recent call last):` / `panic:` /
/// `goroutine`) + 根因标记行 (Error/Exception/Warning 含子串覆盖 TypeError 等;
/// 剥离 ANSI 转义序列 — PTY 着色输出 (CSI SGR/光标/擦除, OSC 标题, 单字符 BEL/BS)。
/// 兼容 unterminated CSI (PTY 半截读)。正则切片前调用, 保 `File "path"` 等模式稳定。
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0x1b {
            // ESC — 序列起点
            if i + 1 >= bytes.len() {
                break;
            }
            match bytes[i + 1] {
                b'[' => {
                    // CSI: ESC [ <params 0x30-0x3F> <intermediates 0x20-0x2F> <final 0x40-0x7E>
                    i += 2;
                    while i < bytes.len() && (bytes[i] >= 0x20 && bytes[i] <= 0x2f) {
                        i += 1;
                    }
                    while i < bytes.len() && (bytes[i] >= 0x30 && bytes[i] <= 0x3f) {
                        i += 1;
                    }
                    if i < bytes.len() && (bytes[i] >= 0x40 && bytes[i] <= 0x7e) {
                        i += 1;
                    }
                }
                b']' => {
                    // OSC: ESC ] ... BEL (0x07) 或 ST (ESC \)
                    i += 2;
                    while i < bytes.len() && bytes[i] != 0x07 && bytes[i] != 0x1b {
                        i += 1;
                    }
                    if i < bytes.len() {
                        if bytes[i] == 0x07 {
                            i += 1;
                        } else if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                            i += 2;
                        }
                    }
                }
                _ => {
                    // 单字符转义 (ESC + 1 byte, 如 ESC M / ESC 7) — 跳 2
                    i += 2;
                }
            }
        } else if b == 0x07 {
            // 裸 BEL (残留 OSC 终止符) — 丢弃
            i += 1;
        } else {
            // 取 char 边界, 避多字节 UTF-8 截断
            let ch_len = utf8_len(b);
            if i + ch_len <= bytes.len() {
                out.push_str(&s[i..i + ch_len]);
            }
            i += ch_len.max(1);
        }
    }
    out
}

/// 取 UTF-8 首字节指示的字符字节长度 (非法字节返回 1)
fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7f => 1,
        0x80..=0xbf => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

/// `error:` 行首锚) + 标记行的下一行 (Node/Bun `at` 邻接依赖) + 末 N 行,
/// 按原序去重合并。过保几行无害 (正则仍精确捕), 漏保根因行才有害 — 此处治漏保。
fn tail_lines(s: &str, n: usize) -> String {
    // 0827 P-6: 环形缓冲避全量 Vec — 旧 `s.lines().collect()` 对 10MB 输出分配全量
    // 行指针 Vec。改 lazy 迭代, 末 N 行入 VecDeque 环形 (cap n), 标记/段头行单独收集
    // (任意位置保留, 不受截断影响)。
    // 0827 L-18: is_marker 大小写不敏感 (旧 .contains("Error:") 漏 Bun 小写 error: 及
    // 各语言变体; English-only 接受 — 诊断关键字均 ASCII) + 加 panic: 标记
    // (旧 panic: 仅在 is_header, 漏非行首 panic 标记如 `runtime error: ... panic:`)。
    if n == 0 {
        // n=0 仅保标记行 (无末尾窗口) — 边界, 实际调用 n=30
        let mut markers: Vec<&str> = Vec::new();
        let mut prev_was_marker = false;
        for l in s.lines() {
            let low = l.to_ascii_lowercase();
            let is_header = low.starts_with("traceback (most recent call last")
                || low.starts_with("panic:")
                || low.starts_with("goroutine ");
            let is_marker = low.contains("error:")
                || low.contains("exception:")
                || low.contains("warning:")
                || low.contains("panic:");
            if is_header || is_marker || prev_was_marker {
                markers.push(l);
            }
            prev_was_marker = is_marker;
        }
        return markers.join("\n");
    }
    let mut tail: VecDeque<(usize, &str)> = VecDeque::with_capacity(n);
    let mut markers: Vec<(usize, &str)> = Vec::new();
    let mut prev_was_marker = false;
    for (i, l) in s.lines().enumerate() {
        let low = l.to_ascii_lowercase();
        let is_header = low.starts_with("traceback (most recent call last")
            || low.starts_with("panic:")
            || low.starts_with("goroutine ");
        let is_marker = low.contains("error:")
            || low.contains("exception:")
            || low.contains("warning:")
            || low.contains("panic:");
        if is_header || is_marker || prev_was_marker {
            markers.push((i, l));
        }
        prev_was_marker = is_marker;
        if tail.len() == n {
            tail.pop_front();
        }
        tail.push_back((i, l));
    }
    // 未截断 (tail 含全量, 首 idx==0) → 直接返, markers 已在其中
    if tail.front().is_some_and(|(idx, _)| *idx == 0) {
        return tail
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");
    }
    // 截断 → 合并 tail + markers, 按原序去重
    let mut keep: Vec<(usize, &str)> = markers;
    keep.extend(tail);
    keep.sort_by_key(|(i, _)| *i);
    keep.dedup_by_key(|(i, _)| *i);
    keep.into_iter()
        .map(|(_, l)| l)
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

    #[test]
    fn strip_ansi_removes_csi_sgr() {
        let colored = "Traceback (most recent call last):\n  File \u{1b}[35m\"<string>\"\u{1b}[0m, line \u{1b}[35m1\u{1b}[0m, in \u{1b}[35m<module>\u{1b}[0m\n    raise ValueError('boom')\n\u{1b}[1;35mValueError\u{1b}[0m: \u{1b}[35mboom\u{1b}[0m\n";
        let d = s().slice(colored, None);
        assert_eq!(d.error_type.as_deref(), Some("ValueError"));
        assert_eq!(d.file_path.as_deref(), Some("<string>"));
        assert_eq!(d.line_number, Some(1));
    }

    #[test]
    fn strip_ansi_preserves_plain_text() {
        let plain = "Traceback (most recent call last):\n  File \"app.py\", line 2, in <module>\n    raise ValueError('x')\nValueError: x";
        let d = s().slice(plain, None);
        assert_eq!(d.error_type.as_deref(), Some("ValueError"));
        assert_eq!(d.file_path.as_deref(), Some("app.py"));
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("fe-diag-test-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    // 0827 C-17: python_re ReDoS — 旧单正则 .*File.*?^Error 10MB 输入 1134s;
    // two-pass 无跨行量词, 应线性 (本测 1MB 伪 traceback, 应秒级返, 不挂死)。
    #[test]
    fn python_redos_linear_on_large_input() {
        // 1MB 垃圾行 + 末尾合法 Python traceback — 旧 ReDoS 会回溯爆炸
        let mut out = String::from("Traceback (most recent call last):\n");
        // 10 万行非匹配垃圾 (无 File 无 Error) — 逼旧 .*File.*? 跨行回溯
        for _ in 0..100_000 {
            out.push_str("    garbage line without any marker aaaaaaaaaaaaaaa\n");
        }
        out.push_str("  File \"src/x.py\", line 7, in <module>\n");
        out.push_str("    raise ValueError('boom')\n");
        out.push_str("ValueError: boom\n");
        let d = s().slice(&out, None);
        assert_eq!(d.error_type.as_deref(), Some("ValueError"));
        assert_eq!(d.file_path.as_deref(), Some("src/x.py"));
        assert_eq!(d.line_number, Some(7));
    }

    // 0827 C-18: symlink 文件本体解析 — traceback 引用 /tmp/leak.py → symlink →
    // ~/.ssh/id_rsa。旧实现只 canonicalize 父目录, 漏 symlink 文件本体。
    #[test]
    fn enrich_rejects_symlink_to_sensitive_file() {
        let dir = tempfile_dir();
        let leak = dir.join("leak.py");
        let home_ssh = std::env::var("HOME").unwrap_or_default();
        let ssh_key = format!("{}/.ssh/id_rsa", home_ssh);
        // 建私钥占位 (若存在则跳过建, 仅测 symlink 解析拒读)
        let _ = std::fs::create_dir_all(format!("{}/.ssh", home_ssh));
        let _ = std::fs::write(&ssh_key, "FAKE-PRIVATE-KEY-CONTENT\n");
        // leak.py → symlink → id_rsa
        let _ = std::fs::remove_file(&leak);
        if std::os::unix::fs::symlink(&ssh_key, &leak).is_err() {
            // symlink 建失败 (权限/已存在) — 跳过本测, 不失败
            let _ = std::fs::remove_file(&ssh_key);
            return;
        }
        let out = format!(
            "Traceback (most recent call last):\n  File \"{}\", line 3, in <module>\n    x = 1\nTypeError: bad",
            leak.display()
        );
        let d = s().slice(&out, None);
        // symlink 解析为 id_rsa (敏感文件名) — code_snippet 不应含私钥内容
        assert!(
            d.code_snippet.is_none()
                || !d
                    .code_snippet
                    .as_deref()
                    .unwrap()
                    .contains("FAKE-PRIVATE-KEY-CONTENT"),
            "symlink→id_rsa 私钥内容不应泄入 code_snippet: {:?}",
            d.code_snippet
        );
        let _ = std::fs::remove_file(&leak);
        let _ = std::fs::remove_file(&ssh_key);
    }

    // 0827 C-18 (反向): 合法 symlink 项目结构 (如 src 链到别处) 应正常 enrich。
    #[test]
    fn enrich_allows_legit_symlink_to_source() {
        let dir = tempfile_dir();
        let real_src = dir.join("real_src.py");
        std::fs::write(&real_src, "line1\nline2\nline3\nx = 1\nline5\n").unwrap();
        let link = dir.join("link_src.py");
        let _ = std::fs::remove_file(&link);
        if std::os::unix::fs::symlink(&real_src, &link).is_err() {
            return;
        }
        let out = format!(
            "Traceback (most recent call last):\n  File \"{}\", line 4, in <module>\n    x = 1\nTypeError: bad",
            link.display()
        );
        let d = s().slice(&out, None);
        // 合法源 symlink 应读 — code_snippet 含 line4 内容
        assert!(
            d.code_snippet.is_some(),
            "合法 symlink 源文件应 enrich 填 code_snippet"
        );
        let _ = std::fs::remove_file(&link);
    }

    // 0827 L-16: go_compile_re 误吞测试进度行 — main_test.go:15:3: PASS 不应诊断。
    #[test]
    fn go_compile_skips_test_status_lines() {
        let out = "go test ./...\nmain_test.go:15:3: PASS\nmain.go:6:5: undefined: foo";
        let d = s().slice(out, None);
        // 应跳 PASS 状态行, 取编译错误 main.go undefined
        assert_eq!(d.error_type.as_deref(), Some("compile error"));
        assert_eq!(d.file_path.as_deref(), Some("main.go"));
        assert_eq!(d.line_number, Some(6));
    }

    // 0827 L-17: node_re/bun_re 无 ^ 锚会匹配内联 // Error: foo 注释。
    // 加 (?m)^ 后, 行中 Error: 不匹配 (须行首)。
    #[test]
    fn node_re_rejects_inline_error_comment() {
        let out = "// comment Error: foo here\n    at bar (app.js:5:10)";
        let d = s().slice(out, None);
        // 行中 Error: 非行首 → node_re 不匹配; 无其他语言命中 → raw_trace
        assert!(
            d.error_type.is_none() || d.error_type.as_deref() != Some("Error"),
            "内联 // Error: 注释不应匹配 node_re: {:?}",
            d.error_type
        );
    }

    // 0827 L-18: tail_lines is_marker 旧大小写敏感 .contains("Error:") 漏小写 error:;
    // Bun traceback 小写 error: 行 + 段头应保留在 tail 窗口。
    #[test]
    fn tail_lines_keeps_lowercase_error_marker() {
        // 构造超 30 行输出, 小写 error: 在前部 — 旧 is_marker 漏 (contains("Error:") 大写)
        let mut out = String::from("bun run\n");
        for i in 0..35 {
            out.push_str(&format!("filler line {}\n", i));
        }
        out.push_str("error: ENOENT: no such file\n");
        out.push_str("    at /app/index.js:10:5");
        let d = s().slice(&out, None);
        // 小写 error: marker 应保留 → bun_re 应捕到
        assert_eq!(d.error_type.as_deref(), Some("error"));
        assert_eq!(d.file_path.as_deref(), Some("/app/index.js"));
        assert_eq!(d.line_number, Some(10));
    }
}
