// fe-pyo3 — PyO3 绑定, maturin 目标 crate
//
// 产出 fusion_executor._native 扩展, 纯 Python executor.py 包装
// P1: 最小 execute_sync; 后续暴露 rollback/gui/serve

use pyo3::prelude::*;
use pyo3::types::PyAny;

use fe_core::gui::{GuiAction, GuiResult as RsGuiResult};
use fe_core::tools::{
    EditResult as RsEditResult, GlobEntry as RsGlobEntry, GrepMatch as RsGrepMatch,
};
use fe_core::{
    Diagnostics as RsDiag, ExecutionRequest, ExecutionResult as RsResult, ExecutionStreamEvent,
    Executor,
};
use fe_ipc::IpcServer;

/// Python 可见诊断 — 镜像 Rust Diagnostics
#[pyclass(name = "NativeDiagnostics", skip_from_py_object)]
#[derive(Clone)]
struct PyDiagnostics {
    #[pyo3(get)]
    error_type: Option<String>,
    #[pyo3(get)]
    file_path: Option<String>,
    #[pyo3(get)]
    line_number: Option<u32>,
    #[pyo3(get)]
    code_snippet: Option<String>,
    #[pyo3(get)]
    raw_trace: Option<String>,
}

impl From<RsDiag> for PyDiagnostics {
    fn from(d: RsDiag) -> Self {
        Self {
            error_type: d.error_type,
            file_path: d.file_path,
            line_number: d.line_number,
            code_snippet: d.code_snippet,
            raw_trace: d.raw_trace,
        }
    }
}

/// Python 可见结果 — 镜像 Rust ExecutionResult
#[pyclass(name = "NativeExecutionResult", skip_from_py_object)]
#[derive(Clone)]
struct PyExecutionResult {
    #[pyo3(get)]
    exit_code: i32,
    #[pyo3(get)]
    stdout: String,
    #[pyo3(get)]
    stderr: String,
    #[pyo3(get)]
    task_id: Option<String>,
    #[pyo3(get)]
    command: Option<String>,
    #[pyo3(get)]
    duration_sec: f64,
    #[pyo3(get)]
    timed_out: bool,
    #[pyo3(get)]
    blocked_by_security: bool,
    #[pyo3(get)]
    security_reason: Option<String>,
    #[pyo3(get)]
    snapshot_id: Option<String>,
    #[pyo3(get)]
    diagnostics: Option<PyDiagnostics>,
}

impl From<RsResult> for PyExecutionResult {
    fn from(r: RsResult) -> Self {
        Self {
            exit_code: r.exit_code,
            stdout: r.stdout,
            stderr: r.stderr,
            task_id: r.task_id,
            command: r.command,
            duration_sec: r.duration_sec,
            timed_out: r.timed_out,
            blocked_by_security: r.blocked_by_security,
            security_reason: r.security_reason,
            snapshot_id: r.snapshot_id,
            diagnostics: r.diagnostics.map(PyDiagnostics::from),
        }
    }
}

/// Python 可见 GUI 结果 — 镜像 fe_gui::GuiResult
#[pyclass(name = "NativeGuiResult", skip_from_py_object)]
#[derive(Clone)]
struct PyGuiResult {
    #[pyo3(get)]
    ok: bool,
    #[pyo3(get)]
    node_tree: Option<String>,
    #[pyo3(get)]
    screenshot_png_b64: Option<String>,
    #[pyo3(get)]
    screenshot_width: Option<u32>,
    #[pyo3(get)]
    screenshot_height: Option<u32>,
    #[pyo3(get)]
    error: Option<String>,
}

impl From<RsGuiResult> for PyGuiResult {
    fn from(r: RsGuiResult) -> Self {
        Self {
            ok: r.ok,
            node_tree: r.node_tree,
            screenshot_png_b64: r.screenshot_png_b64,
            screenshot_width: r.screenshot_width,
            screenshot_height: r.screenshot_height,
            error: r.error,
        }
    }
}

/// Python 可见文件工具结果 — 镜像 fe_tools::EditResult
#[pyclass(name = "NativeEditResult", skip_from_py_object)]
#[derive(Clone)]
struct PyEditResult {
    #[pyo3(get)]
    ok: bool,
    #[pyo3(get)]
    path: Option<String>,
    #[pyo3(get)]
    error: Option<String>,
    #[pyo3(get)]
    matches: u32,
}

impl From<RsEditResult> for PyEditResult {
    fn from(r: RsEditResult) -> Self {
        Self {
            ok: r.ok,
            path: r.path,
            error: r.error,
            matches: r.matches,
        }
    }
}

/// Python 可见 glob 命中 — 镜像 fe_tools::GlobEntry
#[pyclass(name = "NativeGlobEntry", skip_from_py_object)]
#[derive(Clone)]
struct PyGlobEntry {
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    is_dir: bool,
}

impl From<RsGlobEntry> for PyGlobEntry {
    fn from(e: RsGlobEntry) -> Self {
        Self {
            path: e.path,
            is_dir: e.is_dir,
        }
    }
}

/// Python 可见 grep 命中 — 镜像 fe_tools::GrepMatch
#[pyclass(name = "NativeGrepMatch", skip_from_py_object)]
#[derive(Clone)]
struct PyGrepMatch {
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    line_number: u32,
    #[pyo3(get)]
    content: String,
}

impl From<RsGrepMatch> for PyGrepMatch {
    fn from(m: RsGrepMatch) -> Self {
        Self {
            path: m.path,
            line_number: m.line_number,
            content: m.content,
        }
    }
}

/// 流式迭代器 — 消费 tokio mpsc<ExecutionStreamEvent>, 每次 __next__ 返回一帧 dict
/// chunk: {"type":"chunk","data":"..."} / done: {"type":"done","result":{...ExecutionResult}}
/// 通道关闭 → StopIteration
#[pyclass(name = "NativeStreamIterator", skip_from_py_object)]
struct PyStreamIterator {
    rx: Option<tokio::sync::mpsc::Receiver<ExecutionStreamEvent>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl PyStreamIterator {
    fn new(
        rx: tokio::sync::mpsc::Receiver<ExecutionStreamEvent>,
        handle: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            rx: Some(rx),
            handle: Some(handle),
        }
    }
}

#[pymethods]
impl PyStreamIterator {
    fn __iter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __next__(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let rx = match self.rx.as_mut() {
            Some(rx) => rx,
            None => return Err(pyo3::exceptions::PyStopIteration::new_err("exhausted")),
        };
        // detach GIL, 在 BLOCKING_RT 上收帧 (与 execute_sync 同 runtime, 避免嵌套 panic)
        let ev = py.detach(|| fe_core::BLOCKING_RT.block_on(rx.recv()));
        let ev = match ev {
            Some(e) => e,
            None => {
                // 通道关闭 → 释放 handle, 抛 StopIteration
                self.rx = None;
                if let Some(h) = self.handle.take() {
                    fe_core::BLOCKING_RT.block_on(async {
                        let _ = h.await;
                    });
                }
                return Err(pyo3::exceptions::PyStopIteration::new_err("done"));
            }
        };
        // serde → JSON 字符串 → python json.loads → dict (与 gui_action 路径一致)
        let json_str = serde_json::to_string(&ev)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("帧序列化失败: {e}")))?;
        let obj = py
            .import("json")?
            .call_method1("loads", (json_str,))?
            .unbind();
        if matches!(ev, ExecutionStreamEvent::Done(_)) {
            self.rx = None;
            if let Some(h) = self.handle.take() {
                fe_core::BLOCKING_RT.block_on(async {
                    let _ = h.await;
                });
            }
        }
        Ok(obj)
    }
}

#[pyclass(name = "NativeExecutor", skip_from_py_object)]
struct PyExecutor {
    inner: Executor,
}

#[pymethods]
impl PyExecutor {
    #[new]
    fn new() -> Self {
        Self {
            inner: Executor::new(),
        }
    }

    /// execute_sync(command, task_id=None, cwd=None, timeout_sec=30.0, env_vars=None, enable_rollback_snapshot=True)
    /// -> NativeExecutionResult
    fn execute_sync(
        &self,
        command: String,
        task_id: Option<String>,
        cwd: Option<String>,
        timeout_sec: Option<f64>,
        env_vars: Option<std::collections::HashMap<String, String>>,
        enable_rollback_snapshot: Option<bool>,
    ) -> PyExecutionResult {
        let req = ExecutionRequest {
            command: command.clone(),
            task_id: task_id.clone(),
            cwd,
            timeout_sec: timeout_sec.unwrap_or(30.0),
            env_vars,
            enable_rollback_snapshot: enable_rollback_snapshot.unwrap_or(true),
        };
        match self.inner.execute(req) {
            Ok(r) => r.into(),
            Err(e) => PyExecutionResult {
                exit_code: -1,
                stderr: format!("executor 内部错误: {}", e),
                task_id,
                command: Some(command),
                duration_sec: 0.0,
                blocked_by_security: false,
                timed_out: false,
                stdout: String::new(),
                security_reason: None,
                snapshot_id: None,
                diagnostics: None,
            },
        }
    }

    /// snapshot_create(cwd) -> str (快照 id; 非 repo 为空串)
    fn snapshot_create(&self, cwd: String) -> String {
        match fe_core::BLOCKING_RT.block_on(self.inner.snapshot_create_async(&cwd)) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(error = %e, "snapshot_create 失败");
                String::new()
            }
        }
    }

    /// rollback(snapshot_id, cwd) -> bool
    fn rollback(&self, snapshot_id: String, cwd: String) -> bool {
        match fe_core::BLOCKING_RT.block_on(self.inner.rollback_async(&snapshot_id, &cwd)) {
            Ok(ok) => ok,
            Err(e) => {
                tracing::warn!(error = %e, "rollback 失败");
                false
            }
        }
    }

    /// gui_action(action: dict) -> NativeGuiResult
    /// action: GuiAction dict (tag "kind": focus_app/click/type_text/keypress/screenshot/inspect_tree)
    /// 经 Python json.dumps → Rust serde_json 反序列化为 GuiAction, 调 fe-gui 执行
    fn gui_action(&self, py: Python<'_>, action: &Bound<'_, PyAny>) -> PyGuiResult {
        let json_str: String = match py
            .import("json")
            .and_then(|json| json.call_method1("dumps", (action,)))
            .and_then(|s| s.extract::<String>())
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "gui_action 入参转 JSON 失败");
                return PyGuiResult {
                    ok: false,
                    node_tree: None,
                    screenshot_png_b64: None,
                    screenshot_width: None,
                    screenshot_height: None,
                    error: Some(format!("action 入参无效: {e}")),
                };
            }
        };
        let gui_action: GuiAction = match serde_json::from_str(&json_str) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, json = %json_str, "gui_action 反序列化失败");
                return PyGuiResult {
                    ok: false,
                    node_tree: None,
                    screenshot_png_b64: None,
                    screenshot_width: None,
                    screenshot_height: None,
                    error: Some(format!("action 反序列化失败: {e}")),
                };
            }
        };
        match self.inner.gui_action(gui_action) {
            Ok(r) => r.into(),
            Err(e) => {
                tracing::warn!(error = %e, "gui_action 执行失败");
                PyGuiResult {
                    ok: false,
                    node_tree: None,
                    screenshot_png_b64: None,
                    screenshot_width: None,
                    screenshot_height: None,
                    error: Some(format!("gui_action 失败: {e}")),
                }
            }
        }
    }

    /// execute_streaming(command, task_id=None, cwd=None, timeout_sec=30.0, env_vars=None, enable_rollback_snapshot=True)
    /// -> NativeStreamIterator — 迭代 yield chunk 帧 {type:"chunk",data} 直至 done 帧 {type:"done",result:{...}}
    fn execute_streaming(
        &self,
        command: String,
        task_id: Option<String>,
        cwd: Option<String>,
        timeout_sec: Option<f64>,
        env_vars: Option<std::collections::HashMap<String, String>>,
        enable_rollback_snapshot: Option<bool>,
    ) -> PyResult<PyStreamIterator> {
        let req = ExecutionRequest {
            command,
            task_id,
            cwd,
            timeout_sec: timeout_sec.unwrap_or(30.0),
            env_vars,
            enable_rollback_snapshot: enable_rollback_snapshot.unwrap_or(true),
        };
        // execute_streaming async → BLOCKING_RT.block_on 取 (rx, handle); 后续 __next__ 同 RT 收帧
        let (rx, handle) = fe_core::BLOCKING_RT
            .block_on(self.inner.execute_streaming(req))
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("execute_streaming 失败: {e}"))
            })?;
        Ok(PyStreamIterator::new(rx, handle))
    }

    /// file_edit(path, old_string, new_string, cwd=None) -> NativeEditResult
    /// 唯一匹配 old_string → new_string 精确替换, 原子写
    fn file_edit(
        &self,
        path: String,
        old_string: String,
        new_string: String,
        cwd: Option<String>,
    ) -> PyEditResult {
        match self
            .inner
            .file_edit(&path, &old_string, &new_string, cwd.as_deref())
        {
            Ok(r) => r.into(),
            Err(e) => {
                tracing::warn!(error = %e, "file_edit 失败");
                PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("file_edit 失败: {e}")),
                    matches: 0,
                }
            }
        }
    }

    /// glob(pattern, cwd=None) -> list[NativeGlobEntry]
    fn glob(&self, pattern: String, cwd: Option<String>) -> PyResult<Vec<PyGlobEntry>> {
        self.inner
            .glob(&pattern, cwd.as_deref())
            .map(|entries| entries.into_iter().map(PyGlobEntry::from).collect())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("glob 失败: {e}")))
    }

    /// grep(pattern, paths, cwd=None) -> list[NativeGrepMatch]
    fn grep(
        &self,
        pattern: String,
        paths: Vec<String>,
        cwd: Option<String>,
    ) -> PyResult<Vec<PyGrepMatch>> {
        self.inner
            .grep(&pattern, &paths, cwd.as_deref())
            .map(|ms| ms.into_iter().map(PyGrepMatch::from).collect())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("grep 失败: {e}")))
    }

    /// apply_patch(diff, cwd=None) -> NativeEditResult — Unified Diff 应用, 禁全文件重写
    fn apply_patch(&self, diff: String, cwd: Option<String>) -> PyEditResult {
        match self.inner.apply_patch(&diff, cwd.as_deref()) {
            Ok(r) => r.into(),
            Err(e) => {
                tracing::warn!(error = %e, "apply_patch 失败");
                PyEditResult {
                    ok: false,
                    path: None,
                    error: Some(format!("apply_patch 失败: {e}")),
                    matches: 0,
                }
            }
        }
    }

    /// replace_function(path, fn_name, new_body, cwd=None) -> NativeEditResult — 函数级替换
    fn replace_function(
        &self,
        path: String,
        fn_name: String,
        new_body: String,
        cwd: Option<String>,
    ) -> PyEditResult {
        match self
            .inner
            .replace_function(&path, &fn_name, &new_body, cwd.as_deref())
        {
            Ok(r) => r.into(),
            Err(e) => {
                tracing::warn!(error = %e, "replace_function 失败");
                PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("replace_function 失败: {e}")),
                    matches: 0,
                }
            }
        }
    }

    /// serve(sock_path=None) — 启动 UDS JSON-RPC 2.0 服务器, 永驻直到进程退出
    fn serve(&self, sock_path: Option<String>) -> PyResult<()> {
        let sock = IpcServer::resolve_sock(sock_path.as_deref());
        let server = IpcServer::with_executor(Executor::new());
        tracing::info!(sock = %sock, "PyO3 serve() — 启动 IPC 服务器");
        match server.serve_blocking(&sock) {
            Ok(()) => Ok(()),
            Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "serve 失败: {}",
                e
            ))),
        }
    }
}

#[pymodule]
fn _native(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyDiagnostics>()?;
    m.add_class::<PyExecutionResult>()?;
    m.add_class::<PyGuiResult>()?;
    m.add_class::<PyEditResult>()?;
    m.add_class::<PyGlobEntry>()?;
    m.add_class::<PyGrepMatch>()?;
    m.add_class::<PyStreamIterator>()?;
    m.add_class::<PyExecutor>()?;
    Ok(())
}
