// fe-pyo3 — PyO3 绑定, maturin 目标 crate
//
// 产出 fusion_executor._native 扩展, 纯 Python executor.py 包装
// P1: 最小 execute_sync; 后续暴露 rollback/gui/serve

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};

use fe_core::gui::{GuiAction, GuiResult as RsGuiResult};
use fe_core::telemetry::{TelemetryConfig, TelemetrySample};
use fe_core::tools::{
    EditResult as RsEditResult, GlobEntry as RsGlobEntry, GrepMatch as RsGrepMatch,
    GrepOptions as RsGrepOptions,
};
use fe_core::{
    Diagnostics as RsDiag, ExecutionRequest, ExecutionResult as RsResult, ExecutionStreamEvent,
    Executor, RollbackPolicy,
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
    #[pyo3(get)]
    auto_rolled_back: bool,
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
            auto_rolled_back: r.auto_rolled_back,
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

/// Python 可见 grep 命中 — 镜像 fe_tools::GrepMatch (#7 +上下文)
#[pyclass(name = "NativeGrepMatch", skip_from_py_object)]
#[derive(Clone)]
struct PyGrepMatch {
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    line_number: u32,
    #[pyo3(get)]
    content: String,
    #[pyo3(get)]
    context_before: Vec<String>,
    #[pyo3(get)]
    context_after: Vec<String>,
}

impl From<RsGrepMatch> for PyGrepMatch {
    fn from(m: RsGrepMatch) -> Self {
        Self {
            path: m.path,
            line_number: m.line_number,
            content: m.content,
            context_before: m.context_before,
            context_after: m.context_after,
        }
    }
}

/// Python 可见 grep 计数行 — 镜像 fe_tools::GrepFileCount (#7 count 模式)
#[pyclass(name = "NativeGrepFileCount", skip_from_py_object)]
#[derive(Clone)]
struct PyGrepFileCount {
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    count: u32,
}

impl From<fe_core::tools::GrepFileCount> for PyGrepFileCount {
    fn from(c: fe_core::tools::GrepFileCount) -> Self {
        Self {
            path: c.path,
            count: c.count,
        }
    }
}

/// Python 可见 grep 输出 — 镜像 fe_tools::GrepOutput (#7 三模式聚合)
/// serde 序列化后透传 Python (避免逐字段拷贝); content 模式 matches 非空, files_with_matches 模式 files 非空
#[pyclass(name = "NativeGrepOutput", skip_from_py_object)]
struct PyGrepOutput {
    raw: String,
}

#[pymethods]
impl PyGrepOutput {
    /// 返回 dict (json.loads 反序列化), 与 Python Pydantic GrepOutput 一致
    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let json = py.import("json")?;
        Ok(json.call_method1("loads", (self.raw.clone(),))?.unbind())
    }

    #[getter]
    fn output_mode(&self) -> PyResult<String> {
        let v: serde_json::Value = serde_json::from_str(&self.raw)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("序列化错误: {e}")))?;
        Ok(v.get("output_mode")
            .and_then(|m| m.as_str())
            .unwrap_or("content")
            .to_string())
    }

    #[getter]
    fn matches(&self) -> PyResult<Vec<PyGrepMatch>> {
        let v: serde_json::Value = serde_json::from_str(&self.raw)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("序列化错误: {e}")))?;
        let ms: Vec<RsGrepMatch> = v
            .get("matches")
            .and_then(|m| serde_json::from_value(m.clone()).ok())
            .unwrap_or_default();
        Ok(ms.into_iter().map(PyGrepMatch::from).collect())
    }

    #[getter]
    fn files(&self) -> PyResult<Vec<String>> {
        let v: serde_json::Value = serde_json::from_str(&self.raw)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("序列化错误: {e}")))?;
        Ok(v.get("files")
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    #[getter]
    fn counts(&self) -> PyResult<Vec<PyGrepFileCount>> {
        let v: serde_json::Value = serde_json::from_str(&self.raw)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("序列化错误: {e}")))?;
        let cs: Vec<fe_core::tools::GrepFileCount> = v
            .get("counts")
            .and_then(|c| serde_json::from_value(c.clone()).ok())
            .unwrap_or_default();
        Ok(cs.into_iter().map(PyGrepFileCount::from).collect())
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

    // C-PYO3-04: 提前 Drop (调用方未迭代到 done 就弃迭代器) → abort 协调任务,
    // 避免后台任务泄漏。rx.take() 关通道, handle.abort() 停任务。
    fn cleanup(&mut self) {
        self.rx = None;
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

impl Drop for PyStreamIterator {
    fn drop(&mut self) {
        self.cleanup();
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
        let ev: ExecutionStreamEvent = match ev {
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

/// 遥测迭代器 — 消费 tokio mpsc<TelemetrySample>, 每次 __next__ 返回一帧 dict
/// sample: {"type":"sample","ts_ms":..,"cpu_pct":..,"mem_mb":..,"gpu_pct":null,...}
/// 通道关闭 → StopIteration
#[pyclass(name = "NativeTelemetryIterator", skip_from_py_object)]
struct PyTelemetryIterator {
    rx: Option<tokio::sync::mpsc::Receiver<TelemetrySample>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl PyTelemetryIterator {
    // C-PYO3-04: 同 PyStreamIterator — Drop abort 协调任务防泄漏
    fn cleanup(&mut self) {
        self.rx = None;
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

impl Drop for PyTelemetryIterator {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[pymethods]
impl PyTelemetryIterator {
    fn __iter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __next__(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let rx = match self.rx.as_mut() {
            Some(rx) => rx,
            None => return Err(pyo3::exceptions::PyStopIteration::new_err("exhausted")),
        };
        let sample = py.detach(|| fe_core::BLOCKING_RT.block_on(rx.recv()));
        let sample: TelemetrySample = match sample {
            Some(s) => s,
            None => {
                self.rx = None;
                if let Some(h) = self.handle.take() {
                    fe_core::BLOCKING_RT.block_on(async {
                        let _ = h.await;
                    });
                }
                return Err(pyo3::exceptions::PyStopIteration::new_err("done"));
            }
        };
        let json_str = serde_json::to_string(&sample).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("遥测帧序列化失败: {e}"))
        })?;
        let obj = py
            .import("json")?
            .call_method1("loads", (json_str,))?
            .unbind();
        Ok(obj)
    }
}

#[pyclass(name = "NativeExecutor", skip_from_py_object)]
struct PyExecutor {
    inner: Executor,
    extra_whitelist: Vec<String>,
}

#[pymethods]
impl PyExecutor {
    #[new]
    #[pyo3(signature = (extra_whitelist=None))]
    fn new(extra_whitelist: Option<Vec<String>>) -> Self {
        let extras: Vec<&str> = extra_whitelist
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .collect();
        let inner = if extras.is_empty() {
            Executor::new()
        } else {
            tracing::info!(count = extras.len(), "PyExecutor 构造带项目级白名单扩展");
            Executor::new().with_extra_whitelist(&extras)
        };
        Self {
            inner,
            extra_whitelist: extra_whitelist.unwrap_or_default(),
        }
    }

    /// execute_sync(command, task_id=None, cwd=None, timeout_sec=30.0, env_vars=None,
    ///               enable_rollback_snapshot=True, auto_rollback_policy=None)
    /// -> NativeExecutionResult
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (command, task_id=None, cwd=None, timeout_sec=None, env_vars=None,
                        enable_rollback_snapshot=None, auto_rollback_policy=None,
                        seatbelt=None, inherit_env=None, use_pty=None,
                        max_nproc=None, max_cpu_sec=None))]
    fn execute_sync(
        &self,
        py: Python<'_>,
        command: String,
        task_id: Option<String>,
        cwd: Option<String>,
        timeout_sec: Option<f64>,
        env_vars: Option<std::collections::HashMap<String, String>>,
        enable_rollback_snapshot: Option<bool>,
        auto_rollback_policy: Option<Bound<'_, PyAny>>,
        seatbelt: Option<bool>,
        inherit_env: Option<bool>,
        use_pty: Option<bool>,
        max_nproc: Option<u32>,
        max_cpu_sec: Option<u32>,
    ) -> PyResult<PyExecutionResult> {
        // L-PYO3-02: policy 入参无效应 fail-loud (旧版 warn+None 静默吞错, 调用方以为开了回滚实则没开)
        let policy = match auto_rollback_policy {
            None => None,
            Some(obj) => Some({
                let json_str: String = py
                    .import("json")
                    .and_then(|json| json.call_method1("dumps", (&obj,)))
                    .and_then(|s| s.extract::<String>())
                    .map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "auto_rollback_policy 转 JSON 失败: {e}"
                        ))
                    })?;
                serde_json::from_str::<RollbackPolicy>(&json_str).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "auto_rollback_policy 反序列化失败: {e}"
                    ))
                })?
            }),
        };
        let req = ExecutionRequest {
            command: command.clone(),
            task_id,
            cwd,
            timeout_sec: timeout_sec.unwrap_or(30.0),
            env_vars,
            enable_rollback_snapshot: enable_rollback_snapshot.unwrap_or(true),
            auto_rollback_policy: policy,
            seatbelt: seatbelt.unwrap_or(false),
            inherit_env: inherit_env.unwrap_or(false),
            use_pty: use_pty.unwrap_or(true),
            max_nproc: max_nproc.unwrap_or(1024),
            max_cpu_sec: max_cpu_sec.unwrap_or(0),
        };
        // M-PYO3-02: 内部错误 fail-loud (旧版伪造 exit_code=-1 ExecutionResult, 调用方无法区分
        // 安全拦截与 executor bug; execute 仅在 sandbox 内部异常返 Err, 应上抛)
        self.inner
            .execute(req)
            .map(PyExecutionResult::from)
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("executor 内部错误: {e}"))
            })
    }

    /// snapshot_create(cwd) -> str (快照 id; 非 repo 为空串, 合法契约)
    /// M-PYO3-01: git 失败 (非 "非 repo 空串") fail-loud 抛 PyRuntimeError
    fn snapshot_create(&self, cwd: String) -> PyResult<String> {
        fe_core::BLOCKING_RT
            .block_on(self.inner.snapshot_create_async(&cwd))
            .map_err(|e| {
                tracing::error!(error = %e, "snapshot_create 失败");
                pyo3::exceptions::PyRuntimeError::new_err(format!("snapshot_create 失败: {e}"))
            })
    }

    /// rollback(snapshot_id, cwd) -> bool (Ok(false) = 跳过/非 repo, 合法)
    /// M-PYO3-01: git 失败 (Err) fail-loud 抛 PyRuntimeError
    fn rollback(&self, snapshot_id: String, cwd: String) -> PyResult<bool> {
        fe_core::BLOCKING_RT
            .block_on(self.inner.rollback_async(&snapshot_id, &cwd))
            .map_err(|e| {
                tracing::error!(error = %e, "rollback 失败");
                pyo3::exceptions::PyRuntimeError::new_err(format!("rollback 失败: {e}"))
            })
    }

    /// validate(command) -> dict {allowed, blocked, reason, stage}
    /// Issue #11 / #12.4: 非执行预校验 — 调用方先问用户授权再 execute (Option A, caller owns gating)。
    /// 同步 (纯 CPU 校验, 无 I/O, 不需 BLOCKING_RT)。
    fn validate<'py>(&self, py: Python<'py>, command: String) -> PyResult<Bound<'py, PyDict>> {
        let verdict = self.inner.validate(&command);
        let dict = PyDict::new(py);
        dict.set_item("allowed", verdict.allowed)?;
        dict.set_item("blocked", !verdict.allowed)?;
        dict.set_item("reason", verdict.reason.clone())?;
        // stage: SecurityStage → 字符串 ("regex"/"tokenizer"), 避 serde_json 带引号
        let stage_str = verdict.stage.map(|s| match s {
            fe_core::security::SecurityStage::Regex => "regex",
            fe_core::security::SecurityStage::Tokenizer => "tokenizer",
        });
        dict.set_item("stage", stage_str)?;
        Ok(dict)
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
        // 2.2: 释 GIL 执行 — gui_action 含 Wait (thread::sleep 最多 60s) + AX/CGEvent 阻塞调用。
        // 旧版持 GIL → wait(60) 冻结 Python 解释器 60s (其他 Agent run_async 无法调度)。
        // py.detach 释 GIL 期间 Python 线程可跑; self.inner 是 Rust 结构体非 Python 对象, 借用安全。
        let result = py.detach(|| self.inner.gui_action(gui_action));
        match result {
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

    /// execute_streaming(command, task_id=None, cwd=None, timeout_sec=30.0, env_vars=None,
    ///                    enable_rollback_snapshot=True, auto_rollback_policy=None)
    /// -> NativeStreamIterator — 迭代 yield chunk 帧 {type:"chunk",data} 直至 done 帧 {type:"done",result:{...}}
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (command, task_id=None, cwd=None, timeout_sec=None, env_vars=None,
                        enable_rollback_snapshot=None, auto_rollback_policy=None,
                        seatbelt=None, inherit_env=None, use_pty=None,
                        max_nproc=None, max_cpu_sec=None))]
    fn execute_streaming(
        &self,
        py: Python<'_>,
        command: String,
        task_id: Option<String>,
        cwd: Option<String>,
        timeout_sec: Option<f64>,
        env_vars: Option<std::collections::HashMap<String, String>>,
        enable_rollback_snapshot: Option<bool>,
        auto_rollback_policy: Option<Bound<'_, PyAny>>,
        seatbelt: Option<bool>,
        inherit_env: Option<bool>,
        use_pty: Option<bool>,
        max_nproc: Option<u32>,
        max_cpu_sec: Option<u32>,
    ) -> PyResult<PyStreamIterator> {
        let policy = match auto_rollback_policy {
            None => None,
            Some(obj) => Some({
                let json_str: String = py
                    .import("json")
                    .and_then(|json| json.call_method1("dumps", (&obj,)))
                    .and_then(|s| s.extract::<String>())
                    .map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "auto_rollback_policy 转 JSON 失败: {e}"
                        ))
                    })?;
                serde_json::from_str::<RollbackPolicy>(&json_str).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "auto_rollback_policy 反序列化失败: {e}"
                    ))
                })?
            }),
        };
        let req = ExecutionRequest {
            command,
            task_id,
            cwd,
            timeout_sec: timeout_sec.unwrap_or(30.0),
            env_vars,
            enable_rollback_snapshot: enable_rollback_snapshot.unwrap_or(true),
            auto_rollback_policy: policy,
            seatbelt: seatbelt.unwrap_or(false),
            inherit_env: inherit_env.unwrap_or(false),
            use_pty: use_pty.unwrap_or(true),
            max_nproc: max_nproc.unwrap_or(1024),
            max_cpu_sec: max_cpu_sec.unwrap_or(0),
        }; // L-PYO3-01: execute_streaming async → 释 GIL 后在 BLOCKING_RT block_on (旧版持 GIL
           // 整个 spawn + 校验期间, 阻塞 Python 线程; detach 后 Python 可并发跑其他协程)
        let (rx, handle) = py
            .detach(|| fe_core::BLOCKING_RT.block_on(self.inner.execute_streaming(req)))
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("execute_streaming 失败: {e}"))
            })?;
        Ok(PyStreamIterator::new(rx, handle))
    }

    /// telemetry_stream(interval_ms=100, max_samples=0) -> NativeTelemetryIterator
    /// 迭代 yield TelemetrySample dict (ts_ms/cpu_pct/mem_mb/gpu_pct/gpu_mem_mb/task_id)
    /// 默认 10Hz 无限采样; max_samples>0 达此值后结束
    fn telemetry_stream(
        &self,
        interval_ms: Option<u64>,
        max_samples: Option<u64>,
    ) -> PyResult<PyTelemetryIterator> {
        let cfg = TelemetryConfig {
            interval_ms: interval_ms.unwrap_or(100),
            max_samples: max_samples.unwrap_or(0),
        };
        let (rx, handle) = self.inner.telemetry_stream(cfg);
        Ok(PyTelemetryIterator {
            rx: Some(rx),
            handle: Some(handle),
        })
    }

    /// file_edit(path, old_string, new_string, cwd=None, replace_all=False) -> NativeEditResult
    /// 唯一匹配 old_string → new_string 精确替换 (replace_all=True 全量), 原子写
    #[pyo3(signature = (path, old_string, new_string, cwd=None, replace_all=false))]
    fn file_edit(
        &self,
        path: String,
        old_string: String,
        new_string: String,
        cwd: Option<String>,
        replace_all: bool,
    ) -> PyEditResult {
        match self
            .inner
            .file_edit(&path, &old_string, &new_string, cwd.as_deref(), replace_all)
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

    /// write_file(path, content, cwd=None) -> NativeEditResult — 整文件创建/覆盖 + 建父目录 (#2)
    #[pyo3(signature = (path, content, cwd=None))]
    fn write_file(&self, path: String, content: String, cwd: Option<String>) -> PyEditResult {
        match self.inner.write_file(&path, &content, cwd.as_deref()) {
            Ok(r) => r.into(),
            Err(e) => {
                tracing::warn!(error = %e, "write_file 失败");
                PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("write_file 失败: {e}")),
                    matches: 0,
                }
            }
        }
    }

    /// multi_edit(path, edits, cwd=None) -> NativeEditResult
    /// 同文件顺序批量编辑, 原子 all-or-nothing
    fn multi_edit(
        &self,
        py: Python<'_>,
        path: String,
        edits: &Bound<'_, PyAny>,
        cwd: Option<String>,
    ) -> PyEditResult {
        let edits_json = py
            .import("json")
            .and_then(|json| json.call_method1("dumps", (edits,)))
            .and_then(|s| s.extract::<String>());
        let parsed: Vec<fe_core::tools::MultiEditItem> = match edits_json {
            Ok(s) => match serde_json::from_str(&s) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "multi_edit edits 反序列化失败");
                    return PyEditResult {
                        ok: false,
                        path: Some(path),
                        error: Some(format!("multi_edit edits 解析失败: {e}")),
                        matches: 0,
                    };
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "multi_edit JSON 序列化失败");
                return PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("multi_edit edits 序列化失败: {e}")),
                    matches: 0,
                };
            }
        };
        match self.inner.multi_edit(&path, &parsed, cwd.as_deref()) {
            Ok(r) => r.into(),
            Err(e) => {
                tracing::warn!(error = %e, "multi_edit 失败");
                PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("multi_edit 失败: {e}")),
                    matches: 0,
                }
            }
        }
    }

    /// notebook_edit(path, cell_id=None, cell_number=None, new_source, edit_mode="replace", cwd=None) -> NativeEditResult
    /// Jupyter .ipynb 单元格编辑 (replace/insert/delete)
    #[pyo3(signature = (path, new_source, cell_id=None, cell_number=None, edit_mode="replace", cwd=None))]
    fn notebook_edit(
        &self,
        path: String,
        new_source: String,
        cell_id: Option<String>,
        cell_number: Option<i64>,
        edit_mode: &str,
        cwd: Option<String>,
    ) -> PyEditResult {
        let mode = match serde_json::from_value::<fe_core::tools::NotebookEditMode>(
            serde_json::Value::String(edit_mode.to_string()),
        ) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, mode = edit_mode, "notebook_edit edit_mode 无效");
                return PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("edit_mode 无效: {e}")),
                    matches: 0,
                };
            }
        };
        match self.inner.notebook_edit(
            &path,
            cell_id.as_deref(),
            cell_number,
            &new_source,
            mode,
            cwd.as_deref(),
        ) {
            Ok(r) => r.into(),
            Err(e) => {
                tracing::warn!(error = %e, "notebook_edit 失败");
                PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("notebook_edit 失败: {e}")),
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

    /// #7 ripgrep parity — grep_with_opts(pattern, paths, opts, cwd=None) -> NativeGrepOutput
    /// opts: dict (output_mode/after/before/context/multiline/glob_include/glob_exclude), 字段全可选
    fn grep_with_opts(
        &self,
        pattern: String,
        paths: Vec<String>,
        opts: &Bound<'_, PyAny>,
        cwd: Option<String>,
        py: Python<'_>,
    ) -> PyResult<Py<PyGrepOutput>> {
        // dict → json str → serde GrepOptions (字段全 #[serde(default)])
        let json_mod = py.import("json")?;
        let opts_str: String = json_mod
            .call_method1("dumps", (opts,))?
            .extract()
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("opts 序列化失败: {e}"))
            })?;
        let rs_opts: RsGrepOptions = serde_json::from_str(&opts_str).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("opts 解析失败: {e}"))
        })?;
        let out = self
            .inner
            .grep_with_opts(&pattern, &paths, cwd.as_deref(), &rs_opts)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("grep 失败: {e}")))?;
        let raw = serde_json::to_string(&out).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("输出序列化失败: {e}"))
        })?;
        Py::new(py, PyGrepOutput { raw })
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
    /// P-PYO3-01: serve 用独立 Executor::new() 而非 self.inner — Executor 每任务无状态
    /// (CLAUDE.md 约定: consecutive-failure counting owned by caller), 跨调用无共享状态,
    /// 故 serve 的 IPC 请求与进程内 self.inner.execute 语义等价。隔离避免长驻 serve 影响
    /// 调用方持有的 self.inner (如 serve 内命令改动 cwd 影响进程内调用)。
    fn serve(&self, py: pyo3::Python<'_>, sock_path: Option<String>) -> PyResult<()> {
        let sock = IpcServer::resolve_sock(sock_path.as_deref());
        let extras: Vec<&str> = self.extra_whitelist.iter().map(String::as_str).collect();
        let exec = if extras.is_empty() {
            Executor::new()
        } else {
            Executor::new().with_extra_whitelist(&extras)
        };
        let server = IpcServer::with_executor(exec);
        tracing::info!(sock = %sock, "PyO3 serve() — 启动 IPC 服务器 (释 GIL, 信号可停)");
        // C-PYO3-02: 释 GIL 跑 serve_blocking — Rust 侧 tokio::signal 监听 SIGINT/SIGTERM
        // 中断 accept_loop (不依赖 Python 信号 handler, 后者在 GIL 持有时不执行)。
        // py.detach 释 GIL 期间 Python 信号 handler 亦可运行; 双路皆干净退出。
        py.detach(|| match server.serve_blocking(&sock) {
            Ok(()) => Ok(()),
            Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "serve 失败: {}",
                e
            ))),
        })
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
    m.add_class::<PyTelemetryIterator>()?;
    m.add_class::<PyExecutor>()?;
    Ok(())
}
