// fe-pyo3 — PyO3 绑定, maturin 目标 crate
//
// 产出 fusion_executor._native 扩展, 纯 Python executor.py 包装
// P1: 最小 execute_sync; 后续暴露 rollback/gui/serve

use std::sync::Arc;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};

use fe_core::gui::{GuiAction, GuiResult as RsGuiResult};
use fe_core::shell::{ShellRegistry, ShellStartParams, ShellStartResult as RsShellStartResult};
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

/// C-3: 流式迭代器 __next__ 每帧 recv 超时 (秒)。沙箱 timeout_sec 上限 DEFAULT_TIMEOUT_CAP_SEC=120s
/// (fe-sandbox, 私有不导出), 加 10s grace 给转发任务发 Done → 130s。超时 → PyTimeoutError
/// (非 StopIteration — 超时是错, 非干净 EOF)。病态命令卡转发任务 (PTY 死锁/D 态/runtime 饱和/满通道)
/// 时, recv() 永久阻塞 → Python 消费者楔死。此 deadline 守 IPC 桥, 不守叶子 (沙箱心跳守叶子)。
pub const STREAM_RECV_TIMEOUT_SECS: u64 = 130;

/// C-3: Done 帧后 join 转发任务的超时 (秒)。超时 → abort (避免 Python 消费者等悬挂任务)。
pub const JOIN_TIMEOUT_SECS: u64 = 5;

/// C-3: 遥测迭代器 __next__ idle 超时 (秒)。遥测源 10Hz (interval_ms=100), idle 30s 无帧 = 源任务死。
pub const TELEMETRY_IDLE_TIMEOUT_SECS: u64 = 30;

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
    /// L-2: 回滚保障失效标记 — guard 出错时置 true (fail-loud, 不静默)。
    /// 与 auto_rolled_back 互补: 后者表 "已回滚", 此字段表 "本应回滚但保障不可用"。
    #[pyo3(get)]
    rollback_unavailable: bool,
    /// L-1 (审计 0827): 回滚跳过原因 — rollback 尝试过但跳过 (快照失效/解析失败/非 git/repo 不匹配)
    /// 时填充。与 auto_rolled_back/rollback_unavailable 互补, 三轴独立 (fail-loud)。
    #[pyo3(get)]
    rollback_skipped_reason: Option<String>,
    /// M-OPS-06: 跨层关联 id (回填请求侧或入口自动生成)
    #[pyo3(get)]
    trace_id: Option<String>,
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
            rollback_unavailable: r.rollback_unavailable,
            rollback_skipped_reason: r.rollback_skipped_reason.clone(),
            trace_id: r.trace_id,
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

/// Python 可见 shell 启动结果 — 镜像 fe_shell::ShellStartResult (#1)
/// raw serde 透传; 安全校验在 fe-core (blocked_by_security=true 时 shell_id=None)
#[pyclass(name = "NativeShellStartResult", skip_from_py_object)]
struct PyShellStartResult {
    raw: String,
}

#[pymethods]
impl PyShellStartResult {
    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let json = py.import("json")?;
        Ok(json.call_method1("loads", (self.raw.clone(),))?.unbind())
    }

    #[getter]
    fn ok(&self) -> PyResult<bool> {
        let v: serde_json::Value = serde_json::from_str(&self.raw)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("序列化错误: {e}")))?;
        Ok(v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false))
    }

    #[getter]
    fn shell_id(&self) -> PyResult<Option<String>> {
        let v: serde_json::Value = serde_json::from_str(&self.raw)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("序列化错误: {e}")))?;
        Ok(v.get("shell_id").and_then(|s| s.as_str()).map(String::from))
    }
}

/// Python 可见 shell 轮询结果 — 镜像 fe_shell::ShellOutput (#1)
#[pyclass(name = "NativeShellOutput", skip_from_py_object)]
struct PyShellOutput {
    raw: String,
}

#[pymethods]
impl PyShellOutput {
    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let json = py.import("json")?;
        Ok(json.call_method1("loads", (self.raw.clone(),))?.unbind())
    }

    #[getter]
    fn running(&self) -> PyResult<bool> {
        let v: serde_json::Value = serde_json::from_str(&self.raw)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("序列化错误: {e}")))?;
        Ok(v.get("running").and_then(|b| b.as_bool()).unwrap_or(false))
    }
}

/// Python 可见 shell 信息 — 镜像 fe_shell::ShellInfo (#1)
#[pyclass(name = "NativeShellInfo", skip_from_py_object)]
#[derive(Clone)]
struct PyShellInfo {
    raw: String,
}

#[pymethods]
impl PyShellInfo {
    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let json = py.import("json")?;
        Ok(json.call_method1("loads", (self.raw.clone(),))?.unbind())
    }
}

/// chunk: {"type":"chunk","data":"..."} / done: {"type":"done","result":{...ExecutionResult}}
/// 通道关闭 + saw_done → StopIteration; 通道关闭 + !saw_done → PyRuntimeError (C-4)
#[pyclass(name = "NativeStreamIterator", skip_from_py_object)]
struct PyStreamIterator {
    rx: Option<tokio::sync::mpsc::Receiver<ExecutionStreamEvent>>,
    handle: Option<tokio::task::JoinHandle<()>>,
    /// C-4: 是否已发 Done 帧。recv()→None (通道关闭) 时, !saw_done = 转发任务 panic/abort
    /// 未发 Done (fe-core catch_unwind 兜底但仍可能通道先关), 抛 PyRuntimeError 非 StopIteration
    /// (干净 EOF vs 任务崩不可区分 → 都当干净吞结果, Agent 循环看似成功无结果)。
    saw_done: bool,
}

impl PyStreamIterator {
    fn new(
        rx: tokio::sync::mpsc::Receiver<ExecutionStreamEvent>,
        handle: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            rx: Some(rx),
            handle: Some(handle),
            saw_done: false,
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
        // C-3: 每帧 recv deadline — 病态命令卡转发任务时 recv() 永久阻塞楔死 Python 消费者。
        // 超时 → PyTimeoutError (非 StopIteration — 超时是错, 非干净 EOF)。沙箱心跳守叶子,
        // 此 deadline 守 IPC 桥 (PTY 死锁/D 态/runtime 饱和/满通道 不会让 recv() 返)。
        // C-4: 三态显式区分 — Ok(Some)=帧, Ok(None)=通道关, Err(Elapsed)=超时。
        // 通道关 + !saw_done = 转发任务 panic/abort 未发 Done → PyRuntimeError (非 StopIteration)。
        // fe-core catch_unwind 兜底发显式 Done, 但 spawn 任务被 abort (Drop) 时通道先关仍可能无 Done。
        let outcome: Result<Option<ExecutionStreamEvent>, ()> = py.detach(|| {
            // C-3: timeout 须在 block_on 的 async 块内构造 — 外层构造的 tokio::time::timeout
            // 的 Sleep 在 block_on 前 poll 时无 reactor (panic "no reactor running")。
            let secs = STREAM_RECV_TIMEOUT_SECS;
            fe_core::BLOCKING_RT.block_on(async {
                match tokio::time::timeout(Duration::from_secs(secs), rx.recv()).await {
                    Ok(opt) => Ok(opt),
                    Err(_elapsed) => {
                        tracing::error!(secs, "流式 recv 超时 — 转发任务楔死, 抛 PyTimeoutError");
                        Err(())
                    }
                }
            })
        });
        let ev = match outcome {
            Ok(Some(e)) => e,
            Ok(None) => {
                // 通道关闭: saw_done=干净 EOF→StopIteration; !saw_done=任务崩未发 Done→PyRuntimeError
                self.rx = None;
                self.join_forward_task();
                if self.saw_done {
                    return Err(pyo3::exceptions::PyStopIteration::new_err("done"));
                }
                return Err(pyo3::exceptions::PyRuntimeError::new_err(
                    "stream ended without Done frame — 转发任务 panic/abort 未发 Done, 结果丢失",
                ));
            }
            Err(()) => {
                // C-3: 超时 — 通道未关, 但转发任务楔死。abort 任务, 抛 PyTimeoutError。
                self.rx = None;
                self.join_forward_task();
                return Err(pyo3::exceptions::PyTimeoutError::new_err(format!(
                    "流式 recv 超时 ({STREAM_RECV_TIMEOUT_SECS}s) — 转发任务楔死"
                )));
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
            self.saw_done = true;
            self.rx = None;
            self.join_forward_task();
        }
        Ok(obj)
    }

    /// C-3: join 转发任务带 5s 超时, 超时 abort (避免 Python 消费者等悬挂任务)。
    fn join_forward_task(&mut self) {
        if let Some(h) = self.handle.take() {
            let joined = fe_core::BLOCKING_RT.block_on(async {
                tokio::time::timeout(Duration::from_secs(JOIN_TIMEOUT_SECS), h).await
            });
            if joined.is_err() {
                tracing::warn!("join 转发任务超时 {JOIN_TIMEOUT_SECS}s, abort");
            }
        }
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
        // C-3: idle 超时 — 遥测源 10Hz (interval_ms=100), TELEMETRY_IDLE_TIMEOUT_SECS 无帧 = 源任务死。
        // 三态: Ok(Some)=帧, Ok(None)=通道关 (干净 EOF→StopIteration), Err(Elapsed)=idle 超时→PyTimeoutError。
        let outcome: Result<Option<TelemetrySample>, ()> = py.detach(|| {
            // C-3: timeout 须在 block_on 的 async 块内构造 (同 PyStreamIterator — 外层构造的
            // tokio::time::timeout Sleep 在 block_on 前 poll 时无 reactor, panic)。
            let secs = TELEMETRY_IDLE_TIMEOUT_SECS;
            fe_core::BLOCKING_RT.block_on(async {
                match tokio::time::timeout(Duration::from_secs(secs), rx.recv()).await {
                    Ok(opt) => Ok(opt),
                    Err(_elapsed) => {
                        tracing::error!(secs, "遥测 idle 超时 — 采样任务死, 抛 PyTimeoutError");
                        Err(())
                    }
                }
            })
        });
        let sample = match outcome {
            Ok(Some(s)) => s,
            Ok(None) => {
                self.rx = None;
                self.join_sampler();
                return Err(pyo3::exceptions::PyStopIteration::new_err("done"));
            }
            Err(()) => {
                self.rx = None;
                self.join_sampler();
                return Err(pyo3::exceptions::PyTimeoutError::new_err(format!(
                    "遥测 idle 超时 ({TELEMETRY_IDLE_TIMEOUT_SECS}s) — 采样任务死"
                )));
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

    /// C-3: join 采样任务带 5s 超时, 超时 abort。
    fn join_sampler(&mut self) {
        if let Some(h) = self.handle.take() {
            let joined = fe_core::BLOCKING_RT.block_on(async {
                tokio::time::timeout(Duration::from_secs(JOIN_TIMEOUT_SECS), h).await
            });
            if joined.is_err() {
                tracing::warn!("join 采样任务超时 {JOIN_TIMEOUT_SECS}s, abort");
            }
        }
    }
}

#[pyclass(name = "NativeExecutor", skip_from_py_object)]
struct PyExecutor {
    // A-4: Arc<Executor> — serve() 共享同一 Arc 而非重建 Executor。SIGHUP 重载白名单
    // (reload_extra_whitelist 改 Executor 内 ArcSwap) 跨 in-process 与 serve-path 持久;
    // 旧版 serve 重建 Executor → in-process self.inner 白名单与 serve-path 离婚。
    inner: Arc<Executor>,
    // M-ARCH-1: ShellRegistry 归 PyExecutor (非 Executor)。serve() 时 self.shells.clone()
    // (Arc 浅拷) 共享进 IpcServer — in-process path 与 serve-path 同一 registry, serve 重启不丢句柄。
    shells: Arc<ShellRegistry>,
}

#[pymethods]
impl PyExecutor {
    #[new]
    #[pyo3(signature = (extra_whitelist=None))]
    fn new(extra_whitelist: Option<Vec<String>>) -> Self {
        // extra_whitelist 经 with_extra_whitelist 烘焙进 inner 的 ArcSwap; A-4 后 serve() 共享
        // inner, 无需单独存。SIGHUP reload 从 FUSION_EXECUTOR_EXTRA_WHITELIST env 读 (m-OPS-02)。
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
            inner: Arc::new(inner),
            shells: Arc::new(ShellRegistry::new()),
        }
    }

    /// execute_sync(command, task_id=None, cwd=None, timeout_sec=30.0, env_vars=None,
    ///               enable_rollback_snapshot=True, auto_rollback_policy=None)
    /// -> NativeExecutionResult
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (command, task_id=None, cwd=None, timeout_sec=None, env_vars=None,
                        enable_rollback_snapshot=None, auto_rollback_policy=None,
                        seatbelt=None, inherit_env=None, use_pty=None,
                        max_nproc=None, max_cpu_sec=None, trace_id=None))]
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
        trace_id: Option<String>,
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
            trace_id,
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
                        max_nproc=None, max_cpu_sec=None, trace_id=None))]
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
        trace_id: Option<String>,
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
            trace_id,
        }; // L-PYO3-01: execute_streaming async → 释 GIL 后在 BLOCKING_RT block_on (旧版持 GIL
           // 整个 spawn + 校验期间, 阻塞 Python 线程; detach 后 Python 可并发跑其他协程)
        let (rx, handle) = py
            .detach(|| fe_core::BLOCKING_RT.block_on(self.inner.execute_streaming(req)))
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("execute_streaming 失败: {e}"))
            })?;
        Ok(PyStreamIterator::new(rx, handle))
    }

    /// telemetry_stream(interval_ms=100, max_samples=0, pid=None) -> NativeTelemetryIterator
    /// 迭代 yield TelemetrySample dict (ts_ms/cpu_pct/mem_mb/gpu_pct/gpu_mem_mb/task_id)
    /// 默认 10Hz 无限采样; max_samples>0 达此值后结束
    /// pid=None 采样 executor 自身 (默认); 传入沙箱子进程 PID 采样真实任务 (L-15)
    #[pyo3(signature = (interval_ms=100, max_samples=0, pid=None))]
    fn telemetry_stream(
        &self,
        interval_ms: u64,
        max_samples: u64,
        pid: Option<u32>,
    ) -> PyResult<PyTelemetryIterator> {
        let cfg = TelemetryConfig {
            interval_ms,
            max_samples,
            pid,
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

    /// shell_start(command, cwd=None, env_vars=None, task_id=None, max_output_chars=100000,
    ///             seatbelt=False, inherit_env=False, max_nproc=1024, max_cpu_sec=0,
    ///             max_idle_sec=3600)
    /// -> NativeShellStartResult — 后台持久 shell 启动 (#1, run_in_background parity)
    /// 安全校验在 fe-core (fail-closed); blocked → ok=false, shell_id=None
    /// max_idle_sec (m-SEC-01): 无输出超此值 (秒) 自动 kill; 0=不限。默认 3600。
    /// kill_grace_ms (M-9): kill 宽限期 (毫秒), SIGINT→grace→SIGKILL 间隔; 0=立即 SIGKILL。默认 500。
    #[pyo3(signature = (
        command,
        cwd=None,
        env_vars=None,
        task_id=None,
        max_output_chars=100_000,
        seatbelt=false,
        inherit_env=false,
        max_nproc=1024,
        max_cpu_sec=0,
        max_idle_sec=fe_core::shell::DEFAULT_MAX_IDLE_SEC,
        kill_grace_ms=500,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn shell_start(
        &self,
        py: Python<'_>,
        command: String,
        cwd: Option<String>,
        env_vars: Option<&Bound<'_, PyAny>>,
        task_id: Option<String>,
        max_output_chars: usize,
        seatbelt: bool,
        inherit_env: bool,
        max_nproc: u32,
        max_cpu_sec: u32,
        max_idle_sec: u64,
        kill_grace_ms: u64,
    ) -> PyResult<Py<PyShellStartResult>> {
        let env: std::collections::HashMap<String, String> = match env_vars {
            Some(obj) => {
                let json_mod = py.import("json")?;
                let s: String = json_mod
                    .call_method1("dumps", (obj,))?
                    .extract()
                    .map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "env_vars 序列化失败: {e}"
                        ))
                    })?;
                serde_json::from_str(&s).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("env_vars 解析失败: {e}"))
                })?
            }
            None => std::collections::HashMap::new(),
        };
        let sp = ShellStartParams {
            command,
            cwd,
            env,
            task_id,
            max_output_chars,
            seatbelt,
            inherit_env,
            max_nproc,
            max_cpu_sec,
            max_idle_sec,
            kill_grace_ms,
        };
        let r: RsShellStartResult = self.inner.shell_start(&self.shells, sp);
        let raw = serde_json::to_string(&r)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("序列化失败: {e}")))?;
        Py::new(py, PyShellStartResult { raw })
    }

    /// shell_output(shell_id) -> NativeShellOutput — 轮询 tail 快照 + 运行/退出状态 (#1)
    fn shell_output(&self, py: Python<'_>, shell_id: String) -> PyResult<Py<PyShellOutput>> {
        match Executor::shell_output(&self.shells, &shell_id) {
            Ok(out) => {
                let raw = serde_json::to_string(&out).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("序列化失败: {e}"))
                })?;
                Py::new(py, PyShellOutput { raw })
            }
            Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "shell_output 失败: {e}"
            ))),
        }
    }

    /// kill_shell(shell_id) -> bool — kill 进程树 (#1, KillShell parity)
    fn kill_shell(&self, shell_id: String) -> PyResult<bool> {
        Executor::kill_shell(&self.shells, &shell_id)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("kill_shell 失败: {e}")))
    }

    /// list_shells() -> list[NativeShellInfo] — 列出全部后台 shell (#1)
    fn list_shells(&self) -> PyResult<Vec<PyShellInfo>> {
        let list = Executor::list_shells(&self.shells);
        let mut out = Vec::with_capacity(list.len());
        for info in list {
            let raw = serde_json::to_string(&info).map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("序列化失败: {e}"))
            })?;
            out.push(PyShellInfo { raw });
        }
        Ok(out)
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
    /// A-4: 共享 self.inner (Arc<Executor>) 而非重建 — SIGHUP 重载白名单跨 in-process/serve 持久。
    /// Executor 每任务无状态 (CLAUDE.md), Arc 共享不改无状态语义; 仅白名单 (ArcSwap 内部可变) 共享。
    fn serve(&self, py: pyo3::Python<'_>, sock_path: Option<String>) -> PyResult<()> {
        // M-OPS-01: fe_ipc::logging init_tracing — JSON+滚动文件 (FE_LOG_DIR) + stderr,
        // EnvFilter 运行时可 reload (SIGHUP, m-OPS-02)。幂等, handle 存 fe-ipc 静态。
        let _ = fe_ipc::logging::init_tracing();
        let sock = IpcServer::resolve_sock(sock_path.as_deref());
        // A-4: 共享 Executor Arc — in-process path 与 serve-path 同一白名单 (SIGHUP 重载两者皆生效)。
        let server =
            IpcServer::with_executor_arc_and_shells(self.inner.clone(), self.shells.clone());
        tracing::info!(sock = %sock, "PyO3 serve() — 启动 IPC 服务器 (共享 Executor Arc, 释 GIL, 信号可停)");
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

/// C-OPS-06: 版本/构建信息 — build.rs 注入 FE_GIT_SHA/FE_BUILD_TIME, 版本取 CARGO_PKG_VERSION
/// Python __init__.py 经此读 __version__; IPC health 经 fe-ipc 读 (fe-ipc 自身 env! CARGO_PKG_VERSION)
#[pyfunction]
fn version_info() -> (String, String, String) {
    (
        env!("CARGO_PKG_VERSION").to_string(),
        env!("FE_GIT_SHA").to_string(),
        env!("FE_BUILD_TIME").to_string(),
    )
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
    m.add_class::<PyShellStartResult>()?;
    m.add_class::<PyShellOutput>()?;
    m.add_class::<PyShellInfo>()?;
    m.add_class::<PyExecutor>()?;
    m.add_function(wrap_pyfunction!(version_info, m)?)?;
    Ok(())
}
