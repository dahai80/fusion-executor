// fe-pyo3 — PyO3 bindings, the maturin target crate
//
// Produces the fusion_executor._native extension; pure-Python executor.py wraps it
// P1: minimal execute_sync; rollback/gui/serve exposed later

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
// Issue #34: per-command seatbelt profile (fe-core re-exports fe_sandbox as sandbox).
use fe_core::sandbox::seatbelt::SandboxProfile;
use fe_ipc::{IpcServer, StreamRegistry};

/// C-3: per-frame recv timeout (seconds) for the stream iterator's __next__. The sandbox
/// timeout_sec cap is DEFAULT_TIMEOUT_CAP_SEC=120s (fe-sandbox, private and not exported) plus
/// a 10s grace for the forward task to emit Done → 130s. On timeout → PyTimeoutError
/// (not StopIteration — a timeout is an error, not a clean EOF). With pathological commands
/// wedging the forward task (PTY deadlock / D state / runtime saturation / full channel),
/// recv() blocks forever → the Python consumer wedges. This deadline guards the IPC bridge,
/// not the leaves (the sandbox heartbeat guards leaves).
pub const STREAM_RECV_TIMEOUT_SECS: u64 = 130;

/// C-3: timeout (seconds) for joining the forward task after the Done frame. On timeout →
/// abort (avoids the Python consumer waiting on a hung task).
pub const JOIN_TIMEOUT_SECS: u64 = 5;

/// C-3: idle timeout (seconds) for the telemetry iterator's __next__. The telemetry source runs
/// at 10Hz (interval_ms=100); 30s of idle with no frame = the source task is dead.
pub const TELEMETRY_IDLE_TIMEOUT_SECS: u64 = 30;

/// Python-visible diagnostics — mirrors the Rust Diagnostics
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

/// Python-visible result — mirrors the Rust ExecutionResult
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
    /// L-2: rollback-assurance-unavailable flag — set true when the guard errors (fail-loud,
    /// never silent). Complementary to auto_rolled_back: the latter means "rolled back", this
    /// field means "should have rolled back but the assurance was unavailable".
    #[pyo3(get)]
    rollback_unavailable: bool,
    /// L-1 (audit 0827): rollback skip reason — filled when rollback was attempted but skipped
    /// (stale snapshot / parse failure / non-git / repo mismatch). Complementary to
    /// auto_rolled_back/rollback_unavailable; three independent axes (fail-loud).
    #[pyo3(get)]
    rollback_skipped_reason: Option<String>,
    /// M-OPS-06: cross-layer correlation id (backfilled from the request side or auto-generated at the entry)
    #[pyo3(get)]
    trace_id: Option<String>,
    /// D3-4 (audit 0827 product): RSS watchdog trigger flag (child process tree killed for
    /// exceeding rss_limit_mb)
    #[pyo3(get)]
    oom_killed: bool,
    /// RUN-11: sandbox child PID (callers pass it to telemetry_stream to sample the real task)
    #[pyo3(get)]
    pid: Option<u32>,
    /// Issue #23 (guard Phase 3): the guard's action_id for block/preview verdicts — the caller
    /// uses it to send guard a confirm approval loop (the executor only passes it through,
    /// never sends confirm). Guard OFF or allow → None.
    /// Additive wire field, 4-layer From/Pydantic/done-frame auto-flow.
    #[pyo3(get)]
    guard_action_id: Option<String>,
    /// Issue #32: server-side cancel triggers a deterministic process-tree kill
    /// (exit_code=-1, cancelled=true). The caller sends executor.cancel → fe-sandbox
    /// kill_process_group. Additive wire, 4-layer auto-flow.
    #[pyo3(get)]
    cancelled: bool,
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
            oom_killed: r.oom_killed,
            pid: r.pid,
            guard_action_id: r.guard_action_id,
            cancelled: r.cancelled,
        }
    }
}

/// Python-visible GUI result — mirrors fe_gui::GuiResult
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
    /// #38: backing scale factor — physical PNG pixels / logical points (Retina=2.0)
    #[pyo3(get)]
    scale_factor: f32,
    /// #43: display inventory JSON (filled by display_info), None = not a display_info result
    #[pyo3(get)]
    displays: Option<String>,
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
            scale_factor: r.scale_factor,
            displays: r.displays,
            error: r.error,
        }
    }
}

/// Python-visible file tool result — mirrors fe_tools::EditResult
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

/// Python-visible glob hit — mirrors fe_tools::GlobEntry
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

/// Python-visible grep hit — mirrors fe_tools::GrepMatch (#7 with context)
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

/// D6-03 (audit 0827 product): Python-visible snapshot entry — mirrors fe_rollback::SnapshotInfo.
#[pyclass(name = "NativeSnapshotInfo", skip_from_py_object)]
#[derive(Clone)]
struct PySnapshotInfo {
    #[pyo3(get)]
    id: String,
    #[pyo3(get)]
    created_ms: u64,
    #[pyo3(get)]
    kind: String,
}

impl From<fe_rollback::SnapshotInfo> for PySnapshotInfo {
    fn from(s: fe_rollback::SnapshotInfo) -> Self {
        Self {
            id: s.id,
            created_ms: s.created_ms,
            kind: s.kind,
        }
    }
}

#[pymethods]
impl PySnapshotInfo {
    /// Dict view — lets the Python side construct via Pydantic model_validate(fields).
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("id", self.id.clone())?;
        d.set_item("created_ms", self.created_ms)?;
        d.set_item("kind", self.kind.clone())?;
        Ok(d)
    }
}

/// Python-visible grep count row — mirrors fe_tools::GrepFileCount (#7 count mode)
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

/// Python-visible grep output — mirrors fe_tools::GrepOutput (#7 three-mode aggregation)
/// Passed to Python after serde serialization (avoids per-field copying); content mode has
/// non-empty matches, files_with_matches mode has non-empty files
#[pyclass(name = "NativeGrepOutput", skip_from_py_object)]
struct PyGrepOutput {
    raw: String,
}

#[pymethods]
impl PyGrepOutput {
    /// Returns a dict (deserialized via json.loads), matching the Python Pydantic GrepOutput
    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let json = py.import("json")?;
        Ok(json.call_method1("loads", (self.raw.clone(),))?.unbind())
    }

    #[getter]
    fn output_mode(&self) -> PyResult<String> {
        let v: serde_json::Value = serde_json::from_str(&self.raw).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("serialization error: {e}"))
        })?;
        Ok(v.get("output_mode")
            .and_then(|m| m.as_str())
            .unwrap_or("content")
            .to_string())
    }

    #[getter]
    fn matches(&self) -> PyResult<Vec<PyGrepMatch>> {
        let v: serde_json::Value = serde_json::from_str(&self.raw).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("serialization error: {e}"))
        })?;
        let ms: Vec<RsGrepMatch> = v
            .get("matches")
            .and_then(|m| serde_json::from_value(m.clone()).ok())
            .unwrap_or_default();
        Ok(ms.into_iter().map(PyGrepMatch::from).collect())
    }

    #[getter]
    fn files(&self) -> PyResult<Vec<String>> {
        let v: serde_json::Value = serde_json::from_str(&self.raw).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("serialization error: {e}"))
        })?;
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
        let v: serde_json::Value = serde_json::from_str(&self.raw).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("serialization error: {e}"))
        })?;
        let cs: Vec<fe_core::tools::GrepFileCount> = v
            .get("counts")
            .and_then(|c| serde_json::from_value(c.clone()).ok())
            .unwrap_or_default();
        Ok(cs.into_iter().map(PyGrepFileCount::from).collect())
    }
}

/// Python-visible shell start result — mirrors fe_shell::ShellStartResult (#1)
/// Raw serde passthrough; security validation lives in fe-core (blocked_by_security=true →
/// shell_id=None)
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
        let v: serde_json::Value = serde_json::from_str(&self.raw).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("serialization error: {e}"))
        })?;
        Ok(v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false))
    }

    #[getter]
    fn shell_id(&self) -> PyResult<Option<String>> {
        let v: serde_json::Value = serde_json::from_str(&self.raw).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("serialization error: {e}"))
        })?;
        Ok(v.get("shell_id").and_then(|s| s.as_str()).map(String::from))
    }
}

/// Python-visible shell poll result — mirrors fe_shell::ShellOutput (#1)
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
        let v: serde_json::Value = serde_json::from_str(&self.raw).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("serialization error: {e}"))
        })?;
        Ok(v.get("running").and_then(|b| b.as_bool()).unwrap_or(false))
    }
}

/// Python-visible shell info — mirrors fe_shell::ShellInfo (#1)
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
/// Channel closed + saw_done → StopIteration; channel closed + !saw_done → PyRuntimeError (C-4)
#[pyclass(name = "NativeStreamIterator", skip_from_py_object)]
struct PyStreamIterator {
    rx: Option<tokio::sync::mpsc::Receiver<ExecutionStreamEvent>>,
    handle: Option<tokio::task::JoinHandle<()>>,
    /// C-4: whether a Done frame was sent. When recv() → None (channel closed), !saw_done =
    /// the forward task panicked/aborted without sending Done (fe-core catch_unwind backstops
    /// this, but the channel may still close first) → raise PyRuntimeError, not StopIteration
    /// (a clean EOF vs a crashed task is indistinguishable → swallowing the result as clean
    /// makes the Agent loop look successful with no result).
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

    // C-PYO3-04: early Drop (the caller abandons the iterator before reaching done) → abort
    // the coordinator task to avoid leaking background tasks. rx.take() closes the channel;
    // handle.abort() stops the task.
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
        // C-3: per-frame recv deadline — with a pathological command wedging the forward task,
        // recv() blocks forever and wedges the Python consumer. On timeout → PyTimeoutError
        // (not StopIteration — a timeout is an error, not a clean EOF). The sandbox heartbeat
        // guards leaves; this deadline guards the IPC bridge (PTY deadlock / D state / runtime
        // saturation / full channel will not let recv() return).
        // C-4: three states explicitly distinguished — Ok(Some)=frame, Ok(None)=channel closed,
        // Err(Elapsed)=timeout.
        // Channel closed + !saw_done = the forward task panicked/aborted without sending Done
        // → PyRuntimeError (not StopIteration).
        // fe-core catch_unwind backstops with an explicit Done, but when the spawned task is
        // aborted (Drop) the channel can still close first without a Done.
        let outcome: Result<Option<ExecutionStreamEvent>, ()> = py.detach(|| {
            // C-3: the timeout must be constructed inside the block_on async block — a Sleep
            // from a tokio::time::timeout built outside block_on has no reactor when polled
            // before block_on (panic "no reactor running").
            let secs = STREAM_RECV_TIMEOUT_SECS;
            fe_core::BLOCKING_RT.block_on(async {
                match tokio::time::timeout(Duration::from_secs(secs), rx.recv()).await {
                    Ok(opt) => Ok(opt),
                    Err(_elapsed) => {
                        tracing::error!(
                            secs,
                            "stream recv timed out — forward task wedged, raising PyTimeoutError"
                        );
                        Err(())
                    }
                }
            })
        });
        let ev = match outcome {
            Ok(Some(e)) => e,
            Ok(None) => {
                // Channel closed: saw_done = clean EOF → StopIteration;
                // !saw_done = task crashed without sending Done → PyRuntimeError
                self.rx = None;
                self.join_forward_task();
                if self.saw_done {
                    return Err(pyo3::exceptions::PyStopIteration::new_err("done"));
                }
                return Err(pyo3::exceptions::PyRuntimeError::new_err(
                    "stream ended without Done frame — forward task panicked/aborted without sending Done, result lost",
                ));
            }
            Err(()) => {
                // C-3: timeout — channel not closed but the forward task is wedged. Abort the
                // task and raise PyTimeoutError.
                self.rx = None;
                self.join_forward_task();
                return Err(pyo3::exceptions::PyTimeoutError::new_err(format!(
                    "stream recv timed out ({STREAM_RECV_TIMEOUT_SECS}s) — forward task wedged"
                )));
            }
        };
        // Perf CRITICAL #2: the hot path (high-frequency Chunks) skips the serde→JSON string→
        // json.loads round-trip (full serialize+deserialize per frame breaks the UDS <2ms NFR
        // at high frame rates). Chunk builds a PyDict directly; the Done cold path (once,
        // ~20 fields) keeps the JSON round-trip (reuses ExecutionResult's serde shape, DRY).
        let obj: Py<PyAny> = match &ev {
            ExecutionStreamEvent::Chunk { data } => {
                let d = pyo3::types::PyDict::new(py);
                d.set_item("type", "chunk")?;
                d.set_item("data", data.clone())?;
                d.into_any().unbind()
            }
            ExecutionStreamEvent::Done(_) => {
                let json_str = serde_json::to_string(&ev).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "frame serialization failed: {e}"
                    ))
                })?;
                py.import("json")?
                    .call_method1("loads", (json_str,))?
                    .unbind()
            }
        };
        if matches!(ev, ExecutionStreamEvent::Done(_)) {
            self.saw_done = true;
            self.rx = None;
            self.join_forward_task();
        }
        Ok(obj)
    }

    /// C-3: join the forward task with a 5s timeout; on timeout abort (avoids the Python
    /// consumer waiting on a hung task).
    fn join_forward_task(&mut self) {
        if let Some(h) = self.handle.take() {
            let joined = fe_core::BLOCKING_RT.block_on(async {
                tokio::time::timeout(Duration::from_secs(JOIN_TIMEOUT_SECS), h).await
            });
            if joined.is_err() {
                tracing::warn!("join forward task timed out {JOIN_TIMEOUT_SECS}s, aborting");
            }
        }
    }
}

/// Telemetry iterator — consumes tokio mpsc<TelemetrySample>; each __next__ returns one dict
/// frame: {"type":"sample","ts_ms":..,"cpu_pct":..,"mem_mb":..,"gpu_pct":null,...}
/// Channel closed → StopIteration
#[pyclass(name = "NativeTelemetryIterator", skip_from_py_object)]
struct PyTelemetryIterator {
    rx: Option<tokio::sync::mpsc::Receiver<TelemetrySample>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl PyTelemetryIterator {
    // C-PYO3-04: same as PyStreamIterator — Drop aborts the coordinator task to prevent leaks
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
        // C-3: idle timeout — the telemetry source runs at 10Hz (interval_ms=100); no frame
        // within TELEMETRY_IDLE_TIMEOUT_SECS = the source task is dead.
        // Three states: Ok(Some)=frame, Ok(None)=channel closed (clean EOF → StopIteration),
        // Err(Elapsed)=idle timeout → PyTimeoutError.
        let outcome: Result<Option<TelemetrySample>, ()> = py.detach(|| {
            // C-3: the timeout must be constructed inside the block_on async block (same as
            // PyStreamIterator — a Sleep built outside block_on has no reactor when polled
            // before block_on, panic).
            let secs = TELEMETRY_IDLE_TIMEOUT_SECS;
            fe_core::BLOCKING_RT.block_on(async {
                match tokio::time::timeout(Duration::from_secs(secs), rx.recv()).await {
                    Ok(opt) => Ok(opt),
                    Err(_elapsed) => {
                        tracing::error!(
                            secs,
                            "telemetry idle timeout — sampler task dead, raising PyTimeoutError"
                        );
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
                    "telemetry idle timeout ({TELEMETRY_IDLE_TIMEOUT_SECS}s) — sampler task dead"
                )));
            }
        };
        let json_str = serde_json::to_string(&sample).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "telemetry frame serialization failed: {e}"
            ))
        })?;
        let obj = py
            .import("json")?
            .call_method1("loads", (json_str,))?
            .unbind();
        Ok(obj)
    }

    /// C-3: join the sampler task with a 5s timeout; on timeout abort.
    fn join_sampler(&mut self) {
        if let Some(h) = self.handle.take() {
            let joined = fe_core::BLOCKING_RT.block_on(async {
                tokio::time::timeout(Duration::from_secs(JOIN_TIMEOUT_SECS), h).await
            });
            if joined.is_err() {
                tracing::warn!("join sampler task timed out {JOIN_TIMEOUT_SECS}s, aborting");
            }
        }
    }
}

#[pyclass(name = "NativeExecutor", skip_from_py_object)]
struct PyExecutor {
    // A-4: Arc<Executor> — serve() shares the same Arc instead of rebuilding the Executor.
    // The SIGHUP whitelist reload (reload_extra_whitelist mutates the ArcSwap inside the
    // Executor) persists across in-process and serve paths; the old serve rebuilt the
    // Executor → the in-process self.inner whitelist diverged from the serve path.
    inner: Arc<Executor>,
    // M-ARCH-1: ShellRegistry belongs to PyExecutor (not Executor). serve() shares
    // self.shells.clone() (an Arc shallow copy) into the IpcServer — the in-process path and
    // the serve path use the same registry, so a serve restart does not drop handles.
    shells: Arc<ShellRegistry>,
    // C-1 (arch adversarial): StreamRegistry symmetrically belongs to PyExecutor, like
    // M-ARCH-1. A serve() restart shares the same registry — a cancel (Issue #32) for an
    // in-flight execute_stream is not silently missed due to serve() re-entry.
    streams: Arc<StreamRegistry>,
}

#[pymethods]
impl PyExecutor {
    #[new]
    #[pyo3(signature = (extra_whitelist=None, disable_bundle_allowlist=false, allow_inline_interpreter=false, trusted_bin_dirs=None, guard_sock=None, guard_tenant=None))]
    fn new(
        extra_whitelist: Option<Vec<String>>,
        disable_bundle_allowlist: bool,
        allow_inline_interpreter: bool,
        trusted_bin_dirs: Option<Vec<String>>,
        guard_sock: Option<String>,
        guard_tenant: Option<String>,
    ) -> Self {
        // extra_whitelist is baked into inner's ArcSwap via with_extra_whitelist; after A-4 serve()
        // shares inner, no separate storage needed. SIGHUP reload reads FUSION_EXECUTOR_EXTRA_WHITELIST from env (m-OPS-02).
        let extras: Vec<&str> = extra_whitelist
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(String::as_str)
            .collect();
        let mut inner = if extras.is_empty() {
            Executor::new()
        } else {
            tracing::info!(
                count = extras.len(),
                "PyExecutor constructed with project-level allowlist extensions"
            );
            Executor::new().with_extra_whitelist(&extras)
        };
        // D3-6 (audit 0827 product 4-layer): trusted_bin_dirs registers the directories where project tools live —
        // extra_whitelist tools must resolve into a trusted directory to pass (fail-closed against /tmp poisoning).
        // After Python tests/callers register their project bin dirs, extension tools are allowed only when resolution passes.
        if let Some(dirs) = trusted_bin_dirs.as_ref() {
            let dir_refs: Vec<&str> = dirs.iter().map(String::as_str).collect();
            tracing::info!(
                count = dir_refs.len(),
                "PyExecutor constructed, registering trusted bin directories (D3-6)"
            );
            inner = inner.with_trusted_bin_dirs(&dir_refs);
        }
        // D3-1 (audit 0827 product): inline interpreter gateway opt-in. Default false (enterprise hardening rejects python -c /
        // node -e / ruby -e / perl -e); true keeps trusted-caller inline execution (test machines / local interaction).
        if allow_inline_interpreter {
            tracing::info!("PyExecutor constructed with inline interpreter enabled (D3-1 trusted-caller opt-in)");
            inner = inner.with_allow_inline_interpreter(true);
        }
        // RUN-12: disable_bundle_allowlist=True → GuiConfig{allowed_bundle_ids: None} = unlimited
        //   (explicit opt-in, audit-logged); default False uses GuiConfig::default's safe set (Terminal/
        //   TextEdit/finder). Test machines that need to drive any app pass True explicitly to lift the limit.
        if disable_bundle_allowlist {
            tracing::info!("PyExecutor constructed with GUI focus-app allowlist disabled (RUN-12 explicit unlimited opt-in)");
            inner = inner.with_gui_config(fe_core::gui::GuiConfig {
                allowed_bundle_ids: None,
                allow_type_into_secure: false,
            });
        }
        // ARCH-4: the in-process path (execute_sync/run) bypasses the fe-ipc BroadcastHub; when the recorder is
        // not installed, record_exec_outcome's metrics::counter! is a no-op. Install it here (idempotent OnceLock)
        // so in-process execute also counts Prometheus. Failure only warns and does not block (degrade = no metrics, non-fatal).
        let _ = fe_ipc::install_prometheus_recorder();
        // Issue #23 (guard Phase 3): guard defaults OFF (backward compatible). guard_sock Some → with_guard enables
        // authorization orchestration (GuardClient + RulesCache, ping probe + seed). tenant None → default "default".
        if let Some(sock) = guard_sock.as_deref() {
            let tenant = guard_tenant
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("default");
            tracing::info!(
                sock,
                tenant,
                "PyExecutor constructed with guard authorization enabled (Issue #23)"
            );
            inner = inner.with_guard(sock, tenant);
        }
        Self {
            inner: Arc::new(inner),
            shells: Arc::new(ShellRegistry::new()),
            streams: Arc::new(StreamRegistry::new()),
        }
    }

    /// execute_sync(command, task_id=None, cwd=None, timeout_sec=30.0, env_vars=None,
    ///               enable_rollback_snapshot=True, auto_rollback_policy=None)
    /// -> NativeExecutionResult
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (command, task_id=None, cwd=None, timeout_sec=None, env_vars=None,
                        enable_rollback_snapshot=None, auto_rollback_policy=None,
                        seatbelt=None, inherit_env=None, use_pty=None,
                        max_nproc=None, max_cpu_sec=None, max_nofile=None, rss_limit_mb=None,
                        trace_id=None, sandbox=None))]
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
        max_nofile: Option<u32>,
        rss_limit_mb: Option<u32>,
        trace_id: Option<String>,
        sandbox: Option<Bound<'_, PyAny>>,
    ) -> PyResult<PyExecutionResult> {
        // L-PYO3-02: an ineffective policy argument must fail-loud (the old version warned + None, silently swallowing
        // the error so callers thought rollback was enabled when it was not)
        let policy = match auto_rollback_policy {
            None => None,
            Some(obj) => Some({
                let json_str: String = py
                    .import("json")
                    .and_then(|json| json.call_method1("dumps", (&obj,)))
                    .and_then(|s| s.extract::<String>())
                    .map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "auto_rollback_policy to JSON failed: {e}"
                        ))
                    })?;
                serde_json::from_str::<RollbackPolicy>(&json_str).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "auto_rollback_policy deserialization failed: {e}"
                    ))
                })?
            }),
        };
        // Issue #34: sandbox profile — PyAny → json.dumps → serde_json::from_str (same pattern as auto_rollback_policy).
        let sandbox_profile = match sandbox {
            None => None,
            Some(obj) => Some({
                let json_str: String = py
                    .import("json")
                    .and_then(|json| json.call_method1("dumps", (&obj,)))
                    .and_then(|s| s.extract::<String>())
                    .map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "sandbox to JSON failed: {e}"
                        ))
                    })?;
                serde_json::from_str::<SandboxProfile>(&json_str).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "sandbox deserialization failed: {e}"
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
            // ARCH-1: default true — aligns with fe-core serde default_true (commercial security default).
            // The old unwrap_or(false) diverged from the fe-core/fe-ipc path (UDS execute defaults true via serde;
            // only the Python run() path went through false here) — fixing the cross-layer inconsistency (Rule 7).
            seatbelt: seatbelt.unwrap_or(true),
            inherit_env: inherit_env.unwrap_or(false),
            use_pty: use_pty.unwrap_or(true),
            max_nproc: max_nproc.unwrap_or(1024),
            max_cpu_sec: max_cpu_sec.unwrap_or(0),
            max_nofile: max_nofile.unwrap_or(1024),
            rss_limit_mb: rss_limit_mb.unwrap_or(2048),
            trace_id,
            sandbox: sandbox_profile,
        };
        // M-PYO3-02: internal errors fail-loud (the old version fabricated an exit_code=-1 ExecutionResult, leaving
        // callers unable to distinguish a security block from an executor bug; execute only returns Err on sandbox
        // internal errors, which should propagate)
        //
        // RUN-1: execute() is synchronous and blocks for the child's whole wall-clock. py.detach releases the GIL so
        // other Python threads can run (no need to hold the GIL while the child runs). The inner Arc is cloned into the
        // closure (Sync, UnwindSafe via AssertUnwindSafe).
        // ARCH-4: the success path calls record_exec_outcome to add Prometheus counts (the in-process path bypasses
        // the fe-ipc hub); blocked_with's ExecutionResult exit_code=-1 blocked_by_security=true is also counted (mirrors fe-ipc).
        let inner = self.inner.clone();
        let result = py.detach(move || inner.execute(req)).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("executor internal error: {e}"))
        })?;
        // ARCH-4: in-process execute counting (the recorder is installed in PyExecutor::new). Internal Err is not counted
        // (mirrors fe-ipc: execute Err does not call record_exec; only success/blocked/timeout/failed branches count).
        fe_core::record_exec_outcome(&result);
        Ok(PyExecutionResult::from(result))
    }

    /// snapshot_create(cwd) -> str (snapshot id; empty string for non-repos, a valid contract)
    /// M-PYO3-01: git failure (not the "non-repo empty string") fails loud with PyRuntimeError
    /// RUN-1: block_on blocks across git IO; py.detach releases the GIL (Python threads can run while git runs)
    fn snapshot_create(&self, py: Python<'_>, cwd: String) -> PyResult<String> {
        let inner = self.inner.clone();
        py.detach(move || fe_core::BLOCKING_RT.block_on(inner.snapshot_create_async(&cwd)))
            .map_err(|e| {
                tracing::error!(error = %e, "snapshot_create failed");
                pyo3::exceptions::PyRuntimeError::new_err(format!("snapshot_create failed: {e}"))
            })
    }

    /// D6-03: list_snapshots(cwd) -> Vec<NativeSnapshotInfo> — reads the on-disk index back.
    /// RUN-1: block_on blocks across git IO; py.detach releases the GIL.
    fn list_snapshots(&self, py: Python<'_>, cwd: String) -> PyResult<Vec<PySnapshotInfo>> {
        let inner = self.inner.clone();
        let snaps = py
            .detach(move || fe_core::BLOCKING_RT.block_on(inner.list_snapshots_async(&cwd)))
            .map_err(|e| {
                tracing::error!(error = %e, "list_snapshots failed");
                pyo3::exceptions::PyRuntimeError::new_err(format!("list_snapshots failed: {e}"))
            })?;
        Ok(snaps.into_iter().map(PySnapshotInfo::from).collect())
    }

    /// rollback(snapshot_id, cwd) -> bool (Ok(false) = skipped/non-repo, valid)
    /// M-PYO3-01: git failure (Err) fails loud with PyRuntimeError
    /// RUN-1: block_on blocks across git IO; py.detach releases the GIL
    fn rollback(&self, py: Python<'_>, snapshot_id: String, cwd: String) -> PyResult<bool> {
        let inner = self.inner.clone();
        py.detach(move || fe_core::BLOCKING_RT.block_on(inner.rollback_async(&snapshot_id, &cwd)))
            .map_err(|e| {
                tracing::error!(error = %e, "rollback failed");
                pyo3::exceptions::PyRuntimeError::new_err(format!("rollback failed: {e}"))
            })
    }

    /// validate(command) -> dict {allowed, blocked, reason, stage}
    /// Issue #11 / #12.4: pre-execution validation — the caller asks the user for authorization before execute (Option A, caller owns gating).
    /// Synchronous (pure CPU validation, no I/O, no BLOCKING_RT needed).
    fn validate<'py>(&self, py: Python<'py>, command: String) -> PyResult<Bound<'py, PyDict>> {
        let verdict = self.inner.validate(&command);
        let dict = PyDict::new(py);
        dict.set_item("allowed", verdict.allowed)?;
        dict.set_item("blocked", !verdict.allowed)?;
        dict.set_item("reason", verdict.reason.clone())?;
        // stage: SecurityStage → string ("regex"/"tokenizer"), avoiding serde_json's quoted form
        let stage_str = verdict.stage.map(|s| match s {
            fe_core::security::SecurityStage::Regex => "regex",
            fe_core::security::SecurityStage::Tokenizer => "tokenizer",
            // Issue #23: the guard-orchestrated verdict stage.
            fe_core::security::SecurityStage::Semantic => "semantic",
        });
        dict.set_item("stage", stage_str)?;
        Ok(dict)
    }

    /// gui_action(action: dict) -> NativeGuiResult
    /// action: GuiAction dict (tag "kind": focus_app/click/type_text/keypress/screenshot/inspect_tree)
    /// Via Python json.dumps → Rust serde_json deserializes to GuiAction, then fe-gui executes it
    fn gui_action(&self, py: Python<'_>, action: &Bound<'_, PyAny>) -> PyGuiResult {
        let json_str: String = match py
            .import("json")
            .and_then(|json| json.call_method1("dumps", (action,)))
            .and_then(|s| s.extract::<String>())
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "gui_action input to JSON failed");
                return PyGuiResult {
                    ok: false,
                    node_tree: None,
                    screenshot_png_b64: None,
                    screenshot_width: None,
                    screenshot_height: None,
                    scale_factor: 1.0,
                    displays: None,
                    error: Some(format!("invalid action input: {e}")),
                };
            }
        };
        let gui_action: GuiAction = match serde_json::from_str(&json_str) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, json = %json_str, "gui_action deserialization failed");
                return PyGuiResult {
                    ok: false,
                    node_tree: None,
                    screenshot_png_b64: None,
                    screenshot_width: None,
                    screenshot_height: None,
                    scale_factor: 1.0,
                    displays: None,
                    error: Some(format!("action deserialization failed: {e}")),
                };
            }
        };
        // 2.2: release the GIL for execution — gui_action contains Wait (thread::sleep up to 60s) + AX/CGEvent blocking calls.
        // The old version held the GIL → wait(60) froze the Python interpreter for 60s (other agents' run_async could not schedule).
        // Python threads can run while py.detach holds the GIL released; self.inner is a Rust struct, not a Python object, so borrowing is safe.
        let result = py.detach(|| self.inner.gui_action(gui_action));
        match result {
            Ok(r) => r.into(),
            Err(e) => {
                tracing::warn!(error = %e, "gui_action execution failed");
                PyGuiResult {
                    ok: false,
                    node_tree: None,
                    screenshot_png_b64: None,
                    screenshot_width: None,
                    screenshot_height: None,
                    scale_factor: 1.0,
                    displays: None,
                    error: Some(format!("gui_action failed: {e}")),
                }
            }
        }
    }

    /// #39: gui_action_batch(actions: list[dict]) -> list[NativeGuiResult]
    /// Executes multiple actions in order, collecting each step's result. Via json.dumps → serde deserializes Vec<GuiAction>.
    fn gui_action_batch(
        &self,
        py: Python<'_>,
        actions: &Bound<'_, PyAny>,
    ) -> PyResult<Vec<PyGuiResult>> {
        let json_str: String = py
            .import("json")?
            .call_method1("dumps", (actions,))?
            .extract()?;
        let gui_actions: Vec<GuiAction> = match serde_json::from_str(&json_str) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, json = %json_str, "gui_action_batch deserialization failed");
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "actions deserialization failed: {e}"
                )));
            }
        };
        let results = py
            .detach(|| self.inner.gui_action_batch(gui_actions))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{e}")))?;
        Ok(results.into_iter().map(PyGuiResult::from).collect())
    }

    /// execute_streaming(command, task_id=None, cwd=None, timeout_sec=30.0, env_vars=None,
    ///                    enable_rollback_snapshot=True, auto_rollback_policy=None)
    /// -> NativeStreamIterator — yields chunk frames {type:"chunk",data} until the done frame {type:"done",result:{...}}
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (command, task_id=None, cwd=None, timeout_sec=None, env_vars=None,
                        enable_rollback_snapshot=None, auto_rollback_policy=None,
                        seatbelt=None, inherit_env=None, use_pty=None,
                        max_nproc=None, max_cpu_sec=None, max_nofile=None, rss_limit_mb=None,
                        trace_id=None, sandbox=None))]
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
        max_nofile: Option<u32>,
        rss_limit_mb: Option<u32>,
        trace_id: Option<String>,
        sandbox: Option<Bound<'_, PyAny>>,
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
                            "auto_rollback_policy to JSON failed: {e}"
                        ))
                    })?;
                serde_json::from_str::<RollbackPolicy>(&json_str).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "auto_rollback_policy deserialization failed: {e}"
                    ))
                })?
            }),
        };
        // Issue #34: sandbox profile (same pattern as execute_sync).
        let sandbox_profile = match sandbox {
            None => None,
            Some(obj) => Some({
                let json_str: String = py
                    .import("json")
                    .and_then(|json| json.call_method1("dumps", (&obj,)))
                    .and_then(|s| s.extract::<String>())
                    .map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "sandbox to JSON failed: {e}"
                        ))
                    })?;
                serde_json::from_str::<SandboxProfile>(&json_str).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "sandbox deserialization failed: {e}"
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
            // ARCH-1: default true — aligns with fe-core serde default_true (commercial security default).
            // The old unwrap_or(false) diverged from the fe-core/fe-ipc path (UDS execute defaults true via serde;
            // only the Python run() path went through false here) — fixing the cross-layer inconsistency (Rule 7).
            seatbelt: seatbelt.unwrap_or(true),
            inherit_env: inherit_env.unwrap_or(false),
            use_pty: use_pty.unwrap_or(true),
            max_nproc: max_nproc.unwrap_or(1024),
            max_cpu_sec: max_cpu_sec.unwrap_or(0),
            max_nofile: max_nofile.unwrap_or(1024),
            rss_limit_mb: rss_limit_mb.unwrap_or(2048),
            trace_id,
            sandbox: sandbox_profile,
        }; // L-PYO3-01: execute_streaming async → releases the GIL then block_on on BLOCKING_RT (the old version held
           // the GIL for the whole spawn + validation, blocking Python threads; after detach Python can run other coroutines concurrently)
        let (rx, handle) = py
            .detach(|| fe_core::BLOCKING_RT.block_on(self.inner.execute_streaming(req, None)))
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("execute_streaming failed: {e}"))
            })?;
        Ok(PyStreamIterator::new(rx, handle))
    }

    /// telemetry_stream(interval_ms=100, max_samples=0, pid=None) -> NativeTelemetryIterator
    /// Yields TelemetrySample dicts (ts_ms/cpu_pct/mem_mb/gpu_pct/gpu_mem_mb/task_id)
    /// Default 10Hz unlimited sampling; max_samples>0 ends once reached
    /// pid=None samples the executor itself (default); pass the sandbox child PID to sample the real task (L-15)
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
    /// Unique-match old_string → exact new_string replacement (replace_all=True for all), atomic write
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
                tracing::warn!(error = %e, "file_edit failed");
                PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("file_edit failed: {e}")),
                    matches: 0,
                }
            }
        }
    }

    /// write_file(path, content, cwd=None) -> NativeEditResult — full-file create/overwrite + parent dir creation (#2)
    #[pyo3(signature = (path, content, cwd=None))]
    fn write_file(&self, path: String, content: String, cwd: Option<String>) -> PyEditResult {
        match self.inner.write_file(&path, &content, cwd.as_deref()) {
            Ok(r) => r.into(),
            Err(e) => {
                tracing::warn!(error = %e, "write_file failed");
                PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("write_file failed: {e}")),
                    matches: 0,
                }
            }
        }
    }

    /// shell_start(command, cwd=None, env_vars=None, task_id=None, max_output_chars=100000,
    ///             seatbelt=True, inherit_env=False, max_nproc=1024, max_cpu_sec=0,
    ///             max_idle_sec=3600)
    /// -> NativeShellStartResult — background persistent shell start (#1, run_in_background parity)
    /// Security validation lives in fe-core (fail-closed); blocked → ok=false, shell_id=None
    /// max_idle_sec (m-SEC-01): auto-kill when no output exceeds this value (seconds); 0=unlimited. Default 3600.
    /// kill_grace_ms (M-9): kill grace period (milliseconds), the SIGINT→grace→SIGKILL interval; 0=immediate SIGKILL. Default 500.
    #[pyo3(signature = (
        command,
        cwd=None,
        env_vars=None,
        task_id=None,
        max_output_chars=100_000,
        seatbelt=true,
        inherit_env=false,
        max_nproc=1024,
        max_cpu_sec=0,
        max_nofile=1024,
        max_idle_sec=fe_core::shell::DEFAULT_MAX_IDLE_SEC,
        kill_grace_ms=500,
        sandbox=None,
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
        max_nofile: u32,
        max_idle_sec: u64,
        kill_grace_ms: u64,
        sandbox: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyShellStartResult>> {
        let env: std::collections::HashMap<String, String> = match env_vars {
            Some(obj) => {
                let json_mod = py.import("json")?;
                let s: String = json_mod
                    .call_method1("dumps", (obj,))?
                    .extract()
                    .map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "env_vars serialization failed: {e}"
                        ))
                    })?;
                serde_json::from_str(&s).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("env_vars parse failed: {e}"))
                })?
            }
            None => std::collections::HashMap::new(),
        };
        let sandbox_profile: Option<fe_sandbox::seatbelt::SandboxProfile> = match sandbox {
            Some(obj) => {
                let json_mod = py.import("json")?;
                let s: String = json_mod
                    .call_method1("dumps", (obj,))?
                    .extract()
                    .map_err(|e| {
                        pyo3::exceptions::PyRuntimeError::new_err(format!(
                            "sandbox serialization failed: {e}"
                        ))
                    })?;
                Some(serde_json::from_str(&s).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("sandbox parse failed: {e}"))
                })?)
            }
            None => None,
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
            max_nofile,
            max_idle_sec,
            kill_grace_ms,
            sandbox_profile,
        };
        let r: RsShellStartResult = self.inner.shell_start(&self.shells, sp);
        let raw = serde_json::to_string(&r).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("serialization failed: {e}"))
        })?;
        Py::new(py, PyShellStartResult { raw })
    }

    /// shell_output(shell_id) -> NativeShellOutput — polls the tail snapshot + running/exit status (#1)
    fn shell_output(&self, py: Python<'_>, shell_id: String) -> PyResult<Py<PyShellOutput>> {
        match Executor::shell_output(&self.shells, &shell_id) {
            Ok(out) => {
                let raw = serde_json::to_string(&out).map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("serialization failed: {e}"))
                })?;
                Py::new(py, PyShellOutput { raw })
            }
            Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "shell_output failed: {e}"
            ))),
        }
    }

    /// kill_shell(shell_id) -> bool — kills the process tree (#1, KillShell parity)
    fn kill_shell(&self, shell_id: String) -> PyResult<bool> {
        Executor::kill_shell(&self.shells, &shell_id).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("kill_shell failed: {e}"))
        })
    }

    /// list_shells() -> list[NativeShellInfo] — lists all background shells (#1)
    fn list_shells(&self) -> PyResult<Vec<PyShellInfo>> {
        let list = Executor::list_shells(&self.shells);
        let mut out = Vec::with_capacity(list.len());
        for info in list {
            let raw = serde_json::to_string(&info).map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("serialization failed: {e}"))
            })?;
            out.push(PyShellInfo { raw });
        }
        Ok(out)
    }

    /// multi_edit(path, edits, cwd=None) -> NativeEditResult
    /// Sequential batch edits on one file, atomic all-or-nothing
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
                    tracing::warn!(error = %e, "multi_edit edits deserialization failed");
                    return PyEditResult {
                        ok: false,
                        path: Some(path),
                        error: Some(format!("multi_edit edits parse failed: {e}")),
                        matches: 0,
                    };
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "multi_edit JSON serialization failed");
                return PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("multi_edit edits serialization failed: {e}")),
                    matches: 0,
                };
            }
        };
        match self.inner.multi_edit(&path, &parsed, cwd.as_deref()) {
            Ok(r) => r.into(),
            Err(e) => {
                tracing::warn!(error = %e, "multi_edit failed");
                PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("multi_edit failed: {e}")),
                    matches: 0,
                }
            }
        }
    }

    /// notebook_edit(path, cell_id=None, cell_number=None, new_source, edit_mode="replace", cwd=None) -> NativeEditResult
    /// Jupyter .ipynb cell editing (replace/insert/delete)
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
                tracing::warn!(error = %e, mode = edit_mode, "notebook_edit invalid edit_mode");
                return PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("invalid edit_mode: {e}")),
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
                tracing::warn!(error = %e, "notebook_edit failed");
                PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("notebook_edit failed: {e}")),
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
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("glob failed: {e}")))
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
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("grep failed: {e}")))
    }

    /// #7 ripgrep parity — grep_with_opts(pattern, paths, opts, cwd=None) -> NativeGrepOutput
    /// opts: dict (output_mode/after/before/context/multiline/glob_include/glob_exclude), all fields optional
    fn grep_with_opts(
        &self,
        pattern: String,
        paths: Vec<String>,
        opts: &Bound<'_, PyAny>,
        cwd: Option<String>,
        py: Python<'_>,
    ) -> PyResult<Py<PyGrepOutput>> {
        // dict → json str → serde GrepOptions (all fields #[serde(default)])
        let json_mod = py.import("json")?;
        let opts_str: String = json_mod
            .call_method1("dumps", (opts,))?
            .extract()
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("opts serialization failed: {e}"))
            })?;
        let rs_opts: RsGrepOptions = serde_json::from_str(&opts_str).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("opts parse failed: {e}"))
        })?;
        let out = self
            .inner
            .grep_with_opts(&pattern, &paths, cwd.as_deref(), &rs_opts)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("grep failed: {e}")))?;
        let raw = serde_json::to_string(&out).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("output serialization failed: {e}"))
        })?;
        Py::new(py, PyGrepOutput { raw })
    }

    /// apply_patch(diff, cwd=None) -> NativeEditResult — unified diff apply, full-file rewrite forbidden
    fn apply_patch(&self, diff: String, cwd: Option<String>) -> PyEditResult {
        match self.inner.apply_patch(&diff, cwd.as_deref()) {
            Ok(r) => r.into(),
            Err(e) => {
                tracing::warn!(error = %e, "apply_patch failed");
                PyEditResult {
                    ok: false,
                    path: None,
                    error: Some(format!("apply_patch failed: {e}")),
                    matches: 0,
                }
            }
        }
    }

    /// replace_function(path, fn_name, new_body, cwd=None) -> NativeEditResult — function-level replacement
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
                tracing::warn!(error = %e, "replace_function failed");
                PyEditResult {
                    ok: false,
                    path: Some(path),
                    error: Some(format!("replace_function failed: {e}")),
                    matches: 0,
                }
            }
        }
    }

    /// serve(sock_path=None) — starts the UDS JSON-RPC 2.0 server, resident until the process exits
    /// A-4: shares self.inner (Arc<Executor>) instead of rebuilding — the SIGHUP allowlist reload persists across in-process/serve.
    /// The Executor is stateless per task (CLAUDE.md); Arc sharing does not change the stateless semantics; only the allowlist (mutable inside ArcSwap) is shared.
    fn serve(&self, py: pyo3::Python<'_>, sock_path: Option<String>) -> PyResult<()> {
        // M-OPS-01: fe_ipc::logging init_tracing — JSON + rolling files (FE_LOG_DIR) + stderr,
        // EnvFilter reloadable at runtime (SIGHUP, m-OPS-02). Idempotent, the handle lives in a fe-ipc static.
        // IMPL-11: fail-loud — on init failure (subscriber taken) do not start a server without audit logs.
        // An idempotent second call returns Ok; only a first-call failure (global subscriber conflict) triggers this Err.
        if let Err(e) = fe_ipc::logging::init_tracing() {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "FATAL: logging init failed — refusing to start a server without audit logs: {}",
                e
            )));
        }
        let sock = IpcServer::resolve_sock(sock_path.as_deref());
        // A-4: shared Executor Arc — the in-process path and the serve path share one allowlist (SIGHUP reload affects both).
        // C-1 (arch adversarial): shared StreamRegistry — serve() re-entry does not lose an in-flight cancel (Issue #32).
        let server = IpcServer::with_executor_arc_shells_and_streams(
            self.inner.clone(),
            self.shells.clone(),
            self.streams.clone(),
        );
        tracing::info!(sock = %sock, "PyO3 serve() — starting the IPC server (shared Executor Arc, GIL released, signal-stoppable)");
        // C-PYO3-02: run serve_blocking with the GIL released — the Rust side uses tokio::signal to watch SIGINT/SIGTERM
        // and interrupt the accept_loop (does not rely on Python signal handlers, which do not run while the GIL is held).
        // While py.detach holds the GIL released, Python signal handlers can also run; both paths exit cleanly.
        py.detach(|| match server.serve_blocking(&sock) {
            Ok(()) => Ok(()),
            Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "serve failed: {}",
                e
            ))),
        })
    }
}

/// C-OPS-06: version/build info — build.rs injects FE_GIT_SHA/FE_BUILD_TIME, version from CARGO_PKG_VERSION
/// Python __init__.py reads __version__ through this; IPC health reads it via fe-ipc (fe-ipc has its own env! CARGO_PKG_VERSION)
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
    m.add_class::<PySnapshotInfo>()?;
    m.add_class::<PyStreamIterator>()?;
    m.add_class::<PyTelemetryIterator>()?;
    m.add_class::<PyShellStartResult>()?;
    m.add_class::<PyShellOutput>()?;
    m.add_class::<PyShellInfo>()?;
    m.add_class::<PyExecutor>()?;
    m.add_function(wrap_pyfunction!(version_info, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    // D1-1 (audit 0827 arch / product): fe-pyo3 previously had zero Rust unit tests — pyclass From conversions are
    // pure Rust logic (field mapping, no GIL), covered directly by cargo test -p fe-pyo3. Guards against 4-layer wire field drift (Rule 9).

    use super::*;

    #[test]
    fn d11_execution_result_from_maps_all_fields() {
        let rs = RsResult {
            exit_code: 0,
            stdout: "out".into(),
            stderr: "err".into(),
            task_id: Some("t-1".into()),
            command: Some("echo".into()),
            duration_sec: 1.25,
            timed_out: false,
            blocked_by_security: false,
            security_reason: None,
            snapshot_id: Some("snap-9".into()),
            diagnostics: Some(RsDiag {
                error_type: Some("ValueError".into()),
                file_path: Some("a.py".into()),
                line_number: Some(7),
                code_snippet: Some("x = 1".into()),
                raw_trace: Some("Traceback".into()),
            }),
            auto_rolled_back: false,
            rollback_unavailable: true,
            rollback_skipped_reason: Some("snapshot-stale".into()),
            trace_id: Some("trace-42".into()),
            oom_killed: true,
            pid: Some(1234),
            guard_action_id: Some("11111111-2222-3333-4444-555555555555".into()),
            cancelled: true,
        };
        let py = PyExecutionResult::from(rs);
        assert_eq!(py.exit_code, 0);
        assert_eq!(py.stdout, "out");
        assert_eq!(py.stderr, "err");
        assert_eq!(py.task_id.as_deref(), Some("t-1"));
        assert_eq!(py.command.as_deref(), Some("echo"));
        assert!((py.duration_sec - 1.25).abs() < f64::EPSILON);
        assert!(!py.timed_out);
        assert!(!py.blocked_by_security);
        assert!(py.security_reason.is_none());
        assert_eq!(py.snapshot_id.as_deref(), Some("snap-9"));
        let diag = py.diagnostics.expect("diagnostics should be Some");
        assert_eq!(diag.error_type.as_deref(), Some("ValueError"));
        assert_eq!(diag.file_path.as_deref(), Some("a.py"));
        assert_eq!(diag.line_number, Some(7));
        assert_eq!(diag.code_snippet.as_deref(), Some("x = 1"));
        assert_eq!(diag.raw_trace.as_deref(), Some("Traceback"));
        assert!(!py.auto_rolled_back);
        assert!(py.rollback_unavailable);
        assert_eq!(
            py.rollback_skipped_reason.as_deref(),
            Some("snapshot-stale")
        );
        assert_eq!(py.trace_id.as_deref(), Some("trace-42"));
        assert!(py.oom_killed);
        assert_eq!(py.pid, Some(1234));
        assert_eq!(
            py.guard_action_id.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert!(
            py.cancelled,
            "Issue #32: cancelled should pass through as true"
        );
    }

    #[test]
    fn d11_execution_result_from_none_diagnostics_is_none() {
        let rs = RsResult::default();
        let py = PyExecutionResult::from(rs);
        assert!(
            py.diagnostics.is_none(),
            "PyDiagnostics should be None when there are no diagnostics"
        );
        assert_eq!(py.exit_code, 0);
        assert!(py.trace_id.is_none());
        assert!(!py.oom_killed);
    }

    #[test]
    fn d11_tools_from_conversions_map_fields() {
        let er = PyEditResult::from(RsEditResult {
            ok: true,
            path: Some("p.rs".into()),
            error: None,
            matches: 3,
        });
        assert!(er.ok);
        assert_eq!(er.path.as_deref(), Some("p.rs"));
        assert!(er.error.is_none());
        assert_eq!(er.matches, 3);

        let ge = PyGlobEntry::from(RsGlobEntry {
            path: "src/a.py".into(),
            is_dir: false,
        });
        assert_eq!(ge.path, "src/a.py");
        assert!(!ge.is_dir);

        let gm = PyGrepMatch::from(RsGrepMatch {
            path: "b.go".into(),
            line_number: 9,
            content: "panic".into(),
            context_before: vec!["ctx1".into()],
            context_after: vec!["ctx2".into()],
        });
        assert_eq!(gm.path, "b.go");
        assert_eq!(gm.line_number, 9);
        assert_eq!(gm.content, "panic");
        assert_eq!(gm.context_before, vec!["ctx1".to_string()]);
        assert_eq!(gm.context_after, vec!["ctx2".to_string()]);
    }
}
