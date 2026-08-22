// fe-ipc — UDS JSON-RPC 2.0 server (P3) + 双向 server-push (v1.5 #14)
//
// Socket /tmp/fusion-executor.sock (override FUSION_EXECUTOR_SOCK), 换行分隔
// Mirror fusion-cowork/fusion_cowork/server/desk_rpc.py 协议:
//   line = read_line(); 响应 = serde_json::to_string(resp) + "\n"
//   jsonrpc "2.0", id 透传; 错误码 -32700(parse)/-32600(invalid req)/-32601(method)/-32603(internal)
//   扩展: -32010 安全拦截, -32011 超时, -32012 回滚失败, -32013 AX 未授权
// 匹配 fusion-studio IPCClient.swift: 按字节读到 0x0A, 8s 超时
//
// 方法: executor.health/execute/execute_stream/telemetry_stream/snapshot_create/rollback/gui_action/diagnostics
//       executor.file_edit/glob/grep/apply_patch/replace_function/shutdown
//       executor.subscribe/unsubscribe  (v1.5 #14 — 双向 server-push)
//
// v1.5 #14 双向 server-push (PRD §5 — fusion-studio 120Hz 看板广播):
//   连接 DUPLEX: read_task (分发请求) + push_task (写 server-push 帧) 共享 writer (Arc<Mutex>)。
//   subscribe {channels:["telemetry"|"stdio"|"screenshot"], interval_ms?:100, screenshot_interval_ms?:1000}
//     → 响应 {ok:true, subscription_id:"sub-N"}; 之后 server 持续推 notification 帧:
//       {"jsonrpc":"2.0","method":"executor.event","params":{"subscription_id":..,"channel":..,"data":..}}
//     notification 无 id (JSON-RPC notification 约定), 客户端按有无 id 区分响应 vs 推送。
//   通道源 (hub 内 lazy 启停, 0 订阅自退):
//     telemetry — 单一 executor.telemetry_stream 扇出给所有 telemetry 订阅 (10Hz 默认)。
//     screenshot — 周期 executor.gui_action(Screenshot), TCC 未授权 → 帧 data.ok=false 不崩。
//     stdio — execute/execute_stream 处理器扇出 chunk/done 给所有 stdio 订阅 (跨连接广播)。
//   unsubscribe {subscription_id} → 停该订阅; 连接断开 → 清该连接所有订阅。

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use fe_core::gui::GuiAction;
use fe_core::TelemetryStreamConfig;
use fe_core::{Diagnostics, ExecutionRequest, ExecutionResult, Executor};

/// 默认 socket 路径
pub const DEFAULT_SOCK: &str = "/tmp/fusion-executor.sock";

/// JSON-RPC 错误码
const ERR_PARSE: i64 = -32700;
const ERR_INVALID_REQ: i64 = -32600;
const ERR_METHOD_NOT_FOUND: i64 = -32601;
const ERR_INTERNAL: i64 = -32603;

/// 通道名常量
const CH_TELEMETRY: &str = "telemetry";
const CH_STDIO: &str = "stdio";
const CH_SCREENSHOT: &str = "screenshot";

/// 默认采样间隔
const DEFAULT_INTERVAL_MS: u64 = 100;
const DEFAULT_SCREENSHOT_INTERVAL_MS: u64 = 1000;

/// 订阅者 — 一条连接可能持多个订阅, 共享该连接的 push tx
struct Subscriber {
    conn_id: u64,
    channels: HashSet<String>,
    tx: mpsc::Sender<Value>,
}

/// 广播中心 (v1.5 #14) — Arc 共享给 accept_loop/handle_conn/源任务。
/// registry: sub_id → Subscriber。源任务 lazy 启停: 0 订阅自退, 下次 subscribe 重启。
struct BroadcastHub {
    registry: Mutex<HashMap<String, Subscriber>>,
    executor: Arc<Executor>,
    conn_counter: AtomicU64,
    sub_counter: AtomicU64,
    telemetry_task: Mutex<Option<JoinHandle<()>>>,
    screenshot_task: Mutex<Option<JoinHandle<()>>>,
}

impl BroadcastHub {
    fn new(executor: Arc<Executor>) -> Arc<Self> {
        Arc::new(Self {
            registry: Mutex::new(HashMap::new()),
            executor,
            conn_counter: AtomicU64::new(1),
            sub_counter: AtomicU64::new(1),
            telemetry_task: Mutex::new(None),
            screenshot_task: Mutex::new(None),
        })
    }

    fn next_conn_id(&self) -> u64 {
        self.conn_counter.fetch_add(1, Ordering::Relaxed)
    }

    fn next_sub_id(&self) -> String {
        format!("sub-{}", self.sub_counter.fetch_add(1, Ordering::Relaxed))
    }

    /// 注册订阅 — 返回 subscription_id。channels 去重存小写。
    fn subscribe(
        self: &Arc<Self>,
        conn_id: u64,
        channels: HashSet<String>,
        tx: mpsc::Sender<Value>,
    ) -> String {
        let sub_id = self.next_sub_id();
        let has_telemetry = channels.contains(CH_TELEMETRY);
        let has_screenshot = channels.contains(CH_SCREENSHOT);
        {
            let mut reg = self.registry.lock().unwrap();
            reg.insert(
                sub_id.clone(),
                Subscriber {
                    conn_id,
                    channels,
                    tx,
                },
            );
        }
        info!(%sub_id, conn_id, "订阅注册");
        if has_telemetry {
            self.ensure_telemetry_source();
        }
        if has_screenshot {
            self.ensure_screenshot_source();
        }
        sub_id
    }

    /// 取消订阅 — 返回是否找到并移除
    fn unsubscribe(&self, sub_id: &str) -> bool {
        let removed = self.registry.lock().unwrap().remove(sub_id).is_some();
        if removed {
            info!(%sub_id, "订阅取消");
        }
        removed
    }

    /// 连接断开 — 清该连接所有订阅
    fn drop_conn(&self, conn_id: u64) {
        let mut reg = self.registry.lock().unwrap();
        let before = reg.len();
        reg.retain(|_, s| s.conn_id != conn_id);
        let dropped = before - reg.len();
        if dropped > 0 {
            info!(conn_id, dropped, "连接断开, 清理订阅");
        }
    }

    /// 确保遥测源任务运行 — 无则启动。源任务 0 telemetry 订阅自退并清 handle。
    fn ensure_telemetry_source(self: &Arc<Self>) {
        let mut slot = self.telemetry_task.lock().unwrap();
        if slot.is_some() {
            return;
        }
        let hub = self.clone();
        let handle = tokio::spawn(async move {
            hub.run_telemetry_source(DEFAULT_INTERVAL_MS).await;
            hub.telemetry_task.lock().unwrap().take();
        });
        *slot = Some(handle);
        info!("遥测源任务启动");
    }

    /// 确保截图源任务运行
    fn ensure_screenshot_source(self: &Arc<Self>) {
        let mut slot = self.screenshot_task.lock().unwrap();
        if slot.is_some() {
            return;
        }
        let hub = self.clone();
        let handle = tokio::spawn(async move {
            hub.run_screenshot_source(DEFAULT_SCREENSHOT_INTERVAL_MS)
                .await;
            hub.screenshot_task.lock().unwrap().take();
        });
        *slot = Some(handle);
        info!("截图源任务启动");
    }

    /// 遥测源 — executor.telemetry_stream 单流扇出, 0 订阅自退。
    async fn run_telemetry_source(&self, interval_ms: u64) {
        let cfg = TelemetryStreamConfig {
            interval_ms,
            max_samples: 0,
        };
        let (mut rx, handle) = self.executor.telemetry_stream(cfg);
        while let Some(sample) = rx.recv().await {
            let targets = self.collect_targets(CH_TELEMETRY);
            if targets.is_empty() {
                info!("遥测 0 订阅, 源任务自退");
                break;
            }
            let data = serde_json::to_value(&sample).unwrap_or(json!({}));
            for (sub_id, tx) in targets {
                let frame = notification(sub_id, CH_TELEMETRY, data.clone());
                let _ = tx.try_send(frame);
            }
        }
        drop(rx);
        let _ = handle.await;
    }

    /// 截图源 — 周期 gui_action(Screenshot) 扇出, TCC 未授权帧 data.ok=false 不崩。0 订阅自退。
    async fn run_screenshot_source(&self, interval_ms: u64) {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
        interval.tick().await;
        loop {
            interval.tick().await;
            let targets = self.collect_targets(CH_SCREENSHOT);
            if targets.is_empty() {
                info!("截图 0 订阅, 源任务自退");
                break;
            }
            let executor = self.executor.clone();
            let shot =
                tokio::task::spawn_blocking(move || executor.gui_action(GuiAction::Screenshot {}))
                    .await;
            let data = match shot {
                Ok(Ok(r)) => serde_json::to_value(&r).unwrap_or(json!({"ok": false})),
                Ok(Err(e)) => {
                    warn!(error = %e, "截图源 gui_action 失败");
                    json!({"ok": false, "error": format!("screenshot 失败: {e}")})
                }
                Err(e) => {
                    warn!(error = %e, "截图源 spawn_blocking 失败");
                    json!({"ok": false, "error": format!("screenshot 任务失败: {e}")})
                }
            };
            for (sub_id, tx) in targets {
                let frame = notification(sub_id, CH_SCREENSHOT, data.clone());
                let _ = tx.try_send(frame);
            }
        }
    }

    /// 收集某通道所有 (sub_id, tx) — 锁内快照, 锁外发送
    fn collect_targets(&self, channel: &str) -> Vec<(String, mpsc::Sender<Value>)> {
        let reg = self.registry.lock().unwrap();
        reg.iter()
            .filter(|(_, s)| s.channels.contains(channel))
            .map(|(id, s)| (id.clone(), s.tx.clone()))
            .collect()
    }

    /// stdio 广播 — execute/execute_stream 处理器调, 扇出给所有 stdio 订阅
    fn broadcast_stdio(&self, data: Value) {
        let targets = self.collect_targets(CH_STDIO);
        for (sub_id, tx) in targets {
            let frame = notification(sub_id, CH_STDIO, data.clone());
            let _ = tx.try_send(frame);
        }
    }
}

/// 构造 server-push notification Value (无 id, JSON-RPC notification 约定)
fn notification(sub_id: String, channel: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "executor.event",
        "params": {
            "subscription_id": sub_id,
            "channel": channel,
            "data": data,
        }
    })
}

/// IPC 服务器 — 持有 Arc<Executor> + Arc<BroadcastHub>, 换行分隔 JSON-RPC 2.0 over UDS
pub struct IpcServer {
    executor: Arc<Executor>,
    hub: Arc<BroadcastHub>,
}

impl IpcServer {
    pub fn new() -> Self {
        info!("IpcServer::new() — 持有 Executor + BroadcastHub");
        let executor = Arc::new(Executor::new());
        let hub = BroadcastHub::new(executor.clone());
        Self { executor, hub }
    }

    pub fn with_executor(executor: Executor) -> Self {
        info!("IpcServer::with_executor()");
        let executor = Arc::new(executor);
        let hub = BroadcastHub::new(executor.clone());
        Self { executor, hub }
    }

    /// 解析 socket 路径 — 参数覆盖 > 环境变量 FUSION_EXECUTOR_SOCK > 默认
    pub fn resolve_sock(override_path: Option<&str>) -> String {
        if let Some(p) = override_path {
            if !p.is_empty() {
                return p.to_string();
            }
        }
        std::env::var("FUSION_EXECUTOR_SOCK").unwrap_or_else(|_| DEFAULT_SOCK.to_string())
    }

    /// 异步 serve — bind + unlink 旧 sock + chmod 0o666 + accept 循环
    /// 返回 (shutdown_tx, join_handle): 调用方发 shutdown_tx 触发优雅退出, 可 await join 等待清理
    pub async fn serve(
        &self,
        sock_path: &str,
    ) -> Result<(oneshot::Sender<()>, tokio::task::JoinHandle<()>)> {
        let path = Path::new(sock_path).to_path_buf();
        if path.exists() {
            info!(sock = %path.display(), "清理旧 socket");
            let _ = std::fs::remove_file(&path);
        }
        let listener = UnixListener::bind(&path)
            .map_err(|e| anyhow::anyhow!("bind {} 失败: {}", path.display(), e))?;
        chmod_666(&path);
        info!(sock = %path.display(), "IPC 服务器监听中");

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let executor = self.executor.clone();
        let hub = self.hub.clone();
        let join = tokio::spawn(async move {
            accept_loop(listener, executor, hub, shutdown_rx).await;
            let _ = std::fs::remove_file(&path);
        });
        Ok((shutdown_tx, join))
    }

    /// 同步阻塞 serve — 供 PyO3 serve() 直接调用 (走 BLOCKING_RT)
    /// 永驻直到进程退出; shutdown 走进程信号
    pub fn serve_blocking(&self, sock_path: &str) -> Result<()> {
        let path = sock_path.to_string();
        let executor = self.executor.clone();
        let hub = self.hub.clone();
        fe_core::BLOCKING_RT.block_on(async move {
            let p = Path::new(&path).to_path_buf();
            if p.exists() {
                let _ = std::fs::remove_file(&p);
            }
            let listener = UnixListener::bind(&p)
                .map_err(|e| anyhow::anyhow!("bind {} 失败: {}", p.display(), e))?;
            chmod_666(&p);
            info!(sock = %p.display(), "IPC 服务器监听中 (blocking, 永驻)");
            let (_tx, rx) = oneshot::channel::<()>();
            accept_loop(listener, executor, hub, rx).await;
            let _ = std::fs::remove_file(&p);
            Ok(())
        })
    }
}

impl Default for IpcServer {
    fn default() -> Self {
        Self::new()
    }
}

/// accept 循环 — 收到 shutdown 信号或 listener 关闭则退出
async fn accept_loop(
    listener: UnixListener,
    executor: Arc<Executor>,
    hub: Arc<BroadcastHub>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown_rx => {
                info!("shutdown 信号收到, 停止 accept");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let ex = executor.clone();
                        let h = hub.clone();
                        tokio::spawn(handle_conn(stream, ex, h));
                    }
                    Err(e) => warn!(error = %e, "accept 失败"),
                }
            }
        }
    }
}

/// 单连接处理 — DUPLEX (v1.5 #14):
///   read_task: read_line 分发请求, 响应/流式帧写 locked writer
///   push_task: 读 push_rx, server-push notification 写 locked writer
///   共享 writer = Arc<AsyncMutex<OwnedWriteHalf>>, 行写原子 (锁内 write_all)
///   连接断开 → 清订阅 + close push_task
async fn handle_conn(stream: UnixStream, executor: Arc<Executor>, hub: Arc<BroadcastHub>) {
    let conn_id = hub.next_conn_id();
    let (reader, writer) = stream.into_split();
    let writer = Arc::new(AsyncMutex::new(writer));
    let (push_tx, push_rx) = mpsc::channel::<Value>(128);
    let (close_tx, close_rx) = oneshot::channel::<()>();

    // push_task — server-push 帧写出
    let push_writer = writer.clone();
    let push_handle = tokio::spawn(async move {
        let mut rx = push_rx;
        let mut close = close_rx;
        loop {
            tokio::select! {
                biased;
                _ = &mut close => {
                    info!(conn_id, "push_task 收 close, 退出");
                    break;
                }
                frame = rx.recv() => {
                    match frame {
                        Some(v) => {
                            let line = serde_json::to_string(&v).unwrap_or_default() + "\n";
                            let mut w = push_writer.lock().await;
                            if w.write_all(line.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    // read_task — 逐行分发
    let mut lines = BufReader::new(reader).lines();
    let read_hub = hub.clone();
    let read_exec = executor.clone();
    let read_push_tx = push_tx.clone();
    let read_writer = writer.clone();
    let read_close = close_tx;
    let mut read_active = true;
    while read_active {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            _ => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let data = serde_json::to_string(&err_resp(
                    Value::Null,
                    ERR_PARSE,
                    &format!("Parse error: {}", e),
                ))
                .unwrap_or_default()
                    + "\n";
                let mut w = read_writer.lock().await;
                let _ = w.write_all(data.as_bytes()).await;
                continue;
            }
        };
        let req_id = parsed.get("id").cloned().unwrap_or(Value::Null);
        let method = parsed.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = parsed.get("params").cloned().unwrap_or(Value::Null);

        if method == "executor.execute_stream" {
            if let Err(e) =
                handle_execute_stream(&read_writer, req_id, params, &read_exec, &read_hub).await
            {
                warn!(error = %e, "execute_stream 写帧失败");
                read_active = false;
            }
            continue;
        }
        if method == "executor.telemetry_stream" {
            if let Err(e) = handle_telemetry_stream(&read_writer, req_id, params, &read_exec).await
            {
                warn!(error = %e, "telemetry_stream 写帧失败");
                read_active = false;
            }
            continue;
        }
        if method == "executor.subscribe" {
            handle_subscribe(
                &read_writer,
                req_id,
                params,
                conn_id,
                &read_hub,
                &read_push_tx,
            )
            .await;
            continue;
        }
        if method == "executor.unsubscribe" {
            handle_unsubscribe(&read_writer, req_id, params, &read_hub).await;
            continue;
        }

        let resp = match handle_method(method, params, &read_exec, &read_hub).await {
            Ok(r) => ok_resp(req_id, r),
            Err((code, msg)) => err_resp(req_id, code, &msg),
        };
        let data = serde_json::to_string(&resp)
            .unwrap_or_else(|_| err_str(Value::Null, ERR_INTERNAL, "响应序列化失败"))
            + "\n";
        let mut w = read_writer.lock().await;
        if w.write_all(data.as_bytes()).await.is_err() {
            read_active = false;
        }
    }
    // 连接断开 — 清订阅 + 关 push_task
    hub.drop_conn(conn_id);
    let _ = read_close.send(());
    let _ = push_handle.await;
}

/// 订阅 — 解析 channels/interval, 注册 hub, 响应 {ok, subscription_id}
async fn handle_subscribe(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    params: Value,
    conn_id: u64,
    hub: &Arc<BroadcastHub>,
    push_tx: &mpsc::Sender<Value>,
) {
    let channels: HashSet<String> = params
        .get("channels")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    if channels.is_empty() {
        let resp = err_resp(id, ERR_INVALID_REQ, "缺少 channels");
        write_line(writer, resp).await;
        return;
    }
    let sub_id = hub.subscribe(conn_id, channels, push_tx.clone());
    let resp = ok_resp(id, json!({"ok": true, "subscription_id": sub_id}));
    write_line(writer, resp).await;
}

/// 取消订阅 — 移除 hub 注册, 响应 {ok}
async fn handle_unsubscribe(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    params: Value,
    hub: &Arc<BroadcastHub>,
) {
    let sub_id = match params.get("subscription_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            let resp = err_resp(id, ERR_INVALID_REQ, "缺少 subscription_id");
            write_line(writer, resp).await;
            return;
        }
    };
    let ok = hub.unsubscribe(&sub_id);
    let resp = ok_resp(id, json!({"ok": ok}));
    write_line(writer, resp).await;
}

/// 写一行 JSON Value (锁内 write_all, 原子)
async fn write_line(writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>, v: Value) {
    let line = serde_json::to_string(&v).unwrap_or_default() + "\n";
    let mut w = writer.lock().await;
    let _ = w.write_all(line.as_bytes()).await;
}

/// 流式执行 — chunk 帧 + done 帧, 共用 id, 换行分隔逐帧写出。
/// v1.5 #14: chunk/done 同时广播给 stdio 订阅 (跨连接 fan-out)。
/// chunk: {"jsonrpc":"2.0","id":id,"result":{"type":"chunk","data":"..."}}
/// done:  {"jsonrpc":"2.0","id":id,"result":{"type":"done","result":{...ExecutionResult}}}
async fn handle_execute_stream(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    params: Value,
    executor: &Arc<Executor>,
    hub: &Arc<BroadcastHub>,
) -> Result<()> {
    let req: ExecutionRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            let frame = serde_json::to_string(&err_resp(
                id,
                ERR_INVALID_REQ,
                &format!("params 无效: {}", e),
            ))? + "\n";
            let mut w = writer.lock().await;
            w.write_all(frame.as_bytes()).await?;
            return Ok(());
        }
    };
    let task_id = req.task_id.clone();
    let (mut rx, handle) = match executor.execute_streaming(req).await {
        Ok(p) => p,
        Err(e) => {
            let frame = serde_json::to_string(&err_resp(
                id,
                ERR_INTERNAL,
                &format!("execute_stream 失败: {}", e),
            ))? + "\n";
            let mut w = writer.lock().await;
            w.write_all(frame.as_bytes()).await?;
            return Ok(());
        }
    };
    while let Some(ev) = rx.recv().await {
        let result = match ev {
            fe_core::ExecutionStreamEvent::Chunk { data } => {
                hub.broadcast_stdio(json!({"task_id": task_id, "event": "chunk", "data": data}));
                json!({"type": "chunk", "data": data})
            }
            fe_core::ExecutionStreamEvent::Done(r) => {
                let result_val = serde_json::to_value(&r).unwrap_or(json!({}));
                hub.broadcast_stdio(json!({
                    "task_id": task_id,
                    "event": "done",
                    "result": result_val.clone(),
                }));
                json!({"type": "done", "result": result_val})
            }
        };
        let frame = serde_json::to_string(&ok_resp(id.clone(), result))? + "\n";
        let mut w = writer.lock().await;
        if w.write_all(frame.as_bytes()).await.is_err() {
            break;
        }
    }
    let _ = handle.await;
    Ok(())
}

/// 实时遥测流 (请求发起, 非 subscribe) — 逐帧写出 TelemetrySample, 共用 id。
/// sample: {"jsonrpc":"2.0","id":id,"result":{"type":"sample",...TelemetrySample}}
/// params: {interval_ms?:u64, max_samples?:u64} (缺省 10Hz / 无限)
async fn handle_telemetry_stream(
    writer: &Arc<AsyncMutex<tokio::net::unix::OwnedWriteHalf>>,
    id: Value,
    params: Value,
    executor: &Arc<Executor>,
) -> Result<()> {
    let interval_ms = params
        .get("interval_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(100);
    let max_samples = params
        .get("max_samples")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cfg = TelemetryStreamConfig {
        interval_ms,
        max_samples,
    };
    let (mut rx, handle) = executor.telemetry_stream(cfg);
    while let Some(sample) = rx.recv().await {
        let frame = serde_json::to_string(&ok_resp(
            id.clone(),
            json!({"type": "sample", "sample": serde_json::to_value(&sample).unwrap_or(json!({}))}),
        ))? + "\n";
        let mut w = writer.lock().await;
        if w.write_all(frame.as_bytes()).await.is_err() {
            break;
        }
    }
    let _ = handle.await;
    Ok(())
}

/// 处理单个方法 → Ok(Value) | Err((code, msg))
/// v1.5 #14: execute (非流式) 完成后广播 stdio done 给订阅
async fn handle_method(
    method: &str,
    params: Value,
    executor: &Arc<Executor>,
    hub: &Arc<BroadcastHub>,
) -> Result<Value, (i64, String)> {
    match method {
        "executor.health" => Ok(json!({
            "ok": true,
            "version": env!("CARGO_PKG_VERSION"),
            "ax_trusted": true
        })),
        "executor.execute" => {
            let req: ExecutionRequest = serde_json::from_value(params)
                .map_err(|e| (ERR_INVALID_REQ, format!("params 无效: {}", e)))?;
            let task_id = req.task_id.clone();
            let r: ExecutionResult = executor
                .execute_async(req)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("execute 失败: {}", e)))?;
            let val = serde_json::to_value(&r).unwrap_or(json!({}));
            hub.broadcast_stdio(json!({
                "task_id": task_id,
                "event": "done",
                "result": val.clone(),
            }));
            Ok(val)
        }
        "executor.snapshot_create" => {
            let cwd = param_str(&params, "cwd").ok_or((ERR_INVALID_REQ, "缺少 cwd".to_string()))?;
            let id = executor
                .snapshot_create_async(&cwd)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("snapshot_create 失败: {}", e)))?;
            Ok(json!({"snapshot_id": id}))
        }
        "executor.rollback" => {
            let snapshot_id = param_str(&params, "snapshot_id")
                .ok_or((ERR_INVALID_REQ, "缺少 snapshot_id".to_string()))?;
            let cwd = param_str(&params, "cwd").ok_or((ERR_INVALID_REQ, "缺少 cwd".to_string()))?;
            let ok = executor
                .rollback_async(&snapshot_id, &cwd)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("rollback 失败: {}", e)))?;
            if !ok {
                return Err((-32012, "rollback 失败 (stash apply 或非 repo)".to_string()));
            }
            Ok(json!({"ok": true}))
        }
        "executor.diagnostics" => {
            let stderr = param_str(&params, "stderr")
                .or_else(|| param_str(&params, "output"))
                .unwrap_or_default();
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let slicer = fe_core::diagnostics::Slicer::new();
            let d: Diagnostics = slicer.slice(&stderr, cwd).into();
            Ok(serde_json::to_value(&d).unwrap_or(json!({})))
        }
        "executor.gui_action" => {
            let action_val = params
                .get("action")
                .ok_or((ERR_INVALID_REQ, "缺少 action".to_string()))?;
            let action: GuiAction = serde_json::from_value(action_val.clone())
                .map_err(|e| (ERR_INVALID_REQ, format!("action 反序列化失败: {e}")))?;
            let result = executor
                .gui_action(action)
                .map_err(|e| (ERR_INTERNAL, format!("gui_action 失败: {e}")))?;
            Ok(serde_json::to_value(&result).unwrap_or(json!({})))
        }
        "executor.shutdown" => {
            info!("收到 shutdown 请求 (注意: 按进程退出, 此方法仅回确认)");
            Ok(json!({"ok": true}))
        }
        "executor.file_edit" => {
            let path =
                param_str(&params, "path").ok_or((ERR_INVALID_REQ, "缺少 path".to_string()))?;
            let old_string = param_str(&params, "old_string")
                .ok_or((ERR_INVALID_REQ, "缺少 old_string".to_string()))?;
            let new_string = param_str(&params, "new_string")
                .ok_or((ERR_INVALID_REQ, "缺少 new_string".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .file_edit(&path, &old_string, &new_string, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("file_edit 失败: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.glob" => {
            let pattern = param_str(&params, "pattern")
                .ok_or((ERR_INVALID_REQ, "缺少 pattern".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let entries = executor
                .glob(&pattern, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("glob 失败: {}", e)))?;
            Ok(serde_json::to_value(&entries).unwrap_or(json!({})))
        }
        "executor.grep" => {
            let pattern = param_str(&params, "pattern")
                .ok_or((ERR_INVALID_REQ, "缺少 pattern".to_string()))?;
            let paths: Vec<String> = params
                .get("paths")
                .and_then(|p| p.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .ok_or((ERR_INVALID_REQ, "缺少 paths 数组".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let matches = executor
                .grep(&pattern, &paths, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("grep 失败: {}", e)))?;
            Ok(serde_json::to_value(&matches).unwrap_or(json!({})))
        }
        "executor.apply_patch" => {
            let diff =
                param_str(&params, "diff").ok_or((ERR_INVALID_REQ, "缺少 diff".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .apply_patch(&diff, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("apply_patch 失败: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        "executor.replace_function" => {
            let path =
                param_str(&params, "path").ok_or((ERR_INVALID_REQ, "缺少 path".to_string()))?;
            let fn_name = param_str(&params, "fn_name")
                .ok_or((ERR_INVALID_REQ, "缺少 fn_name".to_string()))?;
            let new_body = param_str(&params, "new_body")
                .ok_or((ERR_INVALID_REQ, "缺少 new_body".to_string()))?;
            let cwd = params.get("cwd").and_then(|c| c.as_str());
            let r = executor
                .replace_function(&path, &fn_name, &new_body, cwd)
                .map_err(|e| (ERR_INTERNAL, format!("replace_function 失败: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
        }
        _ => Err((
            ERR_METHOD_NOT_FOUND,
            format!("Method not found: {}", method),
        )),
    }
}

/// 取 params["key"] 字符串
fn param_str(params: &Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn ok_resp(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn err_resp(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn err_str(id: Value, code: i64, message: &str) -> String {
    serde_json::to_string(&err_resp(id, code, message)).unwrap_or_default()
}

/// chmod 0o666 — 允许同机其他用户进程连接 (mirror desk_rpc.py)
#[cfg(unix)]
fn chmod_666(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
}

#[cfg(not(unix))]
fn chmod_666(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixStream;

    fn tmp_sock(tag: &str) -> String {
        let p =
            std::env::temp_dir().join(format!("fe-ipc-test-{}-{}.sock", std::process::id(), tag));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    async fn rpc(sock: &str, req: &str) -> Value {
        let mut s = UnixStream::connect(sock).await.unwrap();
        s.write_all((req.to_string() + "\n").as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        let mut reader = BufReader::new(s);
        reader.read_until(b'\n', &mut buf).await.unwrap();
        let line = String::from_utf8_lossy(&buf).trim().to_string();
        serde_json::from_str(&line).unwrap_or(Value::Null)
    }

    #[tokio::test]
    async fn health_ok() {
        let sock = tmp_sock("health");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.health","params":{}}"#,
        )
        .await;
        assert_eq!(resp["result"]["ok"], true);
        assert_eq!(resp["result"]["ax_trusted"], true);
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn unknown_method_returns_32601() {
        let sock = tmp_sock("unknown");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":2,"method":"nope","params":{}}"#,
        )
        .await;
        assert_eq!(resp["error"]["code"], -32601);
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn malformed_json_returns_32700() {
        let sock = tmp_sock("malformed");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(&sock, r#"{not valid json"#).await;
        assert_eq!(resp["error"]["code"], -32700);
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn execute_echo_over_uds() {
        let sock = tmp_sock("exec");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","id":3,"method":"executor.execute","params":{"command":"echo hi"}}"#;
        let resp = rpc(&sock, req).await;
        assert_eq!(resp["result"]["exit_code"], 0);
        assert_eq!(resp["result"]["stdout"], "hi\n");
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn execute_stream_chunks_then_done_over_uds() {
        let sock = tmp_sock("stream");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","id":7,"method":"executor.execute_stream","params":{"command":"echo hi","enable_rollback_snapshot":false}}"#;
        let mut s = UnixStream::connect(&sock).await.unwrap();
        s.write_all((req.to_string() + "\n").as_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new(s);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            reader.read_until(b'\n', &mut buf).await.unwrap();
            let line = String::from_utf8_lossy(&buf).trim().to_string();
            if line.is_empty() {
                break;
            }
            let v: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["id"], 7, "所有帧应共用 id");
            let rtype = v["result"]["type"].as_str().unwrap_or("");
            if rtype == "done" {
                assert_eq!(v["result"]["result"]["exit_code"], 0);
                assert!(v["result"]["result"]["stdout"]
                    .as_str()
                    .unwrap_or("")
                    .contains("hi"));
                break;
            }
            assert_eq!(rtype, "chunk");
        }
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn execute_stream_blocked_single_done_frame_over_uds() {
        let sock = tmp_sock("stream-blocked");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","id":9,"method":"executor.execute_stream","params":{"command":"rm -rf /","enable_rollback_snapshot":false}}"#;
        let mut s = UnixStream::connect(&sock).await.unwrap();
        s.write_all((req.to_string() + "\n").as_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new(s);
        let mut buf = Vec::new();
        reader.read_until(b'\n', &mut buf).await.unwrap();
        let v: Value = serde_json::from_str(String::from_utf8_lossy(&buf).trim()).unwrap();
        assert_eq!(v["id"], 9);
        assert_eq!(v["result"]["type"], "done");
        assert_eq!(v["result"]["result"]["exit_code"], -1);
        assert_eq!(v["result"]["result"]["blocked_by_security"], true);
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn telemetry_stream_samples_over_uds() {
        let sock = tmp_sock("telemetry");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let req = r#"{"jsonrpc":"2.0","id":11,"method":"executor.telemetry_stream","params":{"interval_ms":20,"max_samples":3}}"#;
        let mut s = UnixStream::connect(&sock).await.unwrap();
        s.write_all((req.to_string() + "\n").as_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new(s);
        let mut buf = Vec::new();
        let mut count = 0;
        loop {
            buf.clear();
            if reader.read_until(b'\n', &mut buf).await.unwrap() == 0 {
                break;
            }
            let line = String::from_utf8_lossy(&buf).trim().to_string();
            if line.is_empty() {
                break;
            }
            let v: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["id"], 11, "遥测帧共用 id");
            assert_eq!(v["result"]["type"], "sample");
            let sample = &v["result"]["sample"];
            assert!(sample["mem_mb"].as_f64().unwrap_or(0.0) >= 0.0);
            assert!(sample["cpu_pct"].as_f64().unwrap_or(-1.0) >= 0.0);
            count += 1;
            if count >= 3 {
                break;
            }
        }
        assert_eq!(count, 3, "应收到 3 帧遥测样本");
        let _ = std::fs::remove_file(&sock);
    }

    // ── v1.5 #14 双向 server-push 测试 ──

    /// 读一行 (用于 subscribe 后持续读推送帧)
    async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Option<Value> {
        let mut buf = Vec::new();
        if reader.read_until(b'\n', &mut buf).await.unwrap() == 0 {
            return None;
        }
        let line = String::from_utf8_lossy(&buf).trim().to_string();
        if line.is_empty() {
            return None;
        }
        serde_json::from_str(&line).ok()
    }

    #[tokio::test]
    async fn subscribe_telemetry_pushes_event_frames() {
        let sock = tmp_sock("sub-telemetry");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let mut s = UnixStream::connect(&sock).await.unwrap();
        s.write_all(
            br#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["telemetry"],"interval_ms":20}}
"#,
        )
        .await
        .unwrap();
        let mut reader = BufReader::new(s);
        // 第一行 = subscribe 响应
        let resp = read_line(&mut reader).await.expect("subscribe 响应");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["ok"], true);
        let sub_id = resp["result"]["subscription_id"]
            .as_str()
            .expect("subscription_id")
            .to_string();
        assert!(sub_id.starts_with("sub-"));
        // 后续行 = server-push notification (无 id, 有 method=executor.event)
        let mut got = 0;
        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                frame = read_line(&mut reader) => {
                    let frame = match frame { Some(f) => f, None => break };
                    assert!(frame.get("id").is_none(), "notification 无 id: {frame}");
                    assert_eq!(frame["method"], "executor.event");
                    assert_eq!(frame["params"]["subscription_id"], sub_id);
                    assert_eq!(frame["params"]["channel"], "telemetry");
                    assert!(frame["params"]["data"]["mem_mb"].as_f64().unwrap_or(-1.0) >= 0.0);
                    got += 1;
                    if got >= 3 { break; }
                }
            }
        }
        assert!(got >= 3, "应收到 >=3 telemetry 推送帧, got={got}");
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn subscribe_missing_channels_returns_32600() {
        let sock = tmp_sock("sub-bad");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let resp = rpc(
            &sock,
            r#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{}}"#,
        )
        .await;
        assert_eq!(resp["error"]["code"], -32600);
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn unsubscribe_stops_push_for_that_sub() {
        let sock = tmp_sock("unsub");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        let s = UnixStream::connect(&sock).await.unwrap();
        let (rh, mut writer) = s.into_split();
        let mut reader = BufReader::new(rh);
        let req = br#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["telemetry"],"interval_ms":20}}
"#;
        writer.write_all(req).await.unwrap();
        let resp = read_line(&mut reader).await.unwrap();
        let sub_id = resp["result"]["subscription_id"]
            .as_str()
            .unwrap()
            .to_string();
        // 等一帧确认推送在工作
        let first = read_line(&mut reader).await.unwrap();
        assert_eq!(first["params"]["subscription_id"], sub_id);
        // 取消订阅
        let unsub = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"executor.unsubscribe","params":{{"subscription_id":"{sub_id}"}}}}
"#,
        );
        writer.write_all(unsub.as_bytes()).await.unwrap();
        let unsub_resp = read_line(&mut reader).await.unwrap();
        assert_eq!(unsub_resp["id"], 2);
        assert_eq!(unsub_resp["result"]["ok"], true);
        // 取消后短时内不应再收到该 sub 的推送 (遥测源 0 订阅自退)
        // 读 300ms — 最多拿到 0 帧 (源已停); 容忍可能的残留 1 帧
        let mut extra = 0;
        let deadline = tokio::time::sleep(Duration::from_millis(300));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                frame = read_line(&mut reader) => {
                    if frame.is_some() { extra += 1; }
                }
            }
        }
        assert!(extra <= 1, "取消订阅后不应持续推送, extra={extra}");
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn stdio_broadcasts_across_connections() {
        // 连接 A 订阅 stdio, 连接 B execute_stream → A 应收到 stdio chunk/done 推送
        let sock = tmp_sock("stdio-bcast");
        let server = IpcServer::new();
        let (_tx, _join) = server.serve(&sock).await.unwrap();
        // 连接 A: subscribe stdio
        let sa = UnixStream::connect(&sock).await.unwrap();
        let (rha, mut writer_a) = sa.into_split();
        let mut reader_a = BufReader::new(rha);
        let _ = writer_a.write_all(
            br#"{"jsonrpc":"2.0","id":1,"method":"executor.subscribe","params":{"channels":["stdio"]}}
"#,
        )
        .await;
        let resp = read_line(&mut reader_a).await.unwrap();
        assert_eq!(resp["result"]["ok"], true);
        let sub_id = resp["result"]["subscription_id"]
            .as_str()
            .unwrap()
            .to_string();
        // 连接 B: execute_stream echo
        let sb = UnixStream::connect(&sock).await.unwrap();
        let (rhb, mut writer_b) = sb.into_split();
        let mut reader_b = BufReader::new(rhb);
        let _ = writer_b.write_all(
            br#"{"jsonrpc":"2.0","id":7,"method":"executor.execute_stream","params":{"command":"echo hi","enable_rollback_snapshot":false}}
"#,
        )
        .await;
        // B 读到自己的 done 帧
        let mut b_done = false;
        // A 应收到 stdio 推送 (chunk 和/或 done)
        let mut a_stdio = false;
        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        let mut buf_b = Vec::new();
        let mut buf_a = Vec::new();
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                r = async {
                    buf_b.clear();
                    let n = reader_b.read_until(b'\n', &mut buf_b).await.unwrap();
                    if n == 0 { return None; }
                    let line = String::from_utf8_lossy(&buf_b).trim().to_string();
                    serde_json::from_str::<Value>(&line).ok()
                } => {
                    match r {
                        Some(v) => {
                            if v["id"] == 7 && v["result"]["type"] == "done" { b_done = true; }
                        }
                        None => break,
                    }
                }
                r = async {
                    buf_a.clear();
                    let n = reader_a.read_until(b'\n', &mut buf_a).await.unwrap();
                    if n == 0 { return None; }
                    let line = String::from_utf8_lossy(&buf_a).trim().to_string();
                    serde_json::from_str::<Value>(&line).ok()
                } => {
                    match r {
                        Some(v) => {
                            if v.get("id").is_none() && v["method"] == "executor.event"
                                && v["params"]["channel"] == "stdio"
                                && v["params"]["subscription_id"] == sub_id {
                                a_stdio = true;
                            }
                        }
                        None => break,
                    }
                }
            }
            if b_done && a_stdio {
                break;
            }
        }
        assert!(b_done, "B 应收到自己 done 帧");
        assert!(a_stdio, "A 应收到 stdio 跨连接推送");
        let _ = std::fs::remove_file(&sock);
    }
}
