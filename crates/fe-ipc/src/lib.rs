// fe-ipc — UDS JSON-RPC 2.0 server (P3)
//
// Socket /tmp/fusion-executor.sock (override FUSION_EXECUTOR_SOCK), 换行分隔
// Mirror fusion-cowork/fusion_cowork/server/desk_rpc.py 协议:
//   line = read_line(); 响应 = serde_json::to_string(resp) + "\n"
//   jsonrpc "2.0", id 透传; 错误码 -32700(parse)/-32600(invalid req)/-32601(method)/-32603(internal)
//   扩展: -32010 安全拦截, -32011 超时, -32012 回滚失败, -32013 AX 未授权
// 匹配 fusion-studio IPCClient.swift: 按字节读到 0x0A, 8s 超时
//
// 方法: executor.health/execute/execute_stream/snapshot_create/rollback/gui_action/diagnostics
//       executor.file_edit/glob/grep/apply_patch/replace_function/shutdown

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tracing::{info, warn};

use fe_core::gui::GuiAction;
use fe_core::{Diagnostics, ExecutionRequest, ExecutionResult, Executor};

/// 默认 socket 路径
pub const DEFAULT_SOCK: &str = "/tmp/fusion-executor.sock";

/// JSON-RPC 错误码
const ERR_PARSE: i64 = -32700;
const ERR_INVALID_REQ: i64 = -32600;
const ERR_METHOD_NOT_FOUND: i64 = -32601;
const ERR_INTERNAL: i64 = -32603;

/// IPC 服务器 — 持有 Arc<Executor>, 换行分隔 JSON-RPC 2.0 over UDS
pub struct IpcServer {
    executor: Arc<Executor>,
}

impl IpcServer {
    pub fn new() -> Self {
        info!("IpcServer::new() — 持有 Executor");
        Self {
            executor: Arc::new(Executor::new()),
        }
    }

    pub fn with_executor(executor: Executor) -> Self {
        info!("IpcServer::with_executor()");
        Self {
            executor: Arc::new(executor),
        }
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
        let join = tokio::spawn(async move {
            accept_loop(listener, executor, shutdown_rx).await;
            let _ = std::fs::remove_file(&path);
        });
        Ok((shutdown_tx, join))
    }

    /// 同步阻塞 serve — 供 PyO3 serve() 直接调用 (走 BLOCKING_RT)
    /// 永驻直到进程退出; shutdown 走进程信号
    pub fn serve_blocking(&self, sock_path: &str) -> Result<()> {
        let path = sock_path.to_string();
        let executor = self.executor.clone();
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
            accept_loop(listener, executor, rx).await;
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
                        tokio::spawn(handle_conn(stream, ex));
                    }
                    Err(e) => warn!(error = %e, "accept 失败"),
                }
            }
        }
    }
}

/// 单连接处理 — read_line 分发, 每行一个请求
/// execute_stream 方法特殊路径: 多帧 (chunk/done) 共用同一 id, 换行分隔逐帧写出
async fn handle_conn(stream: UnixStream, executor: Arc<Executor>) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
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
                let _ = writer.write_all(data.as_bytes()).await;
                continue;
            }
        };
        let req_id = parsed.get("id").cloned().unwrap_or(Value::Null);
        let method = parsed.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = parsed.get("params").cloned().unwrap_or(Value::Null);

        if method == "executor.execute_stream" {
            if let Err(e) = handle_execute_stream(&mut writer, req_id, params, &executor).await {
                warn!(error = %e, "execute_stream 写帧失败");
                break;
            }
            continue;
        }

        let resp = match handle_method(method, params, &executor).await {
            Ok(r) => ok_resp(req_id, r),
            Err((code, msg)) => err_resp(req_id, code, &msg),
        };
        let data = serde_json::to_string(&resp)
            .unwrap_or_else(|_| err_str(Value::Null, ERR_INTERNAL, "响应序列化失败"))
            + "\n";
        if writer.write_all(data.as_bytes()).await.is_err() {
            break;
        }
    }
}

/// 流式执行 — chunk 帧 + done 帧, 共用 id, 换行分隔逐帧写出
/// chunk: {"jsonrpc":"2.0","id":id,"result":{"type":"chunk","data":"..."}}
/// done:  {"jsonrpc":"2.0","id":id,"result":{"type":"done","result":{...ExecutionResult}}}
async fn handle_execute_stream(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    id: Value,
    params: Value,
    executor: &Arc<Executor>,
) -> Result<()> {
    let req: ExecutionRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            let frame = serde_json::to_string(&err_resp(
                id,
                ERR_INVALID_REQ,
                &format!("params 无效: {}", e),
            ))? + "\n";
            writer.write_all(frame.as_bytes()).await?;
            return Ok(());
        }
    };
    let (mut rx, handle) = match executor.execute_streaming(req).await {
        Ok(p) => p,
        Err(e) => {
            let frame = serde_json::to_string(&err_resp(
                id,
                ERR_INTERNAL,
                &format!("execute_stream 失败: {}", e),
            ))? + "\n";
            writer.write_all(frame.as_bytes()).await?;
            return Ok(());
        }
    };
    while let Some(ev) = rx.recv().await {
        let result = match ev {
            fe_core::ExecutionStreamEvent::Chunk { data } => json!({"type": "chunk", "data": data}),
            fe_core::ExecutionStreamEvent::Done(r) => json!({
                "type": "done",
                "result": serde_json::to_value(&r).unwrap_or(json!({}))
            }),
        };
        let frame = serde_json::to_string(&ok_resp(id.clone(), result))? + "\n";
        if writer.write_all(frame.as_bytes()).await.is_err() {
            break;
        }
    }
    let _ = handle.await;
    Ok(())
}

/// 处理单个方法 → Ok(Value) | Err((code, msg))
async fn handle_method(
    method: &str,
    params: Value,
    executor: &Arc<Executor>,
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
            let r: ExecutionResult = executor
                .execute_async(req)
                .await
                .map_err(|e| (ERR_INTERNAL, format!("execute 失败: {}", e)))?;
            Ok(serde_json::to_value(&r).unwrap_or(json!({})))
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
        // 读到 done 帧 (含 "type":"done") 为止
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
        // 拦截 → 仅单帧 done
        assert_eq!(v["result"]["type"], "done");
        assert_eq!(v["result"]["result"]["exit_code"], -1);
        assert_eq!(v["result"]["result"]["blocked_by_security"], true);
        let _ = std::fs::remove_file(&sock);
    }
}
