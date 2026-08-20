# fusion-executor IPC — TypeScript Client Sketch (P3)

> fusion-code (TypeScript) 消费 fusion-executor 的 UDS JSON-RPC 2.0 接口的 sketch。
> **参考接口，不修改 fusion-code 工程代码** (monorepo 规则: 只改本工程)。

## 协议

- 传输: Unix Domain Socket, 路径 `/tmp/fusion-executor.sock` (override `FUSION_EXECUTOR_SOCK`)
- 编码: UTF-8, 换行分隔 (`0x0A`) — 每行一个 JSON-RPC 2.0 请求/响应
- 请求: `{"jsonrpc":"2.0","id":<number>,"method":"executor.<m>","params":{...}}`
- 响应: `{"jsonrpc":"2.0","id":<number>,"result":{...}}` 或 `{"jsonrpc":"2.0","id":<number>,"error":{"code":<int>,"message":<str>}}`
- 错误码: `-32700` parse / `-32600` invalid req / `-32601` method not found / `-32603` internal; 扩展 `-32010` 安全拦截 / `-32011` 超时 / `-32012` 回滚失败 / `-32013` AX 未授权
- 超时: client 默认 8s; 长任务 (`executor.execute`) 按 `timeout_sec + 5s`

## 方法

| Method | Params | Result |
|---|---|---|
| `executor.health` | `{}` | `{"ok":true,"version":"0.1.0","ax_trusted":true}` |
| `executor.execute` | `ExecutionRequest` | `ExecutionResult` |
| `executor.snapshot_create` | `{"cwd":string}` | `{"snapshot_id":string}` |
| `executor.rollback` | `{"snapshot_id":string,"cwd":string}` | `{"ok":boolean}` |
| `executor.diagnostics` | `{"stderr":string,"cwd"?:string}` | `Diagnostics` |
| `executor.gui_action` | `{"action":GuiAction}` | `GuiResult` (P4) |
| `executor.shutdown` | `{}` | `{"ok":true}` |

## TypeScript Sketch

```typescript
// fusion-code 侧的薄客户端 — 替代 ShellCommand.ts 内部, 走 UDS 调 fusion-executor
import net from "node:net";

const DEFAULT_SOCK = "/tmp/fusion-executor.sock";

export interface ExecutionRequest {
  command: string;
  task_id?: string;
  cwd?: string;
  timeout_sec?: number;
  env_vars?: Record<string, string>;
  enable_rollback_snapshot?: boolean;
}

export interface ExecutionResult {
  exit_code: number;          // 0=ok, -124=timeout, -1=blocked/internal
  stdout: string;
  stderr: string;
  timed_out: boolean;
  blocked_by_security: boolean;
  security_reason: string | null;
  snapshot_id: string | null;
  diagnostics: Diagnostics | null;
}

export interface Diagnostics {
  error_type: string | null;
  file_path: string | null;
  line_number: number | null;
  code_snippet: string | null;
  raw_trace: string | null;
}

export class FusionExecutorClient {
  private sock: string;
  private nextId = 1;

  constructor(sock: string = process.env.FUSION_EXECUTOR_SOCK ?? DEFAULT_SOCK) {
    this.sock = sock;
  }

  private rpc(method: string, params: unknown, timeoutMs = 8000): Promise<any> {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      const socket = net.createConnection(this.sock);
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`IPC 超时 ${method} (${timeoutMs}ms)`));
      }, timeoutMs);

      let buf = "";
      socket.on("data", (chunk) => {
        buf += chunk.toString("utf-8");
        const nl = buf.indexOf("\n");
        if (nl >= 0) {
          clearTimeout(timer);
          socket.end();
          const resp = JSON.parse(buf.slice(0, nl));
          if (resp.error) reject(new Error(`${resp.error.code}: ${resp.error.message}`));
          else resolve(resp.result);
        }
      });
      socket.on("error", (e) => {
        clearTimeout(timer);
        reject(e);
      });
      socket.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  health() {
    return this.rpc("executor.health", {});
  }

  execute(req: ExecutionRequest): Promise<ExecutionResult> {
    return this.rpc("executor.execute", req, (req.timeout_sec ?? 30) * 1000 + 5000);
  }

  snapshotCreate(cwd: string): Promise<{ snapshot_id: string }> {
    return this.rpc("executor.snapshot_create", { cwd });
  }

  rollback(snapshotId: string, cwd: string): Promise<{ ok: boolean }> {
    return this.rpc("executor.rollback", { snapshot_id: snapshotId, cwd });
  }

  diagnostics(stderr: string, cwd?: string): Promise<Diagnostics> {
    return this.rpc("executor.diagnostics", { stderr, cwd });
  }
}
```

## 用法 (fusion-code self-healing loop 视角)

```typescript
const ex = new FusionExecutorClient();

// fusion-code 落盘 patch → 跑测试 → 结构化诊断回填
const result = await ex.execute({ command: "pytest tests/", cwd: repoPath, timeout_sec: 120 });
if (result.exit_code !== 0 && result.diagnostics) {
  // diagnostics.error_type / file_path / line_number / code_snippet → 喂下一轮 LLM 自愈
}

// 回滚 (caller-driven; executor 无状态)
const snap = await ex.snapshotCreate(repoPath);
// ... 应用失败的改动 ...
await ex.rollback(snap.snapshot_id, repoPath);
```
