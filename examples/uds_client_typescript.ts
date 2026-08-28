/**
 * Example — TypeScript UDS JSON-RPC 2.0 client for fusion-executor.
 *
 * fusion-code (TypeScript) consumes fusion-executor over Unix Domain Socket.
 * This is a runnable reference client covering the full v0.1.0 surface:
 * health / execute / execute_stream (live stdio) / file tools / rollback /
 * subscribe (bidirectional server-push).
 *
 * Run (Bun or tsx):
 *   bun examples/uds_client_typescript.ts            # health + execute demo
 *   bun examples/uds_client_typescript.ts subscribe  # + telemetry push demo
 *
 * Prerequisite: a server is running on the socket:
 *   python -c "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()"
 */

import net from "node:net";

const DEFAULT_SOCK = require("os").homedir() + "/.fusion-executor/fe.sock";

// ── Wire types (mirror Python Pydantic models / Rust serde structs) ──

interface ExecutionRequest {
    command: string;
    task_id?: string;
    cwd?: string;
    timeout_sec?: number;
    env_vars?: Record<string, string>;
    enable_rollback_snapshot?: boolean;
    seatbelt?: boolean;
}

interface Diagnostics {
    error_type: string | null;
    file_path: string | null;
    line_number: number | null;
    code_snippet: string | null;
    raw_trace: string | null;
}

interface ExecutionResult {
    exit_code: number;           // 0=ok, -124=timeout, -1=blocked/internal
    stdout: string;
    stderr: string;
    task_id: string | null;
    command: string | null;
    duration_sec: number;
    timed_out: boolean;
    blocked_by_security: boolean;
    security_reason: string | null;
    snapshot_id: string | null;
    diagnostics: Diagnostics | null;
    auto_rolled_back: boolean;
}

interface EditResult {
    ok: boolean;
    path: string | null;
    error: string | null;
    matches: number;
}

interface TelemetrySample {
    ts_ms: number;
    cpu_pct: number;
    mem_mb: number;
    gpu_pct?: number;
    gpu_mem_mb?: number;
    task_id?: string;
}

// A server-push notification frame (no `id`; method `executor.event`).
interface PushEvent {
    jsonrpc: "2.0";
    method: "executor.event";
    params: {
        subscription_id: string;
        channel: "telemetry" | "stdio" | "screenshot";
        data: Record<string, unknown>;
    };
}

// ── Client ──

export class FusionExecutorClient {
    private sock: string;
    private nextId = 1;

    constructor(sock: string = process.env.FUSION_EXECUTOR_SOCK ?? DEFAULT_SOCK) {
        this.sock = sock;
    }

    // Single request/response over a fresh connection (newline-delimited JSON-RPC).
    private rpc<T>(method: string, params: unknown, timeoutMs = 8000): Promise<T> {
        return new Promise((resolve, reject) => {
            const id = this.nextId++;
            const socket = net.createConnection(this.sock);
            const timer = setTimeout(() => {
                socket.destroy();
                reject(new Error(`IPC timeout ${method} (${timeoutMs}ms)`));
            }, timeoutMs);

            let buf = "";
            socket.on("data", (chunk) => {
                buf += chunk.toString("utf-8");
                const nl = buf.indexOf("\n");
                if (nl >= 0) {
                    clearTimeout(timer);
                    socket.end();
                    let resp: { result?: T; error?: { code: number; message: string } };
                    try {
                        resp = JSON.parse(buf.slice(0, nl));
                    } catch (e) {
                        reject(new Error(`IPC parse error: ${(e as Error).message}`));
                        return;
                    }
                    if (resp.error) {
                        reject(new Error(`${resp.error.code}: ${resp.error.message}`));
                    } else {
                        resolve(resp.result as T);
                    }
                }
            });
            socket.on("error", (e) => {
                clearTimeout(timer);
                reject(e);
            });
            socket.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
        });
    }

    health(): Promise<{ ok: boolean; version: string; ax_trusted: boolean }> {
        return this.rpc("executor.health", {});
    }

    execute(req: ExecutionRequest): Promise<ExecutionResult> {
        // Long-running commands: timeout_sec + 5s slack on the client side.
        const slack = (req.timeout_sec ?? 30) * 1000 + 5000;
        return this.rpc("executor.execute", req, slack);
    }

    // Live stdio streaming: yields stdout chunks, then a final ExecutionResult.
    // The server sends NDJSON multi-frame: chunk {type:"chunk",data} then done
    // {type:"done",result:{ExecutionResult}} — id reused across frames.
    async *executeStream(req: ExecutionRequest, timeoutMs = 60000): AsyncGenerator<string | ExecutionResult> {
        const id = this.nextId++;
        const socket = net.createConnection(this.sock);
        const queue: (string | ExecutionResult)[] = [];
        let done = false;
        let err: Error | null = null;
        let resolveWait: (() => void) | null = null;

        const timer = setTimeout(() => {
            socket.destroy();
            err = new Error(`IPC stream timeout (${timeoutMs}ms)`);
            done = true;
            resolveWait?.();
        }, timeoutMs);

        let buf = "";
        socket.on("data", (chunk) => {
            buf += chunk.toString("utf-8");
            let nl: number;
            while ((nl = buf.indexOf("\n")) >= 0) {
                const line = buf.slice(0, nl);
                buf = buf.slice(nl + 1);
                let frame: { type: string; data?: string; result?: ExecutionResult };
                try {
                    frame = JSON.parse(line);
                } catch {
                    continue;
                }
                if (frame.type === "chunk" && typeof frame.data === "string") {
                    queue.push(frame.data);
                } else if (frame.type === "done" && frame.result) {
                    queue.push(frame.result);
                    done = true;
                }
                resolveWait?.();
            }
        });
        socket.on("error", (e) => {
            clearTimeout(timer);
            err = e;
            done = true;
            resolveWait?.();
        });
        socket.write(JSON.stringify({ jsonrpc: "2.0", id, method: "executor.execute_stream", params: req }) + "\n");

        while (true) {
            if (queue.length > 0) {
                yield queue.shift() as string | ExecutionResult;
            } else if (done) {
                clearTimeout(timer);
                socket.destroy();
                if (err) throw err;
                return;
            } else {
                await new Promise<void>((r) => {
                    resolveWait = r;
                });
            }
        }
    }

    fileEdit(path: string, oldString: string, newString: string, cwd?: string): Promise<EditResult> {
        return this.rpc("executor.file_edit", { path, old_string: oldString, new_string: newString, cwd });
    }

    snapshotCreate(cwd: string): Promise<{ snapshot_id: string }> {
        return this.rpc("executor.snapshot_create", { cwd });
    }

    rollback(snapshotId: string, cwd: string): Promise<{ ok: boolean }> {
        return this.rpc("executor.rollback", { snapshot_id: snapshotId, cwd });
    }

    // Bidirectional server-push: subscribe to a channel, yield PushEvent frames.
    // Reuses one persistent connection; the server pushes `executor.event`
    // notifications (no id). Call `close()` to unsubscribe + tear down.
    subscribe(
        channels: ("telemetry" | "stdio" | "screenshot")[],
        opts: { interval_ms?: number; idleTimeoutMs?: number } = {},
    ): { next: () => Promise<PushEvent>; close: () => Promise<void> } {
        const id = this.nextId++;
        const socket = net.createConnection(this.sock);
        const queue: PushEvent[] = [];
        let err: Error | null = null;
        let resolveWait: (() => void) | null = null;
        let subId: string | null = null;
        let buf = "";

        socket.on("data", (chunk) => {
            buf += chunk.toString("utf-8");
            let nl: number;
            while ((nl = buf.indexOf("\n")) >= 0) {
                const line = buf.slice(0, nl);
                buf = buf.slice(nl + 1);
                let frame: { id?: number; result?: { subscription_id?: string }; method?: string; params?: unknown };
                try {
                    frame = JSON.parse(line);
                } catch {
                    continue;
                }
                // Subscribe handshake response carries our id + subscription_id.
                if (frame.id === id && frame.result?.subscription_id) {
                    subId = frame.result.subscription_id;
                    resolveWait?.();
                    continue;
                }
                // Server-push notification (no id, method executor.event).
                if (frame.method === "executor.event" && frame.params) {
                    queue.push(frame as unknown as PushEvent);
                    resolveWait?.();
                }
            }
        });
        socket.on("error", (e) => {
            err = e;
            resolveWait?.();
        });
        socket.write(JSON.stringify({
            jsonrpc: "2.0",
            id,
            method: "executor.subscribe",
            params: { channels, interval_ms: opts.interval_ms },
        }) + "\n");

        const idle = opts.idleTimeoutMs ?? 5000;
        return {
            next: () => new Promise<PushEvent>((resolve, reject) => {
                if (queue.length > 0) {
                    resolve(queue.shift() as PushEvent);
                    return;
                }
                if (err) {
                    reject(err);
                    return;
                }
                const to = setTimeout(() => reject(new Error(`subscribe idle timeout (${idle}ms)`)), idle);
                resolveWait = () => {
                    clearTimeout(to);
                    if (queue.length > 0) resolve(queue.shift() as PushEvent);
                    else if (err) reject(err);
                };
            }),
            close: () => new Promise<void>((resolve) => {
                if (subId) {
                    socket.write(JSON.stringify({
                        jsonrpc: "2.0",
                        method: "executor.unsubscribe",
                        params: { subscription_id: subId },
                    }) + "\n");
                }
                socket.destroy();
                resolve();
            }),
        };
    }
}

// ── Demo ──

async function main(): Promise<void> {
    const client = new FusionExecutorClient();
    const wantSubscribe = process.argv[2] === "subscribe";

    console.log("=== health ===");
    const h = await client.health();
    console.log(h);

    console.log("\n=== execute (echo) ===");
    const r = await client.execute({ command: "echo 'hello from TS client'", timeout_sec: 5 });
    console.log({ exit_code: r.exit_code, stdout: r.stdout, duration_sec: r.duration_sec });

    if (wantSubscribe) {
        console.log("\n=== subscribe telemetry ===");
        const sub = client.subscribe(["telemetry"], { interval_ms: 200, idleTimeoutMs: 3000 });
        for (let i = 0; i < 4; i++) {
            const ev = await sub.next();
            const s = ev.params.data as unknown as TelemetrySample;
            console.log(`  push #${i + 1} channel=${ev.params.channel} cpu=${s.cpu_pct}% mem=${s.mem_mb}MB`);
        }
        await sub.close();
        console.log("unsubscribed.");
    }
}

main().catch((e) => {
    console.error("demo failed:", e);
    process.exit(1);
});
