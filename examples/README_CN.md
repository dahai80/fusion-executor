# 示例

> **语言 / Language**: [English](README.md) | **中文**

fusion-executor v0.1.0 可运行示例 —— Fusion 生态的受控执行沙箱 + macOS 系统级控制中枢。

每个示例自包含, 运行时会打印当前动作。它们调用真实的原生扩展 (Rust + PyO3 + maturin), 非模拟。

## 前置准备

```bash
cd /Users/dahai/fusion
source .venv/bin/activate          # 共享 venv —— 必须先执行
cd fusion-executor
maturin develop --release          # 构建 + 安装原生扩展
```

TypeScript 示例另需 `bun` (`brew install oven-sh/bun/bun`)。

## Python 示例

| # | 文件 | 演示内容 |
|---|------|----------|
| 01 | `01_run_echo.py` | 正常路径 —— `run("echo ...")` 返回 `exit_code 0`、stdout、`duration_sec`。 |
| 02 | `02_security_block.py` | 两阶段安全守卫在**任何进程拉起前**拦截 `rm -rf`、`sudo`、`curl|sh`、`os.system` 链。 |
| 03 | `03_streaming.py` | `run_streaming()` 边到边产出 stdout chunk, 最后产出 `ExecutionResult` —— 全 4 层实时 stdio。 |
| 04 | `04_rollback.py` | `snapshot_create()` → 破坏文件 → 失败命令 → `rollback()` 恢复 git 快照。 |
| 05 | `05_file_tools.py` | 原生文件工具: `file_edit` (唯一匹配)、`glob`、`grep`、`apply_patch` (Unified Diff, 禁全文件重写)、`replace_function` (tree-sitter AST)。 |
| 06 | `06_telemetry.py` | `telemetry_stream()` 以 10Hz 产出 `TelemetrySample` (CPU%、内存 MB、墙钟 `ts_ms`)。 |
| 07 | `07_subscribe.py` | 启动 UDS 服务, `subscribe(["telemetry"])`, 打印服务端推送帧, `unsubscribe()`, 停服务。 |

运行单个:

```bash
python examples/01_run_echo.py
python examples/07_subscribe.py
```

## 非 Python 示例

| 文件 | 演示内容 |
|------|----------|
| `regcheck.rs` | 诊断切片正则覆盖 —— 运行 `cargo test -p fe-diagnostics` 查看 Python/Node/Rust/Go/Swift/TS/Bun traceback 被切片为 `{error_type, file_path, line_number, code_snippet}`。 |
| `uds_client_typescript.ts` | 完整的 TypeScript UDS JSON-RPC 2.0 客户端 (fusion-code 将使用的形态): `health` / `execute` / `executeStream` (实时 stdio) / `fileEdit` / `snapshotCreate` / `rollback` / `subscribe` (双向服务端推送)。 |

运行 TypeScript 客户端 (需 socket 上有服务):

```bash
# 终端 1 —— 启动服务
python -c "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()"

# 终端 2 —— 运行客户端
bun examples/uds_client_typescript.ts            # health + execute
bun examples/uds_client_typescript.ts subscribe  # + 遥测推送帧
```

## 注意

- 示例自行清理临时数据, 运行后无残留文件。
- `07_subscribe.py` 与 `uds_client_typescript.ts` 在 `/tmp/fusion-executor.sock` 上启停/连接服务 (可用 `FUSION_EXECUTOR_SOCK` 覆盖)。
- GUI 动作 (点击/输入/截图) **不**在示例中 —— 需 TCC 辅助功能 + 屏幕录制权限及真实 GUI 会话。手动清单见根 `README.md`。
- 所有示例含日志 (`logging.basicConfig`), 符合项目约定。
