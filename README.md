# fusion-executor

受控执行沙箱 + macOS OS 级控制中枢。安全地运行 shell 命令 (Security Guard + PTY Sandbox)、驱动原生 GUI (Computer Use via Accessibility API)、失败回滚 (Git 快照)。替代 Claude SDK BashTool/FileEdit + Docker 沙箱, 但原生 — 无 Docker, macOS 进程隔离 + Git 快照, 初始化 <5ms。

Rust 核心 + PyO3/maturin Python 绑定。Fusion monorepo 第一个 maturin/PyO3 工程 (其余 23 个 Python 工程用 setuptools)。

**状态: v1.2 完成 (P1-P5 + KeyPress + 流式 + 修饰键 + 截图尺寸)** — 安全 + 沙箱 + 诊断切片 + Git 回滚 + UDS JSON-RPC IPC 服务 + macOS GUI (AXUIElement + CoreGraphics + CGEvent 按键合成 + 修饰键组合) + 实时 stdio 流式传输 (NDJSON chunk/done) + 截图 width/height metadata + 加固 (criterion 基准 + 覆盖率 95%)。81 Rust + 40 Python 测试全绿。

## 架构

8-crate Cargo workspace (resolver 2), 一个 PyO3 绑定 crate 由 maturin 构建。

```
fusion-executor/
├── Cargo.toml              # workspace 根 (镜像 fusion-design)
├── pyproject.toml          # maturin 构建后端, fusion_executor Python 包
├── crates/
│   ├── fe-core/            # 编排器: Executor pipeline, BLOCKING_RT
│   ├── fe-security/        # Security Guard: 正则黑名单 + 分词器 + 白名单
│   ├── fe-sandbox/         # PTY 子进程, 超时, 截断, OOM 上限
│   ├── fe-gui/             # macOS Computer Use: AXUIElement + CoreGraphics (P4)
│   ├── fe-rollback/        # git 快照/回滚 (P2)
│   ├── fe-diagnostics/     # Traceback 正则 + tree-sitter 切片 (P2)
│   ├── fe-ipc/             # UDS JSON-RPC 2.0 服务 (P3)
│   └── fe-pyo3/            # PyO3 绑定; maturin target → fusion_executor._native
├── python/
│   └── fusion_executor/    # Pydantic v2 模型 + FusionSandboxExecutor 薄封装
└── python/tests/           # pytest
```

核心 pipeline (fe-core): `validate(command)` → 若拦截返回 `exit_code=-1` → 否则 `sandbox.run()` → 返回 `ExecutionResult`。

### 关键约束

- `[workspace.lints.rust] unsafe_code = "deny"` — 7 crate 禁用 unsafe; fe-gui crate 级 `#![allow(unsafe_code)]` (3 处审计 FFI: AXIsProcessTrusted + AXValueGetValue ×2, rustc 1.96 `unsafe_extern_blocks` 强制)。
- `extension-module` 不在 workspace 默认 features (否则 `cargo test` 无法链接 libpython); maturin 通过 `pyproject features=["pyo3/extension-module"]` 注入。
- PTY 合并 stdout+stderr → 全入 stdout (stderr 空); traceback 在尾部可读。
- 退出码: 0=成功, -124=超时, -1=拦截/内部异常。

## 构建

```bash
cd /Users/dahai/fusion && source .venv/bin/activate   # 共享 venv (Python 3.14)
pip install maturin                                     # 首次
cd fusion-executor
maturin develop --release          # 编辑安装进共享 venv → fusion_executor._native
```

## 测试

```bash
cd /Users/dahai/fusion && source .venv/bin/activate && cd fusion-executor

# Rust (workspace — extension-module 默认关, cargo test 可链接 libpython)
cargo test --workspace
cargo test -p fe-sandbox                # 单 crate
cargo test -p fe-security

# Python
pytest python/tests
pytest python/tests/test_executor.py::test_run_echo -v   # 单测试

# 冒烟
python -c "from fusion_executor import FusionSandboxExecutor; print(repr(FusionSandboxExecutor().run('echo hi').stdout))"
```

## Lint

```bash
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
ruff check .          # Python
ruff format .         # Python
```

## CLI 用法

```bash
fusion-executor "echo hi" --cwd /tmp --timeout 10
fusion-executor "echo hi" -v          # 详细 JSON 输出
```

## Python API

```python
from fusion_executor import FusionSandboxExecutor, ExecutionResult

ex = FusionSandboxExecutor()

# 同步执行 (脚本最简)
r: ExecutionResult = ex.run("echo hi")
assert r.exit_code == 0  # 0=成功, -124=超时, -1=拦截/内部异常
assert r.stdout == "hi\n"
assert not r.blocked_by_security

# 安全拦截
r = ex.run("rm -rf /")
assert r.blocked_by_security and r.exit_code == -1

# 超时
r = ex.run("python3 -c 'while True: pass'", timeout=1.0)
assert r.timed_out and r.exit_code == -124

# 诊断切片 — 失败命令返回结构化 Diagnostics (exit_code != 0 时)
r = ex.run("python3 -c \"raise ValueError('boom')\"")
assert r.diagnostics.error_type == "ValueError"
assert r.diagnostics.raw_trace is not None

# Git 快照 + 回滚 (caller-driven; executor 无状态)
snap = ex.snapshot_create(cwd="/path/to/repo")  # git stash create → SHA
ex.rollback(snap, cwd="/path/to/repo")  # git checkout -- . && git stash apply <id>

# 异步 (asyncio 调用者)
r = await ex.run_async("echo hi", task_id="t1", cwd="/tmp", timeout=30.0)
```

`run` 签名: `run(command, *, task_id=None, cwd=None, timeout=30.0, env_vars=None, enable_rollback_snapshot=True) -> ExecutionResult`。

`ExecutionResult` 字段: `exit_code, stdout, stderr, timed_out, blocked_by_security, security_reason, snapshot_id, diagnostics`。

### 实时 stdio 流式传输 (v1.2)

`run_streaming` 生成器逐帧 yield — chunk 字符串先出, done 帧末尾出 `ExecutionResult`。底层经 4 层 (fe-sandbox `run_streaming` → fe-core `execute_streaming` → fe-pyo3 `NativeStreamIterator` → Python 生成器)。

```python
from fusion_executor import FusionSandboxExecutor, ExecutionResult

ex = FusionSandboxExecutor()
for frame in ex.run_streaming("echo hi", enable_rollback_snapshot=False):
    if isinstance(frame, ExecutionResult):
        print(f"done exit={frame.exit_code}")
    else:
        print(f"chunk: {frame!r}", end="")
```

帧格式 (`ExecutionStreamEvent`, serde tag="type"):
- chunk: `{"type":"chunk","data":"..."}` (逐行 stdout)
- done: `{"type":"done", exit_code:..., stdout:..., diagnostics:...}` (ExecutionResult 字段扁平化进同对象, 非嵌套)

拦截 (安全违规) → 仅单帧 done, 无 chunk。超时 → done 帧 `timed_out=True, exit_code=-124`。失败命令 → done 帧含 `diagnostics`。

## IPC 服务 (UDS JSON-RPC)

启动 UDS JSON-RPC 2.0 服务器 — 供 fusion-code (TypeScript) / fusion-studio (Swift) 经 Unix Domain Socket 调用:

```bash
python -c "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()"
# Socket: /tmp/fusion-executor.sock (override FUSION_EXECUTOR_SOCK)
```

协议: 换行分隔 JSON-RPC 2.0, 错误码 -32700/-32600/-32601/-32603 + 扩展 -32010(安全)/-32011(超时)/-32012(回滚)/-32013(AX)。方法 `executor.health`/`execute`/`execute_stream`/`snapshot_create`/`rollback`/`diagnostics`/`gui_action`/`shutdown`。

`executor.execute_stream` 流式: 多帧 (chunk/done) 共用同一 id, 换行分隔逐帧写出 —
- chunk: `{"jsonrpc":"2.0","id":id,"result":{"type":"chunk","data":"..."}}`
- done: `{"jsonrpc":"2.0","id":id,"result":{"type":"done","result":{...ExecutionResult}}}` (UDS 路径 done 嵌套在 `result.result`, 与 PyO3 路径扁平不同 — 两条路径分离, 各自消费者读对应形状)

fusion-code TS 客户端 sketch 见 `docs/ipc-client-typescript.md`; fusion-studio 用现有 `IPCClient.swift udsCall` 指向同一 socket。

## 状态

- **P1 — 骨架 + 安全 + 沙箱** ✅ 完成
  - fe-security: 正则黑名单 + 分词器链式绕过防御 + 白名单 (38 单元测试)
  - fe-sandbox: PTY 执行 + 超时 kill + 截断 + OOM 环形缓冲 (9 单元测试)
  - fe-core: validate → sandbox → return pipeline
  - fe-pyo3: `execute_sync` 绑定; `maturin develop` 可用; `FusionSandboxExecutor.run("echo hi")` 工作
  - 退出闸门: 真实执行 echo/python; 拦截 `rm -rf /`/sudo 链/ncat; 1s 超时杀无限循环 (exit -124)
- **P2 — 诊断 + 回滚** ✅ 完成
  - fe-diagnostics: 4 语言 (Python/Node/Rust/Swift) traceback 正则提取 + 上下 20 行代码切片, 报错行标 `>` (7 单元测试)
  - fe-rollback: git CLI 快照/回滚 — `snapshot_create` (stash create/HEAD) + `rollback` (checkout + stash apply) + `rollback_file` 单文件 (3 单元测试)
  - fe-core: pipeline 加快照 (exec 前, 非致命) + 诊断切片 (exit_code!=0 时) + `snapshot_create_async`/`rollback_async` 公开
  - fe-pyo3: `NativeDiagnostics` + `diagnostics` 字段 + `snapshot_create`/`rollback` 方法; env_vars/enable_rollback_snapshot 透传
  - 退出闸门: `run("python3 -c 'raise ValueError'")` → `diagnostics.error_type == "ValueError"`; rollback 往返恢复被破坏文件
- **P3 — IPC 服务** ✅ 完成
  - fe-ipc: UDS JSON-RPC 2.0 server — `tokio::net::UnixListener` + 换行分隔 + per-connection spawn; socket `/tmp/fusion-executor.sock` (override `FUSION_EXECUTOR_SOCK`), unlink 旧 sock + chmod 0o666
  - 方法: `executor.health`/`execute`/`snapshot_create`/`rollback`/`diagnostics`/`gui_action`(P4 stub)/`shutdown`; 错误码 -32700/-32600/-32601/-32603 + 扩展 -32010..-32013
  - fe-pyo3: `NativeExecutor.serve(sock_path=None)` 绑定; `FusionSandboxExecutor.serve()` wrapper 永驻
  - 4 Rust 单元测试 (health/unknown -32601/malformed -32700/UDS execute) + 5 Python IPC 测试 (health/execute/diagnostics/unknown/snapshot+rollback 往返)
  - 退出闸门: 外部 raw-socket client 经 UDS 调 `executor.execute` echo → `exit_code=0 stdout="hi\n"`; fusion-code-style TS client sketch 见 `docs/ipc-client-typescript.md`; fusion-studio 用现有 `IPCClient.swift udsCall` 指向 `/tmp/fusion-executor.sock`
- **P4 — macOS GUI** ✅ 完成
  - fe-gui: `accessibility` 0.2 安全封装 (AXUIElement 树/聚焦/点击/键入/inspect) + 3 处审计 unsafe FFI (AXIsProcessTrusted + AXValueGetValue ×2); CoreGraphics `CGDisplay::screenshot` → PNG base64 (Layer B 视觉兜底)
  - GuiAction (tag=kind, snake_case): `focus_app`/`click`/`type_text`/`key_press`/`screenshot`/`inspect_tree`; GuiResult{ok, node_tree, screenshot_png_b64, error}
  - fe-core: `gui: GuiController` 字段 + `gui_action()` 方法; fe-ipc `executor.gui_action` 活 (非 stub); fe-pyo3 `NativeGuiResult` + `gui_action(action)` (json.dumps → serde 反序列化)
  - Python: `GuiResult` Pydantic + `FusionSandboxExecutor.gui_action(action: dict) -> GuiResult`
  - 6 Rust 单元测试 + 6 Python 测试 (model 往返/key_press 降级/坏 kind 降级/screenshot TCC-skip/UDS 往返/坏 kind UDS -32600)
  - 退出闸门: trusted 机 `gui_action({"kind":"screenshot"})` → 3.2MB PNG; `gui_action({"kind":"key_press","key":"Tab"})` → ok=False unsupported (v1, v1.1 修复)。GUI 测试 TCC 手动 (AX Accessibility + Screen Recording)
- **P5 — 加固** ✅ 完成
  - criterion 基准: `Executor::new` = 735µs (<5ms NFR ✓); `truncate_output` ~1.75GB/s (100K=3.9µs / 1M=412µs / 10M=5.7ms); `validate` 10k 复合命令 = 317ns (正则快路径拦截 rm -rf)
  - `truncate_output` 改 pub 供 bench; `ClickCandidate` type alias 消 clippy `type_complexity`; fe-gui `as u32` 冗余转换移除
  - Python 覆盖率 95% (>80% NFR ✓): cli.py 96% (in-process `main()` 测试) / executor.py 90% / models.py 100% / __init__.py 100%; 32 Python 测试 (+6 CLI +1 async +1 rollback-no-cwd)
  - clippy `--all-targets -D warnings` 净 (仅上游 block v0.1.6 future-incompat 通知, 非 fe 代码); `cargo fmt --check` + `ruff check/format` 净; `maturin develop --release` 构建
  - 退出闸门: 67 Rust + 32 Python 测试全绿; NFR 全达标
- **v1 完成** ✅
- **v1.1 — KeyPress 支持** ✅ 完成
  - fe-gui `key_press`: CGEvent 合成 keydown + keyup, post `CGEventTapLocation::HID`; `resolve_keycode` 键名 (大小写不敏感 + 别名: enter=return, esc=escape, up=up_arrow, cmd=command...) → `core_graphics::event::KeyCode` 常量 (40+ 键: Return/Tab/Space/Delete/Forward_delete/Escape/方向键/Home/End/PageUp-Down/Help/F1-F20/Command/Shift/Option/Control/Function/Caps_lock/Mute/Volume)
  - core-graphics 0.24 safe wrapper 封装了 unsafe FFI (CGEventSource::new / CGEvent::new_keyboard_event / post) — 本函数零手写 unsafe block, 复用 fe-gui crate 级 `#![allow(unsafe_code)]` scope
  - 未知键名 → `ok:false` + `unknown-key: ...` 错误含已知键名列表 (不 panic, trusted-independent)
  - +2 Rust 单元测试 (resolve_keycode 映射/未知键 None) + KeyPress 降级测试改写; +1 Python 测试 (keypress_when_trusted, TCC-skip)
  - 退出闸门: trusted 机 `gui_action({"kind":"key_press","key":"Tab"})` → ok=True (keydown+keyup posted); `{"key":"return"}` → ok=True; 未知键 → ok=False unknown-key。69 Rust + 33 Python 测试全绿
- **v1.2 — 流式 + 修饰键 + 截图尺寸** ✅ 完成
  - 实时 stdio 流式传输 (4 层): fe-sandbox `run_streaming` (mpsc `StreamEvent::Chunk{data}`/`Done(SandboxResult)`) → fe-core `execute_streaming` async (校验→快照→`run_streaming`→spawn 任务转发 chunk, Done 时跑诊断切片映射 ExecutionResult; `ExecutionStreamEvent` serde tag="type") → fe-ipc `executor.execute_stream` (多帧 NDJSON, id 复用, chunk `{type,data}`/done `{type,result:{ExecutionResult}}`) → fe-pyo3 `NativeStreamIterator` (`__iter__`/`__next__` via `py.detach` + BLOCKING_RT 收帧 + serde→json.loads) → Python `run_streaming` 生成器
  - 修饰键组合 (KeyPress): `key` 单键名 + `modifiers` 数组 (cmd/ctrl/alt/shift/fn); 顺序合成 — keydown modifiers→keydown key→keyup key→keyup modifiers (CGEvent flags); 单键仅, 无和弦
  - 截图尺寸 metadata: `GuiResult` 加 `screenshot_width`/`screenshot_height` (u32, PNG 像素); fe-gui 从 `CGImageRef` 宽高填充
  - +12 Rust 测试 (fe-core execute_streaming 4: echo/blocked/timeout/diagnostics; fe-ipc 2: stream chunks/done over UDS, blocked single frame) + 5 Python 测试 (streaming echo/blocked/timeout/diagnostics, UDS stream)
  - 退出闸门: 81 Rust + 40 Python 测试全绿; clippy/fmt/ruff 净; maturin 构建

