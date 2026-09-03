# fusion-executor

> **语言 / Language**: [English](README.md) | **中文**

受控执行沙箱 + macOS OS 级控制中枢。安全地运行 shell 命令 (Security Guard + PTY Sandbox)、驱动原生 GUI (Computer Use via Accessibility API)、失败回滚 (Git 快照)。替代 Claude SDK BashTool/FileEdit + Docker 沙箱, 但原生 — 无 Docker, macOS 进程隔离 + Git 快照, 初始化 <5ms。

Rust 核心 + PyO3/maturin Python 绑定。Fusion monorepo 第一个 maturin/PyO3 工程 (其余 23 个 Python 工程用 setuptools)。

**状态: v0.2.4 已发布** — 安全 + 沙箱 + 诊断切片 + Git 回滚 + UDS JSON-RPC IPC 服务 + macOS GUI (AXUIElement + CoreGraphics + CGEvent 按键合成 + 修饰键组合 + scroll/drag/wait + double_click/right_click/hover + 窗口控制 close/minimize/zoom/resize) + 实时 stdio 流式传输 (NDJSON chunk/done) + 截图 width/height metadata + 原生文件工具 (file_edit/glob/grep 本地化替代 Claude SDK FileEdit/Glob/Grep) + 外科补丁引擎 (Unified Diff apply + 函数级替换, 禁全文件重写) + Data Schema §4.1 补齐 (task_id/command/duration_sec) + 自动回滚 (FR-04 可选策略, git status 毁损检测触发) + 实时遥测 (10Hz CPU/内存 UDS 广播, GPU 调用方注入) + macOS seatbelt 运行时沙箱 (sandbox-exec, 禁网 + 13 危险二进制) + 跨节点回滚注册表 (FNV-1a repo 标识) + 双向 IPC server-push (BroadcastHub 三通道 telemetry/stdio/screenshot, 每订阅 scope 隔离) + Pydantic 严格 schema (extra=forbid)。诊断切片覆盖 8 语言 (Python/TS/Node/Bun/Rust/Go-panic/Swift/Go-compile)。18 GuiAction 变体, 审计 fe-gui scope 之外 0 手写 unsafe。glob/grep ripgrep parity (#7): 三种 grep 输出模式 (content/files_with_matches/count), -A/-B/-C 上下文行, multiline (-U), -g glob include/exclude, gitignore-aware glob walk。企业硬化 (v0.2.1~v0.2.3): ShellRegistry 移出无状态 Executor (M-ARCH-1) + 结构化 JSON 日志 + 按日滚动文件 + stderr tee + SIGHUP 热重载 (日志级别 + 白名单 extras) + Prometheus 指标 UDS 导出 (无 HTTP 端口) + 跨层 trace_id + 日志 span + glob E1 规范对齐 (#20, `*` 不跨 `/`, `**` 跨目录)。**v0.2.4 企业级可发布升级**: 产品就绪审计 (`audit/fusion-executor-audit-result-product-0827.md`, 6 真 CRITICAL + 33 MAJOR/MINOR + D3-1 内联解释器网关) 全部落地 (16 批次, 分支 `fix/enterprise-upgrade-0828`) — seatbelt 默认 True (4 层对齐) + resolved-path 白名单 (可信 bin 目录, 拒同名投毒) + 每任务 RSS watchdog (OOM kill, Darwin RLIMIT_AS no-op) + rlimit NOFILE/NPROC + ppid 树 kill (防 setsid 逃逸) + git 超时 + RepoLock 非 async + worktree gitdir + stream/exec 信号量分离 + prompt-injection sanitize + 默认 bundle 白名单 + 截图 Screen-Recording TCC 分离 + 子进程 pid 遥测 + 默认 socket `~/.fusion-executor/fe.sock` + Subscription 崩溃标记 + 内联解释器网关 (`python -c`/`node -e` 默认拦截, 受信调用方 opt-in) + D4 perf (LazyLock profile cache, 16KB 读取, 广播 fast-path, worker clamp) + fe-pyo3 首批 Rust 单元测试。**476 Rust + 195 Python 测试全绿; clippy `--all-targets -D warnings` 净; fmt/ruff 净; maturin 构建。** 四轮审计全部缺陷修复 — 缺陷审计 (T1~T9, 68 defects) + 商用集成审计 (11 Blockers + 13 MAJOR/MINOR, FAIL → PASS) + 企业审计 (10 CRITICAL + 15 MAJOR + 12 MINOR, 全部落地) + 对抗性硬化 (0827: 18 CRITICAL + 18 LOGIC-BUG + 12 ARCHITECTURE + 7 PERFORMANCE + 12 MAINTAINABILITY = 67 findings, P0-P3 全落地) + 产品就绪审计 (0827-product: 6 CRITICAL + 33 MAJOR/MINOR, 企业级可发布)。可运行示例见 `examples/`, 文档地图见 `docs/INDEX.md`。

## 架构

10-crate Cargo workspace (resolver 2), 一个 PyO3 绑定 crate 由 maturin 构建。

```
fusion-executor/
├── Cargo.toml              # workspace 根 (镜像 fusion-design)
├── pyproject.toml          # maturin 构建后端, fusion_executor Python 包
├── crates/
│   ├── fe-core/            # 编排器: Executor pipeline, BLOCKING_RT
│   ├── fe-security/        # Security Guard: 正则黑名单 + 分词器 + 白名单
│   ├── fe-sandbox/         # PTY 子进程, 超时, 截断, OOM 上限
│   ├── fe-gui/             # macOS Computer Use: AXUIElement + CoreGraphics (P4)
│   ├── fe-rollback/        # git 快照/回滚 (P2) + 自动回滚 guard (v1.4)
│   ├── fe-diagnostics/     # Traceback 正则 + tree-sitter 切片 (P2)
│   ├── fe-ipc/             # UDS JSON-RPC 2.0 服务 (P3) + 双向 server-push BroadcastHub (v1.5 #14)
│   ├── fe-tools/           # 原生文件工具: file_edit/glob/grep + 补丁引擎 (v1.3)
│   ├── fe-telemetry/       # 实时遥测: 10Hz CPU/内存采样流 (v1.4)
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

# 启动 UDS server + 订阅广播 (v1.5 #14)
python -c "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()"   # 另一终端
# 另一终端: 订阅 telemetry 推送
python -c "from fusion_executor import FusionSandboxExecutor; s=FusionSandboxExecutor().subscribe(['telemetry'], interval_ms=100); [print(next(s)) for _ in range(3)]; s.unsubscribe()"
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

# 双向 server-push 订阅 (v1.5 #14 — 需运行中的 serve())
# 三通道: telemetry (10Hz CPU/内存) / stdio (跨连接命令流) / screenshot (周期截图)
sub = ex.subscribe(["telemetry", "stdio"], interval_ms=100, screenshot_interval_ms=1000)
for params in sub:  # __next__ yield executor.event 帧的 params (dict)
    print(params["channel"], params["data"])
sub.unsubscribe()  # 或 sub.close()
```

`run` 签名: `run(command, *, task_id=None, cwd=None, timeout=30.0, env_vars=None, enable_rollback_snapshot=True) -> ExecutionResult`。

`ExecutionResult` 字段: `exit_code, stdout, stderr, task_id, command, duration_sec, timed_out, blocked_by_security, security_reason, snapshot_id, diagnostics`。

### 原生文件工具 + 外科补丁引擎 (v1.3)

替代 Claude SDK FileEdit/Glob/Grep — 原生 Rust 实现, 经 fe-security 路径守卫 (拒绝逃逸 cwd / 越敏感目录), 原子写 (`.fe-tmp-{pid}` + rename)。

```python
from fusion_executor import FusionSandboxExecutor, EditResult, GlobEntry, GrepMatch

ex = FusionSandboxExecutor()

# file_edit — 唯一匹配精确替换 (>1 匹配拒绝, 避免误改)
r: EditResult = ex.file_edit("app.py", "x = 1", "x = 99", cwd="/repo")
assert r.ok and r.matches == 1

# glob — 通配符匹配, 返回相对 cwd 路径
entries: list[GlobEntry] = ex.glob("**/*.py", cwd="/repo")

# grep — 正则搜文件/目录 (递归, 跳二进制, 1000 命中上限)
hits: list[GrepMatch] = ex.grep(r"^import\s", ["app.py"], cwd="/repo")

# apply_patch — Unified Diff 应用 (diffy); 禁全文件重写 (new_range 全删 → 拒绝)
r = ex.apply_patch("--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,2 @@\n-x\n+x\n+y\n", cwd="/repo")

# replace_function — 函数级替换 (tree-sitter AST 定位, py/js/ts/rs); 无语法 → 正则兜底
r = ex.replace_function("mod.py", "old_fn", "def old_fn():\n    return 99\n", cwd="/repo")
```

`EditResult{ok, path, error, matches}`; `GlobEntry{path, is_dir}`; `GrepMatch{path, line_number, content}`。replace_function 找不到函数 → `ok=False, error="未找到函数 ..."`。

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

### 服务端确定性取消 (v0.2.7 — Issue #32)

从服务端用**确定性**进程树 kill 取消正在运行的 `execute_stream` — 非协作式 "请停止" 请求。为调用方 (如 fusion-code) 中止失控长跑命令不留孤儿进程而设计。

`cancel_stream(stream_id)` 打开新的 UDS 连接发送 `executor.cancel {id}`, 其中 `stream_id` = `execute_stream` 调用的 JSON-RPC 请求 id。服务端解析运行中的流, 触发 fe-sandbox `run_streaming` 的 `tokio::select!` 正在等待的 oneshot, 然后执行 `kill_process_group_async` (SIGINT → 500ms 宽限 → SIGKILL 整个进程组, 再加 ppid 树后代遍历兜底 `setsid` 孤儿)。原流连接收到终止 Done 帧: `exit_code: -1` + `cancelled: true`。

- 取消**跨连接**: 第二条连接可取消另一条连接启动的流 (`StreamRegistry` 全服务端共享)。调用方保持 execute_stream 连接打开以读取终止 Done 帧。
- 未知 `stream_id` → 返 `False` (best-effort, 不抛异常)。
- 进程内 `run_streaming()` 路径 (无 `serve()` 运行) 不可取消 — 取消仅适用于经 UDS 服务端流。
- `ExecutionResult.cancelled: bool` 非取消路径恒 `False`; 仅真正触发取消时 `True`。

### 每命令沙箱 profile (v0.2.8 — Issue #34)

为分离的 executor 子进程启用 seatbelt/沙箱 — fusion-code G2 沙箱独立。每个 `ExecutionRequest` 携带可选 `sandbox: SandboxProfile`, 为该单条命令调优 macOS `sandbox-exec` profile。默认关 / opt-in: `None` profile 字节保留现有固定 profile (默认禁网 + 定向敏感路径 file-write deny), 现有部署行为完全一致。

```python
from fusion_executor import FusionSandboxExecutor, SandboxProfile

ex = FusionSandboxExecutor(allow_inline_interpreter=True)

# 默认 (None) — 行为同 v0.2.7
r = ex.run("echo hi")
assert r.exit_code == 0

# 每命令: 放行网络, 经 seatbelt deny process-exec 拦指定二进制
r = ex.run(
    "curl https://example.com",
    sandbox=SandboxProfile(network="allow", excluded_commands=["rm", "curl"]),
)

# fail-closed: sandbox-exec 不可用 且 fail_if_unavailable=True 时, 拦截命令 (exit_code -1) 不 spawn
r = ex.run("risky --flag", sandbox=SandboxProfile(fail_if_unavailable=True))
```

`SandboxProfile` 字段 (匹配 fusion-code `SandboxSettings`):

- `network: str | None` — `"allow"` 不注 network deny; `"deny"` (或 None) 保留 `deny network-outbound`。None 不覆盖默认。
- `filesystem: str | None` — `"allow"` 不注 FS deny; `"deny_write"` (默认) 保留定向敏感路径 file-write deny; `"deny"` 加全局 `file-write*` deny。
- `excluded_commands: list[str]` — 注入 `(deny process-exec (literal "<名>"))` 到 seatbelt profile。字符串经净化 (剥 `"`、`\`、控制符) 防 profile 语法注入。
- `fail_if_unavailable: bool` — `True` = sandbox-exec 不在 PATH 时 fail-closed (exit_code -1, 不 spawn); `False` (默认) = 静默降级到无 seatbelt 执行。

profile 是 additive RPC 字段 (`sandbox: { network?, filesystem?, excluded_commands? }`), 经 4 层自动流通 (fe-core `ExecutionRequest.sandbox` → fe-ipc `serde_json::from_value(params)` → fe-pyo3 PyAny→serde → Python Pydantic `_STRICT`)。现有 `executor.execute` / `execute_stream` UDS 方法接受它, 无方法级 wiring 改动。

### 自动回滚 (v1.4 — FR-04 可选策略)

`run()` / `run_streaming()` 接受可选 `auto_rollback: RollbackPolicy`。启用后, 命令失败 (`exit_code != 0`) 且检测到工作区文件改动 (`git status --porcelain` 非空) 时, 自动 `rollback(本次快照)`, 标记 `result.auto_rolled_back=True`。Executor 仍无状态 — guard 生命周期限单次执行, 不跨请求累积失败计数 (连续失败计数归 caller 自愈循环)。

```python
from fusion_executor import FusionSandboxExecutor, RollbackPolicy

ex = FusionSandboxExecutor()
policy = RollbackPolicy(max_consecutive_failures=3, file_damage_check=True)
# 命令写坏 app.py 后失败 → 自动回滚恢复 git 基线
r = ex.run(
    "python3 -c \"open('app.py','w').write('broken'); raise ValueError(1)\"",
    cwd="/repo",
    auto_rollback=policy,
)
assert r.exit_code != 0 and r.auto_rolled_back
```

`RollbackPolicy{max_consecutive_failures=3 (保留字段), file_damage_check=True}`。无快照 (`enable_rollback_snapshot=False`) → guard 跳过。非 git repo → 毁损检测失败视为 0 改动, 不回滚。

### 实时遥测 (v1.4 — GPU/CPU UDS 广播)

`telemetry_stream()` 生成器逐帧 yield `TelemetrySample` — 10Hz (可调 `interval_ms`) 进程 CPU/内存采样。GPU 字段默认 None (executor 不跑模型, 无 GPU 句柄), 由调用方注入。`max_samples>0` 达此值自动结束; 丢弃迭代器则采样任务自动停止 (通道关闭)。Executor 无状态: 每次调用独立流。

```python
from fusion_executor import FusionSandboxExecutor, TelemetrySample

ex = FusionSandboxExecutor()
for s in ex.telemetry_stream(interval_ms=100, max_samples=50):
    print(f"t={s.ts_ms}ms cpu={s.cpu_pct:.1f}% mem={s.mem_mb:.1f}MB")
    # s.gpu_pct / s.gpu_mem_mb 默认 None (serde skip, 调用方注入)
```

`TelemetrySample{ts_ms (毫秒, 调用方纪元), cpu_pct (单核倍数), mem_mb (常驻内存 MB), gpu_pct?, gpu_mem_mb?, task_id?}`。底层 fe-telemetry `start_stream(cfg, rt::Handle)` 在 `BLOCKING_RT` 上 spawn sysinfo 采样任务; 4 层 wiring (fe-telemetry → fe-core → fe-ipc `executor.telemetry_stream` 多帧 → fe-pyo3 `NativeTelemetryIterator` → Python 生成器)。

### 双向 server-push 订阅 (v1.5 #14 — fusion-studio §5 120Hz 看板广播)

`subscribe()` 开一条 UDS 连接订阅广播通道 — 一次订阅, server 持续推送 notification 帧, 客户端可在此连接上并发发别的请求 (duplex)。区别于 `telemetry_stream`/`execute_stream` (请求发起, 单流即停): 订阅是 **server 主动推**, 多连接共享同一源 (扇出)。

```python
from fusion_executor import FusionSandboxExecutor

ex = FusionSandboxExecutor()
# 三通道: telemetry (10Hz CPU/内存) / stdio (跨连接命令 chunk+done) / screenshot (周期截图)
sub = ex.subscribe(["telemetry", "stdio"], interval_ms=100, screenshot_interval_ms=1000)
print(sub.subscription_id)  # "sub-N"
for params in sub:
    print(params["channel"], params["data"])
    if ...:
        break
sub.unsubscribe()  # 或 sub.close()
```

三通道源 (fe-ipc `BroadcastHub` 内 lazy 启停, 0 订阅自退):
- **telemetry** — 单一 `executor.telemetry_stream` 扇出给所有 telemetry 订阅 (10Hz 默认, `interval_ms` 可调)。
- **stdio** — `execute`/`execute_stream` 处理器扇出 chunk/done 给所有 stdio 订阅 (**跨连接**: A 订阅, B 跑命令, A 收推送)。
- **screenshot** — 周期 `gui_action(Screenshot)` 采样扇出 (`screenshot_interval_ms` 默认 1000, 慢于 telemetry); TCC 未授权 → 帧 `data.ok=false`/error, 不崩 (走 fe-gui safe wrapper)。

推帧格式 (server 主动, **无 id** — JSON-RPC notification 约定; 客户端按有无 `id` 区分响应 vs 推送):
- `{"jsonrpc":"2.0","method":"executor.event","params":{"subscription_id":"sub-1","channel":"telemetry","data":{...}}}`

`Subscription` 纯 Python UDS 客户端 — 连接运行中的 `serve()` socket; `__next__` 过滤 `executor.event` 帧匹配本 sub_id, 跳过非 event 帧; `unsubscribe()` 发 unsubscribe + 关 socket。`SUB_CHANNELS = ("telemetry", "stdio", "screenshot")` — 未知通道 `ValueError`。fe-ipc 0 新增 unsafe (截图复用 fe-gui safe wrapper); fe-core Executor 保持无状态 (广播扇出是 IPC broker 关注点, 非 executor 状态)。

## IPC 服务 (UDS JSON-RPC)

启动 UDS JSON-RPC 2.0 服务器 — 供 fusion-code (TypeScript) / fusion-studio (Swift) 经 Unix Domain Socket 调用:

```bash
python -c "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()"
# Socket: /tmp/fusion-executor.sock (override FUSION_EXECUTOR_SOCK)
```

协议: 换行分隔 JSON-RPC 2.0, 错误码 -32700/-32600/-32601/-32603 + 扩展 -32010(安全)/-32011(超时)/-32012(回滚)/-32013(AX)。方法 `executor.health`/`execute`/`execute_stream`/`snapshot_create`/`rollback`/`diagnostics`/`gui_action`/`file_edit`/`glob`/`grep`/`apply_patch`/`replace_function`/`telemetry_stream`/`subscribe`/`unsubscribe`/`shutdown`。

`executor.execute_stream` 流式: 多帧 (chunk/done) 共用同一 id, 换行分隔逐帧写出 —
- chunk: `{"jsonrpc":"2.0","id":id,"result":{"type":"chunk","data":"..."}}`
- done: `{"jsonrpc":"2.0","id":id,"result":{"type":"done","result":{...ExecutionResult}}}` (UDS 路径 done 嵌套在 `result.result`, 与 PyO3 路径扁平不同 — 两条路径分离, 各自消费者读对应形状)

`executor.telemetry_stream` 流式: 多帧 sample 共用同一 id, 换行分隔逐帧写出 —
- sample: `{"jsonrpc":"2.0","id":id,"result":{"type":"sample","sample":{...TelemetrySample}}}` (params `interval_ms`(默认 100)/`max_samples`(默认 0=无限); GPU 字段 None 时 serde skip 省略)

`executor.subscribe` / `executor.unsubscribe` (v1.5 #14 双向 server-push) — 见上「双向 server-push 订阅」小节。subscribe 响应 `{ok:true, subscription_id:"sub-N"}`, 之后 server 持续推 notification 帧 (无 id, `method:"executor.event"`); 连接 duplex, 可并发发别的请求。params `channels`(`["telemetry","stdio","screenshot"]`)/`interval_ms`(默认 100)/`screenshot_interval_ms`(默认 1000)。

fusion-code TS 客户端 sketch 见 `docs/ipc-client-typescript.md`; fusion-studio 用现有 `IPCClient.swift udsCall` 指向同一 socket。

## 状态

- **P1 — 骨架 + 安全 + 沙箱** ✅ 完成
  - fe-security: 正则黑名单 + 分词器链式绕过防御 + 白名单 (38 单元测试)
  - fe-sandbox: PTY 执行 + 超时 kill + 截断 + OOM 环形缓冲 (9 单元测试)
  - fe-core: validate → sandbox → return pipeline
  - fe-pyo3: `execute_sync` 绑定; `maturin develop` 可用; `FusionSandboxExecutor.run("echo hi")` 工作
  - 退出闸门: 真实执行 echo/python; 拦截 `rm -rf /`/sudo 链/ncat; 1s 超时杀无限循环 (exit -124)
- **P2 — 诊断 + 回滚** ✅ 完成
  - fe-diagnostics: 8 语言 (Python/TS/Node/Bun/Rust/Go/Swift/Go-compile) traceback 正则提取 + 上下 20 行代码切片, 报错行标 `>` (12 单元测试)
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
- **v1.3 — Data Schema 补齐 + 原生文件工具 + 外科补丁引擎** ✅ 完成
  - Data Schema §4.1 补齐 (Gap #1): `ExecutionResult` 加 `task_id`/`command`/`duration_sec` 字段, 4 层贯穿 (fe-core serde struct → fe-pyo3 `NativeExecutionResult` → Python `ExecutionResult` Pydantic → fe-ipc done 帧回填)。`blocked_with` 带回 task_id/command; 拦截结果 `duration_sec=0.0`
  - fe-tools 新 crate (Gap #2): `file_edit` (唯一匹配精确替换, >1 拒绝, 原子写) / `glob` (通配符, 相对 cwd 路径, 规范化 base 修相对路径 bug) / `grep` (正则, 递归 walkdir, 跳二进制, 1000 上限)。依赖 fe-security `validate_cwd` 路径守卫 (拒逃逸 cwd / 越敏感目录)
  - 外科补丁引擎 (Gap #3, fe-tools): `apply_patch` (diffy Unified Diff apply; 全文件重写启发式 `new_range.start==0 && end==0` → 拒绝; target 从 `patch.modified()`/`original()` 取 `a/`/`b/` 前缀) + `replace_function` (tree-sitter AST 定位函数节点 — 栈式前序遍历修 tree-sitter 0.25 `Node::children(&mut cursor)` 借用问题, 无 `descendants()`; py/js/ts/tsx/rs 语法, 无则正则兜底; 字节切片替换 `[..span.start]+new_body+[span.end..]`)
  - 4 层接线: fe-core `tools: Tools` 字段 + 5 wrapper 方法 (`file_edit`/`glob`/`grep`/`apply_patch`/`replace_function`); fe-ipc `executor.file_edit`/`glob`/`grep`/`apply_patch`/`replace_function` 5 arm; fe-pyo3 `NativeEditResult`/`NativeGlobEntry`/`NativeGrepMatch` pyclass + 5 `#[pymethods]`; Python `EditResult`/`GlobEntry`/`GrepMatch` Pydantic + `FusionSandboxExecutor` 5 方法
  - clippy 修 `ExecutionStreamEvent::Done(ExecutionResult)` → `Done(Box<ExecutionResult>)` (large_enum_variant, Done 264B vs Chunk 24B; serde 对 Box 透明, 序列化不变)
  - +13 fe-tools Rust 单元测试 (file_edit 唯一/无匹配/歧义/未找到, glob, grep 命中/递归, apply_patch 简单/未找到, replace_function python/未找到/rust, guard_path 逃逸) + 12 Python 测试 (file_edit 唯一/歧义, glob, grep, apply_patch, replace_function python/未找到, file_edit/glob UDS 往返 subprocess 模式)
  - 退出闸门: 94 Rust + 52 Python 测试全绿; clippy `--all-targets -D warnings` 净 (仅上游 block v0.1.6 future-incompat); fmt/ruff 净; maturin 构建
- **v1.4 — 自动回滚 + 实时遥测 + GUI scroll/drag/wait** ✅ 完成
  - 自动回滚 (FR-04 可选策略, fe-core `AutoRollbackGuard` + fe-rollback): `RollbackPolicy{max_consecutive_failures (保留字段), file_damage_check}`; 命令失败 + `git status --porcelain` 非空 → `rollback(本次快照)` + `result.auto_rolled_back=True`; guard 限单次执行 (Executor 无状态, 连续失败计数归 caller); 4 层 wiring (fe-core `execute_async`/`execute_streaming` 构造 guard → fe-pyo3 `auto_rollback_policy` dict→serde → Python `RollbackPolicy` Pydantic + `run()`/`run_streaming()` kwargs); fe-rollback HEAD 基线 bug 修 (stash SHA != HEAD 时 stash apply, 相等则 skip)
  - 实时遥测 (fe-telemetry 新 crate): `TelemetrySample{ts_ms,cpu_pct,mem_mb,gpu_pct?,gpu_mem_mb?,task_id?}` + `TelemetryConfig{interval_ms=100(10Hz),max_samples=0(无限)}`; `start_stream(cfg, rt::Handle)` 在 `BLOCKING_RT` 上 spawn sysinfo 采样任务 (`refresh_processes_specifics(pid, mem+cpu)`, 首帧 sleep 后采); 通道关闭/max_samples 达则停; GPU 默认 None (调用方注入), serde `skip_serializing_if`; 4 层 wiring (fe-core `telemetry_stream(cfg)` → fe-ipc `executor.telemetry_stream` 多帧 sample → fe-pyo3 `NativeTelemetryIterator` `__next__` block_on(rx.recv) → Python `telemetry_stream()` 生成器 yield `TelemetrySample`); never-type fallback 修 (显式 `TelemetrySample` 类型标注)
  - GUI scroll/drag/wait (fe-gui CGEvent 合成): `scroll` (dx/dy 像素, CGEvent scrollWheel 单位轴) / `drag` (from x,y → to x,y, mouseMove+leftMouseDown+move+leftMouseUp) / `wait` (seconds 睡眠, 测试辅助); +14 Rust 单元测试 + 14 Python GUI 测试
  - +3 fe-telemetry Rust 单元测试 (stream 产样/通道关闭停止/序列化) +1 fe-core +1 fe-ipc (UDS telemetry 3 帧) +5 Python auto-rollback 测试 +3 Python telemetry 测试 (native iter/wrapper/UDS)
  - 退出闸门: 105 Rust + 60 Python 测试全绿; clippy `--all-targets -D warnings` 净 (仅上游 block v0.1.6 future-incompat); fmt/ruff 净; maturin 构建
- **v1.5 完成**
  - **#12 — 诊断切片扩语言 (TS/Go)** ✅ 完成
    - fe-diagnostics `Slicer` 正则 4→9 覆盖 8 语言: 新增 `ts_re` (tsc 括号 `file.ts(l,c): error TSxxxx:`) / `ts_dash_re` (tsc watch `file.ts:l:c - error TSxxxx:`) / `bun_re` (Bun 小写 `error:` + 裸 `at`) / `go_panic_re` (`(?s)` 跨行 `panic: ... goroutine ... \tfile.go:line`, 取末栈帧) / `go_compile_re` (`file.go:l:c: msg` 无 `error:` 关键字)。新增 `extract_ts`/`extract_bun`/`extract_go_panic`/`extract_go_compile` 方法; `slice()` 排序 ts→python→node→bun→rust→go_panic→swift→go_compile (按扩展名/关键字互不冲突)。零新依赖 (纯文本行切片)
    - fe-security 白名单 +`go` +`tsc` (否则真实 `go build`/`tsc --noEmit` 被 Stage-2 拦截无 E2E)
    - +5 fe-diagnostics 单元测试 +1 白名单测试。真实工具链 E2E: tsc 7.0.2 `TS2322`/`bad.ts`/line 2 ✓; `go build` `compile error`/`main.go`/line 6 ✓; `go run` panic `panic.go`/line 7 ✓。诊断自动经 execute→ExecutionResult.diagnostics 流通 (exit_code!=0), 无 4 层 wiring
  - **#13 — GUI 更多动作** ✅ 完成
    - fe-gui `GuiAction` 9→16 变体: 新增 `double_click` (ax_label/ax_position, CGEvent 2× LeftMouseDown/Up, 第二击 `EventField::MOUSE_EVENT_CLICK_STATE=2`) / `right_click` (ax_label/ax_position, CGEvent RightMouseDown/Up + `CGMouseButton::Right`) / `hover` (ax_position, CGEvent MouseMoved 无按键) / `window_close` / `window_minimize` / `window_zoom` (bundle_id, AX 按钮属性 `kAXCloseButtonAttribute`/`kAXMinimizeButtonAttribute`/`kAXZoomButtonAttribute` → `press()`) / `window_resize` (bundle_id + width/height, 拖右下角 resize 把手 — 读 AXPosition+AXSize 算坐标, 复用 `drag()` CGEvent; 非 AXValueCreate 设 AXSize 避免新增 unsafe block, 留在既定 3 处 unsafe scope 内)
    - `resolve_click_position` helper 共用 click/double_click/right_click (ax_position 优先, 否则 ax_label→AX 树定位读 AXPosition; 无二者报错)
    - **4 层 auto-flow**: fe-core/fe-ipc/fe-pyo3 在 GuiAction enum 级反序列化后 dispatch — 新变体零 wiring 自动流通 (仅 fe-gui 改 enum+execute+方法+测试); Python `gui_action(action: dict)` 通用无 per-variant 逻辑
    - **0 新增 unsafe**: 全走 accessibility 0.2 safe wrapper (attribute/press) + core-graphics 0.24 safe wrapper (CGEvent/set_integer_value_field); 复用 fe-gui crate 级 `#![allow(unsafe_code)]` scope
    - +5 fe-gui Rust 单元测试 (serde 往返/snake_case/window 降级/pointer 降级/no-target) +2 Python 测试 (new_variants_degrade CI 路径 / pointer_variants_when_trusted TCC 路径; `_ax_access_trusted()` 探测分离 TCC Accessibility 与 Screen Recording 两权限)
    - 退出闸门: trusted 机 hover/double_click/right_click 带坐标 → `ok=True` (CGEvent posted); window_* 需真实 GUI 会话 (AX 窗口树) 沙箱内降级。116 Rust + 62 Python 测试全绿; clippy `--all-targets -D warnings` 净 (仅上游 block v0.1.6); fmt/ruff 净; maturin 构建
  - **#14 — 双向 IPC server-push (订阅/广播)** ✅ 完成
    - fe-ipc `BroadcastHub` (Arc 共享) — IPC broker 关注点, **fe-core Executor 保持无状态** (广播扇出不进 executor)。registry: sub_id → Subscriber{conn_id, channels, tx}; conn/sub counter AtomicU64; telemetry_task/screenshot_task `Mutex<Option<JoinHandle>>` lazy 启停 (0 订阅自退, 下次 subscribe 重启; 源方法取 `&self` 非 `self: Arc<Self>` — 避免自移后 `.take()`)
    - 连接 DUPLEX: `handle_conn` 拆 read_task (分发请求) + push_task (写 server-push 帧) 共享 `Arc<AsyncMutex<OwnedWriteHalf>>` (锁下行写原子); 每连接 `mpsc::channel<Value>(128)` push 帧 + oneshot close
    - 三广播源: **telemetry** (单一 `executor.telemetry_stream` 扇出, 10Hz 默认 `interval_ms=100`) / **stdio** (execute/execute_stream 处理器调 `hub.broadcast_stdio()` 扇出 chunk/done — **跨连接** A 订阅 B 跑命令 A 收推送) / **screenshot** (周期 `gui_action(Screenshot)` 采样 `spawn_blocking`, `screenshot_interval_ms=1000` 慢于 telemetry; TCC 未授权 → 帧 data.ok=false 不崩, 复用 fe-gui safe wrapper)
    - 推帧格式: `{"jsonrpc":"2.0","method":"executor.event","params":{"subscription_id":"sub-N","channel":..,"data":..}}` — **无 id** (notification 约定), 客户端按有无 id 区分响应 vs 推送。`collect_targets(channel)` 锁外 try_send (快照 sub_id+tx 后释放锁)
    - fe-ipc **0 新增 unsafe** (截图复用 fe-gui safe wrapper, crate 仍 `unsafe_code="deny"`)。fe-pyo3 无改动 — server-push 需运行中 server, 纯 Python UDS 客户端 `Subscription` 连接 `serve()` socket
    - Python `Subscription` 纯 Python UDS 客户端: `_open()` 连接+发 subscribe+读响应设 `_sub_id`; `__next__` 过滤 `executor.event` 帧匹配 sub_id, 跳过非 event 帧; `unsubscribe()` 发 unsubscribe+关 socket; `SUB_CHANNELS=("telemetry","stdio","screenshot")` 未知通道 `ValueError`。`FusionSandboxExecutor.subscribe(channels, *, sock_path, interval_ms, screenshot_interval_ms) -> Subscription`
    - +7 fe-ipc Rust 单元测试 (subscribe telemetry 推帧/missing channels -32600/unsubscribe 停推/stdio 跨连接广播 + 原有 health/unknown/malformed/execute/stream) +3 Python 测试 (subscribe telemetry 推帧/stdio 跨连接广播/未知通道 ValueError); 测试用 `UnixStream::into_split()` → `(OwnedReadHalf, OwnedWriteHalf)` 避借用后移
    - 退出闸门: 120 Rust + 70 Python (6 skip TCC) 测试全绿; clippy `--all-targets -D warnings` 净 (仅上游 block v0.1.6); fmt/ruff 净; maturin 构建
- **v1.5 完成** (#12 诊断切片扩语言 + #13 GUI 更多动作 + #14 双向 IPC server-push) — 120 Rust + 70 Python (6 skip TCC) 测试全绿; 10 crates; clippy `--all-targets -D warnings` 净 (仅上游 block v0.1.6 future-incompat); `cargo fmt --check` + `ruff check/format` 净; `maturin develop --release` 构建。零新增 unsafe (#13/#14 均走 safe wrapper)。下一步: v1.6 或按需。
- **审计 T1~T9 — 缺陷审计 (2026-08-24/25)** ✅ 完成
  - 跨 fe-security/fe-sandbox/fe-ipc/fe-tools/fe-rollback/fe-core/fe-pyo3+fe-telemetry/Python 层/fe-diagnostics 共 68 defects, 全修复: kill 升级 + killpg + 死锁/OOM 守卫, socket 0o600 + 行上限 + semaphore, 原子 NamedTempFile 写 + 全文件重写拒绝 + glob 逐命中校验 + grep 64MB 上限, git `reset --hard` 单步 + tag 前缀 snapshot_id + `is_valid_ref`, 前后 git-status diff (无误回滚) + streaming abort+timeout + worker_threads(1), 墙钟 ts_ms + Drop abort + `py.detach` 释放 GIL + fail-loud PyRuntimeError + serve 信号/清理, Subscription GC + stream 测试抗竞态, tail_lines 保 traceback 段头 + python_re 贪心最深帧 + swift_re 扩展名守卫。Commit `36e8790`。
- **审计 0825 — 商用集成审计 (2026-08-25)** ✅ 完成 — **FAIL → PASS**
  - 10 CRITICAL / 23 MAJOR / 4 MINOR。商用级集成 11 Blockers 落地 (commit `0341ccb`): B1 macOS seatbelt 运行时沙箱 (sandbox-exec 禁网 + 13 危险二进制), B2 read-path `validate_argv` + diagnostics 富化 guard, B3 `guard_path` canonicalize + `..` 永久 reject, B4 rollback path 接入 fe-security, B5 BLOCKING_RT worker_threads(1)→(N), B6 `run_streaming` 可取消 + kill 子进程, B7 `read_capped_line` chunked + in-loop cap, B8 file tools 大小上限 (64MB) + flock 原子写, B9 rollback registry + FNV-1a repo 标识 snapshot_id, B10 stdio 每订阅 scope 过滤 (跨租户隔离), B11 Pydantic `extra="forbid"` + Rust serde schema 同步。
  - 13 MAJOR/MINOR 扫尾 (#45): GUI wait 释放 GIL, kill grace 50ms→500ms, truncate 字节偏移, partial stdout 保留, exec semaphore, request multiplexing, glob cap+ignore, grep cap(2000)+max_depth(20)+ignore, apply_patch 多文件切分 + 聚合全文件重写拒绝, diagnostics 读 stdout (PTY 合并), telemetry 严格 `model_validate`, `replace_function` 无 grammar fail-loud `Err`, `Subscription` 可配 `idle_timeout`, `serve(path)` resolved-path + version 同步。
  - 出口: **223 Rust + 113 Python (6 skip TCC) 测试全绿**; clippy `--all-targets -D warnings` 净; `cargo fmt --check` + `ruff check/format` 净; `maturin develop --release` 构建。
- **v0.2.0 ~ v0.2.3 企业硬化** ✅ — v0.2.0 fe-shell 后台任务 API (poll 模型持久 shell 注册表, PR #16/#18) + v0.2.0 发布; v0.2.1~v0.2.2 架构 + 运维硬化 (M-ARCH-1 ShellRegistry 移出无状态 Executor + M-OPS-01 结构化 JSON 日志 + M-OPS-02 Prometheus 指标 UDS 导出 + M-OPS-06 跨层 trace_id + m-OPS-02 SIGHUP 热重载); v0.2.3 企业硬化发布 (审计 0826 CRITICALs + PR #19 + glob E1 规范对齐 #20)。审计 0826 (企业级商用): 10 CRITICAL + 15 MAJOR + 12 MINOR 全落地。审计 0827 (对抗性硬化): 18 CRITICAL + 18 LOGIC-BUG + 12 ARCHITECTURE + 7 PERFORMANCE + 12 MAINTAINABILITY = 67 findings, P0-P3 全落地 (分支 `fix/audit0827-p0-p3`, #94-#105)。架构审计 0827 (31 findings: 12C+17M+2MIN) + 架构 Batch 1-13 全落地 (ARCH-1..7, RUN-1..12, IMPL-1..12, PR #25)。出口随各版本: 419 Rust + 190 Python 测试全绿; clippy `--all-targets -D warnings` 净 (仅上游 block v0.1.6 future-incompat); fmt/ruff 净; maturin 构建。
- **v0.2.4 已发布** ✅ — 企业级可发布升级。产品就绪审计 (`audit/fusion-executor-audit-result-product-0827.md`, 基线 `9b96aeb`) 6 真 CRITICAL + 33 MAJOR/MINOR + D3-1 内联解释器网关, 全部落地 (16 批次, 分支 `fix/enterprise-upgrade-0828`)。要点: (1) **D3-1 内联解释器网关** — `python -c`/`node -e`/`ruby -e`/`perl -e` 默认拦截 (企业硬化, 防 agent 生成 payload); 受信调用方经 `with_allow_inline_interpreter(true)` opt-in。(2) **ARCH-1 seatbelt 默认 True** — 4 层对齐 (Rust serde `default_true` + executor.py + Pydantic), 漂移断言测试锁定。(3) **ARCH-2 resolved-path 白名单** — 二进制 basename 校验 + 绝对路径 `starts_with(trusted_bin_dirs)` (拒 `/tmp/python3` 同名投毒), venv bin 自动注册。(4) **D3-4 每任务 RSS watchdog** — sysinfo 轮询子进程树 RSS, OOM kill (exit -124, `oom_killed=true`), 因 Darwin RLIMIT_AS no-op。(5) **RUN-3 stream/exec 信号量分离** — 16 并发 exec + 64 并发 stream, 长流不饿死短命令。(6) **IMPL-7 prompt-injection sanitize** — 单一 chokepoint sanitize `file_path`/`raw_trace`/`error_type` (换行切分 + 注入模式中和 + 大小上限)。(7) **D4 perf** — LazyLock profile cache + 16KB 读取 + 广播 fast-path + exec_sem gauge + worker clamp(2,8)。(8) **ARCH-3 集成骨架** — `examples/08_integrate_fusion_code.py` + fusion-code 单向 issue (ARCH-7 调用方熔断文档化)。(9) **fe-pyo3 首批 Rust 单元测试** (D1-1 From 转换覆盖)。(10) 文档: 默认 socket `~/.fusion-executor/fe.sock`, 默认 bundle 白名单 (Terminal/TextEdit/Finder), 截图 Screen-Recording TCC 分离, NFS flock warn。跨工程 Issue #23 (fusion-guard Phase 3) 延期 — 超范围。出口: **476 Rust + 195 Python (6 skip TCC) 测试全绿**; clippy `--all-targets -D warnings` 净 (仅上游 block v0.1.6 future-incompat); fmt/ruff 净; maturin 构建。
- **v0.1.0 已发布** ✅ — 打 tag `v0.1.0` (annotated), 推到 `origin`。首个稳定版。可运行示例见 `examples/` (Python API 01~07 + TypeScript UDS client), 文档地图见 `docs/INDEX.md`。
