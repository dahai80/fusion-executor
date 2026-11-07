---
doc_id: fusion-executor/get-started
product: fusion-executor
class: platform
entry: service
doc_type: get-started
title: {zh: "fusion-executor 快速开始", en: "fusion-executor Get Started"}
audience: engineer
status: draft
version: 0.2.20
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - README.md
  - pyproject.toml
  - examples/
---

# fusion-executor 快速开始 / Get Started

Requirements: macOS 13+ (Apple Silicon), Rust toolchain, Python >= 3.11 (the shared monorepo venv is 3.14), `maturin`.

## 1. Build and install / 构建安装

```bash
cd /Users/dahai/fusion && source .venv/bin/activate
pip install maturin        # first time
cd fusion-executor
maturin develop --release  # builds fusion_executor._native, editable install
```

Or build only the Rust workspace: `cargo build --release`.

## 2. First execution / 首次执行

```bash
python -c "from fusion_executor import FusionSandboxExecutor; print(repr(FusionSandboxExecutor().run('echo hi').stdout))"
# 'hi\n'
```

CLI form:

```bash
fusion-executor "echo hi" --cwd /tmp --timeout 10   # -v for verbose JSON
```

## 3. Security block and timeout / 安全拦截与超时

```python
from fusion_executor import FusionSandboxExecutor

ex = FusionSandboxExecutor()
r = ex.run("rm -rf /")
assert r.blocked_by_security and r.exit_code == -1

r = ex.run("python3 -c 'while True: pass'", timeout=1.0)
assert r.timed_out and r.exit_code == -124

r = ex.run("python3 -c \"raise ValueError('boom')\"")
assert r.diagnostics.error_type == "ValueError"   # structured diagnostics slicer
```

## 4. Start the UDS JSON-RPC service / 启动 UDS 服务

```bash
python -c "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()"
```

Default socket `~/.fusion-executor/fe.sock` (HOME-private, override `FUSION_EXECUTOR_SOCK`). There is no TCP listener. Subscribe to server-push from another terminal:

```bash
python -c "from fusion_executor import FusionSandboxExecutor; s=FusionSandboxExecutor().subscribe(['telemetry'], interval_ms=100); [print(next(s)) for _ in range(3)]; s.unsubscribe()"
```

## 5. Run the tests / 运行测试

```bash
cargo test --workspace      # 528 Rust tests
pytest python/tests         # 282 Python tests
cargo clippy --workspace -- -D warnings && ruff check .
```

## 6. Explore the examples / 示例

Runnable demos under `examples/` (index: `examples/README.md`): `01_run_echo.py` through `11_task_service.py` — security block, streaming, rollback, file tools, telemetry, subscription, fusion-code integration, tool selection, agent loop, batch tasks.

## Next steps / 下一步

- Full method and protocol reference: [api-reference.md](api-reference.md) and [architecture.md](architecture.md)
- Environment variables: [config-reference.md](config-reference.md)
- Production deployment: [PRODUCTION_RUNBOOK.md](PRODUCTION_RUNBOOK.md)
- Troubleshooting: [troubleshooting.md](troubleshooting.md)
