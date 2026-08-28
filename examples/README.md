# Examples

> **Language / 语言**: **English** | [中文](README_CN.md)

Runnable examples for **fusion-executor** v0.1.0 — the controlled execution
sandbox + macOS OS-level control hub for the Fusion ecosystem.

Each example is self-contained and prints what it is doing. They exercise
the real native extension (Rust + PyO3 via maturin), not mocks.

## Prerequisites

```bash
cd /Users/dahai/fusion
source .venv/bin/activate          # shared venv — REQUIRED
cd fusion-executor
maturin develop --release          # build + install the native extension
```

The TypeScript example additionally needs `bun` (`brew install oven-sh/bun/bun`).

## Python examples

| # | File | What it shows |
|---|------|---------------|
| 01 | `01_run_echo.py` | The happy path — `run("echo ...")` returns `exit_code 0`, stdout, `duration_sec`. |
| 02 | `02_security_block.py` | The two-stage Security Guard rejects `rm -rf`, `sudo`, `curl|sh`, `os.system` chains **before** any process spawns. |
| 03 | `03_streaming.py` | `run_streaming()` yields stdout chunks as they arrive, then a final `ExecutionResult` — live stdio through all 4 layers. |
| 04 | `04_rollback.py` | `snapshot_create()` → corrupt a file → failing command → `rollback()` restores the git snapshot. |
| 05 | `05_file_tools.py` | Native file tools: `file_edit` (unique-match), `glob`, `grep`, `apply_patch` (Unified Diff, no full-rewrite), `replace_function` (tree-sitter AST). |
| 06 | `06_telemetry.py` | `telemetry_stream()` yields `TelemetrySample` at 10Hz (CPU%, mem MB, wall-clock `ts_ms`). |
| 07 | `07_subscribe.py` | Starts the UDS server, `subscribe(["telemetry"])`, prints server-push frames, `unsubscribe()`, stops server. |
| 08 | `08_integrate_fusion_code.py` | **Integration skeleton (ARCH-3)** — the self-healing loop an upstream agent (fusion-code) should run: parse `result.diagnostics`, own the consecutive-failure count as a circuit breaker (`RollbackPolicy.max_consecutive_failures`), optional `auto_rollback`. One-way reference; does not import fusion-code. |

Run any one:

```bash
python examples/01_run_echo.py
python examples/07_subscribe.py
```

## Non-Python examples

| File | What it shows |
|------|---------------|
| `regcheck.rs` | Diagnostics Slicer regex coverage — run `cargo test -p fe-diagnostics` to see Python/Node/Rust/Go/Swift/TS/Bun tracebacks sliced to `{error_type, file_path, line_number, code_snippet}`. |
| `uds_client_typescript.ts` | A complete TypeScript UDS JSON-RPC 2.0 client (the shape fusion-code would use): `health` / `execute` / `executeStream` (live stdio) / `fileEdit` / `snapshotCreate` / `rollback` / `subscribe` (bidirectional server-push). |

Run the TypeScript client (needs a server on the socket):

```bash
# terminal 1 — start the server
python -c "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()"

# terminal 2 — run the client
bun examples/uds_client_typescript.ts            # health + execute
bun examples/uds_client_typescript.ts subscribe  # + telemetry push frames
```

## Notes

- Examples clean up their own temp data; no leftover files after a run.
- `07_subscribe.py` and `uds_client_typescript.ts` start/connect to a server on `~/.fusion-executor/fe.sock` (override via `FUSION_EXECUTOR_SOCK`).
- GUI actions (click/type/screenshot) are **not** in these examples — they need TCC Accessibility + Screen Recording permission and a real GUI session. See the manual checklist in the root `README.md`.
- All examples include logging (`logging.basicConfig`) per project convention.
