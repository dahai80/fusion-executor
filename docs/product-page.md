---
doc_id: fusion-executor/product-page
product: fusion-executor
class: platform
entry: service
doc_type: product-page
title: {zh: "fusion-executor 产品页", en: "fusion-executor Product Page"}
audience: engineer
status: draft
version: 0.2.20
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - README.md
  - CLAUDE.md
  - Cargo.toml
---

# fusion-executor 产品页 / Product Page

| | |
|---|---|
| Product | fusion-executor |
| Class | platform |
| Entry | service (library + UDS JSON-RPC daemon) |
| Version | 0.2.20 |
| Language | Rust (12-crate workspace) + Python binding (PyO3/maturin) |

## What it is / 它是什么

fusion-executor is a controlled execution sandbox and macOS OS-level control hub. It runs shell commands safely (Security Guard + PTY/stdio sandbox), drives native GUI (Computer Use via the Accessibility API and CGEvent synthesis), and rolls back on failure (Git snapshots). Native, no Docker: macOS process isolation + Git snapshots, sandbox init <5ms. It exposes the same surface as a Rust library, a PyO3 Python module (`fusion_executor`), a CLI (`fusion-executor`), and a UDS JSON-RPC daemon.

fusion-executor 是受控执行沙箱 + macOS 系统级控制中枢：安全执行 shell 命令（Security Guard + PTY/stdio 沙箱）、驱动原生 GUI（Accessibility API + CGEvent 合成）、失败回滚（Git 快照）。原生实现、无 Docker：macOS 进程隔离 + Git 快照，沙箱初始化 <5ms。同一能力以 Rust 库、PyO3 模块（`fusion_executor`）、CLI（`fusion-executor`）与 UDS JSON-RPC daemon 四种形态提供。

## What consumers no longer have to do / 消费方不再需要做什么

- **No hand-rolled command validation.** Callers stop writing their own blocklist regexes, timeouts, stdio capture, and truncation logic — `ex.run()` returns a structured `ExecutionResult` with exit code, security verdict, diagnostics, and snapshot id. Constraint: the executor is stateless; the caller owns loop-level failure counting (`RollbackPolicy.max_consecutive_failures` is a caller circuit-breaker contract, ARCH-7).
- **No Docker/subprocess glue for self-healing loops.** fusion-code-style loops delegate command execution to the executor and consume structured `Diagnostics` (traceback slicing for 8 languages) instead of parsing stderr themselves. Constraint: diagnostics cover the 8 languages the slicer ships with; other runtimes get raw output.
- **No bespoke rollback plumbing.** `snapshot_create` / `rollback` wrap Git snapshots; optional auto-rollback reverts per execute. Constraint: rollback is Git-based — it protects tracked files, not arbitrary filesystem state.
- **No separate telemetry/stdio pipelines to dashboards.** `serve()` + `subscribe()` broadcast telemetry (10Hz CPU/mem), stdio streams, and screenshots over UDS with bidirectional server-push. Constraint: UDS only — no TCP listener; consumers must be on the same host.
- **No own tool-selection LLM calls.** `LayaToolSelector` / `AgentLoop` do deterministic tool selection (dual Python/HTTP backends), with the LLM as fallback for low-confidence misses. Constraint: 421M classifier — misses degrade to the LLM path by design.
- **No per-app batch-task engines.** `TaskManager` provides a shared async batch-task service (state machine, retry backoff, SQLite persistence across restarts, live progress protocol) for business apps. Constraint: single-host, single-process service.

## Key capabilities / 核心能力

| Capability | Surface | Consumer benefit | Constraint |
|---|---|---|---|
| Safe execution | `run` / `run_async` / `run_streaming` | Security Guard + PTY sandbox + timeout + OOM cap | `exit_code` -124 = timeout, -1 = blocked/internal |
| Background shells | `start_shell` / shell poll APIs | run_in_background parity | Registry is per-process |
| Native file tools | `file_edit` / `glob` / `grep` / `write_file` / `multi_edit` / `notebook_edit` | Surgical patch engine, no ad-hoc sed scripting | macOS-first |
| Diagnostics slicer | `ExecutionResult.diagnostics` | Traceback → structured error, 8 languages | Feature-gated per grammar |
| Git rollback | `snapshot_create` / `rollback` | Caller-driven or auto-rollback | Git-tracked files only |
| Computer Use | GUI actions (20 variants) + screenshots | Native AXUIElement + CoreGraphics + CGEvent | Requires TCC Accessibility / Screen Recording grants |
| Telemetry & push | `serve` + `subscribe` | 10Hz CPU/mem, stdio, screenshot channels | UDS-only, same host |
| fusion-guard auth | `guard_sock=` / `FUSION_GUARD_SOCK` | Zero-trust allow/preview/redact/block before every command | Default OFF; on mismatch → fail-closed block |
| Tool selection | `LayaToolSelector` / `AgentLoop` | Deterministic selection <15ms AC8 | LLM fallback for misses |
| Batch tasks | `TaskManager` | Shared queue, retry, persistence, progress protocol | For business apps, SQLite-backed |

## Interfaces / 接入方式

- **Python (in-process)**: `maturin develop --release` → `from fusion_executor import FusionSandboxExecutor`. See [api-reference.md](api-reference.md).
- **UDS JSON-RPC daemon**: `FusionSandboxExecutor().serve()`; default socket `~/.fusion-executor/fe.sock` (override `FUSION_EXECUTOR_SOCK`). TypeScript client sketch: [ipc-client-typescript.md](ipc-client-typescript.md).
- **CLI**: `fusion-executor "echo hi" --cwd /tmp --timeout 10`.
- **launchd**: `scripts/launchd/com.fusion.executor.plist`.

## What it is not / 边界

- Not an HTTP service: IPC is UDS JSON-RPC (latency target <2ms for traceback transfer); inference is delegated to fusion-mlx / fusion-gateway.
- Not a container: isolation is macOS process-level (seatbelt) + Git snapshots, not filesystem images.
- Not a guard replacement: when fusion-guard is enabled it consumes the guard verdict; it does not define policy.

## Status / 状态

v0.2.20 released. 528 Rust + 282 Python (2 skip) tests green; clippy `--all-targets -D warnings` clean. Release history in [CHANGELOG.md](../CHANGELOG.md); operations detail in [PRODUCTION_RUNBOOK.md](PRODUCTION_RUNBOOK.md).
