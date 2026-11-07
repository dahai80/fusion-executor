---
doc_id: fusion-executor/agent-loop-integration
product: fusion-executor
class: platform
entry: service
doc_type: guide
title: {zh: "将 Agent 自修复循环接入 fusion-executor", en: "Wiring an Agent Self-Healing Loop to fusion-executor"}
audience: engineer
status: draft
version: 0.2.20
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - examples/08_integrate_fusion_code.py
  - CLAUDE.md
---

# 将 Agent 自修复循环接入 fusion-executor / Wiring an Agent Self-Healing Loop to fusion-executor

Reference skeleton: `examples/08_integrate_fusion_code.py` (consumes the executor API only, no upstream imports). This guide states the two contract points every caller must own, and what the executor takes over.

## What the caller no longer builds / 调用方不再自建

Delegating execution to fusion-executor replaces the caller's own subprocess + file-IO glue: command validation (Security Guard), timeout, stdio capture and truncation, PTY sandbox, Git snapshots, and traceback slicing all come from the executor. Constraint: the executor is per-task stateless — anything that spans tasks (loop counters, circuit breakers) stays with the caller.

## Contract point 1: diagnostics, not stderr parsing

On `exit_code != 0`, read `result.diagnostics` (`error_type` / `file_path` / `line_number` / `code_snippet`) to build the next model prompt. The executor already sliced the traceback (8 languages); the caller must not re-parse raw stdout.

```python
result = ex.run(command, cwd=repo, timeout=60.0)
if result.exit_code != 0:
    d = result.diagnostics
    next_prompt = f"Fix {d.error_type} at {d.file_path}:{d.line_number}\n{d.code_snippet}"
```

## Contract point 2: the caller owns the circuit breaker

The executor does NOT count consecutive failures. The caller keeps the count and reads `RollbackPolicy.max_consecutive_failures` as its threshold; hitting it stops the loop (fail visibly) instead of looping forever (ARCH-7 caller-circuit contract).

```python
from fusion_executor import RollbackPolicy

policy = RollbackPolicy(max_consecutive_failures=5)  # threshold read by the caller
failures = 0
for attempt in range(max_attempts):
    result = ex.run(command, cwd=repo, auto_rollback=policy)
    if result.exit_code == 0:
        break
    failures += 1
    if failures >= policy.max_consecutive_failures:
        raise RuntimeError("circuit breaker open — stop the loop")
```

Auto-rollback (optional, FR-04): passing `auto_rollback=RollbackPolicy(...)` makes the executor roll the Git snapshot back on failure with detected file damage and set `result.auto_rolled_back=True`. Auto-rollback is per-execute, not per-loop — the caller still owns the consecutive-failure count.

## Optional: zero-trust mode / 零信任模式

If the loop executes model-generated commands, enable fusion-guard so every command is authorized before execution:

```python
ex = FusionSandboxExecutor(guard_sock="/tmp/fusion-guard.sock", guard_tenant="fusion-code")
```

On guard Block/L3, `result.guard_action_id` carries guard's action id for the human confirm loop. A guard RPC failure blocks the command (fail-closed). Requires the guard daemon running (`~/fusion/fusion-guard/start.sh start`); tenant must match guard's UID binding.

## Batch loops: TaskManager

For fan-out workloads (many independent commands), prefer `TaskManager` over ad-hoc thread pools: task_id polling, retry backoff, SQLite persistence across restarts, and the `TASK_PROGRESS:` live progress protocol — see `examples/11_task_service.py` and [api-reference.md](../api-reference.md).
