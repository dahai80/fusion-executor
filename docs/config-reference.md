---
doc_id: fusion-executor/config-reference
product: fusion-executor
class: platform
entry: service
doc_type: config-reference
title: {zh: "fusion-executor 配置参考", en: "fusion-executor Configuration Reference"}
audience: engineer
status: draft
version: 0.2.20
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - crates/fe-ipc/src/lib.rs
  - CLAUDE.md
  - scripts/launchd/com.fusion.executor.plist
---

# fusion-executor 配置参考 / Configuration Reference

Configuration is via environment variables plus constructor/CLI arguments. Sources: `crates/fe-ipc/src/lib.rs`, `CLAUDE.md`, `scripts/launchd/com.fusion.executor.plist`.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `FUSION_EXECUTOR_SOCK` | `~/.fusion-executor/fe.sock` | UDS JSON-RPC socket path. HOME-private directory (0o700) by design — not `/tmp` (m-OPS-01 + M-SEC-01) |
| `FUSION_EXECUTOR_EXTRA_WHITELIST` | empty | Extra Security Guard whitelist commands, comma-separated (whitespace trimmed, empties dropped) → `Executor.reload_whitelist` |
| `FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS` | `10` | Graceful shutdown timeout for the IPC server; bounds `1..=300`, out-of-range falls back to the default |
| `FUSION_EXECUTOR_TENANT` | — | Implicit fusion-guard tenant; must match the tenant bound to the executor OS identity (UID) in guard, else evaluate returns -32001 → fail-closed block |
| `FUSION_GUARD_SOCK` | — | Implicitly enables fusion-guard integration (equivalent to `guard_sock=`) |
| `FUSION_EXECUTOR_PIDFILE` | — | PID file for the IPC service (used by the launchd/service setup) |

## MLX / LLM resolution (fusion-core, issue #60)

`LayaToolSelector` HTTP backend resolves credentials through `fusion_core.config` single-point helpers (`client_key()` / `default_mlx_base_url()`, default `http://localhost:11434/v1`) — no hand-rolled resolvers and no secret default literals in this repo. Behavior: dev with missing key = empty key + warning; prod = `RuntimeError`. Explicit `api_key=` / `mlx_url=` constructor arguments win over the helpers.

## Constructor / call-time options

| Option | Default | Meaning |
|---|---|---|
| `guard_sock` | None (guard OFF) | Explicit guard UDS path; enabling is opt-in and backward compatible |
| `guard_tenant` | — | Guard tenant for the 4-layer plumbing (`guard_sock` + `guard_tenant` together) |
| `run(..., timeout)` | `30.0` | Per-command timeout; `exit_code -124` on expiry |
| `run(..., cwd, env_vars, task_id, trace_id)` | None / None / None / None | Working directory, environment override, task correlation, cross-layer trace id |
| `run(..., enable_rollback_snapshot)` | `True` | Git snapshot before execution |
| `subscribe(..., interval_ms, screenshot_interval_ms)` | — | Telemetry/stdio/screenshot push intervals |

## Security Guard whitelist

The Guard blocks by regex blocklist + tokenizer stage, with a whitelist fence. Extend at runtime with `FUSION_EXECUTOR_EXTRA_WHITELIST` (env, read at startup per m-OPS-02). When fusion-guard is enabled, the guard verdict is authoritative and the static blocklist remains as the base layer.

## launchd

`scripts/launchd/com.fusion.executor.plist` registers the UDS service with launchd (desktop sessions). The daemon is UDS-only — there is no TCP port, so nothing to register in `architecture/port-registry.yaml` port-wise; the socket path is the identity.

## Logging

Rust side uses `tracing` (English log lines); the Python layer logs via the standard `logging` module. Verbose CLI output: `fusion-executor "cmd" -v` (JSON).
