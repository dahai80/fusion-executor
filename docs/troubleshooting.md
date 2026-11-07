---
doc_id: fusion-executor/troubleshooting
product: fusion-executor
class: platform
entry: service
doc_type: troubleshooting
title: {zh: "fusion-executor 故障排查", en: "fusion-executor Troubleshooting"}
audience: engineer
status: draft
version: 0.2.20
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - README.md
  - docs/PRODUCTION_RUNBOOK.md
  - CLAUDE.md
---

# fusion-executor 故障排查 / Troubleshooting

## Build / install

**`maturin develop` fails or `import fusion_executor` raises ImportError** — the shared venv must be active first (`source ~/fusion/.venv/bin/activate`), and `pip install maturin` once. Confirm the native extension built: `python -c "import fusion_executor._native"`.

**`cargo test --workspace` link errors** — the workspace builds with `extension-module` off by default so cargo test can link libpython; if you overrode features, build default. Python tests: `pytest python/tests` from the repo root with the venv active.

## Execution semantics

**`exit_code == -124`** — the command hit `timeout` (default 30.0s). Not an error in the sandbox; raise `timeout` or fix the command.

**`exit_code == -1` and `blocked_by_security=True`** — Security Guard blocked the command (blocklist regex + tokenizer). `security_reason` says why. If the command is legitimate, add it via `FUSION_EXECUTOR_EXTRA_WHITELIST` (comma-separated) — whitelist changes take effect via `Executor.reload_whitelist`.

**Command expected to fail but no `diagnostics`** — the slicer produces structured output only for recognized runtimes (8 languages); unknown runtimes return raw stderr.

**`auto_rolled_back=True`** — auto-rollback (RollbackPolicy) reverted the working tree after a failing command. Inspect `RollbackOutcome` (`applied`, `skipped_reason`, `wip_sha`); rollback only restores Git-tracked files. Loop-level circuit breaking is the caller's job (`max_consecutive_failures` is a caller contract, ARCH-7).

**GUI actions do nothing / screenshots black** — TCC grants are separate: Accessibility for AX actions, Screen Recording for screenshots. Probe each; a grant for one does not cover the other (audit C-11/C-12/C-13). Coordinates are wrong → check `scale_factor` coordinate mapping on Retina displays.

## IPC service

**Connection refused on the socket** — the service is not running: `python -c "from fusion_executor import FusionSandboxExecutor; FusionSandboxExecutor().serve()"`. Check the actual path with `ls ~/.fusion-executor/fe.sock` (override: `FUSION_EXECUTOR_SOCK`). There is no TCP listener — connecting over TCP fails by design.

**Socket permission denied** — the default socket lives in a HOME-private 0o700 directory; only the same user may connect. Running the client as another user fails by design.

**Subscription gets no frames** — `subscribe()` requires a running `serve()` (cross-connection push). Verify the channel names (`telemetry` / `stdio` / `screenshot`) and intervals. The client-side buffer is capped at 8MB (audit C-fix) — a stalled consumer drops frames rather than growing unbounded.

**Stream won't stop on cancel** — use `cancel_stream(stream_id)` (server-side deterministic cancel of in-flight streams, issue #32); killing the client connection alone may leave the stream running.

**Service shutdown hangs** — graceful shutdown waits `FUSION_EXECUTOR_SHUTDOWN_TIMEOUT_SECS` (default 10s, bounds 1..=300). Long in-flight commands delay shutdown up to the bound.

## fusion-guard integration

**Every command blocked with guard enabled** — usually a tenant mismatch: `guard_tenant` / `FUSION_EXECUTOR_TENANT` must match the tenant bound to the executor's OS identity (UID) in the guard daemon; mismatch returns guard error -32001 and the executor fails closed (block, not degrade). Disable by removing `guard_sock` / `FUSION_GUARD_SOCK` (default OFF).

**guard.ping fails at startup** — the guard daemon must be running (`~/fusion/fusion-guard/start.sh start`, socket `/tmp/fusion-guard.sock`). The executor pings guard and seeds its epoch cache when enabled.

**Latency jumped when guard is on** — each command now takes a guard evaluate roundtrip; that is expected. Guard OFF restores v0.2.5 behavior.

## Tool selection

**LayaToolSelector slow (>15ms)** — under concurrent fusion-mlx Metal load, prefer `backend="http"`; the python backend degrades when fusion-mlx runs other models. Low-confidence misses (conf < 0.7) intentionally route to the LLM fallback.

**Benchmarks** — `scripts/bench_laya_tool_selector.py --backend http --compare-llm`; baseline results in `benchmarks/results/laya-tool-selection/report.json`.

## Diagnostics checklist

```bash
source ~/fusion/.venv/bin/activate
python -c "from fusion_executor import FusionSandboxExecutor; print(FusionSandboxExecutor().run('echo hi').exit_code)"
ls -la ~/.fusion-executor/            # socket dir
cargo test --workspace 2>&1 | tail -5
pytest python/tests 2>&1 | tail -5
```

Deep operational detail (deployment, incident playbooks, API stability): [PRODUCTION_RUNBOOK.md](PRODUCTION_RUNBOOK.md).
