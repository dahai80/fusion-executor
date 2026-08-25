# Documentation Index

> **Language / 语言**: **English** | [中文](INDEX_CN.md)

Navigation for all **fusion-executor** documentation. v0.1.0 — controlled
execution sandbox + macOS OS-level control hub for the Fusion ecosystem.

## Start here

| Document | What it covers |
|----------|----------------|
| [README.md](../README.md) | Project overview, four core subsystems, build/test/lint commands, data schema, ecosystem integration, NFRs. Start here. |
| [CLAUDE.md](../CLAUDE.md) | Working guide for Claude Code: project status (per-version changelog), build/test/lint, Python API surface, 4-layer wiring notes, monorepo conventions, key paths. |
| [examples/README.md](../examples/README.md) | Runnable examples index — 7 Python + 1 Rust + 1 TypeScript, each with what-it-shows and run instructions. |

## Architecture & design

| Document | What it covers |
|----------|----------------|
| [docs/architecture.md](architecture.md) | In-repo architecture: 10-crate layout, 4-layer wiring (fe-core → fe-ipc → fe-pyo3 → Python), pipeline diagram, per-crate responsibilities. |
| PRD (monorepo) | Full PRD at `../../architecture/fusion-executor-prd.md` (monorepo root `architecture/` dir): §4 data schema (ExecutionRequest/ExecutionResult fields), §4.2 Diagnostics Slicer algorithm, fusion-code refactor plan, Claude-SDK/DeepSeek-Harness capability comparison. |
| Audit (monorepo) | `../../audit/fusion-executor-audit-report-0825.md` — commercial-grade integration audit (10 CRITICAL / 23 MAJOR / 4 MINOR); the audit-0825-pass memory documents all 11 Blockers + 13 MAJOR/MINOR landed. |

## IPC integration

| Document | What it covers |
|----------|----------------|
| [docs/ipc-client-typescript.md](ipc-client-typescript.md) | UDS JSON-RPC 2.0 protocol for the TypeScript consumer (fusion-code): method table, error codes, `FusionExecutorClient` sketch. The runnable version is [examples/uds_client_typescript.ts](../examples/uds_client_typescript.ts). |

## Wire contract reference

The data schema (Pydantic models ↔ Rust serde structs) is documented inline in
`CLAUDE.md` ("Data Schema (Pydantic)" section) and in the PRD §4. Key models:

- `ExecutionRequest` → `ExecutionResult` (exit_code 0/-124/-1; `diagnostics`, `snapshot_id`, `auto_rolled_back`).
- `EditResult` / `GlobEntry` / `GrepMatch` (native file tools).
- `TelemetrySample` / `TelemetryConfig` (10Hz telemetry).
- `RollbackPolicy` (optional auto-rollback kwarg).
- `GuiResult` (16 GuiAction variants).

## Per-version changelog

The full per-version build history (v1 P1–P5 through v1.5, audit T1–T9,
audit-0825 Blockers, v0.1.0 release) lives in `CLAUDE.md` "Project Status".
The release tag is `v0.1.0` (annotated, pushed).
