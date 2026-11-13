---
doc_id: fusion-executor/changelog
product: fusion-executor
class: platform
entry: service
doc_type: changelog
title: {zh: "fusion-executor 变更日志", en: "fusion-executor Changelog"}
audience: engineer
status: draft
version: 0.2.26
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - CHANGELOG.md
  - pyproject.toml
---

# Changelog

All notable changes to fusion-executor are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/), semver versioning.

## [Unreleased]

## [0.2.26] — 2026-11

### Added
- Demo session touch injection (issue #69, iOS acceptance item resolved): `inject_touch(session_id, x, y, action="tap"|"swipe", x2, y2, duration_ms)` — iOS goes through idb (the XCTest-based UI automation stack), Android via `adb shell input tap/swipe`. Executor owns the idb companion lifecycle (`_ensure_companion`/`_stop_companion`): spawns `idb_companion --udid <udid> --only simulator`, parses the grpc port from its log, `idb connect`s the CLI, tears the companion down in `end_session`. Without owned-companion lifecycle the idb CLI either reuses a stale companion with an invalidated HID connection (`dtuhidd connection invalidated`) or fails with "Failed to connect to companion" — both observed and fixed. Live E2E verified on a booted iPhone simulator: tap round-trip ~327ms steady state (first tap ~5.3s HID handshake), swipe verified. Not the <30ms fe-gui native target — this is the demo-session remote-injection path via XCTest.
- Missing-tool failures stay visible: idb CLI / idb_companion absent → explicit `DemoSessionError` with install commands, never a silent skip.
- Dependencies are external tools, not package deps: `brew install facebook/fb/idb-companion` + `pip install fb-idb` (iOS touch only).

### Fixed
- Companion log handle now opened in a context manager (fd leak on early-exit path).

## [0.2.25] — 2026-11

### Added
- Demo session screen streaming (issue #69, partial): `open_stream(session_id)` — iOS kind serves an MJPEG stream over HTTP (stdlib `ThreadingHTTPServer`, `simctl io screenshot` snapshot loop to a temp file, bind-wait before URL issuance, idempotent re-open returns same URL); web kind verifies and returns the demo-app-provided stream page URL (`stream_path` config opt-in, e.g. noVNC `vnc.html`). Explicitly NOT the ~120ms WebRTC acceptance target: iOS touch injection has no public simctl API (needs XCTest stack) and MJPEG latency is ~0.5-1s — blocked upstream, documented in issue #69.
- Android demo session kind (issue #69, code path): `kind="android"` in `DemoSessionConfig` — Linux demo host + `/dev/kvm` pre-flight (visible `DemoSessionError` on non-Linux, never silent), docker `--privileged` emulator container (configurable `android_image`), `adb connect` + boot-completed poll (600s) + optional APK install + launch via monkey; capacity knob `max_android`; teardown = `docker rm -f` (data burned). Live verification blocked on a Linux+KVM host — code path + unit/preflight tests only.
- Per-session LLM metering readback (issue #69, verified): `session_cost(session_id)` — reads the session's own fk- key from state (workspace now `0o700`; key stored at rest) and queries gateway `GET /v1/cost` (own-key scope, gateway-owned metering). Live E2E verified end-to-end: demo session → scenario injection → in-container curl through gateway (stream mode) → `POST /api/v1/keys` fk- key → `/v1/cost` shows `by_key` entry + `total_tokens` > 0 → key revoked. NOTE gateway gap found during verification: non-stream `/v1/chat/completions` does not record cost (stream does) — upstream issue dahai80/fusion-gateway#639.
- `llm_api_key` now persisted in session state (0o700 workspace) so metering readback survives across processes.

### Fixed
- iOS live test in CI: headless GitHub runners boot simulators but app launch hangs (no GUI session) — test gated off CI via `GITHUB_ACTIONS`; simulator device discovery tolerant of slow cold-start simctl (120s + skip on failure); UDS shell-output roundtrip poll replaces fixed sleep (load-flake root cause).

## [0.2.24] — 2026-11

### Added
- Session-scoped demo host orchestration (issue #68): `DemoSessionManager` + `DemoSessionConfig` (`python/fusion_executor/demo_sessions.py`) — per-customer-click ephemeral demo stacks. Web kind: docker compose per-session project name + port from the registered demo range 11600-11669 (free-port probe) + healthcheck-gated readiness (reuses `PreviewStackRunner.up`, now with `extra_env` passthrough); TTL countdown → teardown, data burned (`compose down -v`); scenario/stub injection `inject_scenario(session_id, scenario_id)` runs the sample's recorded fixture via `docker compose exec`, every injection logged `[stub] <scenario> -> <cmd>` (hard rule: demo path never calls real third-party APIs); iOS kind: `xcrun simctl` boot + (optional) app install + launch + shutdown on Mac host, concurrency cap 2 with persisted queue (position + ETA, daemon dispatcher starts next when a slot frees), shorter TTL (15 min); per-session LLM attribution: `FUSION_LLM_API_KEY` (fk- key) + `FUSION_LLM_BASE_URL` (:11432 gateway, single metering point) injected into compose env; `get_session`/`end_session`/`rollup(slug)` health badges (healthy/maintenance/unknown); library API (HTTP surface owned by consumer). Deadlock fix in the making: `_lock` is an `RLock` (TTL arm inside capacity-held lock).
- Live E2E verified: web session up → healthy → scenario injection (stub file served, `[stub]` log emitted) → TTL teardown → cross-session burn check (session B sees no session A data); iOS: 2 simulators booted concurrently + queue position reported + shutdown_all clean; ports verified inside 11600-11669. +9 Python tests (`test_demo_sessions.py`, live classes skip when docker daemon / xcrun unavailable).
- Deferred (out of scope, tracked upstream): WebRTC/noVNC screen streaming (web container + simulator), Android emulator container (Linux demo host), gateway `/v1/cost` metering verification — follow-up issue filed.

## [0.2.23] — 2026-11

### Added
- Automated sandbox preview stack runner (issue #65, companion to fusion-cowork#422): `PreviewStackRunner` + `PreviewProject` (`python/fusion_executor/preview_stack.py`) — per-project docker compose overlay (ordered `compose_files` base→overlay + `profile`), synthetic demo data injection via project-provided `seed_cmd` (`docker compose exec`, never real customer data), health-check gate before URL issuance (`/healthz` poll; unhealthy stack auto-torn-down, no URL issued), preview URL `http://127.0.0.1:<host_port>/` with `PREVIEW_HOST_PORT`/`PREVIEW_SERVICE_PORT` env injection into compose, TTL auto-teardown (daemon timer) + explicit `teardown`/`teardown_all`, port-in-use pre-flight probe (fail visibly), state persisted `<workspace>/<name>.json`, idempotent `up` (healthy re-up returns same URL), `notify` hook for readiness notification (email channel owned by consumer, e.g. cowork cow#404). Provision = clone (https with ssh fallback) / `git pull --ff-only`. No CLI by design (library API for cowork pipeline consumption). Port-registry note: preview binds 127.0.0.1 ephemeral/unregistered test ports only — no new business ports in this repo (check-ports unchanged).
- Live E2E verified: fixture repo (nginx:alpine + overlay profile) → clone/compose up → health 200 → synthetic seed file served → idempotent re-up → teardown clean (0 leftover containers); unhealthy-stack auto-teardown verified. +8 Python tests (`test_preview_stack.py`, live class skipped when docker daemon unavailable).

## [0.2.22] — 2026-11

### Added
- Demo/test environment sandbox runner (issue #64): `DemoEnvRunner` (`python/fusion_executor/demo_env.py`) — guest runs ONE ai-* app, heavy deps consumed from the host. Provision (clone https w/ ssh fallback, shared venv, `pip install -e` when `pyproject.toml` present), start via the app's own `start.sh` (missing → visible error + manual hint, never silently skipped), `up`/`status`/`stop` idempotent actions, single-app-per-guest policy, host gateway probe (`/healthz` then `/v1/models`) informational only. App process runs via `shell_start` with `SandboxProfile(network=allow)` + env wiring `FUSION_LLM_BASE_URL`/`FUSION_MLX_URL` → host gateway. CLI: `--demo-up REPO_URL` / `--demo-status` / `--demo-stop` (+ `--demo-workspace` / `--demo-llm-url` / `--demo-env`).
- `shell_start` gains optional per-shell `sandbox: SandboxProfile` (4-layer additive plumb: fe-shell `ShellStartParams.sandbox_profile` → `SandboxConfig`, fe-ipc serde param, fe-pyo3 PyAny bridge, Python kwarg; `None` = byte-identical prior behavior).

## [0.2.21] — 2026-11

### Added
- fusion docs-system v1.1 adoption: `docs/product-page.md`, `docs/get-started.md`, `docs/api-reference.md`, `docs/config-reference.md`, `docs/troubleshooting.md`, `docs/guides/`, `ci/validate_docs.py` (frontmatter + link validator, stdlib only), `.github/workflows/docs.yml`; contract frontmatter on existing markdown docs. Grid classification: platform x service.

### Fixed
- CI runner label `macos-14` → `macos-latest` (macos-15) — unblocks queued jobs on retired-runner label.
- fe-security resolved-path check: trust `/opt/homebrew/opt/rustup/bin` (Homebrew rustup shim dir) — macos-15 runner PATH resolves bare `cargo` there; same trust class as the Homebrew prefix (package-manager-managed, root-owned).

## [0.2.20] — 2026-11

### Changed
- Single-point key/env resolution via `fusion_core.config` — issue #60: `client_key()` / `default_mlx_base_url()`, no hand-rolled resolvers, no secret default literals. Dev missing key = empty + warning; prod = RuntimeError. (PR #61)

## [0.2.19]

### Added
- Shared async batch-task service `TaskManager` — issue #57: task_id polling, queued→running→done/failed/cancelled state machine, retry backoff, SQLite persistence across restarts, `TASK_PROGRESS:` live progress protocol, result export/report.

> Note: this file was created during docs-system onboarding; sections before 0.2.20 are a summary. Per-version release history lives in `CLAUDE.md` (project status) and git tags.
