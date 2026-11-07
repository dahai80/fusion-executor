---
doc_id: fusion-executor/changelog
product: fusion-executor
class: platform
entry: service
doc_type: changelog
title: {zh: "fusion-executor 变更日志", en: "fusion-executor Changelog"}
audience: engineer
status: draft
version: 0.2.20
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - CHANGELOG.md
  - pyproject.toml
---

# Changelog

All notable changes to fusion-executor are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/), semver versioning.

## [Unreleased]

### Changed
- Adopted the fusion docs-system v1.1 contract: added `docs/product-page.md`, `docs/get-started.md`, `docs/api-reference.md`, `docs/config-reference.md`, `docs/troubleshooting.md`, `docs/guides/`, `ci/validate_docs.py`, and `.github/workflows/docs.yml`; added contract frontmatter to existing markdown docs. Grid classification: platform x service. No functional code changes.

## [0.2.20] — 2026-11

### Changed
- Single-point key/env resolution via `fusion_core.config` — issue #60: `client_key()` / `default_mlx_base_url()`, no hand-rolled resolvers, no secret default literals. Dev missing key = empty + warning; prod = RuntimeError. (PR #61)

## [0.2.19]

### Added
- Shared async batch-task service `TaskManager` — issue #57: task_id polling, queued→running→done/failed/cancelled state machine, retry backoff, SQLite persistence across restarts, `TASK_PROGRESS:` live progress protocol, result export/report.

> Note: this file was created during docs-system onboarding; sections before 0.2.20 are a summary. Per-version release history lives in `CLAUDE.md` (project status) and git tags.
