# 文档索引

> **语言 / Language**: [English](INDEX.md) | **中文**

fusion-executor 全部文档导航。v0.1.0 —— Fusion 生态的受控执行沙箱 + macOS 系统级控制中枢。

## 从这里开始

| 文档 | 覆盖内容 |
|------|----------|
| [README.md](../README.md) | 项目概览、四大核心子系统、构建/测试/检查命令、数据契约、生态集成、NFR。从此处入门。 |
| [CLAUDE.md](../CLAUDE.md) | Claude Code 工作指南: 项目状态 (逐版本变更记录)、构建/测试/检查、Python API 全貌、4 层 wiring 笔记、单仓约定、关键路径。 |
| [examples/README.md](../examples/README.md) | 可运行示例索引 —— 7 个 Python + 1 个 Rust + 1 个 TypeScript, 含演示内容与运行方法。 |

## 架构与设计

| 文档 | 覆盖内容 |
|------|----------|
| [docs/architecture.md](architecture.md) | 仓内架构: 10 crate 布局、4 层 wiring (fe-core → fe-ipc → fe-pyo3 → Python)、管线图、各 crate 职责。 |
| PRD (单仓级) | 完整 PRD 在 `../../architecture/fusion-executor-prd.md` (单仓根 `architecture/` 目录): §4 数据契约 (ExecutionRequest/ExecutionResult 字段)、§4.2 诊断切片算法、fusion-code 重构计划、Claude-SDK/DeepSeek-Harness 能力对比。 |
| 审计 (单仓级) | `../../audit/fusion-executor-audit-report-0825.md` —— 商用级集成审计 (10 CRITICAL / 23 MAJOR / 4 MINOR); audit-0825-pass 记忆记录了全部 11 Blocker + 13 MAJOR/MINOR 已落地。 |

## IPC 集成

| 文档 | 覆盖内容 |
|------|----------|
| [docs/ipc-client-typescript.md](ipc-client-typescript.md) | 面向 TypeScript 消费方 (fusion-code) 的 UDS JSON-RPC 2.0 协议: 方法表、错误码、`FusionExecutorClient` 草稿。可运行版本见 [examples/uds_client_typescript.ts](../examples/uds_client_typescript.ts)。 |

## 线上契约参考

数据契约 (Pydantic 模型 ↔ Rust serde 结构体) 内联记录在 `CLAUDE.md` ("Data Schema (Pydantic)" 段) 及 PRD §4。关键模型:

- `ExecutionRequest` → `ExecutionResult` (exit_code 0/-124/-1; `diagnostics`、`snapshot_id`、`auto_rolled_back`)。
- `EditResult` / `GlobEntry` / `GrepMatch` (原生文件工具)。
- `TelemetrySample` / `TelemetryConfig` (10Hz 遥测)。
- `RollbackPolicy` (可选自动回滚 kwarg)。
- `GuiResult` (16 个 GuiAction 变体)。

## 逐版本变更记录

完整逐版本构建历史 (v1 P1–P5 至 v1.5、审计 T1–T9、审计-0825 Blocker、v0.1.0 发布) 见 `CLAUDE.md` "Project Status"。发布标签为 `v0.1.0` (annotated, 已推送)。
