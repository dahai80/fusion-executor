from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Callable
from typing import Any

from .executor import FusionSandboxExecutor
from .laya_tool_selector import LayaToolSelector
from .models import ToolDecision

logger = logging.getLogger("fusion_executor.agent_loop")

# AC7 (Issue #46): Agent loop — 把 LayaToolSelector 接进 executor 管线。
# 之前 LayaToolSelector 是独立库 + example + benchmark, executor.py 零引用 (re-acceptance P0 gap)。
# AgentLoop: build context → laya select tool → execute via FusionSandboxExecutor → feed back → repeat。
MAX_STEPS_DEFAULT = 8


class AgentStep:
    """单步执行记录 — 供调用方审计 / 回放。"""

    def __init__(self, step: int, decision: ToolDecision, tool_result: Any, error: str | None) -> None:
        self.step = step
        self.decision = decision
        self.tool_result = tool_result
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "tool_id": self.decision.tool_id,
            "confidence": self.decision.confidence,
            "params": self.decision.params,
            "fell_back": self.decision.fell_back,
            "latency_ms": self.decision.latency_ms,
            "has_result": self.tool_result is not None,
            "error": self.error,
        }


class AgentLoop:
    """Issue #46 AC7: 多步 agent 循环 — laya 选工具, executor 执行, 结果回灌, 重复。

    替代 "LLM 生成 tool call JSON" 步骤:
      1. build context state from conversation
      2. LayaToolSelector.select_tool → ToolDecision
      3. tool_id != "none" 且非降级 → 执行工具 → 结果回灌 conversation
      4. tool_id == "none" 或降级 → 终止 (调用方走 LLM 生成响应)
      5. 重复直到 none/降级/达到 max_steps

    工具执行映射 tool_id → FusionSandboxExecutor 方法 (确定性, 非 LLM):
      file_edit    → file_edit(path, ...)
      write_file   → write_file(path, content)
      shell_exec   → run(command, ...)
      code_search  → grep(pattern, ...)
      web_fetch    → (无原生工具 — 调用方注入 handler)
      rag_query    → (同上)
      gui_action   → gui_action(action)
    """

    def __init__(
        self,
        selector: LayaToolSelector,
        executor: FusionSandboxExecutor | None = None,
        *,
        max_steps: int = MAX_STEPS_DEFAULT,
        whitelist: dict[str, str] | None = None,
        extra_handlers: dict[str, Callable[[dict], Any]] | None = None,
    ) -> None:
        if max_steps < 1:
            raise ValueError(f"max_steps 须 >= 1, got {max_steps}")
        self.selector = selector
        self.executor = executor
        self.max_steps = max_steps
        self.whitelist = whitelist
        # extra_handlers: tool_id -> callable(params_dict) -> result
        # 注入 web_fetch/rag_query 等无原生 executor 方法的工具
        self.extra_handlers = extra_handlers or {}
        self._metrics = Counter()

    def run(self, user_request: str, context: str = "") -> dict[str, Any]:
        """执行 agent 循环 — 返回步骤记录 + 最终状态。

        Args:
            user_request: 用户原始请求
            context: 初始上下文 (已有会话状态 / 文件列表等)

        Returns:
            {steps: [AgentStep.to_dict], completed: bool, final_tool: str, metrics: dict}
        """
        conversation = f"{context}\n{user_request}".strip() if context else user_request
        steps: list[AgentStep] = []
        completed = False
        final_tool = "none"

        for step_num in range(1, self.max_steps + 1):
            self._metrics["steps"] += 1
            decision = self.selector.decide(conversation, self.whitelist)
            logger.info(
                "agent step %d: tool=%s conf=%.3f fell_back=%s",
                step_num,
                decision.tool_id,
                decision.confidence,
                decision.fell_back,
            )

            # none 或降级 → 终止循环 (调用方走 LLM)
            if decision.tool_id == "none":
                self._metrics["none"] += 1
                steps.append(AgentStep(step_num, decision, None, None))
                final_tool = "none"
                completed = True
                break
            if decision.fell_back or decision.tool_id == "llm_fallback":
                self._metrics["fallback"] += 1
                steps.append(AgentStep(step_num, decision, None, None))
                final_tool = "llm_fallback"
                completed = True
                break

            # 执行选中工具
            tool_result, error = self._execute_tool(decision.tool_id, decision.params)
            steps.append(AgentStep(step_num, decision, tool_result, error))
            final_tool = decision.tool_id
            self._metrics[f"exec:{decision.tool_id}"] += 1

            if error:
                self._metrics["exec_errors"] += 1
                logger.warning("agent step %d tool %s 执行失败: %s", step_num, decision.tool_id, error)
                # 执行失败 → 回灌错误信息, 让 laya 下一轮重选
                conversation = f"{conversation}\n[tool {decision.tool_id} failed: {error}]"
            else:
                # 结果回灌 conversation (供下一轮 laya 决策)
                result_text = self._stringify_result(tool_result)
                conversation = f"{conversation}\n[tool {decision.tool_id} result: {result_text}]"

            # 单工具请求通常一步即完成 — 检查是否还需继续
            # 若 laya 下一轮选 none 则终止; 否则继续直到 max_steps
            # 此处不提前 break — 让 laya 自行决定是否需要更多步骤

        if not completed:
            self._metrics["max_steps_reached"] += 1
            logger.warning("agent loop 达 max_steps=%d 未终止", self.max_steps)

        return {
            "steps": [s.to_dict() for s in steps],
            "completed": completed,
            "final_tool": final_tool,
            "step_count": len(steps),
            "metrics": self._metrics_snapshot(),
        }

    def _execute_tool(self, tool_id: str, params: dict[str, Any]) -> tuple[Any, str | None]:
        """执行单个工具 — 映射 tool_id → executor 方法 / extra_handler。

        返回 (result, error); error 非 None 表示执行失败。
        """
        # 优先 extra_handlers (注入的工具)
        if tool_id in self.extra_handlers:
            try:
                return self.extra_handlers[tool_id](params), None
            except Exception as e:
                return None, f"{tool_id} handler: {e}"

        if self.executor is None:
            return None, f"无 executor 实例, 无法执行 {tool_id}"

        try:
            if tool_id == "file_edit":
                path = params.get("file_path")
                if not path:
                    return None, "file_edit 缺 file_path 参数"
                # file_edit 需 old_string/new_string — params 仅提取 path, 实际编辑内容由 LLM 提供
                # 此处返回 path 供调用方确认; 真正编辑调 executor.file_edit(path, old, new)
                return {"file_path": path, "ready": True}, None
            if tool_id == "write_file":
                path = params.get("file_path")
                if not path:
                    return None, "write_file 缺 file_path 参数"
                return {"file_path": path, "ready": True}, None
            if tool_id == "shell_exec":
                cmd = params.get("command")
                if not cmd:
                    return None, "shell_exec 缺 command 参数"
                result = self.executor.run(cmd)
                return result, None
            if tool_id == "code_search":
                # search_query 可能为 None (regex 未匹配) — 回退用请求原文作 pattern
                query = params.get("search_query") or ""
                if not query:
                    return None, "code_search 缺 search_query 参数 (laya 未提取到查询词)"
                max_results = params.get("max_results", 5)
                if self.executor is not None:
                    matches = self.executor.grep(query, ["."], cwd=None)
                    return {"matches": matches[: int(max_results)], "count": len(matches)}, None
                return None, "无 executor, 无法 code_search"
            if tool_id == "gui_action":
                action_str = params.get("action", "")
                # action_str 是原始描述 — 调用方解析为 GuiAction dict; 此处透传
                return {"action": action_str, "ready": True}, None
            # web_fetch / rag_query 无原生 executor 方法 — 须注入 handler
            return None, f"工具 {tool_id} 无原生实现 — 注入 extra_handlers[{tool_id!r}]"
        except Exception as e:
            return None, f"{tool_id} 执行异常: {e}"

    @staticmethod
    def _stringify_result(result: Any) -> str:
        """把工具结果转为回灌 conversation 的文本 (截断防 context 爆炸)。"""
        if result is None:
            return "none"
        text = str(result)
        return text[:500] + "..." if len(text) > 500 else text

    def _metrics_snapshot(self) -> dict[str, int]:
        return dict(self._metrics)

    def metrics(self) -> dict[str, int]:
        """返回进程内指标 (steps/none/fallback/exec_errors/per-tool)。"""
        return self._metrics_snapshot()
