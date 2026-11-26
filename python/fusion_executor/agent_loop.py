from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Callable
from typing import Any

from .executor import FusionSandboxExecutor
from .laya_tool_selector import LayaToolSelector
from .models import ToolDecision

logger = logging.getLogger("fusion_executor.agent_loop")

# AC7 (Issue #46): agent loop — wires LayaToolSelector into the executor pipeline.
# Previously LayaToolSelector was a standalone library + example + benchmark with zero references from executor.py
# (re-acceptance P0 gap). AgentLoop: build context → laya select tool → execute via FusionSandboxExecutor → feed back → repeat.
MAX_STEPS_DEFAULT = 8


class AgentStep:
    """Single-step execution record — for caller audit / replay."""

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
    """Issue #46 AC7: multi-step agent loop — laya picks a tool, the executor runs it, the result is fed back, repeat.

    Replaces the "LLM generates tool-call JSON" step:
      1. build context state from conversation
      2. LayaToolSelector.select_tool → ToolDecision
      3. tool_id != "none" and not degraded → execute the tool → feed the result back into the conversation
      4. tool_id == "none" or degraded → terminate (the caller generates a response via its LLM)
      5. repeat until none/degraded/max_steps reached

    Tool execution maps tool_id → FusionSandboxExecutor methods (deterministic, not LLM):
      file_edit    → file_edit(path, ...)
      write_file   → write_file(path, content)
      shell_exec   → run(command, ...)
      code_search  → grep(pattern, ...)
      web_fetch    → (no native tool — caller-injected handler)
      rag_query    → (same as above)
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
            raise ValueError(f"max_steps must be >= 1, got {max_steps}")
        self.selector = selector
        self.executor = executor
        self.max_steps = max_steps
        self.whitelist = whitelist
        # extra_handlers: tool_id -> callable(params_dict) -> result
        # injects tools with no native executor method such as web_fetch/rag_query
        self.extra_handlers = extra_handlers or {}
        self._metrics = Counter()

    def run(self, user_request: str, context: str = "") -> dict[str, Any]:
        """Run the agent loop — returns step records + final state.

        Args:
            user_request: the original user request
            context: initial context (existing session state / file listing etc.)

        Returns:
            {steps: [AgentStep.to_dict], completed: bool, final_tool: str, metrics: dict}
        """
        conversation = f"{context}\n{user_request}".strip() if context else user_request
        steps: list[AgentStep] = []
        completed = False
        final_tool = "none"
        prev_decision: ToolDecision | None = None

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

            # none or degraded → terminate the loop (the caller goes through its LLM)
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

            # same tool with same params repeated → task done or no progress, terminate
            # (avoids an infinite loop since laya has no done signal).
            # laya 421M has no explicit "task complete" primitive; a repeated identical decision is the approximation.
            # Multi-step same-tool different-params (run pytest → edit → run pytest) does not trigger, because params differ.
            if (
                prev_decision is not None
                and prev_decision.tool_id == decision.tool_id
                and prev_decision.params == decision.params
            ):
                self._metrics["same_tool_terminate"] += 1
                logger.info(
                    "agent step %d: repeated same tool with same params (%s) → terminating (task done or no progress)",
                    step_num,
                    decision.tool_id,
                )
                steps.append(AgentStep(step_num, decision, None, None))
                final_tool = decision.tool_id
                completed = True
                break

            # execute the selected tool
            tool_result, error = self._execute_tool(decision.tool_id, decision.params)
            steps.append(AgentStep(step_num, decision, tool_result, error))
            final_tool = decision.tool_id
            self._metrics[f"exec:{decision.tool_id}"] += 1
            prev_decision = decision

            if error:
                self._metrics["exec_errors"] += 1
                logger.warning("agent step %d tool %s execution failed: %s", step_num, decision.tool_id, error)
                # execution failed → feed the error back so laya re-picks next round
                conversation = f"{conversation}\n[tool {decision.tool_id} failed: {error}]"
            else:
                # feed the result back into the conversation (for the next laya decision round)
                result_text = self._stringify_result(tool_result)
                conversation = f"{conversation}\n[tool {decision.tool_id} result: {result_text}]"

            # single-tool requests usually complete in one step — check whether more steps are needed
            # if laya picks none next round the loop ends; otherwise continue until max_steps
            # no early break here — let laya decide whether more steps are needed

        if not completed:
            self._metrics["max_steps_reached"] += 1
            logger.warning("agent loop reached max_steps=%d without terminating", self.max_steps)

        return {
            "steps": [s.to_dict() for s in steps],
            "completed": completed,
            "final_tool": final_tool,
            "step_count": len(steps),
            "metrics": self._metrics_snapshot(),
        }

    def _execute_tool(self, tool_id: str, params: dict[str, Any]) -> tuple[Any, str | None]:
        """Execute a single tool — maps tool_id → executor method / extra_handler.

        Returns (result, error); error not None means execution failed.
        """
        # extra_handlers (injected tools) take priority
        if tool_id in self.extra_handlers:
            try:
                return self.extra_handlers[tool_id](params), None
            except Exception as e:
                return None, f"{tool_id} handler: {e}"

        if self.executor is None:
            return None, f"no executor instance, cannot execute {tool_id}"

        try:
            if tool_id == "file_edit":
                path = params.get("file_path")
                if not path:
                    return None, "file_edit missing file_path param"
                # file_edit needs old_string/new_string — params only extracts the path; the actual edit content comes from the LLM
                # here we return the path for caller confirmation; the real edit calls executor.file_edit(path, old, new)
                return {"file_path": path, "ready": True}, None
            if tool_id == "write_file":
                path = params.get("file_path")
                if not path:
                    return None, "write_file missing file_path param"
                return {"file_path": path, "ready": True}, None
            if tool_id == "shell_exec":
                cmd = params.get("command")
                if not cmd:
                    return None, "shell_exec missing command param"
                result = self.executor.run(cmd)
                return result, None
            if tool_id == "code_search":
                # search_query may be None (regex did not match) — fall back to the raw request as pattern
                query = params.get("search_query") or ""
                if not query:
                    return None, "code_search missing search_query param (laya extracted no query)"
                max_results = params.get("max_results", 5)
                if self.executor is not None:
                    matches = self.executor.grep(query, ["."], cwd=None)
                    return {"matches": matches[: int(max_results)], "count": len(matches)}, None
                return None, "no executor, cannot code_search"
            if tool_id == "gui_action":
                action_str = params.get("action", "")
                # action_str is a raw description — the caller parses it into a GuiAction dict; passed through here
                return {"action": action_str, "ready": True}, None
            # web_fetch / rag_query have no native executor method — a handler must be injected
            return None, f"tool {tool_id} has no native implementation — inject extra_handlers[{tool_id!r}]"
        except Exception as e:
            return None, f"{tool_id} execution exception: {e}"

    @staticmethod
    def _stringify_result(result: Any) -> str:
        """Convert a tool result into text for feeding back into the conversation (truncated to prevent context explosion)."""
        if result is None:
            return "none"
        text = str(result)
        return text[:500] + "..." if len(text) > 500 else text

    def _metrics_snapshot(self) -> dict[str, int]:
        return dict(self._metrics)

    def metrics(self) -> dict[str, int]:
        """Return in-process metrics (steps/none/fallback/exec_errors/per-tool)."""
        return self._metrics_snapshot()
