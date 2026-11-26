from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# AC7 (Issue #46): AgentLoop tests — no real laya model dependency (mock LayaToolSelector).
# AC1: HTTP backend tests — never loads local laya_mlx (backend=http skips model loading).
# real laya model tests live in test_laya_tool_selector.py (importorskip + model-cache skip).
from fusion_executor import AgentLoop, AgentStep, LayaToolSelector, ToolDecision


def _make_decision(
    tool_id: str, confidence: float = 0.9, fell_back: bool = False, params: dict | None = None
) -> ToolDecision:
    return ToolDecision(
        tool_id=tool_id,
        confidence=confidence,
        probabilities={tool_id: confidence, "none": 1 - confidence},
        params=params or {},
        fell_back=fell_back,
        latency_ms=5.0,
        model="convaiinnovations/laya",
        usage=None,
    )


class FakeSelector:
    """Mock LayaToolSelector — returns a preset decision sequence."""

    def __init__(self, decisions: list[ToolDecision]) -> None:
        self._decisions = list(decisions)
        self._calls = 0

    def decide(self, state: str, whitelist=None) -> ToolDecision:
        if self._calls >= len(self._decisions):
            return _make_decision("none")
        d = self._decisions[self._calls]
        self._calls += 1
        return d

    def select_tool(self, state: str, whitelist=None) -> ToolDecision:
        return self.decide(state, whitelist)

    def metrics(self) -> dict:
        return {"total": self._calls}


class TestAgentLoopWiring:
    """AC7: LayaToolSelector wired into the executor pipeline (P0 gap)."""

    def test_none_terminates_immediately(self):
        """tool_id='none' → single step done, completed=True."""
        sel = FakeSelector([_make_decision("none")])
        loop = AgentLoop(sel, executor=None)
        result = loop.run("hello there")
        assert result["completed"] is True
        assert result["final_tool"] == "none"
        assert result["step_count"] == 1

    def test_fallback_terminates(self):
        """degraded (fell_back=True) → terminate, final_tool='llm_fallback'."""
        sel = FakeSelector([_make_decision("llm_fallback", fell_back=True)])
        loop = AgentLoop(sel, executor=None)
        result = loop.run("ambiguous request")
        assert result["completed"] is True
        assert result["final_tool"] == "llm_fallback"

    def test_tool_executed_then_none(self):
        """pick tool → execute → next round none → done (2 steps)."""
        sel = FakeSelector(
            [
                _make_decision("file_edit", params={"file_path": "src/main.py"}),
                _make_decision("none"),
            ]
        )
        loop = AgentLoop(sel, executor=None)
        result = loop.run("edit src/main.py")
        assert result["completed"] is True
        assert result["step_count"] == 2
        assert result["steps"][0]["tool_id"] == "file_edit"
        assert result["steps"][1]["tool_id"] == "none"

    def test_shell_exec_with_mock_executor(self):
        """shell_exec → calls executor.run(command) → result fed back."""
        mock_executor = MagicMock()
        mock_executor.run.return_value = MagicMock(ok=True, stdout="all tests passed", exit_code=0)
        sel = FakeSelector(
            [
                _make_decision("shell_exec", params={"command": "pytest"}),
                _make_decision("none"),
            ]
        )
        loop = AgentLoop(sel, executor=mock_executor)
        result = loop.run("run pytest")
        assert result["steps"][0]["tool_id"] == "shell_exec"
        assert result["steps"][0]["has_result"] is True
        mock_executor.run.assert_called_once_with("pytest")

    def test_code_search_with_mock_executor(self):
        """code_search → calls executor.grep → returns matches."""
        mock_executor = MagicMock()
        mock_executor.grep.return_value = ["line1", "line2", "line3"]
        sel = FakeSelector(
            [
                _make_decision("code_search", params={"search_query": "TODO", "max_results": 2}),
                _make_decision("none"),
            ]
        )
        loop = AgentLoop(sel, executor=mock_executor)
        result = loop.run("find TODO")
        assert result["steps"][0]["tool_id"] == "code_search"
        mock_executor.grep.assert_called_once_with("TODO", ["."], cwd=None)

    def test_extra_handler_injected(self):
        """web_fetch has no native executor method → injected extra_handler executes it."""
        sel = FakeSelector(
            [
                _make_decision("web_fetch", params={"url": "https://example.com"}),
                _make_decision("none"),
            ]
        )
        handler_calls = []

        def fetch_handler(params):
            handler_calls.append(params)
            return {"content": "<html>example</html>"}

        loop = AgentLoop(sel, executor=None, extra_handlers={"web_fetch": fetch_handler})
        result = loop.run("fetch https://example.com")
        assert result["steps"][0]["tool_id"] == "web_fetch"
        assert result["steps"][0]["has_result"] is True
        assert len(handler_calls) == 1

    def test_tool_without_handler_errors(self):
        """web_fetch with no executor and no handler → error fed back, loop continues."""
        sel = FakeSelector(
            [
                _make_decision("web_fetch", params={"url": "https://example.com"}),
                _make_decision("none"),
            ]
        )
        loop = AgentLoop(sel, executor=None)
        result = loop.run("fetch https://example.com")
        assert result["steps"][0]["error"] is not None
        assert "web_fetch" in result["steps"][0]["error"]

    def test_max_steps_reached(self):
        """keeps picking tools with different args → stops at max_steps, completed=False."""
        decisions = [_make_decision("file_edit", params={"file_path": f"a{i}.py"}) for i in range(10)]
        sel = FakeSelector(decisions)
        loop = AgentLoop(sel, executor=None, max_steps=3)
        result = loop.run("edit many files")
        assert result["completed"] is False
        assert result["step_count"] == 3

    def test_same_tool_same_params_terminates(self):
        """same tool with same args repeated → terminate (task done or no progress, avoids an infinite loop when laya has no done signal).

        step1: file_edit(a.py) executes → step2: laya picks file_edit(a.py) with the same args again → terminate.
        """
        sel = FakeSelector(
            [
                _make_decision("file_edit", params={"file_path": "a.py"}),
                _make_decision("file_edit", params={"file_path": "a.py"}),
            ]
        )
        loop = AgentLoop(sel, executor=None, max_steps=8)
        result = loop.run("edit a.py")
        assert result["completed"] is True
        assert result["step_count"] == 2
        assert result["metrics"]["same_tool_terminate"] == 1

    def test_same_tool_diff_params_continues(self):
        """same tool with different args → do not terminate (multi-step same tool is legal: edit a.py → edit b.py)."""
        sel = FakeSelector(
            [
                _make_decision("file_edit", params={"file_path": "a.py"}),
                _make_decision("file_edit", params={"file_path": "b.py"}),
                _make_decision("none"),
            ]
        )
        loop = AgentLoop(sel, executor=None, max_steps=8)
        result = loop.run("edit a.py then b.py")
        assert result["completed"] is True
        assert result["step_count"] == 3
        assert "same_tool_terminate" not in result["metrics"]

    def test_invalid_max_steps(self):
        """max_steps < 1 → ValueError."""
        with pytest.raises(ValueError, match="max_steps"):
            AgentLoop(FakeSelector([]), max_steps=0)

    def test_metrics_tracked(self):
        """metric counters: steps/none/exec/tool."""
        mock_executor = MagicMock()
        mock_executor.run.return_value = MagicMock(ok=True)
        sel = FakeSelector(
            [
                _make_decision("shell_exec", params={"command": "ls"}),
                _make_decision("none"),
            ]
        )
        loop = AgentLoop(sel, executor=mock_executor)
        loop.run("run ls")
        m = loop.metrics()
        assert m["steps"] == 2
        assert m["none"] == 1
        assert m["exec:shell_exec"] == 1

    def test_step_to_dict(self):
        """AgentStep.to_dict serializes correctly."""
        d = _make_decision("file_edit", params={"file_path": "a.py"})
        step = AgentStep(1, d, {"ready": True}, None)
        sd = step.to_dict()
        assert sd["step"] == 1
        assert sd["tool_id"] == "file_edit"
        assert sd["params"] == {"file_path": "a.py"}
        assert sd["has_result"] is True
        assert sd["error"] is None

    def test_result_stringified_truncated(self):
        """long results truncated to 500 chars to prevent context explosion."""
        long_result = "x" * 1000
        truncated = AgentLoop._stringify_result(long_result)
        assert len(truncated) == 503  # 500 + "..."
        assert truncated.endswith("...")


class TestHTTPBackend:
    """AC1: HTTP backend — LayaToolSelector via /v1/laya/decide (no local model loaded)."""

    def test_http_backend_no_laya_mlx_required(self):
        """HTTP backend does not import laya_mlx (no local model dependency)."""
        # must not trigger a laya_mlx ImportError — backend=http skips model loading
        with patch("httpx.Client") as mock_client:
            mock_client.return_value = MagicMock()
            sel = LayaToolSelector(backend="http", mlx_url="http://localhost:11434/v1", api_key="test-key")
            assert sel.backend == "http"
            assert sel._decide_url == "http://localhost:11434/v1/laya/decide"

    def test_invalid_backend_rejected(self):
        with pytest.raises(ValueError, match="backend"):
            LayaToolSelector(backend="invalid")

    def test_http_invoke_posts_questions(self):
        """_invoke_http POSTs {prompt, questions, model} to /v1/laya/decide."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "model": "laya",
            "answers": {
                "tool": {
                    "type": "choice",
                    "choice": "file_edit",
                    "confidence": 0.8,
                    "probabilities": {"file_edit": 0.8, "none": 0.2},
                }
            },
            "usage": {"input_tokens": 10},
            "latency_ms": 6.0,
        }
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp

        sel = LayaToolSelector.__new__(LayaToolSelector)
        sel.backend = "http"
        sel._http_client = mock_client
        sel._decide_url = "http://localhost:11434/v1/laya/decide"
        sel.model_id = "convaiinnovations/laya"

        result = sel._invoke(
            "edit main.py",
            {
                "tool": {
                    "type": "choice",
                    "instructions": "which tool",
                    "criteria": {"file_edit": "edit file", "none": "no tool"},
                }
            },
        )
        assert result["answers"]["tool"]["choice"] == "file_edit"
        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        payload = call_args[1]["json"]
        assert payload["prompt"] == "edit main.py"
        assert "questions" in payload
        assert payload["model"] == "convaiinnovations/laya"


class TestAgentRunOnExecutor:
    """AC7 wiring acceptance: FusionSandboxExecutor.agent_run — AgentLoop runs through the executor pipeline.

    No real laya model dependency (mock LayaToolSelector via patch). Verifies the agent_run method exists,
    constructs AgentLoop, executes tools with self as the executor, and returns step records.
    """

    def test_agent_run_method_exists(self):
        """FusionSandboxExecutor exposes the agent_run method (wired, not a dead class)."""
        from fusion_executor import FusionSandboxExecutor

        assert callable(getattr(FusionSandboxExecutor, "agent_run", None)), (
            "agent_run not wired into FusionSandboxExecutor — AgentLoop is a dead class (violates #46 AC7)"
        )

    def test_agent_run_none_terminates(self):
        """agent_run: laya picks none → single step done, completed=True."""
        from fusion_executor import FusionSandboxExecutor

        with (
            patch("fusion_executor.laya_tool_selector.LayaToolSelector") as mock_sel_cls,
            patch("fusion_executor.agent_loop.AgentLoop") as mock_loop_cls,
        ):
            mock_sel = MagicMock()
            mock_sel_cls.return_value = mock_sel
            mock_loop = MagicMock()
            mock_loop_cls.return_value = mock_loop
            mock_loop.run.return_value = {
                "steps": [{"step": 1, "tool_id": "none"}],
                "completed": True,
                "final_tool": "none",
                "step_count": 1,
                "metrics": {"steps": 1, "none": 1},
            }

            ex = FusionSandboxExecutor()
            result = ex.agent_run("hello there", max_steps=4)

            assert result["completed"] is True
            assert result["final_tool"] == "none"
            mock_sel_cls.assert_called_once()
            mock_loop_cls.assert_called_once_with(
                mock_sel, executor=ex, max_steps=4, whitelist=None, extra_handlers=None
            )
            mock_loop.run.assert_called_once_with("hello there", context="")

    def test_agent_run_invalid_max_steps(self):
        """agent_run: max_steps < 1 → ValueError."""
        from fusion_executor import FusionSandboxExecutor

        ex = FusionSandboxExecutor()
        with pytest.raises(ValueError, match="max_steps"):
            ex.agent_run("hi", max_steps=0)

    def test_agent_run_invalid_request_type(self):
        """agent_run: user_request not a str → TypeError."""
        from fusion_executor import FusionSandboxExecutor

        ex = FusionSandboxExecutor()
        with pytest.raises(TypeError, match="user_request"):
            ex.agent_run(123)

    def test_agent_run_passes_backend_and_confidence(self):
        """agent_run: backend/min_confidence/whitelist passed through to LayaToolSelector + AgentLoop."""
        from fusion_executor import FusionSandboxExecutor

        with (
            patch("fusion_executor.laya_tool_selector.LayaToolSelector") as mock_sel_cls,
            patch("fusion_executor.agent_loop.AgentLoop") as mock_loop_cls,
        ):
            mock_loop_cls.return_value = MagicMock(
                run=MagicMock(
                    return_value={
                        "completed": True,
                        "final_tool": "shell_exec",
                        "step_count": 2,
                        "metrics": {"steps": 2},
                    }
                )
            )
            ex = FusionSandboxExecutor()
            wl = {"shell_exec": "run cmd", "none": "no tool"}
            ex.agent_run(
                "run ls",
                max_steps=3,
                backend="http",
                mlx_url="http://localhost:11434/v1",
                api_key="test-key",
                min_confidence=0.8,
                whitelist=wl,
                context="prior state",
            )
            mock_sel_cls.assert_called_once_with(
                min_confidence=0.8,
                backend="http",
                mlx_url="http://localhost:11434/v1",
                api_key="test-key",
            )
            _, kwargs = mock_loop_cls.call_args
            assert kwargs["whitelist"] == wl
            assert kwargs["max_steps"] == 3
            mock_loop_cls.return_value.run.assert_called_once_with("run ls", context="prior state")
