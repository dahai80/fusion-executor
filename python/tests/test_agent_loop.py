from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# AC7 (Issue #46): AgentLoop tests — 不依赖 laya 真实模型 (mock LayaToolSelector)。
# AC1: HTTP backend tests — 不加载本地 laya_mlx (backend=http 跳过模型加载)。
# laya 真实模型测试在 test_laya_tool_selector.py (importorskip + 模型缓存跳过)。
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
    """Mock LayaToolSelector — 返回预设决策序列。"""

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
    """AC7: LayaToolSelector 接进 executor 管线 (P0 gap)。"""

    def test_none_terminates_immediately(self):
        """tool_id='none' → 单步完成, completed=True."""
        sel = FakeSelector([_make_decision("none")])
        loop = AgentLoop(sel, executor=None)
        result = loop.run("hello there")
        assert result["completed"] is True
        assert result["final_tool"] == "none"
        assert result["step_count"] == 1

    def test_fallback_terminates(self):
        """降级 (fell_back=True) → 终止, final_tool='llm_fallback'."""
        sel = FakeSelector([_make_decision("llm_fallback", fell_back=True)])
        loop = AgentLoop(sel, executor=None)
        result = loop.run("ambiguous request")
        assert result["completed"] is True
        assert result["final_tool"] == "llm_fallback"

    def test_tool_executed_then_none(self):
        """选工具 → 执行 → 下一轮 none → 完成 (2步)."""
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
        """shell_exec → 调 executor.run(command) → 结果回灌."""
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
        """code_search → 调 executor.grep → 返回 matches."""
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
        """web_fetch 无原生 executor 方法 → 注入 extra_handler 执行."""
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
        """web_fetch 无 executor 无 handler → error 回灌, 继续."""
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
        """持续选工具不停 → 达 max_steps 终止, completed=False."""
        sel = FakeSelector([_make_decision("file_edit", params={"file_path": "a.py"})] * 10)
        loop = AgentLoop(sel, executor=None, max_steps=3)
        result = loop.run("edit many files")
        assert result["completed"] is False
        assert result["step_count"] == 3

    def test_invalid_max_steps(self):
        """max_steps < 1 → ValueError."""
        with pytest.raises(ValueError, match="max_steps"):
            AgentLoop(FakeSelector([]), max_steps=0)

    def test_metrics_tracked(self):
        """指标计数器: steps/none/exec/tool."""
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
        """AgentStep.to_dict 序列化正确."""
        d = _make_decision("file_edit", params={"file_path": "a.py"})
        step = AgentStep(1, d, {"ready": True}, None)
        sd = step.to_dict()
        assert sd["step"] == 1
        assert sd["tool_id"] == "file_edit"
        assert sd["params"] == {"file_path": "a.py"}
        assert sd["has_result"] is True
        assert sd["error"] is None

    def test_result_stringified_truncated(self):
        """长结果截断 500 字符防 context 爆炸."""
        long_result = "x" * 1000
        truncated = AgentLoop._stringify_result(long_result)
        assert len(truncated) == 503  # 500 + "..."
        assert truncated.endswith("...")


class TestHTTPBackend:
    """AC1: HTTP backend — LayaToolSelector 经 /v1/laya/decide (不加载本地模型)."""

    def test_http_backend_no_laya_mlx_required(self):
        """HTTP backend 不 import laya_mlx (无本地模型依赖)."""
        # 不应触发 laya_mlx ImportError — backend=http 跳过模型加载
        with patch("httpx.Client") as mock_client:
            mock_client.return_value = MagicMock()
            sel = LayaToolSelector(backend="http", mlx_url="http://localhost:11434/v1", api_key="test-key")
            assert sel.backend == "http"
            assert sel._decide_url == "http://localhost:11434/v1/laya/decide"

    def test_invalid_backend_rejected(self):
        with pytest.raises(ValueError, match="backend"):
            LayaToolSelector(backend="invalid")

    def test_http_invoke_posts_questions(self):
        """_invoke_http POST {prompt, questions, model} 到 /v1/laya/decide."""
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
