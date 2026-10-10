from __future__ import annotations

import logging
import os
import re
import time
from collections import Counter
from typing import Any

from .models import ToolDecision

logger = logging.getLogger("fusion_executor.laya")

# Issue #46: 默认工具白名单 — 覆盖 fusion-executor 自有工具 + 常见 agent 工具。
# 调用方可传 whitelist dict 覆盖 (不同 workflow 不同工具集)。
DEFAULT_TOOL_WHITELIST: dict[str, str] = {
    "code_search": "search codebase for relevant files/functions/symbols",
    "file_edit": "modify existing file content (edit, patch, replace function)",
    "shell_exec": "execute shell command (build, test, run, install)",
    "write_file": "create or overwrite a whole file",
    "web_fetch": "fetch URL content from the web",
    "rag_query": "query knowledge base / documentation for answers",
    "gui_action": "interact with macOS GUI (click, type, screenshot, window control)",
    "none": "no tool needed, direct LLM response",
}

# 参数槽位定义: tool_id -> list of (slot_name, question_type, instructions, criteria)
# noul: yes/no 判断 "请求是否指定了 X" → 是则 regex 提取值
# score: 0-N 评分 → 映射整数 (如结果数量)
# 保持简单 — laya 判断参数是否出现, regex 提取值 (Rule 5: 能确定性的不用模型)
PARAM_SLOTS: dict[str, list[dict[str, Any]]] = {
    "file_edit": [
        {
            "slot": "file_path",
            "type": "noul",
            "instructions": "Does the request specify a file path to edit?",
            "extract": r"[\w./-]+\.\w+",
        },
    ],
    "write_file": [
        {
            "slot": "file_path",
            "type": "noul",
            "instructions": "Does the request specify a file path to create?",
            "extract": r"[\w./-]+\.\w+",
        },
    ],
    "code_search": [
        {
            "slot": "search_query",
            "type": "noul",
            "instructions": "Does the request specify what to search for?",
            "extract": r'(?:search|find|grep|locate)\s+(?:for\s+)?["\']?(.+?)["\']?(?:\s+in\s+|$)',
        },
        {
            "slot": "max_results",
            "type": "score",
            "instructions": "How many results should the search return? (0=few, 10=many)",
            "criteria": ["0 results", "1 result", "3 results", "5 results", "10 results", "20 results"],
            "scale": 1,  # score 值 × scale = 近似数量
        },
    ],
    "shell_exec": [
        {
            "slot": "command",
            "type": "noul",
            "instructions": "Does the request specify a shell command to run?",
            "extract": r'(?:run|execute|exec)\s+(?:command\s+)?["\']?(.+?)["\']?(?:\s+in\s+|$)',
        },
    ],
    "web_fetch": [
        {
            "slot": "url",
            "type": "noul",
            "instructions": "Does the request specify a URL to fetch?",
            "extract": r"https?://[\w./?=&%-]+",
        },
    ],
    "rag_query": [
        {
            "slot": "query",
            "type": "noul",
            "instructions": "Does the request specify a knowledge base query?",
            "extract": r'(?:query|ask|search)\s+(?:kb|knowledge|docs?|documentation)\s+(?:for\s+)?["\']?(.+?)["\']?(?:\s+in\s+|$)',
        },
    ],
    "gui_action": [
        {
            "slot": "action",
            "type": "noul",
            "instructions": "Does the request specify a GUI action (click/type/screenshot)?",
            "extract": r"(?:click|type|screenshot|scroll|drag|press|window)\s*[\w\s]*",
        },
    ],
}


class LayaToolSelector:
    """Issue #46: 基于 laya-mlx choice 原语的确定性工具选择器。

    替代 LLM 自由生成 tool call JSON — laya 从白名单中确定性选择工具,
    输出结构化 choice + 置信度, 消除 malformed JSON 和幻觉工具调用。

    直接调 laya_mlx.Agent.system_one (Python API), 不经 fusion-mlx HTTP —
    更低延迟 (warm 5-7ms vs HTTP round-trip), 无上游 endpoint 依赖。

    置信度门槛用 answer_confidence (max prob), 非 entropy confidence —
    laya-mlx confidence.py 明确 entropy "not calibrated" 不跨 option 数迁移。
    """

    def __init__(
        self,
        model_id: str = "convaiinnovations/laya",
        subfolder: str | None = "typed-decisions",
        min_confidence: float = 0.7,
        device: str | None = None,
        hf_cache: str | None = None,
    ) -> None:
        if min_confidence < 0 or min_confidence > 1:
            raise ValueError(f"min_confidence 须在 [0,1], got {min_confidence}")
        self.min_confidence = min_confidence
        self.model_id = model_id
        self.subfolder = subfolder

        # HF 模型缓存位置 — 默认 ~/.fusion-mlx/models (fusion monorepo 约定)
        # HF_HUB_CACHE env 覆盖; 镜像站 HF_MIRROR=https://hf-mirror.com (用户规则)
        cache = hf_cache or os.environ.get("HF_HUB_CACHE") or os.path.expanduser("~/.fusion-mlx/models")
        if os.path.isdir(cache) and not os.environ.get("HF_HUB_CACHE"):
            os.environ["HF_HUB_CACHE"] = cache

        try:
            from laya_mlx import Agent
        except ImportError as e:
            raise ImportError(
                "laya-mlx 未安装 — pip install laya-mlx (或 source .venv/bin/activate 共享 venv). "
                "Issue #46 确定性工具调用依赖 laya-mlx runtime."
            ) from e

        logger.info("加载 laya 模型 %s (subfolder=%s, device=%s)", model_id, subfolder, device or "auto")
        t0 = time.perf_counter()
        self._agent = (
            Agent(model_id, subfolder=subfolder, device=device) if subfolder else Agent(model_id, device=device)
        )
        load_ms = (time.perf_counter() - t0) * 1000
        logger.info("laya 模型加载完成 %.0fms", load_ms)

        # 指标计数器 (进程内, 非 Prometheus — Python 层决策, 不经 UDS)
        self._metrics = Counter()

    def select_tool(self, state: str, whitelist: dict[str, str] | None = None) -> ToolDecision:
        """从白名单中选择最佳工具 (choice 原语)。

        Args:
            state: 当前上下文状态 (用户请求 / 会话状态)
            whitelist: tool_id -> description; None 用 DEFAULT_TOOL_WHITELIST

        Returns:
            ToolDecision (不含参数 — 用 extract_params 补参数, 或调 decide 一步到位)
        """
        if whitelist is not None and len(whitelist) == 0:
            raise ValueError("whitelist 不能为空")
        wl = whitelist if whitelist is not None else DEFAULT_TOOL_WHITELIST

        questions = {
            "tool": {
                "type": "choice",
                "instructions": "Which tool should handle this request?",
                "criteria": wl,
            }
        }

        t0 = time.perf_counter()
        result = self._agent.system_one(state, questions)
        latency_ms = (time.perf_counter() - t0) * 1000

        ans = result["answers"]["tool"]
        tool_id = ans.get("choice", "none")
        # answer_confidence = max(p) — 门槛指标 (非 entropy confidence)
        confidence = ans.get("answer_confidence", ans.get("confidence", 0.0))
        probs = ans.get("probabilities", {})

        # "none" = "无需工具" 是正向决策, 不是不确定 — 门槛不触发降级 (issue #46: none → skip tool calling)
        fell_back = confidence < self.min_confidence and tool_id != "none"
        if fell_back:
            logger.warning(
                "laya 工具选择置信度 %.4f < 门槛 %.2f → LLM 降级 (state=%s, choice=%s)",
                confidence,
                self.min_confidence,
                state[:80],
                tool_id,
            )
            self._metrics["fell_back"] += 1
            decision_tool = "llm_fallback"
        else:
            self._metrics[f"tool:{tool_id}"] += 1
            decision_tool = tool_id

        self._metrics["total"] += 1
        self._metrics["latency_ms_sum"] += latency_ms

        logger.info(
            "laya select: tool=%s confidence=%.4f latency=%.1fms fell_back=%s state=%s",
            tool_id,
            confidence,
            latency_ms,
            fell_back,
            state[:60],
        )

        return ToolDecision(
            tool_id=decision_tool,
            confidence=round(confidence, 4),
            probabilities={k: round(v, 4) for k, v in probs.items()},
            params={},
            fell_back=fell_back,
            latency_ms=round(latency_ms, 2),
            model=self.model_id,
            usage=result.get("usage"),
        )

    def extract_params(self, state: str, tool_id: str) -> dict[str, str | int | None]:
        """为选中工具提取参数槽位 (noul/score 原语 + regex)。

        laya 判断参数是否出现 (noul yes/no) 或数量 (score 0-N),
        regex 提取具体值 — 不用 LLM (Rule 5: 能确定性的不用模型)。
        """
        slots_def = PARAM_SLOTS.get(tool_id, [])
        if not slots_def:
            return {}

        questions: dict[str, dict[str, Any]] = {}
        slot_map: dict[str, dict[str, Any]] = {}
        for sd in slots_def:
            qid = f"slot_{sd['slot']}"
            slot_map[qid] = sd
            q: dict[str, Any] = {
                "type": sd["type"],
                "instructions": sd["instructions"],
            }
            # noul: 默认 labels {"false","true"} — 不传 criteria/labels, 用默认
            # score: criteria 是 list (各级别描述)
            if sd["type"] == "score":
                q["criteria"] = sd["criteria"]
            questions[qid] = q

        if not questions:
            return {}

        result = self._agent.system_one(state, questions)
        params: dict[str, str | int | None] = {}

        for qid, sd in slot_map.items():
            ans = result["answers"].get(qid, {})
            if sd["type"] == "noul":
                # noul: p[1] = "yes" 概率; >0.5 则参数存在 → regex 提取值
                yes_prob = ans.get("noul", 0.0)
                if yes_prob > 0.5:
                    extracted = self._regex_extract(state, sd.get("extract", ""))
                    params[sd["slot"]] = extracted
                    logger.debug("param %s: noul=%.3f → 提取 %r", sd["slot"], yes_prob, extracted)
                else:
                    params[sd["slot"]] = None
                    logger.debug("param %s: noul=%.3f → 无", sd["slot"], yes_prob)
            elif sd["type"] == "score":
                score = ans.get("score", 0.0)
                # score 映射整数 — scale 定义乘数
                scale = sd.get("scale", 1)
                val = max(1, round(score * scale))
                params[sd["slot"]] = val
                logger.debug("param %s: score=%.1f → %d", sd["slot"], score, val)

        return params

    def decide(self, state: str, whitelist: dict[str, str] | None = None) -> ToolDecision:
        """一步到位: 选工具 + 提参数 (select_tool + extract_params)。

        低置信度降级时不提参数 (调用方走 LLM 自行解析)。
        tool_id="none" 时不提参数 (无需工具)。
        """
        decision = self.select_tool(state, whitelist)

        if decision.fell_back or decision.tool_id == "none":
            return decision

        try:
            params = self.extract_params(state, decision.tool_id)
            # ToolDecision is frozen-ish Pydantic — reconstruct with params
            updated = decision.model_copy(update={"params": params})
            return updated
        except Exception as e:
            logger.warning("参数提取失败 (tool=%s): %s — 返回无参数决策", decision.tool_id, e)
            return decision

    def metrics(self) -> dict[str, int | float]:
        """返回进程内指标快照 (total / fell_back / per-tool / avg_latency_ms)。"""
        total = self._metrics.get("total", 0)
        fell_back = self._metrics.get("fell_back", 0)
        latency_sum = self._metrics.get("latency_ms_sum", 0.0)
        per_tool = {k[5:]: v for k, v in self._metrics.items() if k.startswith("tool:")}
        return {
            "total": total,
            "fell_back": fell_back,
            "fallback_rate": round(fell_back / total, 4) if total else 0.0,
            "avg_latency_ms": round(latency_sum / total, 2) if total else 0.0,
            "per_tool": per_tool,
        }

    @staticmethod
    def _regex_extract(text: str, pattern: str) -> str | None:
        """从 text 中用 pattern 提取第一个匹配组 (无组则全匹配)。"""
        if not pattern:
            return None
        m = re.search(pattern, text, re.IGNORECASE)
        if not m:
            return None
        return m.group(1) if m.groups() else m.group(0)
