from __future__ import annotations

import logging
import os
import re
import time
from collections import Counter
from typing import Any

from fusion_core.config import client_key, default_mlx_base_url

from .models import ToolDecision

logger = logging.getLogger("fusion_executor.laya")

# Issue #60 (config Phase 2.2): single-point key/URL resolution — fusion_core.config; this repo does not
# copy _resolve functions and keeps no secret default-value literals (config-conventions §3 illegal in prod).
# client_key: new name + legacy-name alias chain during migration (converged inside fusion_core; this repo never references the old name);
# dev missing key = "" + warning, prod missing key = RuntimeError.
# default_mlx_base_url: default http://localhost:11434/v1.

# Issue #46: default tool whitelist — covers fusion-executor's own tools + common agent tools.
# Callers can pass a whitelist dict to override (different workflows use different tool sets).
DEFAULT_TOOL_WHITELIST: dict[str, str] = {
    "code_search": "search the codebase for text, functions, variables, or symbols (grep/find/locate)",
    "file_edit": "modify existing file content (edit, patch, replace function)",
    "shell_exec": "execute a shell command, run tests or build tools (pytest, make, cargo, npm, bash)",
    "write_file": "create or overwrite a whole file",
    "web_fetch": "fetch URL content from the web",
    "rag_query": "query knowledge base / documentation for answers",
    "gui_action": "interact with macOS GUI (click, type, screenshot, window control)",
    "none": "no tool needed, direct LLM response (greeting, question, conversation)",
}

# Parameter slot definitions: tool_id -> list of (slot_name, question_type, instructions, criteria)
# noul: yes/no judgment "does the request specify X" → if yes, regex-extract the value
# score: 0-N rating → mapped to an integer (e.g. result count)
# Keep it simple — laya judges whether a parameter appears, regex extracts the value (Rule 5: deterministic when possible, no model)
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
            "scale": 1,  # score value × scale = approximate count
        },
    ],
    "shell_exec": [
        {
            "slot": "command",
            "type": "noul",
            "instructions": "Does the request specify a shell command to run?",
            # i18n: user-facing - fullwidth colon inside the pattern is functional (matches CJK input)
            "extract": r'(?:run|execute|exec)\s+(?:(?:the|a|an|this|that|following)\s+)*(?:(?:command|cmd)\s*[:：]?\s+)?["\']?(.+?)["\']?(?:\s+in\s+|$)',
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
    """Issue #46: deterministic tool selector based on the laya-mlx choice primitive.

    Replaces LLM free-form tool-call JSON generation — laya deterministically picks a tool
    from the whitelist, emitting a structured choice + confidence, eliminating malformed
    JSON and hallucinated tool calls.

    Calls laya_mlx.Agent.system_one directly (Python API), bypassing the fusion-mlx HTTP —
    lower latency (warm 5-7ms vs HTTP round-trip), no upstream endpoint dependency.

    The confidence gate uses answer_confidence (max prob), not entropy confidence —
    laya-mlx confidence.py states entropy is "not calibrated" and does not transfer across option counts.
    """

    def __init__(
        self,
        model_id: str = "convaiinnovations/laya",
        subfolder: str | None = "typed-decisions",
        min_confidence: float = 0.7,
        device: str | None = None,
        hf_cache: str | None = None,
        *,
        backend: str = "python",
        mlx_url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        if min_confidence < 0 or min_confidence > 1:
            raise ValueError(f"min_confidence must be in [0,1], got {min_confidence}")
        if backend not in ("python", "http"):
            raise ValueError(f"backend must be 'python' | 'http', got {backend!r}")
        self.min_confidence = min_confidence
        self.model_id = model_id
        self.subfolder = subfolder
        self.backend = backend

        # Metric counters (in-process, not Prometheus — Python-layer decisions, not routed over UDS)
        self._metrics = Counter()

        if backend == "http":
            # AC1: HTTP backend — goes through fusion-mlx /v1/laya/decide, no local model loaded.
            # No laya_mlx import / model cache needed; fits remote calls + literal AC satisfaction.
            import httpx

            # Issue #60: explicit api_key wins; the default goes through the fusion_core client_key() single-point
            # resolution (dev missing key = "" + warning / prod missing key = RuntimeError, no default-value literal).
            key = api_key or client_key()
            base_url = (mlx_url or default_mlx_base_url()).rstrip("/")
            self._http_client = httpx.Client(timeout=30.0, headers={"Authorization": f"Bearer {key}"})
            self._decide_url = base_url + "/laya/decide"
            logger.info("LayaToolSelector HTTP backend: %s (model=%s)", self._decide_url, model_id)
            return

        # HF model cache location — default ~/.fusion-mlx/models (fusion monorepo convention)
        # HF_HUB_CACHE env overrides; mirror site HF_MIRROR=https://hf-mirror.com (user rule)
        cache = hf_cache or os.environ.get("HF_HUB_CACHE") or os.path.expanduser("~/.fusion-mlx/models")
        if os.path.isdir(cache) and not os.environ.get("HF_HUB_CACHE"):
            os.environ["HF_HUB_CACHE"] = cache

        try:
            from laya_mlx import Agent
        except ImportError as e:
            raise ImportError(
                "laya-mlx is not installed — pip install laya-mlx (or source .venv/bin/activate for the shared venv). "
                "Issue #46 deterministic tool calling depends on the laya-mlx runtime. "
                "Alternatively use backend='http' via fusion-mlx HTTP (no local laya_mlx needed)."
            ) from e

        logger.info("loading laya model %s (subfolder=%s, device=%s)", model_id, subfolder, device or "auto")
        t0 = time.perf_counter()
        self._agent = (
            Agent(model_id, subfolder=subfolder, device=device) if subfolder else Agent(model_id, device=device)
        )
        load_ms = (time.perf_counter() - t0) * 1000
        logger.info("laya model loaded in %.0fms", load_ms)

    def _invoke(self, state: str, questions: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Unified invoke entry — dispatches to the Python API or HTTP endpoint by backend.

        Both paths return the same shape: {answers: {qid: {choice/confidence/probabilities/...}}, usage, ...}
        """
        if self.backend == "http":
            return self._invoke_http(state, questions)
        return self._agent.system_one(state, questions)

    def _invoke_http(self, state: str, questions: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """AC1: HTTP backend — POST /v1/laya/decide with custom questions.

        The fusion-mlx laya endpoint accepts {prompt, questions, model?} and returns
        {model, answers: {qid: {choice, confidence, probabilities, ...}}, usage, latency_ms}.
        """
        payload: dict[str, Any] = {"prompt": state, "questions": questions}
        if self.model_id:
            payload["model"] = self.model_id
        try:
            resp = self._http_client.post(self._decide_url, json=payload)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error("laya HTTP decide failed (%s): %s", self._decide_url, e)
            raise
        # HTTP returns latency_ms (server-measured); overriding it with client-measured latency is computed by select_tool/extract_params
        logger.debug("laya HTTP decide ok: server_latency_ms=%s", data.get("latency_ms"))
        return data

    def select_tool(self, state: str, whitelist: dict[str, str] | None = None) -> ToolDecision:
        """Pick the best tool from the whitelist (choice primitive).

        Args:
            state: current context state (user request / session state)
            whitelist: tool_id -> description; None uses DEFAULT_TOOL_WHITELIST

        Returns:
            ToolDecision (no params — use extract_params to fill parameters, or call decide for one shot)
        """
        if whitelist is not None and len(whitelist) == 0:
            raise ValueError("whitelist must not be empty")
        wl = whitelist if whitelist is not None else DEFAULT_TOOL_WHITELIST

        questions = {
            "tool": {
                "type": "choice",
                "instructions": "Which tool should handle this request?",
                "criteria": wl,
            }
        }

        t0 = time.perf_counter()
        result = self._invoke(state, questions)
        latency_ms = (time.perf_counter() - t0) * 1000

        ans = result["answers"]["tool"]
        tool_id = ans.get("choice", "none")
        # answer_confidence = max(p) — the gate metric (not entropy confidence)
        # the HTTP backend has no answer_confidence field → recompute as max(probabilities)
        probs = ans.get("probabilities", {})
        confidence = ans.get("answer_confidence", max(probs.values()) if probs else ans.get("confidence", 0.0))

        # "none" = "no tool needed" is a positive decision, not uncertainty — the gate does not trigger fallback (issue #46: none → skip tool calling)
        fell_back = confidence < self.min_confidence and tool_id != "none"
        if fell_back:
            logger.warning(
                "laya tool selection confidence %.4f < gate %.2f → LLM fallback (state=%s, choice=%s)",
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
        """Extract parameter slots for the selected tool (noul/score primitives + regex).

        laya judges whether a parameter appears (noul yes/no) or a quantity (score 0-N);
        regex extracts the concrete value — no LLM (Rule 5: deterministic when possible, no model).
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
            # noul: default labels {"false","true"} — don't pass criteria/labels, use defaults
            # score: criteria is a list (per-level descriptions)
            if sd["type"] == "score":
                q["criteria"] = sd["criteria"]
            questions[qid] = q

        if not questions:
            return {}

        result = self._invoke(state, questions)
        params: dict[str, str | int | None] = {}

        for qid, sd in slot_map.items():
            ans = result["answers"].get(qid, {})
            if sd["type"] == "noul":
                # noul: p[1] = "yes" probability; >0.5 means the parameter exists → regex-extract the value
                yes_prob = ans.get("noul", 0.0)
                if yes_prob > 0.5:
                    extracted = self._regex_extract(state, sd.get("extract", ""))
                    # issue #54: shell_exec command keeps filler words ("the command echo hi")
                    # → the security guard rejects "the" — strip deterministically
                    if sd["slot"] == "command":
                        extracted = self._strip_filler_prefix(extracted)
                    params[sd["slot"]] = extracted
                    logger.debug("param %s: noul=%.3f → extracted %r", sd["slot"], yes_prob, extracted)
                else:
                    params[sd["slot"]] = None
                    logger.debug("param %s: noul=%.3f → absent", sd["slot"], yes_prob)
            elif sd["type"] == "score":
                score = ans.get("score", 0.0)
                # score mapped to integer — scale defines the multiplier
                scale = sd.get("scale", 1)
                val = max(1, round(score * scale))
                params[sd["slot"]] = val
                logger.debug("param %s: score=%.1f → %d", sd["slot"], score, val)

        return params

    def decide(self, state: str, whitelist: dict[str, str] | None = None) -> ToolDecision:
        """One shot: pick the tool + extract params (select_tool + extract_params).

        No param extraction on low-confidence fallback (the caller parses via its own LLM path).
        No param extraction when tool_id="none" (no tool needed).
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
            logger.warning(
                "param extraction failed (tool=%s): %s — returning a decision without params", decision.tool_id, e
            )
            return decision

    def metrics(self) -> dict[str, int | float]:
        """Return the in-process metrics snapshot (total / fell_back / per-tool / avg_latency_ms)."""
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
        """Extract the first match group from text using pattern (full match when no groups).

        re.MULTILINE: `$` anchors to end-of-line instead of end-of-string — issue #54 step 2+
        result-feedback text fed back into the request pollutes extraction (command bloating into the whole
        feedback); line-end anchoring makes extraction stop at the request line.
        """
        if not pattern:
            return None
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if not m:
            return None
        return m.group(1) if m.groups() else m.group(0)

    # Issue #54: shell_exec extraction results keep natural-language filler words → the security guard treats
    # "the" as a binary and rejects it (outside the allowlist). Deterministic cleanup (Rule 5: regex over model) —
    # only strips leading articles/determiners/command lead-ins, never touches real commands
    # (first token is a white-listed binary like echo/ls).
    _FILLER_PREFIX_RE = re.compile(
        # i18n: user-facing - fullwidth colon inside the pattern is functional (matches CJK input)
        r"^(?:the|a|an|this|that|these|those|command|cmd|following)\s*[:：]?\s+",
        re.IGNORECASE,
    )

    @classmethod
    def _strip_filler_prefix(cls, value: str | None) -> str | None:
        """Strip leading filler words from the extracted value (issue #54) — 'the command echo hi' → 'echo hi'."""
        if not value:
            return value
        out = value.strip()
        for _ in range(3):  # strip at most 3 layers (extreme nesting like 'the a command x')
            stripped = cls._FILLER_PREFIX_RE.sub("", out, count=1)
            if stripped == out:
                break
            out = stripped
        return out
