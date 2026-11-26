from __future__ import annotations

import os

import pytest

# laya-mlx is an optional dependency (present in the shared venv, maybe not in CI) — importorskip skips gracefully
laya_mlx = pytest.importorskip("laya_mlx")

# model cache check — skip when uncached (CI macos-14 has no laya model, do not download)
_cache = os.environ.get("HF_HUB_CACHE") or os.path.expanduser("~/.fusion-mlx/models")
_model_dir = os.path.join(_cache, "models--convaiinnovations--laya-typed-decisions")
if not os.path.isdir(_model_dir):
    pytest.skip(f"laya model not cached ({_model_dir}) — skipping real-model tests (CI path)", allow_module_level=True)

from fusion_executor import DEFAULT_TOOL_WHITELIST, LayaToolSelector, ToolDecision  # noqa: E402
from fusion_executor.laya_tool_selector import PARAM_SLOTS  # noqa: E402


@pytest.fixture(scope="module")
def selector():
    """Module-level shared fixture — model load ~17s, reused across tests (warm latency is what matters).

    min_confidence=0.0 (no fallback) — tests tool-selection logic, not the confidence gate.
    Gate fallback is tested separately by test_low_confidence_fallback (0.99 gate).
    8-option whitelist → answer_confidence naturally ~0.3-0.7 (many options, max prob spread out).
    """
    return LayaToolSelector(min_confidence=0.0)


def test_select_tool_file_edit(selector: LayaToolSelector):
    """'edit src/main.py bug' → file_edit (no fallback)."""
    d = selector.select_tool("I need to edit the file src/main.py to fix a bug")
    assert isinstance(d, ToolDecision)
    assert d.tool_id == "file_edit"
    assert not d.fell_back
    assert d.confidence > 0
    assert "file_edit" in d.probabilities
    assert d.latency_ms > 0
    assert d.model == "convaiinnovations/laya"


def test_select_tool_shell_exec(selector: LayaToolSelector):
    """'run pytest' → shell_exec."""
    d = selector.select_tool("run pytest tests/")
    assert d.tool_id == "shell_exec"
    assert not d.fell_back


def test_select_tool_code_search(selector: LayaToolSelector):
    """'find TODO' → code_search."""
    d = selector.select_tool("find all TODO comments in the codebase")
    assert d.tool_id == "code_search"


def test_select_tool_none(selector: LayaToolSelector):
    """'hello' → none (no tool needed)."""
    d = selector.select_tool("hello, how are you today?")
    assert d.tool_id == "none"
    assert not d.fell_back


def test_select_tool_probabilities_sum(selector: LayaToolSelector):
    """probability distribution must cover every whitelist key and sum to ≈ 1."""
    d = selector.select_tool("edit config.yaml")
    total = sum(d.probabilities.values())
    assert abs(total - 1.0) < 0.05, f"probability sum {total} deviates from 1.0"
    for tid in DEFAULT_TOOL_WHITELIST:
        assert tid in d.probabilities, f"whitelist key {tid} missing from the probability distribution"


def test_low_confidence_fallback():
    """confidence < gate → fell_back=True, tool_id='llm_fallback'."""
    # gate set to 0.99 — nearly every decision falls back (exercises the fallback path, not a real scenario)
    sel = LayaToolSelector(min_confidence=0.99)
    d = sel.select_tool("edit main.py")
    assert d.fell_back
    assert d.tool_id == "llm_fallback"
    # on fallback the original confidence + probabilities are still returned (for caller audit)
    assert d.confidence >= 0
    assert len(d.probabilities) > 0


def test_decide_with_params(selector: LayaToolSelector):
    """decide() = select_tool + extract_params — file_edit extracts file_path."""
    d = selector.decide("edit the file src/auth/login.py to add logging")
    assert d.tool_id == "file_edit"
    if not d.fell_back:
        assert "file_path" in d.params
        # the regex should extract the .py path
        fp = d.params.get("file_path")
        assert fp is not None
        assert ".py" in fp


def test_decide_none_no_params(selector: LayaToolSelector):
    """no param extraction when tool_id='none'."""
    d = selector.decide("hello there")
    assert d.tool_id == "none"
    assert d.params == {}


def test_custom_whitelist(selector: LayaToolSelector):
    """custom whitelist — different workflows, different tool sets."""
    custom = {
        "deploy": "deploy the application to production",
        "rollback": "rollback the last deployment",
        "none": "no action needed",
    }
    d = selector.select_tool("deploy to production now", whitelist=custom)
    assert d.tool_id in ("deploy", "rollback", "none", "llm_fallback")
    # the probability distribution should contain only the custom keys
    for k in d.probabilities:
        assert k in custom


def test_empty_whitelist_rejected(selector: LayaToolSelector):
    """empty whitelist → ValueError."""
    with pytest.raises(ValueError, match="whitelist"):
        selector.select_tool("anything", whitelist={})


def test_metrics_track(selector: LayaToolSelector):
    """metric counters: total/fell_back/per_tool/avg_latency."""
    selector.select_tool("edit a.py")
    selector.select_tool("run make test")
    m = selector.metrics()
    assert m["total"] >= 2
    assert m["avg_latency_ms"] > 0
    assert isinstance(m["per_tool"], dict)


def test_warm_latency_under_15ms(selector: LayaToolSelector):
    """AC8 acceptance: warm decision latency < 15ms.

    The python backend calls laya_mlx.Agent.system_one directly (in-process MLX eval).
    ~7ms when fusion-mlx is not running (exclusive Metal device); when fusion-mlx runs, multi-model
    contention on the Metal device inflates latency to ~110-140ms (15-20x). This is MLX device-level
    contention, not laya latency itself. AC8 must be measured with fusion-mlx stopped (isolating contention).
    """
    import httpx

    mlx_url = os.environ.get("FUSION_MLX_URL", "http://localhost:11434/v1").rstrip("/")
    try:
        httpx.get(mlx_url + "/models", timeout=3.0)
        pytest.skip(
            "fusion-mlx running — MLX Metal device multi-model contention inflates latency (~110ms), not laya itself. Stop fusion-mlx to measure true AC8"
        )
    except httpx.RequestError:
        pass

    selector.select_tool("warmup edit a.py")
    selector.select_tool("warmup run test")

    latencies = []
    for s in ["edit a.py", "run pytest", "find TODO", "hello", "edit b.py"]:
        d = selector.select_tool(s)
        latencies.append(d.latency_ms)

    latencies.sort()
    median = latencies[len(latencies) // 2]
    assert median < 15.0, f"warm median latency {median:.1f}ms exceeds the AC8 15ms gate (all: {latencies})"


def test_http_backend_latency_under_15ms():
    """AC8 acceptance (HTTP path): HTTP backend decision latency < 15ms (production default, server-side warm model).

    Requires fusion-mlx running (~/fusion/fusion-mlx/start.sh start) + the laya model resident server-side.
    No server → skip. Server-side multi-model contention (laya evicted) → warmup still >100ms → skip
    (not laya latency, but server-side model swap-in/out).
    committed evidence: benchmarks/results/laya-tool-selection/report.json (backend=http, p50=6.2ms).
    """
    import httpx

    # Issue #60: single-point resolution — explicit key wins, no secret default-value literals
    from fusion_core.config import client_key, default_mlx_base_url

    api_key = client_key()
    url = default_mlx_base_url().rstrip("/") + "/laya/decide"
    try:
        resp = httpx.post(
            url,
            json={"prompt": "ping", "questions": {"t": {"type": "choice", "criteria": {"a": "x", "b": "y"}}}},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5.0,
        )
    except httpx.ConnectError:
        pytest.skip("fusion-mlx not running — skipping HTTP backend AC8 latency test (start.sh start needed locally)")
    if resp.status_code != 200:
        pytest.skip(
            f"fusion-mlx laya/decide probe not 200 (status={resp.status_code}) — skipping HTTP backend AC8 latency test"
        )

    sel = LayaToolSelector(min_confidence=0.0, backend="http")
    warmup_lats = []
    for s in ["warmup edit a.py", "warmup run test", "warmup find TODO", "warmup hello", "warmup edit b.py"]:
        d = sel.select_tool(s)
        warmup_lats.append(d.latency_ms)
    warmup_lats.sort()
    if warmup_lats[-1] > 100.0:
        pytest.skip(
            f"fusion-mlx server-side laya model not resident (warmup {warmup_lats[-1]:.0f}ms >100ms, evicted by multi-model contention) — "
            "not laya latency, but server-side model swap-in. Measure true AC8 with exclusive fusion-mlx"
        )

    latencies = []
    for s in ["edit a.py", "run pytest", "find TODO", "hello", "edit b.py"]:
        d = sel.select_tool(s)
        latencies.append(d.latency_ms)

    latencies.sort()
    median = latencies[len(latencies) // 2]
    assert median < 15.0, f"HTTP backend warm median latency {median:.1f}ms exceeds AC8 15ms (all: {latencies})"


def test_invalid_min_confidence():
    """min_confidence out of range → ValueError."""
    with pytest.raises(ValueError):
        LayaToolSelector(min_confidence=1.5)
    with pytest.raises(ValueError):
        LayaToolSelector(min_confidence=-0.1)


def test_strip_filler_prefix_issue54():
    """issue #54: deterministic stripping of shell_exec command leading fillers — security guard no longer rejects 'the'."""
    strip = LayaToolSelector._strip_filler_prefix
    assert strip("the command echo hello world") == "echo hello world"
    assert strip("command: ls -la") == "ls -la"
    assert strip("cmd echo x") == "echo x"
    assert strip("the a command x y") == "x y"  # nested fillers (at most 3 layers stripped)
    assert strip("echo the quick brown fox") == "echo the quick brown fox"  # real commands are not stripped
    assert strip("pytest tests/") == "pytest tests/"
    assert strip("") == ""
    assert strip(None) is None


def test_regex_extract_multiline_anchor_issue54():
    """issue #54: $ anchors end-of-line (re.MULTILINE) — fed-back feedback text does not pollute extraction."""
    ex = LayaToolSelector._regex_extract
    # a feedback line follows the request line — extraction stops at the request line's end
    polluted = "run the command echo hi\n[tool shell_exec result: exit_code=0 stdout='hi']"
    assert ex(polluted, PARAM_SLOTS["shell_exec"][0]["extract"]) == "echo hi"


def test_decide_shell_exec_command_no_filler(selector: LayaToolSelector):
    """issue #54 E2E: 'run the command X' → command=X (no fillers left, executable by the security guard)."""
    d = selector.decide("run the command echo hello world")
    assert d.tool_id == "shell_exec"
    cmd = d.params.get("command")
    assert cmd is not None
    assert not cmd.startswith(("the ", "command", "result:")), f"command retains filler words: {cmd!r}"
    assert "echo" in cmd


def test_missing_laya_mlx_error(monkeypatch):
    """laya_mlx not installed → ImportError with a clear message (never silent)."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "laya_mlx":
            raise ImportError("simulated: no laya_mlx")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ImportError, match="laya-mlx"):
        LayaToolSelector()
