from __future__ import annotations

import os

import pytest

# laya-mlx 是可选依赖 (共享 venv 有, CI 可能无) — importorskip 优雅跳过
laya_mlx = pytest.importorskip("laya_mlx")

# 模型缓存检查 — 无缓存则跳过 (CI macos-14 无 laya 模型, 不下载)
_cache = os.environ.get("HF_HUB_CACHE") or os.path.expanduser("~/.fusion-mlx/models")
_model_dir = os.path.join(_cache, "models--convaiinnovations--laya-typed-decisions")
if not os.path.isdir(_model_dir):
    pytest.skip(f"laya 模型未缓存 ({_model_dir}) — 跳过真实模型测试 (CI 路径)", allow_module_level=True)

from fusion_executor import DEFAULT_TOOL_WHITELIST, LayaToolSelector, ToolDecision  # noqa: E402
from fusion_executor.laya_tool_selector import PARAM_SLOTS  # noqa: E402


@pytest.fixture(scope="module")
def selector():
    """模块级共享 — 模型加载 ~17s, 测试间复用 (warm latency 才有意义)。

    min_confidence=0.0 (不降级) — 测工具选择逻辑, 非置信度门槛。
    门槛降级由 test_low_confidence_fallback 独立测 (0.99 门槛)。
    8 选项白名单 → answer_confidence 自然 ~0.3-0.7 (option 多, max prob 分散)。
    """
    return LayaToolSelector(min_confidence=0.0)


def test_select_tool_file_edit(selector: LayaToolSelector):
    """'edit src/main.py bug' → file_edit (非降级)."""
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
    """'hello' → none (无需工具)."""
    d = selector.select_tool("hello, how are you today?")
    assert d.tool_id == "none"
    assert not d.fell_back


def test_select_tool_probabilities_sum(selector: LayaToolSelector):
    """概率分布应覆盖白名单全部 key 且和 ≈ 1."""
    d = selector.select_tool("edit config.yaml")
    total = sum(d.probabilities.values())
    assert abs(total - 1.0) < 0.05, f"概率和 {total} 偏离 1.0"
    for tid in DEFAULT_TOOL_WHITELIST:
        assert tid in d.probabilities, f"白名单 key {tid} 缺失于概率分布"


def test_low_confidence_fallback():
    """置信度 < 门槛 → fell_back=True, tool_id='llm_fallback'."""
    # 门槛设 0.99 — 几乎所有决策都降级 (验证降级路径, 非真实场景)
    sel = LayaToolSelector(min_confidence=0.99)
    d = sel.select_tool("edit main.py")
    assert d.fell_back
    assert d.tool_id == "llm_fallback"
    # 降级时仍返回原始置信度 + 概率 (供调用方审计)
    assert d.confidence >= 0
    assert len(d.probabilities) > 0


def test_decide_with_params(selector: LayaToolSelector):
    """decide() = select_tool + extract_params — file_edit 提取 file_path."""
    d = selector.decide("edit the file src/auth/login.py to add logging")
    assert d.tool_id == "file_edit"
    if not d.fell_back:
        assert "file_path" in d.params
        # regex 应提取到 .py 路径
        fp = d.params.get("file_path")
        assert fp is not None
        assert ".py" in fp


def test_decide_none_no_params(selector: LayaToolSelector):
    """tool_id='none' 时不提参数."""
    d = selector.decide("hello there")
    assert d.tool_id == "none"
    assert d.params == {}


def test_custom_whitelist(selector: LayaToolSelector):
    """自定义白名单 — 不同 workflow 不同工具集."""
    custom = {
        "deploy": "deploy the application to production",
        "rollback": "rollback the last deployment",
        "none": "no action needed",
    }
    d = selector.select_tool("deploy to production now", whitelist=custom)
    assert d.tool_id in ("deploy", "rollback", "none", "llm_fallback")
    # 概率分布应仅含自定义 key
    for k in d.probabilities:
        assert k in custom


def test_empty_whitelist_rejected(selector: LayaToolSelector):
    """空白名单 → ValueError."""
    with pytest.raises(ValueError, match="whitelist"):
        selector.select_tool("anything", whitelist={})


def test_metrics_track(selector: LayaToolSelector):
    """指标计数器: total/fell_back/per_tool/avg_latency."""
    selector.select_tool("edit a.py")
    selector.select_tool("run make test")
    m = selector.metrics()
    assert m["total"] >= 2
    assert m["avg_latency_ms"] > 0
    assert isinstance(m["per_tool"], dict)


def test_warm_latency_under_15ms(selector: LayaToolSelector):
    """AC8 验收: warm 决策延迟 < 15ms。

    python backend 直调 laya_mlx.Agent.system_one (in-process MLX eval)。
    无 fusion-mlx 运行时 ~7ms (Metal device 独占); fusion-mlx 运行时多模型
    争用 Metal device → 延迟膨胀到 ~110-140ms (15-20x)。这是 MLX 设备级
    争用, 非 laya 本身延迟。测 AC8 须在 fusion-mlx 停止时跑 (隔离争用)。
    """
    import httpx

    mlx_url = os.environ.get("FUSION_MLX_URL", "http://localhost:11434/v1").rstrip("/")
    try:
        httpx.get(mlx_url + "/models", timeout=3.0)
        pytest.skip(
            "fusion-mlx 运行中 — MLX Metal device 多模型争用膨胀延迟 (~110ms), 非 laya 本身。停 fusion-mlx 后测真实 AC8"
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
    assert median < 15.0, f"warm 中位延迟 {median:.1f}ms 超 AC8 15ms 门槛 (all: {latencies})"


def test_http_backend_latency_under_15ms():
    """AC8 验收 (HTTP 路径): HTTP backend 决策延迟 < 15ms (生产默认, 服务端 warm 模型)。

    需 fusion-mlx 运行 (~/fusion/fusion-mlx/start.sh start) + laya 模型服务端常驻。
    无 server → skip。服务端多模型争用 (laya 被驱逐) → warmup 仍 >100ms → skip
    (非 laya 延迟, 是服务端模型换入换出)。
    committed evidence: benchmarks/results/laya-tool-selection/report.json (backend=http, p50=6.2ms)。
    """
    import httpx

    # Issue #60: 单点解析 — 显式 key 优先, 无 secret 默认值字面量
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
        pytest.skip("fusion-mlx 未运行 — 跳过 HTTP backend AC8 延迟测试 (本地需 start.sh start)")
    if resp.status_code != 200:
        pytest.skip(f"fusion-mlx laya/decide 探活非 200 (status={resp.status_code}) — 跳过 HTTP backend AC8 延迟测试")

    sel = LayaToolSelector(min_confidence=0.0, backend="http")
    warmup_lats = []
    for s in ["warmup edit a.py", "warmup run test", "warmup find TODO", "warmup hello", "warmup edit b.py"]:
        d = sel.select_tool(s)
        warmup_lats.append(d.latency_ms)
    warmup_lats.sort()
    if warmup_lats[-1] > 100.0:
        pytest.skip(
            f"fusion-mlx 服务端 laya 模型未常驻 (warmup {warmup_lats[-1]:.0f}ms >100ms, 多模型争用驱逐) — "
            "非 laya 延迟, 是服务端模型换入。独占 fusion-mlx 后测真实 AC8"
        )

    latencies = []
    for s in ["edit a.py", "run pytest", "find TODO", "hello", "edit b.py"]:
        d = sel.select_tool(s)
        latencies.append(d.latency_ms)

    latencies.sort()
    median = latencies[len(latencies) // 2]
    assert median < 15.0, f"HTTP backend warm 中位延迟 {median:.1f}ms 超 AC8 15ms (all: {latencies})"


def test_invalid_min_confidence():
    """min_confidence 越界 → ValueError."""
    with pytest.raises(ValueError):
        LayaToolSelector(min_confidence=1.5)
    with pytest.raises(ValueError):
        LayaToolSelector(min_confidence=-0.1)


def test_strip_filler_prefix_issue54():
    """issue #54: shell_exec command 前导填充词确定性剥除 — security guard 不再拒 'the'."""
    strip = LayaToolSelector._strip_filler_prefix
    assert strip("the command echo hello world") == "echo hello world"
    assert strip("command: ls -la") == "ls -la"
    assert strip("cmd echo x") == "echo x"
    assert strip("the a command x y") == "x y"  # 嵌套填充 (最多剥 3 层)
    assert strip("echo the quick brown fox") == "echo the quick brown fox"  # 真实命令不剥
    assert strip("pytest tests/") == "pytest tests/"
    assert strip("") == ""
    assert strip(None) is None


def test_regex_extract_multiline_anchor_issue54():
    """issue #54: $ 锚行尾 (re.MULTILINE) — 回灌 feedback 文本不污染提取."""
    ex = LayaToolSelector._regex_extract
    # 请求行后跟 feedback 行 — 提取止于请求行行尾
    polluted = "run the command echo hi\n[tool shell_exec result: exit_code=0 stdout='hi']"
    assert ex(polluted, PARAM_SLOTS["shell_exec"][0]["extract"]) == "echo hi"


def test_decide_shell_exec_command_no_filler(selector: LayaToolSelector):
    """issue #54 E2E: 'run the command X' → command=X (无填充词, security guard 可执行)."""
    d = selector.decide("run the command echo hello world")
    assert d.tool_id == "shell_exec"
    cmd = d.params.get("command")
    assert cmd is not None
    assert not cmd.startswith(("the ", "command", "result:")), f"command 残留填充词: {cmd!r}"
    assert "echo" in cmd


def test_missing_laya_mlx_error(monkeypatch):
    """laya_mlx 未安装 → ImportError 带清晰提示 (非静默)."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "laya_mlx":
            raise ImportError("simulated: no laya_mlx")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ImportError, match="laya-mlx"):
        LayaToolSelector()
