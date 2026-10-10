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
    """Issue #46 验收: warm 决策延迟 < 15ms。

    首次调用含 MLX lazy eval warmup, 跳过; 取后续 3 次中位数。
    """
    # 先 warmup 2 次 (首次 ~70ms, 二次 ~20ms)
    selector.select_tool("warmup edit a.py")
    selector.select_tool("warmup run test")

    latencies = []
    for s in ["edit a.py", "run pytest", "find TODO", "hello", "edit b.py"]:
        d = selector.select_tool(s)
        latencies.append(d.latency_ms)

    latencies.sort()
    median = latencies[len(latencies) // 2]
    assert median < 15.0, f"warm 中位延迟 {median:.1f}ms 超 15ms 门槛 (all: {latencies})"


def test_invalid_min_confidence():
    """min_confidence 越界 → ValueError."""
    with pytest.raises(ValueError):
        LayaToolSelector(min_confidence=1.5)
    with pytest.raises(ValueError):
        LayaToolSelector(min_confidence=-0.1)


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
