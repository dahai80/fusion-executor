"""Example 09: laya-mlx deterministic tool selection (Issue #46).

Replaces LLM-generated tool call JSON with laya-mlx `choice` primitive.
laya selects the best tool from a whitelist in ~5-7ms (warm), outputs
structured choice + confidence — no malformed JSON, no hallucinated tools.

Run: python examples/09_laya_tool_selector.py
"""

from __future__ import annotations

import os

# HF cache: fusion monorepo convention (~/.fusion-mlx/models)
_cache = os.environ.get("HF_HUB_CACHE") or os.path.expanduser("~/.fusion-mlx/models")
if os.path.isdir(_cache) and not os.environ.get("HF_HUB_CACHE"):
    os.environ["HF_HUB_CACHE"] = _cache

from fusion_executor import DEFAULT_TOOL_WHITELIST, LayaToolSelector  # noqa: E402


def main() -> None:
    print("=== Issue #46: laya-mlx Deterministic Tool Selection ===\n")

    # min_confidence=0.7 — low-confidence decisions fall back to LLM (issue requirement)
    selector = LayaToolSelector(min_confidence=0.7)

    # 1. Tool selection with default whitelist
    print("--- Tool Selection (default whitelist) ---")
    print(f"Whitelist: {list(DEFAULT_TOOL_WHITELIST.keys())}\n")

    requests = [
        "edit src/auth.py to add rate limiting",
        "run pytest tests/test_auth.py",
        "find all uses of deprecated_api()",
        "hello, what's the weather?",
    ]

    for req in requests:
        d = selector.select_tool(req)
        status = "fallback→LLM" if d.fell_back else d.tool_id
        print(f"  {req}")
        print(f"    → tool={status}  confidence={d.confidence:.3f}  latency={d.latency_ms:.1f}ms")
        top3 = sorted(d.probabilities.items(), key=lambda x: -x[1])[:3]
        print(f"    top3: {top3}")
        print()

    # 2. Full decide() = select_tool + extract_params
    print("--- Full Decide (tool + parameter extraction) ---")
    d = selector.decide("edit the file src/config.py to add timeout")
    print(f"  tool={d.tool_id}  params={d.params}")
    print()

    # 3. Custom whitelist (different workflow)
    print("--- Custom Whitelist (deploy workflow) ---")
    deploy_wl = {
        "deploy": "deploy application to a server",
        "rollback": "rollback the last deployment",
        "scale": "scale the deployment up or down",
        "none": "no action needed",
    }
    d = selector.select_tool("rollback the last production deploy", whitelist=deploy_wl)
    print(f"  tool={d.tool_id}  confidence={d.confidence:.3f}")
    print(f"  probabilities: {d.probabilities}")
    print()

    # 4. Metrics
    print("--- Metrics ---")
    print(f"  {selector.metrics()}")


if __name__ == "__main__":
    main()
