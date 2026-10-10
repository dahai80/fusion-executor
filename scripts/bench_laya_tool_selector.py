#!/usr/bin/env python3
"""Issue #46 benchmark: laya tool selection latency + success rate.

Measures warm decision latency (target <15ms) and tool selection accuracy
across N inputs. Run: python scripts/bench_laya_tool_selector.py
"""

from __future__ import annotations

import os
import statistics
import sys
import time

# HF cache defaults to ~/.fusion-mlx/models
_cache = os.environ.get("HF_HUB_CACHE") or os.path.expanduser("~/.fusion-mlx/models")
if os.path.isdir(_cache) and not os.environ.get("HF_HUB_CACHE"):
    os.environ["HF_HUB_CACHE"] = _cache

from fusion_executor import LayaToolSelector  # noqa: E402

# 12 测试输入 — 覆盖各工具 + none + 歧义
BENCH_INPUTS = [
    ("edit src/main.py to fix the auth bug", "file_edit"),
    ("create a new file config.yaml", "write_file"),
    ("run pytest tests/", "shell_exec"),
    ("execute make build", "shell_exec"),
    ("find all TODO comments in the codebase", "code_search"),
    ("search for function authenticate_user", "code_search"),
    ("fetch https://api.example.com/users", "web_fetch"),
    ("query the knowledge base for MLX setup", "rag_query"),
    ("click the submit button in the GUI", "gui_action"),
    ("take a screenshot of the current window", "gui_action"),
    ("hello, how are you today?", "none"),
    ("what is the meaning of life?", "none"),
]


def main() -> int:
    print("Loading laya model (convaiinnovations/laya, typed-decisions)...")
    t0 = time.perf_counter()
    sel = LayaToolSelector(min_confidence=0.0)
    print(f"Model loaded in {time.perf_counter() - t0:.1f}s\n")

    # Warmup
    for state, _ in BENCH_INPUTS[:2]:
        sel.select_tool(state)

    latencies = []
    correct = 0
    total = len(BENCH_INPUTS)

    print(f"{'Input':<50} {'Expected':<14} {'Got':<14} {'Conf':>6} {'ms':>7}")
    print("-" * 95)

    for state, expected in BENCH_INPUTS:
        d = sel.select_tool(state)
        latencies.append(d.latency_ms)
        ok = d.tool_id == expected
        correct += ok
        marker = "✓" if ok else "✗"
        print(f"{state[:50]:<50} {expected:<14} {d.tool_id:<14} {d.confidence:>6.3f} {d.latency_ms:>6.1f} {marker}")

    latencies.sort()
    avg = statistics.mean(latencies)
    p50 = latencies[len(latencies) // 2]
    p99 = latencies[int(len(latencies) * 0.99)]
    success_rate = correct / total

    print(f"\n{'=' * 95}")
    print(f"Results: {correct}/{total} correct ({success_rate:.1%})")
    print(f"Latency avg={avg:.1f}ms  p50={p50:.1f}ms  p99={p99:.1f}ms  (target <15ms)")
    print(f"Metrics: {sel.metrics()}")

    # Issue #46 acceptance: latency < 15ms, success rate high
    ok_latency = p50 < 15.0
    ok_rate = success_rate >= 0.9
    print(
        f"\nAcceptance: latency<15ms={'PASS' if ok_latency else 'FAIL'}  success>=90%={'PASS' if ok_rate else 'FAIL'}"
    )
    return 0 if (ok_latency and ok_rate) else 1


if __name__ == "__main__":
    sys.exit(main())
