#!/usr/bin/env python3
"""Issue #46 benchmark: laya tool selection vs LLM tool selection.

AC9: structural integrity (target 99.9%) = laya returns valid structured
choice (no malformed output, no crash) — achievable because laya outputs
structured data, not free-text JSON. Per AC parenthetical "(no malformed
output — laya outputs structured data)", 99.9% gates STRUCTURAL integrity,
NOT accuracy. Accuracy (correct tool) is a SEPARATE model-quality metric,
reported but not gated — laya 421M is not a perfect classifier.

Accuracy is measured at min_confidence=0.0 (raw laya, no LLM fallback gate).
In production (min_confidence=0.7), low-confidence cases fall back to LLM —
those are "handled by LLM", not laya errors. The bench lists which cases
would fall back so production behavior is explicit.

AC12: LLM baseline comparison arm — uses fusion-mlx chat completion to select
a tool from the same whitelist, compares latency + structural integrity + accuracy.

Run: python scripts/bench_laya_tool_selector.py [--compare-llm]
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time

_cache = os.environ.get("HF_HUB_CACHE") or os.path.expanduser("~/.fusion-mlx/models")
if os.path.isdir(_cache) and not os.environ.get("HF_HUB_CACHE"):
    os.environ["HF_HUB_CACHE"] = _cache

from fusion_executor import DEFAULT_TOOL_WHITELIST, LayaToolSelector  # noqa: E402

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

LLM_SYSTEM_PROMPT = """You are a tool selector. Given a user request, choose exactly ONE tool id from this whitelist:
{whitelist}

Respond with ONLY the tool id (no explanation, no JSON). If no tool is needed, respond "none"."""


def bench_laya(sel: LayaToolSelector, min_confidence: float) -> dict:
    """Benchmark laya tool selection — latency + structural_integrity + accuracy.

    min_confidence is the production fallback gate. Cases with confidence below
    it would fall back to LLM in production — listed separately, not counted as
    laya accuracy errors (LLM handles them).
    """
    backend = getattr(sel, "backend", "python")
    for state, _ in BENCH_INPUTS[:2]:
        sel.select_tool(state)

    latencies = []
    correct = 0
    structural_ok = 0
    fallback_cases = []
    total = len(BENCH_INPUTS)

    print(f"{'Input':<50} {'Expected':<14} {'Got':<14} {'Conf':>6} {'ms':>7} {'Struct':>6}")
    print("-" * 102)

    for state, expected in BENCH_INPUTS:
        try:
            d = sel.select_tool(state)
            latencies.append(d.latency_ms)
            struct_ok = d.tool_id in DEFAULT_TOOL_WHITELIST or d.tool_id == "llm_fallback"
            structural_ok += struct_ok
            ok = d.tool_id == expected
            correct += ok
            fb = d.confidence < min_confidence and d.tool_id != "none"
            if fb:
                fallback_cases.append((state[:50], expected, d.tool_id, d.confidence))
            marker = "✓" if ok else "✗"
            fb_marker = "FB" if fb else "  "
            print(
                f"{state[:50]:<50} {expected:<14} {d.tool_id:<14} {d.confidence:>6.3f} {d.latency_ms:>6.1f} {'✓' if struct_ok else '✗'} {marker} {fb_marker}"
            )
        except Exception as e:
            print(f"{state[:50]:<50} ERROR: {e}")
            latencies.append(0)

    latencies_sorted = sorted(latencies)
    avg = statistics.mean(latencies)
    p50 = latencies_sorted[len(latencies_sorted) // 2]
    p99 = latencies_sorted[min(int(len(latencies_sorted) * 0.99), len(latencies_sorted) - 1)]
    accuracy = correct / total
    struct_rate = structural_ok / total

    print(f"\n{'=' * 102}")
    print(f"Laya Results: {correct}/{total} correct ({accuracy:.1%})  [raw, min_confidence=0.0]")
    print(f"  Structural integrity: {structural_ok}/{total} ({struct_rate:.1%})  [AC9 target 99.9%]")
    print(f"  Latency avg={avg:.1f}ms  p50={p50:.1f}ms  p99={p99:.1f}ms  [AC8 target <15ms]")
    print(f"  Metrics: {sel.metrics()}")
    if fallback_cases:
        print(f"  Production fallback (conf<{min_confidence}, LLM handles): {len(fallback_cases)} cases")
        for state, exp, got, conf in fallback_cases:
            print(f"    - {state:<50} expected={exp} got={got} conf={conf:.3f}")
    else:
        print(f"  Production fallback (conf<{min_confidence}): 0 cases — all above gate")

    return {
        "accuracy": round(accuracy, 4),
        "structural_integrity": round(struct_rate, 4),
        "avg_latency_ms": round(avg, 2),
        "p50_latency_ms": round(p50, 2),
        "p99_latency_ms": round(p99, 2),
        "total": total,
        "fallback_cases": len(fallback_cases),
        "backend": backend,
    }


def bench_llm(mlx_url: str | None = None, api_key: str | None = None) -> dict:
    """AC12: LLM baseline — chat completion selects tool from whitelist.

    Compares latency + structural integrity + accuracy vs laya.
    LLM free-text → higher malformed-output risk (lower structural integrity).
    """
    import httpx

    base = (mlx_url or os.environ.get("FUSION_MLX_URL", "http://localhost:11434/v1")).rstrip("/")
    key = api_key or os.environ.get("FUSION_MLX_API_KEY", "fg-admin-key")
    model = os.environ.get("FUSION_MLX_MODEL", "mlx-community/Qwen3.5-4B-MLX-4bit")
    client = httpx.Client(timeout=60.0, headers={"Authorization": f"Bearer {key}"})

    wl_text = "\n".join(f"- {tid}: {desc}" for tid, desc in DEFAULT_TOOL_WHITELIST.items())
    system = LLM_SYSTEM_PROMPT.format(whitelist=wl_text)
    wl_keys = set(DEFAULT_TOOL_WHITELIST.keys())

    latencies = []
    correct = 0
    structural_ok = 0
    total = len(BENCH_INPUTS)

    print(f"\n{'LLM Baseline':<50} {'Expected':<14} {'Got':<14} {'ms':>7} {'Struct':>6}")
    print("-" * 95)

    for state, expected in BENCH_INPUTS:
        try:
            t0 = time.perf_counter()
            resp = client.post(
                f"{base}/chat/completions",
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": state},
                    ],
                    "max_tokens": 16,
                    "temperature": 0.0,
                },
            )
            latency_ms = (time.perf_counter() - t0) * 1000
            resp.raise_for_status()
            data = resp.json()
            raw = data["choices"][0]["message"]["content"].strip().lower()
            latencies.append(latency_ms)

            # parse tool id — LLM may add extra text, extract first word
            got = raw.split()[0].strip(".,;:!?\"'") if raw else "none"
            struct_ok = got in wl_keys
            structural_ok += struct_ok
            ok = got == expected
            correct += ok
            marker = "✓" if ok else "✗"
            print(f"{state[:50]:<50} {expected:<14} {got:<14} {latency_ms:>6.1f} {'✓' if struct_ok else '✗'} {marker}")
        except Exception as e:
            print(f"{state[:50]:<50} ERROR: {e}")
            latencies.append(0)

    latencies_sorted = sorted(latencies)
    avg = statistics.mean(latencies)
    p50 = latencies_sorted[len(latencies_sorted) // 2]
    accuracy = correct / total
    struct_rate = structural_ok / total

    print(f"\n{'=' * 95}")
    print(f"LLM Baseline Results: {correct}/{total} correct ({accuracy:.1%})")
    print(f"  Structural integrity: {structural_ok}/{total} ({struct_rate:.1%})  [free-text parse risk]")
    print(f"  Latency avg={avg:.1f}ms  p50={p50:.1f}ms")

    return {
        "accuracy": round(accuracy, 4),
        "structural_integrity": round(struct_rate, 4),
        "avg_latency_ms": round(avg, 2),
        "p50_latency_ms": round(p50, 2),
        "total": total,
        "model": model,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue #46 laya tool selection benchmark")
    parser.add_argument("--compare-llm", action="store_true", help="AC12: add LLM baseline comparison arm")
    parser.add_argument("--backend", choices=["python", "http"], default="python", help="laya backend (default python)")
    args = parser.parse_args()

    print(f"Loading laya model (backend={args.backend})...\n")
    t0 = time.perf_counter()
    sel = LayaToolSelector(min_confidence=0.0, backend=args.backend)
    print(f"Model loaded in {time.perf_counter() - t0:.1f}s\n")

    prod_min_conf = 0.7
    laya_result = bench_laya(sel, prod_min_conf)

    # AC8: latency <15ms — 两 backend 均满足 (各自环境):
    #   - HTTP backend: 服务端 warm 模型, p50~5-7ms (fusion-mlx 须运行)
    #   - python backend: in-process MLX eval, p50~7ms (fusion-mlx 须停止, 否则
    #     Metal device 多模型争用膨胀到 ~110-140ms — 非 laya 延迟, 是设备争用)
    bk = laya_result["backend"]
    ok_latency = laya_result["p50_latency_ms"] < 15.0
    ok_struct = laya_result["structural_integrity"] >= 0.999
    contention_note = ""
    if bk == "python":
        try:
            import httpx

            httpx.get("http://localhost:11434/v1/models", timeout=1.0)
            contention_note = "  ⚠ fusion-mlx 运行中 — Metal 争用膨胀延迟, 停 fusion-mlx 后测真实 AC8"
        except httpx.ConnectError:
            pass
    print(
        f"\nAC8/AC9 Acceptance (backend={bk}): latency<15ms={'PASS' if ok_latency else 'FAIL'}  "
        f"structural_integrity>=99.9%={'PASS' if ok_struct else 'FAIL'}{contention_note}"
    )
    print(
        f"  (raw accuracy={laya_result['accuracy']:.1%} — model-quality metric, NOT AC9-gated; "
        f"{laya_result['fallback_cases']} cases fall back to LLM at prod min_conf={prod_min_conf})"
    )

    results = {"laya": laya_result}

    if args.compare_llm:
        print("\n" + "=" * 95)
        print("AC12: LLM Baseline Comparison")
        print("=" * 95)
        llm_result = bench_llm()
        results["llm_baseline"] = llm_result

        print(f"\n{'=' * 95}")
        print("Comparison Summary:")
        print(f"  {'Metric':<25} {'Laya':>15} {'LLM':>15}")
        print(f"  {'-' * 55}")
        print(f"  {'accuracy (raw)':<25} {laya_result['accuracy']:>15.1%} {llm_result['accuracy']:>15.1%}")
        print(
            f"  {'structural_integrity':<25} {laya_result['structural_integrity']:>15.1%} {llm_result['structural_integrity']:>15.1%}"
        )
        print(f"  {'p50_latency_ms':<25} {laya_result['p50_latency_ms']:>15.1f} {llm_result['p50_latency_ms']:>15.1f}")

    # write report
    report_path = os.path.join(
        os.path.dirname(__file__), "..", "benchmarks", "results", "laya-tool-selection", "report.json"
    )
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(
            {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": results},
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(f"\nReport written to {report_path}")

    return 0 if (ok_latency and ok_struct) else 1


if __name__ == "__main__":
    sys.exit(main())
