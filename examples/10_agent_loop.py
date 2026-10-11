"""Example 10: AgentLoop wired through FusionSandboxExecutor (Issue #46 AC7).

Demonstrates the production wiring — agent_run() on the executor constructs a
LayaToolSelector + AgentLoop internally, runs the select→execute→feedback→repeat
loop, and returns the step log. Tool execution goes through the real sandboxed
executor path (run/grep/gui_action), not a stub.

Default backend="http" calls fusion-mlx /v1/laya/decide — no local laya_mlx model
needed. Start fusion-mlx first: ~/fusion/fusion-mlx/start.sh start

Run: python examples/10_agent_loop.py
"""

from __future__ import annotations

import json

from fusion_executor import FusionSandboxExecutor


def main() -> None:
    print("=== Issue #46 AC7: AgentLoop wired through FusionSandboxExecutor ===\n")

    # fusion-mlx must be running (~/fusion/fusion-mlx/start.sh start)
    # HTTP backend — no local laya_mlx model needed, calls /v1/laya/decide
    ex = FusionSandboxExecutor()

    # 1. Single-step: laya picks "none" → no tool, caller goes to LLM
    print("--- Single-step (no tool needed) ---")
    result = ex.agent_run("hello, what is the weather today?", max_steps=4)
    print(f"  completed={result['completed']}  final_tool={result['final_tool']}")
    print(f"  step_count={result['step_count']}  metrics={result['metrics']}")
    print()

    # 2. Tool execution: laya picks shell_exec → executor.run() → result fed back
    print("--- Tool execution (shell_exec) ---")
    result = ex.agent_run("run echo hello-agent-loop", max_steps=4)
    print(f"  completed={result['completed']}  final_tool={result['final_tool']}")
    for step in result["steps"]:
        print(
            f"  step {step['step']}: tool={step['tool_id']} conf={step['confidence']:.3f} has_result={step['has_result']}"
        )
        if step["error"]:
            print(f"    error: {step['error']}")
    print(f"  metrics={result['metrics']}")
    print()

    # 3. Code search: laya picks code_search → executor.grep() → matches
    print("--- Code search (grep) ---")
    result = ex.agent_run("find TODO in this codebase", max_steps=4)
    print(f"  completed={result['completed']}  final_tool={result['final_tool']}")
    for step in result["steps"]:
        print(f"  step {step['step']}: tool={step['tool_id']} conf={step['confidence']:.3f}")
    print()

    # 4. Custom whitelist + extra_handlers (web_fetch has no native executor method)
    print("--- Custom whitelist + extra_handler (web_fetch) ---")
    wl = {
        "shell_exec": "execute a shell command",
        "web_fetch": "fetch a URL",
        "none": "no tool needed",
    }

    def fetch_handler(params: dict) -> dict:
        url = params.get("url", "")
        return {"url": url, "content": f"<fetched {url}>"}

    result = ex.agent_run(
        "fetch https://example.com for the docs",
        max_steps=4,
        whitelist=wl,
        extra_handlers={"web_fetch": fetch_handler},
    )
    print(f"  completed={result['completed']}  final_tool={result['final_tool']}")
    print(f"  steps: {json.dumps(result['steps'], indent=2)}")
    print(f"  metrics={result['metrics']}")


if __name__ == "__main__":
    main()
